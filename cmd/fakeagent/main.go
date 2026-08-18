// Command fakeagent stands in for amallo when testing the relay (or,
// later, a real amallo) from outside the Go test binary — see the build
// plan's Steps 3-5. It registers as the "agent" side of a pair and either
// echoes canned responses or proxies requests to a real HTTP upstream
// (e.g. a local Ollama), so `fakeclient`'s streaming requests and CANCEL
// handling can be exercised end to end through a real deployed relay.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/41tunnels/relay/internal/testclient"
	"github.com/41tunnels/relay/internal/wire"
)

func main() {
	relayURL := flag.String("relay", "ws://localhost:8080", "relay base URL (ws:// or wss://)")
	pairFlag := flag.String("pair", "", "pair_id, base64url (generated and printed if empty)")
	pskFlag := flag.String("psk", "", "psk, base64url (generated and printed if empty)")
	insecure := flag.Bool("insecure", false, "skip E2E encryption — dev only, matches amallo's AMALLO_RELAY_INSECURE=1")
	upstream := flag.String("upstream", "", "if set, proxy requests to this HTTP base URL (e.g. http://127.0.0.1:11434); otherwise echo a canned response")
	flag.Parse()

	pairID, psk, err := resolvePairing(*pairFlag, *pskFlag)
	if err != nil {
		log.Fatal(err)
	}

	pairB64 := base64.RawURLEncoding.EncodeToString(pairID[:])
	pskB64 := base64.RawURLEncoding.EncodeToString(psk)
	fmt.Fprintf(os.Stderr, "fakeagent: pair_id=%s\n", pairB64)
	fmt.Fprintf(os.Stderr, "fakeagent: psk=%s\n", pskB64)
	fmt.Fprintf(os.Stderr, "fakeagent: pairing uri: opencharui://pair?v=1&r=%s&i=%s&k=%s\n", *relayURL, pairB64, pskB64)
	if *upstream != "" {
		fmt.Fprintf(os.Stderr, "fakeagent: proxying to %s\n", *upstream)
	} else {
		fmt.Fprintln(os.Stderr, "fakeagent: no -upstream set, echoing canned responses")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	t, err := testclient.Dial(ctx, *relayURL, wire.RoleAgent, pairID, psk, *insecure)
	if err != nil {
		log.Fatalf("fakeagent: dial: %v", err)
	}
	defer t.Close()
	fmt.Fprintln(os.Stderr, "fakeagent: connected, waiting for requests (Ctrl-C to stop)")

	a := &agent{t: t, upstream: *upstream, streams: make(map[uint32]*streamState)}
	a.run(ctx)
}

func resolvePairing(pairFlag, pskFlag string) ([16]byte, []byte, error) {
	if pairFlag == "" && pskFlag == "" {
		return testclient.RandomPairAndPSK()
	}
	var pairID [16]byte
	pb, err := base64.RawURLEncoding.DecodeString(pairFlag)
	if err != nil || len(pb) != 16 {
		return pairID, nil, fmt.Errorf("fakeagent: -pair must be 16 raw bytes, base64url-encoded")
	}
	copy(pairID[:], pb)
	psk, err := base64.RawURLEncoding.DecodeString(pskFlag)
	if err != nil || len(psk) != 32 {
		return pairID, nil, fmt.Errorf("fakeagent: -psk must be 32 raw bytes, base64url-encoded")
	}
	return pairID, psk, nil
}

type reqHeader struct {
	M string      `json:"m"`
	P string      `json:"p"`
	H [][2]string `json:"h"`
}

type streamState struct {
	bodyWriter *io.PipeWriter
	cancel     context.CancelFunc
	// Which session this request arrived under. A response is only sent
	// while that session is still current — see testclient.SendInnerAt.
	epoch uint64
}

type agent struct {
	t        *testclient.Transport
	upstream string

	mu      sync.Mutex
	streams map[uint32]*streamState
}

func (a *agent) run(ctx context.Context) {
	for {
		f, err := a.t.RecvInner(ctx)
		if err != nil {
			if errors.Is(err, testclient.ErrPeerOffline) {
				// A client disconnecting is routine — amallo's own relay
				// connection (and this pair's registration) stays up
				// regardless of whether a client happens to be attached
				// right now. Only exit on a real connection failure or a
				// relay-initiated going_away.
				fmt.Fprintln(os.Stderr, "fakeagent: client disconnected, waiting for a new one")
				continue
			}
			fmt.Fprintf(os.Stderr, "fakeagent: recv: %v\n", err)
			return
		}
		switch f.Type {
		case wire.InnerReq:
			a.handleReq(ctx, f)
		case wire.InnerReqBody:
			a.handleReqBody(f)
		case wire.InnerReqEnd:
			a.handleReqEnd(f)
		case wire.InnerCancel:
			a.handleCancel(f)
		default:
			fmt.Fprintf(os.Stderr, "fakeagent: unexpected inner frame type 0x%02x on stream %d\n", byte(f.Type), f.StreamID)
		}
	}
}

func (a *agent) handleReq(ctx context.Context, f wire.InnerFrame) {
	var h reqHeader
	if err := json.Unmarshal(f.Payload, &h); err != nil {
		fmt.Fprintf(os.Stderr, "fakeagent: bad REQ on stream %d: %v\n", f.StreamID, err)
		return
	}
	fmt.Fprintf(os.Stderr, "fakeagent: stream %d: %s %s\n", f.StreamID, h.M, h.P)

	pr, pw := io.Pipe()
	streamCtx, cancel := context.WithCancel(ctx)
	epoch := a.t.Epoch()
	a.mu.Lock()
	a.streams[f.StreamID] = &streamState{bodyWriter: pw, cancel: cancel, epoch: epoch}
	a.mu.Unlock()

	go a.serve(streamCtx, f.StreamID, epoch, h, pr)
}

func (a *agent) handleReqBody(f wire.InnerFrame) {
	st := a.lookupStream(f.StreamID)
	if st == nil {
		return
	}
	// PipeWriter.Write blocks until serve()'s reader consumes it — this is
	// the same backpressure discipline as everywhere else in the system:
	// a slow upstream naturally stalls RecvInner from pulling the next
	// frame off the wire.
	_, _ = st.bodyWriter.Write(f.Payload)
}

func (a *agent) handleReqEnd(f wire.InnerFrame) {
	st := a.lookupStream(f.StreamID)
	if st == nil {
		return
	}
	_ = st.bodyWriter.Close()
}

func (a *agent) handleCancel(f wire.InnerFrame) {
	a.mu.Lock()
	st := a.streams[f.StreamID]
	delete(a.streams, f.StreamID)
	a.mu.Unlock()
	if st == nil {
		return
	}
	st.cancel()
	_ = st.bodyWriter.CloseWithError(context.Canceled)
}

func (a *agent) lookupStream(id uint32) *streamState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.streams[id]
}

func (a *agent) serve(ctx context.Context, streamID uint32, epoch uint64, h reqHeader, body io.Reader) {
	defer func() {
		a.mu.Lock()
		delete(a.streams, streamID)
		a.mu.Unlock()
	}()

	if a.upstream == "" {
		a.serveEcho(ctx, streamID, epoch, h, body)
		return
	}
	a.serveProxy(ctx, streamID, epoch, h, body)
}

func (a *agent) serveEcho(ctx context.Context, streamID uint32, epoch uint64, h reqHeader, body io.Reader) {
	bodyBytes, _ := io.ReadAll(body)

	respHeaders := [][2]string{{"content-type", "application/json"}}
	respJSON, _ := json.Marshal(map[string]any{"s": 200, "h": respHeaders})
	if err := a.t.SendInnerAt(ctx, epoch, wire.InnerFrame{Type: wire.InnerResp, StreamID: streamID, Payload: respJSON}); err != nil {
		return
	}

	echo, _ := json.Marshal(map[string]any{"echo": true, "method": h.M, "path": h.P, "bodyLen": len(bodyBytes)})
	if err := a.t.SendInnerAt(ctx, epoch, wire.InnerFrame{Type: wire.InnerRespBody, StreamID: streamID, Payload: echo}); err != nil {
		return
	}
	_ = a.t.SendInnerAt(ctx, epoch, wire.InnerFrame{Type: wire.InnerRespEnd, StreamID: streamID})
}

func (a *agent) serveProxy(ctx context.Context, streamID uint32, epoch uint64, h reqHeader, body io.Reader) {
	url := a.upstream + h.P
	req, err := http.NewRequestWithContext(ctx, h.M, url, body)
	if err != nil {
		a.sendError(streamID, epoch, err)
		return
	}
	for _, kv := range h.H {
		req.Header.Add(kv[0], kv[1])
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return // cancelled: spec §6.1 — send nothing further
		}
		a.sendError(streamID, epoch, err)
		return
	}
	defer resp.Body.Close()

	respHeaders := make([][2]string, 0, len(resp.Header))
	for k, vs := range resp.Header {
		for _, v := range vs {
			respHeaders = append(respHeaders, [2]string{strings.ToLower(k), v})
		}
	}
	respJSON, _ := json.Marshal(map[string]any{"s": resp.StatusCode, "h": respHeaders})
	if err := a.t.SendInnerAt(ctx, epoch, wire.InnerFrame{Type: wire.InnerResp, StreamID: streamID, Payload: respJSON}); err != nil {
		return
	}

	buf := make([]byte, 16*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			if sendErr := a.t.SendInnerAt(ctx, epoch, wire.InnerFrame{Type: wire.InnerRespBody, StreamID: streamID, Payload: chunk}); sendErr != nil {
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if ctx.Err() != nil {
				return
			}
			a.sendError(streamID, epoch, err)
			return
		}
	}
	_ = a.t.SendInnerAt(ctx, epoch, wire.InnerFrame{Type: wire.InnerRespEnd, StreamID: streamID})
}

func (a *agent) sendError(streamID uint32, epoch uint64, err error) {
	payload, _ := json.Marshal(map[string]string{"code": "upstream_unreachable", "message": err.Error()})
	_ = a.t.SendInnerAt(context.Background(), epoch, wire.InnerFrame{Type: wire.InnerError, StreamID: streamID, Payload: payload})
}
