// Command fakeclient stands in for web when testing the relay (or,
// later, a real amallo) from outside the Go test binary — see the build
// plan's Steps 3-5. It sends one HTTP-shaped request over the relay to a
// paired agent (fakeagent, or eventually amallo) and prints the streamed
// response, with an optional mid-stream CANCEL for exercising the abort
// path.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/41tunnels/relay/internal/testclient"
	"github.com/41tunnels/relay/internal/wire"
)

const requestStreamID = 1

// Client-initiated stream ids are odd (spec §6), and a new session starts
// its numbering fresh — but reusing 1 across the break would make a stale
// frame from the old session indistinguishable from the retry.
const retryStreamID = 3

func main() {
	relayURL := flag.String("relay", "ws://localhost:8080", "relay base URL (ws:// or wss://)")
	pairFlag := flag.String("pair", "", "pair_id, base64url (required — printed by fakeagent on startup)")
	pskFlag := flag.String("psk", "", "psk, base64url (required unless -insecure)")
	insecure := flag.Bool("insecure", false, "skip E2E encryption — dev only, matches amallo's AMALLO_RELAY_INSECURE=1")
	method := flag.String("method", "GET", "HTTP method")
	path := flag.String("path", "/api/tags", "HTTP path")
	body := flag.String("body", "", "request body")
	headerFlag := flag.String("header", "", "comma-separated k:v headers, e.g. 'content-type:application/json'")
	cancelAfter := flag.Duration("cancel-after", 0, "if >0, send CANCEL this long after the request starts")
	breakSession := flag.Bool("break-session", false, "after the first response, send a frame this session cannot open, then repeat the request — checks the peer recovers the session in place instead of dropping the connection")
	timeout := flag.Duration("timeout", 30*time.Second, "overall timeout")
	flag.Parse()

	pairID, psk, err := parseClientPairing(*pairFlag, *pskFlag, *insecure)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	t, err := testclient.Dial(ctx, *relayURL, wire.RoleClient, pairID, psk, *insecure)
	if err != nil {
		log.Fatalf("fakeclient: dial: %v", err)
	}
	defer t.Close()
	fmt.Fprintln(os.Stderr, "fakeclient: connected")

	reqJSON, err := json.Marshal(map[string]any{
		"m": strings.ToUpper(*method),
		"p": *path,
		"h": parseHeaders(*headerFlag),
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := t.SendInner(ctx, wire.InnerFrame{Type: wire.InnerReq, StreamID: requestStreamID, Payload: reqJSON}); err != nil {
		log.Fatalf("fakeclient: send REQ: %v", err)
	}
	if *body != "" {
		if err := t.SendInner(ctx, wire.InnerFrame{Type: wire.InnerReqBody, StreamID: requestStreamID, Payload: []byte(*body)}); err != nil {
			log.Fatalf("fakeclient: send REQ_BODY: %v", err)
		}
	}
	if err := t.SendInner(ctx, wire.InnerFrame{Type: wire.InnerReqEnd, StreamID: requestStreamID}); err != nil {
		log.Fatalf("fakeclient: send REQ_END: %v", err)
	}

	if *cancelAfter > 0 {
		go func() {
			time.Sleep(*cancelAfter)
			fmt.Fprintln(os.Stderr, "fakeclient: sending CANCEL")
			_ = t.SendInner(ctx, wire.InnerFrame{Type: wire.InnerCancel, StreamID: requestStreamID})
		}()
	}

	readResponse(ctx, t)

	if *breakSession {
		breakAndRetry(ctx, t, reqJSON, *body)
	}
}

// breakAndRetry sends a frame the peer's session cannot open and then
// repeats the request on the same connection.
//
// A peer that treats an unopenable frame as fatal fails the second
// request: its whole socket is gone and, on the agent side, so is its
// registration and the OpenAI endpoint's lane with it. A peer that scopes
// the failure to the session retires it, re-handshakes, and answers.
func breakAndRetry(ctx context.Context, t *testclient.Transport, reqJSON []byte, body string) {
	fmt.Fprintln(os.Stderr, "fakeclient: breaking the session with an unopenable frame")
	if err := t.SendUnopenableCiphertext(ctx); err != nil {
		log.Fatalf("fakeclient: send unopenable frame: %v", err)
	}

	// The peer retires its session and offers a new HELLO, and it is
	// RecvInner that carries that lifecycle — so the reader has to be
	// running for the new session to be built at all. Start it first, then
	// wait for the epoch to move before sending anything: a frame sealed
	// under the dead session would just be dropped by the peer.
	before := t.Epoch()
	done := make(chan struct{})
	go func() {
		defer close(done)
		readResponse(ctx, t)
	}()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && t.Epoch() == before {
		time.Sleep(50 * time.Millisecond)
	}
	if t.Epoch() == before {
		log.Fatal("fakeclient: the peer never rebuilt the session")
	}
	fmt.Fprintln(os.Stderr, "fakeclient: session rebuilt in place; retrying on the same connection")

	if err := t.SendInner(ctx, wire.InnerFrame{Type: wire.InnerReq, StreamID: retryStreamID, Payload: reqJSON}); err != nil {
		log.Fatalf("fakeclient: retry REQ: %v", err)
	}
	if body != "" {
		_ = t.SendInner(ctx, wire.InnerFrame{Type: wire.InnerReqBody, StreamID: retryStreamID, Payload: []byte(body)})
	}
	if err := t.SendInner(ctx, wire.InnerFrame{Type: wire.InnerReqEnd, StreamID: retryStreamID}); err != nil {
		log.Fatalf("fakeclient: retry REQ_END: %v", err)
	}
	<-done
}

func parseClientPairing(pairFlag, pskFlag string, insecure bool) ([16]byte, []byte, error) {
	var pairID [16]byte
	if pairFlag == "" {
		return pairID, nil, fmt.Errorf("fakeclient: -pair is required (see fakeagent's startup output)")
	}
	pb, err := base64.RawURLEncoding.DecodeString(pairFlag)
	if err != nil || len(pb) != 16 {
		return pairID, nil, fmt.Errorf("fakeclient: -pair must be 16 raw bytes, base64url-encoded")
	}
	copy(pairID[:], pb)

	if insecure {
		return pairID, nil, nil
	}
	if pskFlag == "" {
		return pairID, nil, fmt.Errorf("fakeclient: -psk is required unless -insecure")
	}
	psk, err := base64.RawURLEncoding.DecodeString(pskFlag)
	if err != nil || len(psk) != 32 {
		return pairID, nil, fmt.Errorf("fakeclient: -psk must be 32 raw bytes, base64url-encoded")
	}
	return pairID, psk, nil
}

func parseHeaders(s string) [][2]string {
	out := [][2]string{}
	if s == "" {
		return out
	}
	for _, pair := range strings.Split(s, ",") {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) != 2 {
			continue
		}
		out = append(out, [2]string{strings.ToLower(strings.TrimSpace(kv[0])), strings.TrimSpace(kv[1])})
	}
	return out
}

// readResponse prints RESP/RESP_BODY/RESP_END as they arrive: metadata to
// stderr, body bytes to stdout — so `fakeclient ... > out.json` captures
// just the response body, matching how you'd pipe a real curl response.
func readResponse(ctx context.Context, t *testclient.Transport) {
	for {
		f, err := t.RecvInner(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nfakeclient: recv: %v\n", err)
			return
		}
		switch f.Type {
		case wire.InnerResp:
			var resp map[string]any
			_ = json.Unmarshal(f.Payload, &resp)
			fmt.Fprintf(os.Stderr, "fakeclient: RESP %v\n", resp)
		case wire.InnerRespBody:
			os.Stdout.Write(f.Payload)
		case wire.InnerRespEnd:
			fmt.Fprintln(os.Stderr, "\nfakeclient: RESP_END")
			return
		case wire.InnerError:
			fmt.Fprintf(os.Stderr, "\nfakeclient: ERROR %s\n", f.Payload)
			return
		default:
			fmt.Fprintf(os.Stderr, "\nfakeclient: unexpected inner frame type 0x%02x\n", byte(f.Type))
		}
	}
}
