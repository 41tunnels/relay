// Package testclient is the shared connect/handshake/framing logic behind
// cmd/fakeagent and cmd/fakeclient — standalone processes that speak the
// real relay protocol (spec/PROTOCOL.md) for testing the relay, and later
// amallo and web, from outside the Go test binary. Nothing here is used by
// the relay server itself.
package testclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/coder/websocket"

	"github.com/OpenCharUI/relay/internal/proto"
	"github.com/OpenCharUI/relay/internal/wire"
)

var (
	// ErrPeerOffline is returned from RecvInner once the relay reports the
	// other side has disconnected. The connection itself is still up: a
	// later peer_online starts a fresh session on it (spec §4.6), so a
	// caller that keeps reading recovers without reconnecting.
	ErrPeerOffline = errors.New("testclient: peer went offline")
	// ErrGoingAway is returned from RecvInner when the relay announces a
	// graceful shutdown.
	ErrGoingAway = errors.New("testclient: relay is going away")
	// ErrNoSession is returned by SendInner when there is no established
	// session to seal under — either none yet, or the one the caller
	// captured has since been replaced.
	ErrNoSession = errors.New("testclient: no established session")
)

// maxPendingCiphertext bounds the frames held while a handshake finishes.
// The peer sends its first request the moment it has verified our CONFIRM,
// which can be before we have installed the session — spec §4.6 requires
// holding those rather than dropping them. Matches amallo's constant of
// the same name.
const maxPendingCiphertext = 16

// Transport is one connected session with the relay, from either role's
// perspective. The *connection* outlives any one session: a peer leaving
// retires the session, a peer arriving starts a new handshake on the same
// socket, and neither ends the connection (spec §4.6).
type Transport struct {
	ws     *websocket.Conn
	role   wire.Role
	pairID [16]byte
	psk    []byte

	insecure bool

	mu     sync.Mutex // guards the session fields below and serializes writes: spec §5.1's one sealing point
	sealer *proto.Sealer
	opener *proto.Opener
	epoch  uint64

	pending []wire.InnerFrame
}

// RandomPairAndPSK generates a fresh pair_id/psk (spec §4.2) — used when a
// caller wants fakeagent to mint new pairing material rather than reuse an
// existing one.
func RandomPairAndPSK() (pairID [16]byte, psk []byte, err error) {
	if _, err = rand.Read(pairID[:]); err != nil {
		return pairID, nil, err
	}
	psk = make([]byte, 32)
	if _, err = rand.Read(psk); err != nil {
		return pairID, nil, err
	}
	return pairID, psk, nil
}

// wsURLFor builds the ws(s):// URL for role from a relay base URL like
// "ws://localhost:8080" or "wss://relay.example.com".
func wsURLFor(relayURL string, role wire.Role) string {
	base := strings.TrimRight(relayURL, "/")
	if role == wire.RoleAgent {
		return base + "/v1/agent"
	}
	return base + "/v1/client"
}

// Dial connects to the relay and completes the control-channel hello.
//
// For RoleClient it then waits for the peer and completes the first E2E
// handshake, so a caller can send the moment Dial returns. For RoleAgent
// it returns as soon as the relay acknowledges the hello — an agent is
// attached and useful before any browser exists, and its sessions come and
// go underneath (see RecvInner), which is what amallo does. In insecure
// mode channel 0x01 carries raw inner-frame bytes with no AEAD wrapping at
// all; that exists solely to exercise amallo's HTTP-bridge logic before
// its crypto is wired up, and must never be used against a production
// relay.
func Dial(ctx context.Context, relayURL string, role wire.Role, pairID [16]byte, psk []byte, insecure bool) (*Transport, error) {
	url := wsURLFor(relayURL, role)
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("testclient: dial %s: %w", url, err)
	}
	ws.SetReadLimit(8 << 20)

	t := &Transport{ws: ws, role: role, pairID: pairID, psk: psk, insecure: insecure}

	hello := wire.NewHello(role, base64.RawURLEncoding.EncodeToString(pairID[:]))
	helloBytes, err := json.Marshal(hello)
	if err != nil {
		ws.CloseNow()
		return nil, err
	}
	if err := ws.Write(ctx, websocket.MessageBinary, wire.EncodeOuter(wire.ChannelControl, helloBytes)); err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("testclient: send hello: %w", err)
	}

	if err := t.expectControl(ctx, "hello_ok"); err != nil {
		ws.CloseNow()
		return nil, err
	}

	if insecure || role == wire.RoleAgent {
		return t, nil
	}

	if err := t.expectControl(ctx, "peer_online"); err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("testclient: waiting for peer: %w", err)
	}
	if err := t.startSession(ctx, nil); err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("testclient: handshake: %w", err)
	}
	return t, nil
}

// Close closes the underlying connection immediately.
func (t *Transport) Close() error { return t.ws.CloseNow() }

// Epoch identifies the current session. It changes whenever one is
// installed or retired, so a caller streaming a response can tell that the
// peer it was answering is gone — see SendInnerAt.
func (t *Transport) Epoch() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.epoch
}

func (t *Transport) expectControl(ctx context.Context, wantType string) error {
	typ, data, err := t.ws.Read(ctx)
	if err != nil {
		return err
	}
	if typ != websocket.MessageBinary {
		return fmt.Errorf("testclient: expected binary message, got %v", typ)
	}
	hdr, payload, err := wire.ParseOuter(data)
	if err != nil {
		return err
	}
	if hdr.Channel != wire.ChannelControl {
		return fmt.Errorf("testclient: expected control channel, got 0x%02x", byte(hdr.Channel))
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return err
	}
	if m["t"] != wantType {
		return fmt.Errorf("testclient: expected control %q, got %v (%+v)", wantType, m["t"], m)
	}
	return nil
}

// hsSignal is why readHandshakeFrame stopped, when it did not return a
// frame: the peer left mid-handshake, or a newer one attached and the
// CONFIRM we were waiting for will never come.
type hsSignal int

const (
	hsFrame hsSignal = iota
	hsAbandoned
	hsRestart
)

// startSession retires any current session and runs handshakes until one
// completes, is abandoned, or the connection fails. `firstHello` is a peer
// HELLO already read off the wire, if the caller has one.
func (t *Transport) startSession(ctx context.Context, firstHello []byte) error {
	t.retireSession()

	for {
		pending := make([][]byte, 0, 4)
		sealer, opener, sig, err := t.handshake(ctx, firstHello, &pending)
		if err != nil {
			return err
		}
		if sig == hsAbandoned {
			return nil
		}
		if sig == hsRestart {
			// The HELLO that triggered the restart was the signal, not a
			// frame; the new peer sends its own once we send ours.
			firstHello = nil
			continue
		}

		t.mu.Lock()
		t.sealer, t.opener = sealer, opener
		t.epoch++
		t.mu.Unlock()

		// Frames the peer sent between verifying our CONFIRM and now,
		// opened in arrival order — §5's exact-counter rule allows no
		// other. One that fails to open was sealed under a session that no
		// longer exists (a peer that was mid-request when a redial
		// displaced the previous connection); drop it rather than treat a
		// frame the peer has already given up on as fatal.
		for _, payload := range pending {
			plain, err := opener.Open([]byte{byte(wire.ChannelCiphertext), 0x00}, payload)
			if err != nil {
				continue
			}
			frames, err := wire.DecodeInnerAll(plain)
			if err != nil {
				return err
			}
			t.pending = append(t.pending, frames...)
		}
		return nil
	}
}

func (t *Transport) retireSession() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sealer, t.opener = nil, nil
	t.epoch++
}

// handshake performs the full P-256/HKDF/AES-GCM key exchange from spec
// §4, sending our HELLO/CONFIRM on channel 0x02 and validating the peer's.
func (t *Transport) handshake(ctx context.Context, firstHello []byte, pending *[][]byte) (*proto.Sealer, *proto.Opener, hsSignal, error) {
	eph, err := proto.GenerateEphemeral()
	if err != nil {
		return nil, nil, hsFrame, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, hsFrame, err
	}
	myRole := proto.RoleAgent
	peerRole := proto.RoleClient
	if t.role == wire.RoleClient {
		myRole, peerRole = proto.RoleClient, proto.RoleAgent
	}

	myHello, err := proto.BuildHello(t.psk, myRole, t.pairID, eph.PublicKeyBytes(), nonce)
	if err != nil {
		return nil, nil, hsFrame, err
	}
	if err := t.writeFrame(ctx, wire.ChannelHandshake, myHello); err != nil {
		return nil, nil, hsFrame, err
	}

	peerHelloRaw := firstHello
	if peerHelloRaw == nil {
		var sig hsSignal
		peerHelloRaw, sig, err = t.readHandshakeFrame(ctx, pending)
		if err != nil {
			return nil, nil, hsFrame, fmt.Errorf("reading peer HELLO: %w", err)
		}
		if sig != hsFrame {
			return nil, nil, sig, nil
		}
	}
	if _, err := proto.VerifyHello(t.psk, peerHelloRaw, t.pairID, myRole); err != nil {
		return nil, nil, hsFrame, fmt.Errorf("verifying peer HELLO: %w", err)
	}

	var helloAgent, helloWeb []byte
	if t.role == wire.RoleAgent {
		helloAgent, helloWeb = myHello, peerHelloRaw
	} else {
		helloAgent, helloWeb = peerHelloRaw, myHello
	}
	transcript := proto.Transcript(helloAgent, helloWeb)

	ecdhX, err := eph.ECDH(extractEpk(peerHelloRaw))
	if err != nil {
		return nil, nil, hsFrame, fmt.Errorf("ECDH: %w", err)
	}
	keys, err := proto.DeriveSession(t.psk, transcript, ecdhX)
	if err != nil {
		return nil, nil, hsFrame, err
	}

	myConfirm := proto.BuildConfirm(keys.PRK, myRole)
	if err := t.writeFrame(ctx, wire.ChannelHandshake, myConfirm); err != nil {
		return nil, nil, hsFrame, err
	}
	peerConfirmRaw, sig, err := t.readHandshakeFrame(ctx, pending)
	if err != nil {
		return nil, nil, hsFrame, fmt.Errorf("reading peer CONFIRM: %w", err)
	}
	if sig != hsFrame {
		return nil, nil, sig, nil
	}
	if err := proto.VerifyConfirm(keys.PRK, peerConfirmRaw, peerRole); err != nil {
		return nil, nil, hsFrame, fmt.Errorf("verifying peer CONFIRM: %w", err)
	}

	kSeal, npSeal, kOpen, npOpen := keys.KA2W, keys.NPA2W, keys.KW2A, keys.NPW2A
	if t.role == wire.RoleClient {
		kSeal, npSeal, kOpen, npOpen = keys.KW2A, keys.NPW2A, keys.KA2W, keys.NPA2W
	}
	sealer, err := proto.NewSealer(kSeal, npSeal)
	if err != nil {
		return nil, nil, hsFrame, err
	}
	opener, err := proto.NewOpener(kOpen, npOpen)
	if err != nil {
		return nil, nil, hsFrame, err
	}
	return sealer, opener, hsFrame, nil
}

// readHandshakeFrame returns the next channel-0x02 payload, holding any
// ciphertext that overtakes it (spec §4.6) and reporting the control
// messages that end or restart a handshake.
func (t *Transport) readHandshakeFrame(ctx context.Context, pending *[][]byte) ([]byte, hsSignal, error) {
	for {
		typ, data, err := t.ws.Read(ctx)
		if err != nil {
			return nil, hsFrame, err
		}
		if typ != websocket.MessageBinary {
			return nil, hsFrame, fmt.Errorf("testclient: expected binary message, got %v", typ)
		}
		hdr, payload, err := wire.ParseOuter(data)
		if err != nil {
			return nil, hsFrame, err
		}

		switch hdr.Channel {
		case wire.ChannelHandshake:
			return payload, hsFrame, nil
		case wire.ChannelCiphertext:
			if len(*pending) >= maxPendingCiphertext {
				return nil, hsFrame, errors.New("testclient: too many ciphertext frames arrived before the session was established")
			}
			*pending = append(*pending, append([]byte(nil), payload...))
		case wire.ChannelControl:
			var m map[string]any
			if err := json.Unmarshal(payload, &m); err != nil {
				return nil, hsFrame, err
			}
			switch m["t"] {
			case "peer_offline":
				return nil, hsAbandoned, nil
			case "peer_online":
				// A newer peer attached mid-handshake (a redial displacing
				// the one whose CONFIRM we were waiting for).
				return nil, hsRestart, nil
			case "going_away":
				return nil, hsFrame, ErrGoingAway
			case "error":
				return nil, hsFrame, fmt.Errorf("testclient: relay error during handshake: %v", m["code"])
			}
		default:
			return nil, hsFrame, fmt.Errorf("testclient: unexpected channel 0x%02x during handshake", byte(hdr.Channel))
		}
	}
}

func (t *Transport) writeFrame(ctx context.Context, ch wire.Channel, payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ws.Write(ctx, websocket.MessageBinary, wire.EncodeOuter(ch, payload))
}

// SendInner seals (or, in insecure mode, sends verbatim) a single inner
// frame under the current session. Safe for concurrent use — the internal
// mutex is exactly the single-sealing-point discipline spec §5.1 requires,
// made structurally hard to violate rather than merely documented.
func (t *Transport) SendInner(ctx context.Context, f wire.InnerFrame) error {
	return t.SendInnerAt(ctx, t.Epoch(), f)
}

// SendInnerAt is SendInner, but only if the session is still the one the
// caller captured with Epoch(). A response being streamed for a request
// that arrived under an earlier session must not be sealed under the
// current one: the peer never sent that request and, worse, the frame
// consumes a counter the peer's opener is expecting for something else.
func (t *Transport) SendInnerAt(ctx context.Context, epoch uint64, f wire.InnerFrame) error {
	buf, err := wire.EncodeInner(nil, f)
	if err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.insecure {
		return t.ws.Write(ctx, websocket.MessageBinary, wire.EncodeOuter(wire.ChannelCiphertext, buf))
	}
	if t.sealer == nil || t.epoch != epoch {
		return ErrNoSession
	}
	header := []byte{byte(wire.ChannelCiphertext), 0x00}
	sealed, err := t.sealer.Seal(header, buf)
	if err != nil {
		return err
	}
	return t.ws.Write(ctx, websocket.MessageBinary, wire.EncodeOuter(wire.ChannelCiphertext, sealed))
}

// RecvInner returns the next inner frame, transparently handling
// multi-frame batched payloads (spec §6) by buffering, and carrying the
// session lifecycle underneath: `peer_online` starts a fresh handshake on
// this same socket, `peer_offline` retires the session and surfaces as a
// sentinel error the caller is expected to keep reading past.
func (t *Transport) RecvInner(ctx context.Context) (wire.InnerFrame, error) {
	for len(t.pending) == 0 {
		typ, data, err := t.ws.Read(ctx)
		if err != nil {
			return wire.InnerFrame{}, err
		}
		if typ != websocket.MessageBinary {
			return wire.InnerFrame{}, fmt.Errorf("testclient: expected binary message, got %v", typ)
		}
		hdr, payload, err := wire.ParseOuter(data)
		if err != nil {
			return wire.InnerFrame{}, err
		}

		switch hdr.Channel {
		case wire.ChannelControl:
			var m map[string]any
			if err := json.Unmarshal(payload, &m); err != nil {
				return wire.InnerFrame{}, err
			}
			switch m["t"] {
			case "peer_online":
				if t.insecure {
					continue
				}
				if err := t.startSession(ctx, nil); err != nil {
					return wire.InnerFrame{}, err
				}
			case "peer_offline":
				t.retireSession()
				return wire.InnerFrame{}, ErrPeerOffline
			case "going_away":
				return wire.InnerFrame{}, ErrGoingAway
			case "error":
				return wire.InnerFrame{}, fmt.Errorf("testclient: relay error: %v", m["code"])
			}
			continue

		case wire.ChannelHandshake:
			// A peer HELLO that overtook (or replaced) the peer_online
			// that should have preceded it.
			if err := t.startSession(ctx, append([]byte(nil), payload...)); err != nil {
				return wire.InnerFrame{}, err
			}
			continue

		case wire.ChannelCiphertext:
			var plain []byte
			if t.insecure {
				plain = payload
			} else {
				t.mu.Lock()
				opener := t.opener
				t.mu.Unlock()
				if opener == nil {
					return wire.InnerFrame{}, errors.New("testclient: ciphertext frame arrived with no established session")
				}
				header := []byte{byte(wire.ChannelCiphertext), 0x00}
				plain, err = opener.Open(header, payload)
				if err != nil {
					return wire.InnerFrame{}, err
				}
			}
			frames, err := wire.DecodeInnerAll(plain)
			if err != nil {
				return wire.InnerFrame{}, err
			}
			t.pending = append(t.pending, frames...)

		default:
			return wire.InnerFrame{}, fmt.Errorf("testclient: unexpected channel 0x%02x", byte(hdr.Channel))
		}
	}

	f := t.pending[0]
	t.pending = t.pending[1:]
	return f, nil
}

// extractEpk pulls the 65-byte public key straight out of a raw HELLO
// wire encoding (spec §4.3 fixed layout) without needing a second parse.
func extractEpk(hello []byte) []byte {
	const off = 1 + 1 + 16 // ver + role + pair_id
	return hello[off : off+65]
}
