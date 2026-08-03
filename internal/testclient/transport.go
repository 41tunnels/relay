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
	// other side has disconnected.
	ErrPeerOffline = errors.New("testclient: peer went offline")
	// ErrGoingAway is returned from RecvInner when the relay announces a
	// graceful shutdown.
	ErrGoingAway = errors.New("testclient: relay is going away")
)

// Transport is one connected, handshaken (or, in insecure mode,
// unencrypted) session with the relay, from either role's perspective.
type Transport struct {
	ws     *websocket.Conn
	role   wire.Role
	pairID [16]byte

	insecure bool
	sealer   *proto.Sealer
	opener   *proto.Opener

	mu      sync.Mutex // guards writes: exactly one sealing point, per spec §5.1
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

// Dial connects to the relay, completes the control-channel hello, and
// (unless insecure) performs the full E2E handshake from spec §4. In
// insecure mode, channel 0x01 carries raw inner-frame bytes with no AEAD
// wrapping at all — this exists solely to exercise amallo's HTTP-bridge
// logic before its crypto is wired up (see the build plan's Step 4), and
// must never be used against a production relay.
func Dial(ctx context.Context, relayURL string, role wire.Role, pairID [16]byte, psk []byte, insecure bool) (*Transport, error) {
	url := wsURLFor(relayURL, role)
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("testclient: dial %s: %w", url, err)
	}
	ws.SetReadLimit(8 << 20)

	t := &Transport{ws: ws, role: role, pairID: pairID, insecure: insecure}

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

	if insecure {
		return t, nil
	}

	if err := t.expectControl(ctx, "peer_online"); err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("testclient: waiting for peer: %w", err)
	}
	if err := t.handshake(ctx, psk); err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("testclient: handshake: %w", err)
	}
	return t, nil
}

// Close closes the underlying connection immediately.
func (t *Transport) Close() error { return t.ws.CloseNow() }

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

// handshake performs the full P-256/HKDF/AES-GCM key exchange from spec
// §4, sending our HELLO/CONFIRM on channel 0x02 and validating the peer's.
func (t *Transport) handshake(ctx context.Context, psk []byte) error {
	eph, err := proto.GenerateEphemeral()
	if err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	myRole := proto.RoleAgent
	if t.role == wire.RoleClient {
		myRole = proto.RoleClient
	}
	peerRole := proto.RoleClient
	if t.role == wire.RoleClient {
		peerRole = proto.RoleAgent
	}

	myHello, err := proto.BuildHello(psk, myRole, t.pairID, eph.PublicKeyBytes(), nonce)
	if err != nil {
		return err
	}
	if err := t.ws.Write(ctx, websocket.MessageBinary, wire.EncodeOuter(wire.ChannelHandshake, myHello)); err != nil {
		return err
	}

	peerHelloRaw, err := t.readHandshakeFrame(ctx)
	if err != nil {
		return fmt.Errorf("reading peer HELLO: %w", err)
	}
	if _, err := proto.VerifyHello(psk, peerHelloRaw, t.pairID, myRole); err != nil {
		return fmt.Errorf("verifying peer HELLO: %w", err)
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
		return fmt.Errorf("ECDH: %w", err)
	}
	keys, err := proto.DeriveSession(psk, transcript, ecdhX)
	if err != nil {
		return err
	}

	myConfirm := proto.BuildConfirm(keys.PRK, myRole)
	if err := t.ws.Write(ctx, websocket.MessageBinary, wire.EncodeOuter(wire.ChannelHandshake, myConfirm)); err != nil {
		return err
	}
	peerConfirmRaw, err := t.readHandshakeFrame(ctx)
	if err != nil {
		return fmt.Errorf("reading peer CONFIRM: %w", err)
	}
	if err := proto.VerifyConfirm(keys.PRK, peerConfirmRaw, peerRole); err != nil {
		return fmt.Errorf("verifying peer CONFIRM: %w", err)
	}

	if t.role == wire.RoleAgent {
		t.sealer, err = proto.NewSealer(keys.KA2W, keys.NPA2W)
		if err != nil {
			return err
		}
		t.opener, err = proto.NewOpener(keys.KW2A, keys.NPW2A)
		if err != nil {
			return err
		}
	} else {
		t.sealer, err = proto.NewSealer(keys.KW2A, keys.NPW2A)
		if err != nil {
			return err
		}
		t.opener, err = proto.NewOpener(keys.KA2W, keys.NPA2W)
		if err != nil {
			return err
		}
	}
	return nil
}

// extractEpk pulls the 65-byte public key straight out of a raw HELLO
// wire encoding (spec §4.3 fixed layout) without needing a second parse.
func extractEpk(hello []byte) []byte {
	const off = 1 + 1 + 16 // ver + role + pair_id
	return hello[off : off+65]
}

func (t *Transport) readHandshakeFrame(ctx context.Context) ([]byte, error) {
	typ, data, err := t.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, fmt.Errorf("testclient: expected binary message, got %v", typ)
	}
	hdr, payload, err := wire.ParseOuter(data)
	if err != nil {
		return nil, err
	}
	if hdr.Channel != wire.ChannelHandshake {
		return nil, fmt.Errorf("testclient: expected handshake channel, got 0x%02x", byte(hdr.Channel))
	}
	return payload, nil
}

// SendInner seals (or, in insecure mode, sends verbatim) a single inner
// frame. Safe for concurrent use — the internal mutex is exactly the
// single-sealing-point discipline spec §5.1 requires, made structurally
// hard to violate rather than merely documented.
func (t *Transport) SendInner(ctx context.Context, f wire.InnerFrame) error {
	buf, err := wire.EncodeInner(nil, f)
	if err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var outer []byte
	if t.insecure {
		outer = wire.EncodeOuter(wire.ChannelCiphertext, buf)
	} else {
		header := []byte{byte(wire.ChannelCiphertext), 0x00}
		sealed, err := t.sealer.Seal(header, buf)
		if err != nil {
			return err
		}
		outer = wire.EncodeOuter(wire.ChannelCiphertext, sealed)
	}
	return t.ws.Write(ctx, websocket.MessageBinary, outer)
}

// RecvInner returns the next inner frame, transparently handling
// multi-frame batched payloads (spec §6) by buffering. Control-channel
// peer_offline/going_away messages surface as sentinel errors rather than
// InnerFrames.
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
			case "peer_offline":
				return wire.InnerFrame{}, ErrPeerOffline
			case "going_away":
				return wire.InnerFrame{}, ErrGoingAway
			case "error":
				return wire.InnerFrame{}, fmt.Errorf("testclient: relay error: %v", m["code"])
			default:
				continue // peer_online, hello_ok echoes, etc. — ignore
			}
		case wire.ChannelCiphertext:
			var plain []byte
			if t.insecure {
				plain = payload
			} else {
				header := []byte{byte(wire.ChannelCiphertext), 0x00}
				plain, err = t.opener.Open(header, payload)
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
