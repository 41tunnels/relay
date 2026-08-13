package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/OpenCharUI/relay/internal/hub"
	"github.com/OpenCharUI/relay/internal/wire"
)

// connectAgentAndAwaitHelloOK dials as an agent, sends a hello in the
// given mode, and returns only once hello_ok has been observed — the
// same point at which a real agent starts behaving as though it were
// connected.
func connectAgentAndAwaitHelloOK(t *testing.T, ts *httptest.Server, mode wire.Mode, apiKey string) hub.PairID {
	t.Helper()
	c := dial(t, ts, "/v1/agent")
	pairID := randPairID(t)

	hello := wire.Hello{
		T: "hello", V: 1, Role: wire.RoleAgent,
		Pair: base64.RawURLEncoding.EncodeToString(pairID[:]),
		Mode: mode,
	}
	if apiKey != "" {
		hello.TokenHash = hub.HashToken(apiKey).String()
	}
	b, err := json.Marshal(hello)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageBinary, wire.EncodeOuter(wire.ChannelControl, b)); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	expectControlType(t, c, "hello_ok", 5*time.Second)
	t.Cleanup(func() { _ = c.CloseNow() })
	return pairID
}

// hello_ok means "attached and reachable", not merely "your hello
// parsed". Everything an agent does next assumes it: it hands out a
// pairing code, or an API key whose first request may arrive
// immediately. If the acknowledgement outran the registration, that
// request would be answered as though the pair were gone or the key were
// wrong — a spurious 4404 or 401 for a connection that is in fact fine.
//
// These assert the ordering directly rather than relying on a request
// losing the race, which is what let the bug through: it reproduced only
// under CI's scheduling, never locally.
func TestHelloOKFollowsRegistration(t *testing.T) {
	t.Run("http", func(t *testing.T) {
		s, ts := newTestServer(t, httpTestConfig())
		startFakeHTTPAgent(t, ts, "41t_race", okJSON)

		if _, ok := s.httpReg.Lookup(hub.HashToken("41t_race")); !ok {
			t.Fatal("token hash does not resolve immediately after hello_ok")
		}
	})

	t.Run("dual", func(t *testing.T) {
		s, ts := newTestServer(t, httpTestConfig())
		pairID := connectAgentAndAwaitHelloOK(t, ts, wire.ModeDual, "41t_dual")

		// A dual agent is only fully attached once BOTH registrations have
		// landed; either one racing ahead of hello_ok is the same bug.
		if _, ok := s.httpReg.Lookup(hub.HashToken("41t_dual")); !ok {
			t.Error("token hash does not resolve immediately after hello_ok")
		}
		if _, ok := s.hub.Lookup(pairID); !ok {
			t.Error("pair does not resolve immediately after hello_ok")
		}
	})

	t.Run("e2e", func(t *testing.T) {
		s, ts := newTestServer(t, httpTestConfig())
		pairID := connectAgentAndAwaitHelloOK(t, ts, "", "")

		if _, ok := s.hub.Lookup(pairID); !ok {
			t.Fatal("pair does not resolve immediately after hello_ok")
		}
	})
}
