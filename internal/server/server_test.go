package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/41tunnels/relay/internal/auth"
	"github.com/41tunnels/relay/internal/config"
	"github.com/41tunnels/relay/internal/hub"
	"github.com/41tunnels/relay/internal/limits"
	"github.com/41tunnels/relay/internal/metrics"
	"github.com/41tunnels/relay/internal/wire"
)

// --- test scaffolding --------------------------------------------------------

func testConfig() config.Config {
	c := config.Defaults()
	c.PingInterval = 200 * time.Millisecond
	c.PongTimeout = 200 * time.Millisecond
	c.HelloTimeout = 2 * time.Second
	c.WriteTimeout = 2 * time.Second
	c.MaxFrameBytes = 1 << 20
	c.MaxPairs = 10
	c.PairRateBytesPerSec = 10 << 20
	c.IPConnPerMin = 6000 // high: dedicated rate-limit behavior lives in internal/limits' own tests
	c.AllowedOrigins = []string{"*"}
	c.ShutdownGrace = 3 * time.Second
	return c
}

func newTestServer(t *testing.T, cfg config.Config) (*Server, *httptest.Server) {
	t.Helper()
	h := hub.New(cfg.MaxPairs, cfg.PairRateBytesPerSec)
	authz := auth.OpenAuthorizer{}
	ipLim := limits.NewIPLimiter(cfg.IPConnPerMin)
	m := metrics.NewUnregistered()
	s := New(cfg, h, authz, ipLim, m, nil)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func wsURL(ts *httptest.Server, path string) string {
	return "ws" + strings.TrimPrefix(ts.URL, "http") + path
}

func dial(t *testing.T, ts *httptest.Server, path string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL(ts, path), nil)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	// coder/websocket defaults every connection to a 32KiB read limit
	// regardless of which side dialed it. The server sets its own limit
	// from cfg.MaxFrameBytes inside pump(), but these test-side raw
	// connections need the same headroom whenever a test exercises frames
	// close to or above the default (e.g. the backpressure test's 64KiB
	// frames) — set it generously once here rather than per test.
	c.SetReadLimit(4 << 20)
	return c
}

func randPairID(t *testing.T) [16]byte {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func sendHello(t *testing.T, c *websocket.Conn, role wire.Role, pairID [16]byte) {
	t.Helper()
	hello := wire.NewHello(role, base64.RawURLEncoding.EncodeToString(pairID[:]))
	b, err := json.Marshal(hello)
	if err != nil {
		t.Fatal(err)
	}
	frame := wire.EncodeOuter(wire.ChannelControl, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageBinary, frame); err != nil {
		t.Fatalf("send hello: %v", err)
	}
}

func readControl(t *testing.T, c *websocket.Conn, timeout time.Duration) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	typ, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read control: %v", err)
	}
	if typ != websocket.MessageBinary {
		t.Fatalf("expected binary message, got %v", typ)
	}
	hdr, payload, err := wire.ParseOuter(data)
	if err != nil {
		t.Fatalf("parse outer: %v", err)
	}
	if hdr.Channel != wire.ChannelControl {
		t.Fatalf("expected control channel, got 0x%02x", byte(hdr.Channel))
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("unmarshal control payload: %v", err)
	}
	return m
}

func expectControlType(t *testing.T, c *websocket.Conn, want string, timeout time.Duration) map[string]any {
	t.Helper()
	m := readControl(t, c, timeout)
	if m["t"] != want {
		t.Fatalf("control message type = %v, want %q (full message: %+v)", m["t"], want, m)
	}
	return m
}

func expectClose(t *testing.T, c *websocket.Conn, want websocket.StatusCode, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, _, err := c.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("expected a CloseError, got %v (%T)", err, err)
	}
	if ce.Code != want {
		t.Errorf("close code = %v, want %v", ce.Code, want)
	}
}

// handshakeAgentAndClient dials, hellos, and drains hello_ok/peer_online
// for a fresh pair — the setup every forwarding-behavior test starts from.
func handshakeAgentAndClient(t *testing.T, ts *httptest.Server, pairID [16]byte) (agentConn, clientConn *websocket.Conn) {
	t.Helper()
	agentConn = dial(t, ts, "/v1/agent")
	sendHello(t, agentConn, wire.RoleAgent, pairID)
	expectControlType(t, agentConn, "hello_ok", 2*time.Second)

	clientConn = dial(t, ts, "/v1/client")
	sendHello(t, clientConn, wire.RoleClient, pairID)
	expectControlType(t, clientConn, "hello_ok", 2*time.Second)

	expectControlType(t, agentConn, "peer_online", 2*time.Second)
	expectControlType(t, clientConn, "peer_online", 2*time.Second)
	return agentConn, clientConn
}

// --- tests -------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	_, ts := newTestServer(t, testConfig())
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestForwardingBothDirections(t *testing.T) {
	_, ts := newTestServer(t, testConfig())
	pairID := randPairID(t)
	agentConn, clientConn := handshakeAgentAndClient(t, ts, pairID)
	defer agentConn.CloseNow()
	defer clientConn.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	a2c := wire.EncodeOuter(wire.ChannelCiphertext, []byte("agent-to-client payload"))
	if err := agentConn.Write(ctx, websocket.MessageBinary, a2c); err != nil {
		t.Fatalf("agent write: %v", err)
	}
	_, got, err := clientConn.Read(ctx)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(got, a2c) {
		t.Errorf("client received %x, want %x (frames must be forwarded byte-for-byte, relay never touches channel 0x01 payloads)", got, a2c)
	}

	c2a := wire.EncodeOuter(wire.ChannelCiphertext, []byte("client-to-agent payload"))
	if err := clientConn.Write(ctx, websocket.MessageBinary, c2a); err != nil {
		t.Fatalf("client write: %v", err)
	}
	_, got, err = agentConn.Read(ctx)
	if err != nil {
		t.Fatalf("agent read: %v", err)
	}
	if !bytes.Equal(got, c2a) {
		t.Errorf("agent received %x, want %x", got, c2a)
	}
}

func TestUnknownPairRejected(t *testing.T) {
	_, ts := newTestServer(t, testConfig())
	pairID := randPairID(t) // never registered by any agent

	clientConn := dial(t, ts, "/v1/client")
	defer clientConn.CloseNow()
	sendHello(t, clientConn, wire.RoleClient, pairID)

	// hello_ok acknowledges the WS-level handshake was well-formed; it is
	// sent unconditionally before the server checks whether the pair
	// actually exists, so it always arrives first.
	expectControlType(t, clientConn, "hello_ok", 2*time.Second)

	errMsg := expectControlType(t, clientConn, "error", 2*time.Second)
	if errMsg["code"] != "agent_offline" {
		t.Errorf("error code = %v, want %q", errMsg["code"], "agent_offline")
	}
	expectClose(t, clientConn, websocket.StatusCode(wire.CloseAgentOffline), 2*time.Second)
}

func TestClientDisplacement(t *testing.T) {
	_, ts := newTestServer(t, testConfig())
	pairID := randPairID(t)

	agentConn := dial(t, ts, "/v1/agent")
	defer agentConn.CloseNow()
	sendHello(t, agentConn, wire.RoleAgent, pairID)
	expectControlType(t, agentConn, "hello_ok", 2*time.Second)

	client1 := dial(t, ts, "/v1/client")
	defer client1.CloseNow()
	sendHello(t, client1, wire.RoleClient, pairID)
	expectControlType(t, client1, "hello_ok", 2*time.Second)
	expectControlType(t, agentConn, "peer_online", 2*time.Second)
	expectControlType(t, client1, "peer_online", 2*time.Second)

	client2 := dial(t, ts, "/v1/client")
	defer client2.CloseNow()
	sendHello(t, client2, wire.RoleClient, pairID)

	// client1 must be displaced — closed with 4409, and must NOT
	// auto-reconnect-fight (that's a client-side policy; here we just
	// confirm the relay's half: the close code is exactly "displaced").
	expectClose(t, client1, websocket.StatusCode(wire.CloseDisplaced), 2*time.Second)

	expectControlType(t, client2, "hello_ok", 2*time.Second)
}

func TestAgentDisplacement(t *testing.T) {
	_, ts := newTestServer(t, testConfig())
	pairID := randPairID(t)

	agent1 := dial(t, ts, "/v1/agent")
	defer agent1.CloseNow()
	sendHello(t, agent1, wire.RoleAgent, pairID)
	expectControlType(t, agent1, "hello_ok", 2*time.Second)

	agent2 := dial(t, ts, "/v1/agent")
	defer agent2.CloseNow()
	sendHello(t, agent2, wire.RoleAgent, pairID)

	expectClose(t, agent1, websocket.StatusCode(wire.CloseDisplaced), 2*time.Second)
	expectControlType(t, agent2, "hello_ok", 2*time.Second)
}

func TestAgentGoneParksTheClientThenExpires(t *testing.T) {
	cfg := testConfig()
	cfg.AgentGrace = 400 * time.Millisecond
	s, ts := newTestServer(t, cfg)
	pairID := randPairID(t)
	agentConn, clientConn := handshakeAgentAndClient(t, ts, pairID)
	defer clientConn.CloseNow()

	agentConn.Close(websocket.StatusNormalClosure, "bye")

	// The client is told the far side went quiet, but is NOT closed: the
	// agent gets cfg.AgentGrace to come back to the same pair.
	expectControlType(t, clientConn, "peer_offline", 2*time.Second)
	if s.hub.Len() != 1 {
		t.Errorf("hub.Len() = %d, want 1 — the pair is parked, not torn down", s.hub.Len())
	}

	// Nobody comes back, so the park expires and the client gets the 4410
	// it would have received immediately before parking existed.
	expectClose(t, clientConn, websocket.StatusCode(wire.CloseAgentGone), 3*time.Second)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.hub.Len() != 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if s.hub.Len() != 0 {
		t.Errorf("hub.Len() = %d, want 0 once the grace window has run out", s.hub.Len())
	}
}

func TestAgentReturningInsideGraceKeepsTheClientAttached(t *testing.T) {
	cfg := testConfig()
	cfg.AgentGrace = 5 * time.Second
	s, ts := newTestServer(t, cfg)
	pairID := randPairID(t)
	agentConn, clientConn := handshakeAgentAndClient(t, ts, pairID)
	defer clientConn.CloseNow()

	// An agent restart: the socket goes, and comes back moments later.
	agentConn.Close(websocket.StatusNormalClosure, "restarting")
	expectControlType(t, clientConn, "peer_offline", 2*time.Second)

	agent2 := dial(t, ts, "/v1/agent")
	defer agent2.CloseNow()
	sendHello(t, agent2, wire.RoleAgent, pairID)
	expectControlType(t, agent2, "hello_ok", 2*time.Second)

	// Both ends are told the pairing is live again, on the client socket
	// that never went anywhere — so the cost of the restart is one E2E
	// handshake, not a reconnect on both sides.
	expectControlType(t, agent2, "peer_online", 2*time.Second)
	expectControlType(t, clientConn, "peer_online", 2*time.Second)

	if s.hub.Len() != 1 {
		t.Errorf("hub.Len() = %d, want 1", s.hub.Len())
	}

	// And the splice really works again, rather than merely looking live.
	frame := wire.EncodeOuter(wire.ChannelCiphertext, []byte("after the restart"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := agent2.Write(ctx, websocket.MessageBinary, frame); err != nil {
		t.Fatalf("write from the returned agent: %v", err)
	}
	typ, got, err := clientConn.Read(ctx)
	if err != nil {
		t.Fatalf("client read after the agent returned: %v", err)
	}
	if typ != websocket.MessageBinary || !bytes.Equal(got, frame) {
		t.Errorf("forwarded frame = %q, want %q", got, frame)
	}
}

func TestParkedPairIsDroppedWhenTheClientGivesUpFirst(t *testing.T) {
	cfg := testConfig()
	cfg.AgentGrace = 30 * time.Second // long enough that only the client's exit can clear it
	s, ts := newTestServer(t, cfg)
	pairID := randPairID(t)
	agentConn, clientConn := handshakeAgentAndClient(t, ts, pairID)

	agentConn.Close(websocket.StatusNormalClosure, "bye")
	expectControlType(t, clientConn, "peer_offline", 2*time.Second)
	clientConn.Close(websocket.StatusNormalClosure, "closing the tab")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.hub.Len() != 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if s.hub.Len() != 0 {
		t.Errorf("hub.Len() = %d, want 0 — nothing is left to park for", s.hub.Len())
	}
}

func TestPingTimeoutClosesConnection(t *testing.T) {
	cfg := testConfig()
	cfg.PingInterval = 30 * time.Millisecond
	cfg.PongTimeout = 30 * time.Millisecond
	s, ts := newTestServer(t, cfg)

	pairID := randPairID(t)
	agentConn := dial(t, ts, "/v1/agent")
	defer agentConn.CloseNow()
	sendHello(t, agentConn, wire.RoleAgent, pairID)
	expectControlType(t, agentConn, "hello_ok", time.Second)

	// From here on, deliberately stop reading from agentConn. coder/websocket
	// only processes (and auto-answers) control frames — including pings —
	// while the application is calling Read; a peer that stops reading
	// entirely never sends a pong, so the server's ping should time out and
	// close the connection.
	//
	// The close itself is bounded by coder/websocket's hardcoded (not
	// caller-configurable) 5s wait for a reciprocal close frame from a
	// non-responsive peer — see the doc comment on hub.Conn.Close. That
	// wait runs in its own goroutine so it never blocks anything else in
	// the server, but THIS specific connection's own teardown still isn't
	// instant, so the deadline here has to clear 5s comfortably.
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		if s.hub.Len() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("ping timeout did not close the agent connection / tear down its pair within 7s")
}

func TestOversizeFrameClosesConnection(t *testing.T) {
	cfg := testConfig()
	cfg.MaxFrameBytes = 1024
	_, ts := newTestServer(t, cfg)
	pairID := randPairID(t)
	agentConn, clientConn := handshakeAgentAndClient(t, ts, pairID)
	defer agentConn.CloseNow()
	defer clientConn.CloseNow()

	big := wire.EncodeOuter(wire.ChannelCiphertext, make([]byte, cfg.MaxFrameBytes+500))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = clientConn.Write(ctx, websocket.MessageBinary, big) // may error once the server reacts; that's fine

	expectClose(t, clientConn, websocket.StatusCode(wire.CloseFrameTooLarge), 2*time.Second)
}

func TestPairByteRateLimitCloses(t *testing.T) {
	cfg := testConfig()
	cfg.PairRateBytesPerSec = 50 // tiny — a single ~200 byte frame exceeds burst
	_, ts := newTestServer(t, cfg)
	pairID := randPairID(t)
	agentConn, clientConn := handshakeAgentAndClient(t, ts, pairID)
	defer agentConn.CloseNow()
	defer clientConn.CloseNow()

	big := wire.EncodeOuter(wire.ChannelCiphertext, make([]byte, 200))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = clientConn.Write(ctx, websocket.MessageBinary, big)

	expectClose(t, clientConn, websocket.StatusCode(wire.CloseRateLimited), 2*time.Second)
}

func TestIPConnectRateLimit(t *testing.T) {
	cfg := testConfig()
	cfg.IPConnPerMin = 2
	_, ts := newTestServer(t, cfg)

	// httptest.Server dials all connect from 127.0.0.1, so these all share
	// one bucket.
	ok := 0
	rejected := 0
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, resp, err := websocket.Dial(ctx, wsURL(ts, "/v1/agent"), nil)
		cancel()
		if err != nil {
			rejected++
			if resp != nil && resp.StatusCode != http.StatusTooManyRequests {
				t.Errorf("attempt %d: rejected with status %d, want %d", i, resp.StatusCode, http.StatusTooManyRequests)
			}
			continue
		}
		ok++
		c.CloseNow()
	}
	if ok == 0 {
		t.Error("expected at least one connection attempt to succeed under the burst allowance")
	}
	if rejected == 0 {
		t.Error("expected at least one connection attempt to be rate limited")
	}
}

func TestShutdownBroadcastsGoingAwayAndDrains(t *testing.T) {
	s, ts := newTestServer(t, testConfig())
	pairID := randPairID(t)
	agentConn, clientConn := handshakeAgentAndClient(t, ts, pairID)
	defer agentConn.CloseNow()
	defer clientConn.CloseNow()

	shutdownDone := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
		close(shutdownDone)
	}()

	agentMsg := expectControlType(t, agentConn, "going_away", 2*time.Second)
	if _, ok := agentMsg["retry_after_ms"]; !ok {
		t.Error("going_away must include retry_after_ms so clients skip backoff escalation")
	}
	expectControlType(t, clientConn, "going_away", 2*time.Second)

	expectClose(t, agentConn, websocket.StatusCode(wire.CloseGoingAway), 2*time.Second)
	expectClose(t, clientConn, websocket.StatusCode(wire.CloseGoingAway), 2*time.Second)

	select {
	case <-shutdownDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown did not return within its grace period")
	}
}

// TestBackpressurePropagatesToSlowReader is the "no internal buffering"
// check from the build plan: a slow reader on one side must throttle the
// fast writer on the other, because the relay's forwarding pump does not
// read its next frame until the current one has been handed to the peer
// socket (see internal/server/ws.go's pump doc comment).
func TestBackpressurePropagatesToSlowReader(t *testing.T) {
	cfg := testConfig()
	cfg.PairRateBytesPerSec = 1 << 30 // effectively unlimited — isolate backpressure from the separate rate limiter
	cfg.WriteTimeout = 5 * time.Second
	// The agent side below only calls Write in a tight loop — a real
	// client's connection is always pumping Read concurrently (that's what
	// answers keepalive pings), but this synthetic writer isn't. Push ping
	// timing out past the test's expected duration so what's under test
	// here is backpressure, not liveness (that has its own dedicated test).
	cfg.PingInterval = 30 * time.Second
	cfg.PongTimeout = 30 * time.Second
	_, ts := newTestServer(t, cfg)
	pairID := randPairID(t)
	agentConn, clientConn := handshakeAgentAndClient(t, ts, pairID)
	defer agentConn.CloseNow()
	defer clientConn.CloseNow()

	// A large total volume and a proportional (not near-exact) threshold,
	// deliberately: OS-level TCP send/receive buffers on the loopback path
	// legitimately absorb some number of frames "for free" before
	// synchronous backpressure becomes visible in wall-clock terms — how
	// much depends on the OS and its buffer auto-tuning, not on the
	// relay's own design. Pushing enough total data that any reasonable
	// buffer size is a small fraction of it, and asserting only that the
	// writer took at least half the naive expected time, tests the actual
	// property (backpressure propagates, nothing is unboundedly buffered)
	// without being sensitive to exactly how many frames a given machine's
	// socket buffers happen to hold.
	const frameSize = 64 * 1024
	const frameCount = 300
	const readDelay = 8 * time.Millisecond

	readDone := make(chan error, 1)
	go func() {
		for i := 0; i < frameCount; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			_, _, err := clientConn.Read(ctx)
			cancel()
			if err != nil {
				readDone <- err
				return
			}
			time.Sleep(readDelay)
		}
		readDone <- nil
	}()

	frame := wire.EncodeOuter(wire.ChannelCiphertext, make([]byte, frameSize))
	start := time.Now()
	for i := 0; i < frameCount; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := agentConn.Write(ctx, websocket.MessageBinary, frame)
		cancel()
		if err != nil {
			t.Fatalf("agent write %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	if err := <-readDone; err != nil {
		t.Fatalf("client read loop: %v", err)
	}

	naiveExpected := time.Duration(frameCount) * readDelay
	minExpected := naiveExpected / 2
	if elapsed < minExpected {
		t.Errorf("writer finished all %d frames (%d MB) in %s; expected at least %s (half of the reader's own pace of %s) if the relay propagates backpressure from the slow reader instead of buffering internally",
			frameCount, frameCount*frameSize/(1<<20), elapsed, minExpected, naiveExpected)
	}
	t.Logf("writer took %s against a reader pacing at %s (%.0f%% of naive expected) — some fraction below 100%% is normal OS buffering, not a bug",
		elapsed, naiveExpected, 100*float64(elapsed)/float64(naiveExpected))
}
