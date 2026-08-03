// Package server wires the hub, auth, limits and metrics packages into an
// http.Handler serving the two upgrade endpoints (/v1/agent, /v1/client)
// and /healthz. It is the only package that speaks WebSocket protocol
// directly — reading hellos, running the forwarding pump, broadcasting
// going_away on shutdown.
package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"

	"github.com/OpenCharUI/relay/internal/auth"
	"github.com/OpenCharUI/relay/internal/config"
	"github.com/OpenCharUI/relay/internal/hub"
	"github.com/OpenCharUI/relay/internal/limits"
	"github.com/OpenCharUI/relay/internal/metrics"
	"github.com/OpenCharUI/relay/internal/wire"
)

type Server struct {
	cfg   config.Config
	hub   *hub.Hub
	authz auth.Authorizer
	ipLim *limits.IPLimiter
	m     *metrics.Metrics
	log   *slog.Logger

	connSeq atomic.Uint64

	shuttingDown atomic.Bool
	wg           sync.WaitGroup

	connsMu sync.Mutex
	conns   map[*hub.Conn]struct{}

	httpSrv *http.Server
}

func New(cfg config.Config, h *hub.Hub, authz auth.Authorizer, ipLim *limits.IPLimiter, m *metrics.Metrics, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:   cfg,
		hub:   h,
		authz: authz,
		ipLim: ipLim,
		m:     m,
		log:   log,
		conns: make(map[*hub.Conn]struct{}),
	}
}

// Handler returns the mux serving /v1/agent, /v1/client and /healthz —
// exposed separately from Run so tests can drive it via httptest.Server
// without binding a real port.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/agent", s.handleAgentUpgrade)
	mux.HandleFunc("/v1/client", s.handleClientUpgrade)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

// Run listens on cfg.Addr and blocks until ctx is cancelled, then performs
// a graceful shutdown bounded by cfg.ShutdownGrace.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve runs the server on an already-open listener — split out from Run
// so tests can use a listener bound to an ephemeral port.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.httpSrv = &http.Server{Handler: s.Handler()}

	errCh := make(chan error, 1)
	go func() { errCh <- s.httpSrv.Serve(ln) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownGrace)
		defer cancel()
		return s.Shutdown(shutdownCtx)
	}
}

// Shutdown announces going_away to every currently-open connection, waits
// (bounded by ctx) for their pumps to drain, then stops the HTTP listener.
//
// This exists because net/http.Server.Shutdown explicitly does NOT wait
// for hijacked connections — and a WebSocket upgrade hijacks the
// underlying TCP connection — so without this, every open session would
// hang until its own ping-timeout on every deploy instead of getting a
// clean, fast reconnect signal (spec §8: close code 1001, retry with no
// backoff escalation).
func (s *Server) Shutdown(ctx context.Context) error {
	s.shuttingDown.Store(true)

	s.connsMu.Lock()
	conns := make([]*hub.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.connsMu.Unlock()

	for _, c := range conns {
		s.sendControl(c, wire.NewGoingAway(2000))
	}
	for _, c := range conns {
		_ = c.Close(websocket.StatusCode(wire.CloseGoingAway), "going_away")
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}

	if s.httpSrv != nil {
		return s.httpSrv.Shutdown(ctx)
	}
	return nil
}

func (s *Server) trackConn(c *hub.Conn) {
	s.connsMu.Lock()
	s.conns[c] = struct{}{}
	s.connsMu.Unlock()
}

func (s *Server) untrackConn(c *hub.Conn) {
	s.connsMu.Lock()
	delete(s.conns, c)
	s.connsMu.Unlock()
}

// activeConns exposes the live connection count for tests/diagnostics.
func (s *Server) activeConns() int {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	return len(s.conns)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
