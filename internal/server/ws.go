package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/OpenCharUI/relay/internal/auth"
	"github.com/OpenCharUI/relay/internal/hub"
	"github.com/OpenCharUI/relay/internal/logging"
	"github.com/OpenCharUI/relay/internal/wire"
)

var (
	errBadPairID  = errors.New("server: invalid pair_id")
	errNotBinary  = errors.New("server: expected a binary message")
	errNotControl = errors.New("server: expected channel 0x00 (control)")
	errNotHello   = errors.New("server: expected a hello message")
)

func (s *Server) handleAgentUpgrade(w http.ResponseWriter, r *http.Request) {
	s.handleUpgrade(w, r, wire.RoleAgent)
}

func (s *Server) handleClientUpgrade(w http.ResponseWriter, r *http.Request) {
	s.handleUpgrade(w, r, wire.RoleClient)
}

func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request, role wire.Role) {
	if s.shuttingDown.Load() {
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}

	ip := clientIP(r, s.cfg.TrustProxy)
	if !s.ipLim.Allow(ip) {
		s.m.RateLimitedTotal.WithLabelValues("ip_connect").Inc()
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: s.cfg.AllowedOrigins,
		// Payloads past the handshake are AES-GCM ciphertext — incompressible,
		// and compressing the plaintext control/handshake channels ahead of
		// encryption is a CRIME-shaped hazard. Off, unconditionally.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		// Accept already wrote the HTTP error response.
		return
	}

	conn := hub.NewConn(wsConn, role, s.connSeq.Add(1), ip, auth.Grant{})
	s.trackConn(conn)
	s.wg.Add(1)
	defer func() {
		s.wg.Done()
		s.untrackConn(conn)
		conn.CloseNow()
	}()

	handshakeStart := time.Now()
	helloCtx, cancel := context.WithTimeout(r.Context(), s.cfg.HelloTimeout)
	hello, err := readHello(helloCtx, conn)
	cancel()
	if err != nil {
		s.m.ConnectionsTotal.WithLabelValues(string(role), "rejected").Inc()
		s.closeProto(conn, wire.CloseBadFrame, "bad_frame")
		return
	}
	if hello.V != 1 {
		s.m.ConnectionsTotal.WithLabelValues(string(role), "rejected").Inc()
		s.closeProto(conn, wire.CloseBadFrame, "bad_frame")
		return
	}
	if hello.Role != role {
		s.m.ConnectionsTotal.WithLabelValues(string(role), "rejected").Inc()
		s.closeProto(conn, wire.CloseBadFrame, "bad_frame")
		return
	}
	pairID, err := decodePairID(hello.Pair)
	if err != nil {
		s.m.ConnectionsTotal.WithLabelValues(string(role), "rejected").Inc()
		s.closeProto(conn, wire.CloseBadFrame, "bad_frame")
		return
	}
	mode := hello.Mode.Normalized()
	// Only an agent may ask for the HTTP lane: the client half of that
	// path is the relay's own HTTP handler, never a WebSocket peer. A
	// client claiming it is either confused or probing.
	if mode.WantsHTTPLane() && role != wire.RoleAgent {
		s.m.ConnectionsTotal.WithLabelValues(string(role), "rejected").Inc()
		s.closeProto(conn, wire.CloseBadFrame, "bad_frame")
		return
	}
	if mode == wire.ModeHTTP && !s.cfg.HTTPEnabled {
		// An http-only connection has no other purpose, so there is
		// nothing to degrade to.
		s.m.ConnectionsTotal.WithLabelValues(string(role), "rejected").Inc()
		s.closeProto(conn, wire.CloseCapacity, "http_disabled")
		return
	}
	if mode == wire.ModeDual && !s.cfg.HTTPEnabled {
		// A dual connection's primary job is the pairing; the HTTP lane is
		// an add-on. Refusing the whole socket because the operator turned
		// the endpoint off would take the user's browser pairing down with
		// it, so degrade instead.
		s.log.Info("dual agent degraded to e2e: http endpoint disabled", "conn", conn.ID())
		mode = wire.ModeE2E
	}

	grant, err := s.authz.Authorize(r.Context(), pairID, auth.ConnMeta{
		Role:      auth.Role(role),
		RemoteIP:  ip,
		UserAgent: r.UserAgent(),
		Token:     hello.Token,
		Version:   hello.V,
	})
	if err != nil {
		s.m.ConnectionsTotal.WithLabelValues(string(role), "rejected").Inc()
		s.closeProto(conn, wire.CloseCapacity, "capacity")
		return
	}
	conn.SetGrant(grant)
	s.m.HandshakeDuration.Observe(time.Since(handshakeStart).Seconds())

	// hello_ok is deliberately NOT sent here. It means "you are attached
	// and reachable", so each serve path sends it once its registration
	// has landed — otherwise an agent can act on the acknowledgement
	// before its pair or token hash resolves, and a request arriving in
	// that window fails as though the pair were gone or the key wrong.
	sessionStart := time.Now()

	switch {
	case role == wire.RoleAgent && mode == wire.ModeHTTP:
		s.serveHTTPAgent(r.Context(), pairID, conn, hello.TokenHash)
	case role == wire.RoleAgent && mode == wire.ModeDual:
		s.serveDualAgent(r.Context(), pairID, conn, hello.TokenHash)
	// Any other mode value — including one this build does not know —
	// serves the ordinary E2E path. That leniency is deliberate: it is
	// what lets a newer agent roll out against an older relay and still
	// get its pairing, losing only the lane the old relay cannot route.
	case role == wire.RoleAgent:
		s.serveAgent(r.Context(), pairID, conn)
	case role == wire.RoleClient:
		s.serveClient(r.Context(), pairID, conn)
	}

	s.m.ConnectionsTotal.WithLabelValues(string(role), "ok").Inc()
	s.m.SessionDuration.Observe(time.Since(sessionStart).Seconds())
}

func (s *Server) serveAgent(ctx context.Context, id hub.PairID, conn *hub.Conn) {
	pair, displaced, err := s.hub.RegisterAgent(id, conn)
	if err != nil {
		s.closeProto(conn, wire.CloseCapacity, "capacity")
		return
	}
	if displaced != nil {
		s.closeDisplaced(displaced)
	}
	s.m.PairsActive.Set(float64(s.hub.Len()))
	s.m.ConnectionsActive.WithLabelValues("agent", conn.Grant().Tier).Inc()
	defer s.m.ConnectionsActive.WithLabelValues("agent", conn.Grant().Tier).Dec()

	// Attached: a client looking this pair up now finds it.
	s.sendHelloOK(conn)
	s.notifyPeerOnline(pair, conn)

	s.pump(ctx, pair, nil, conn)

	// Shutdown() (see server.go) already broadcasts going_away and closes
	// every tracked connection itself, including this one — that close is
	// exactly what just unblocked pump()'s Read above. Falling through to
	// the ordinary "agent disappeared" cleanup here would race Shutdown's
	// own close of the client connection: whichever goroutine wins can
	// clobber the client's going_away close code with agent_gone,
	// depending on map-iteration order and scheduling. During a shutdown,
	// Shutdown already owns every connection's notification and close, so
	// skip the redundant (and racy) path entirely.
	if s.shuttingDown.Load() {
		return
	}

	s.retireAgent(id, conn)
}

// retireAgent runs the ordinary "agent disappeared" cleanup for the E2E
// registry: drop the pair and tell any attached client why.
func (s *Server) retireAgent(id hub.PairID, conn *hub.Conn) {
	client, removed := s.hub.RemoveIfAgent(id, conn)
	if removed {
		s.m.PairsActive.Set(float64(s.hub.Len()))
		if client != nil {
			s.sendControl(client, wire.PeerOffline())
			s.closeProto(client, wire.CloseAgentGone, "agent_gone")
		}
	}
}

// serveDualAgent serves an agent that carries both lanes on one socket
// (spec §11, ModeDual): the PSK-paired browser session on 0x01/0x02 and
// the OpenAI endpoint's plaintext on 0x03.
//
// The connection is registered in both the pair map and the token-hash
// map, and it is a single WebSocket, so the two lanes share a fate — but
// deliberately nothing else. They keep separate rate budgets (see pump),
// and each is dispatched against its own allowlist on the agent side.
//
// Every failure to establish the HTTP lane degrades to a plain E2E
// agent rather than dropping the connection. The pairing is this
// socket's primary job; a user must not lose their browser session
// because a token hash was malformed or the token registry is full.
func (s *Server) serveDualAgent(ctx context.Context, id hub.PairID, conn *hub.Conn, tokenHashB64 string) {
	pair, displaced, err := s.hub.RegisterAgent(id, conn)
	if err != nil {
		s.closeProto(conn, wire.CloseCapacity, "capacity")
		return
	}
	if displaced != nil {
		s.closeDisplaced(displaced)
	}
	s.m.PairsActive.Set(float64(s.hub.Len()))

	var httpPair *hub.HTTPPair
	if h, err := hub.ParseTokenHash(tokenHashB64); err != nil {
		s.log.Warn("dual agent degraded to e2e: malformed token hash", "conn", conn.ID())
	} else if hp, hpDisplaced, err := s.httpReg.RegisterAgent(h, id, conn); err != nil {
		s.log.Warn("dual agent degraded to e2e: http registry at capacity", "conn", conn.ID())
	} else {
		httpPair = hp
		// The previous holder of this token is usually the same connection
		// the pair map just displaced; closing it twice would double-count
		// the close metric for one event.
		if hpDisplaced != nil && hpDisplaced != displaced {
			s.closeDisplaced(hpDisplaced)
		}
		s.log.Info("dual agent registered",
			"conn", conn.ID(),
			"token", logging.TokenTag(h),
			"http_live", s.httpReg.Len(),
		)
	}

	kind := "agent_dual"
	if httpPair == nil {
		kind = "agent"
	}
	s.m.ConnectionsActive.WithLabelValues(kind, conn.Grant().Tier).Inc()
	defer s.m.ConnectionsActive.WithLabelValues(kind, conn.Grant().Tier).Dec()

	// Both registrations have landed: the pair resolves for a client and,
	// unless the lane degraded, the token hash resolves for an HTTP
	// request. Only now is the acknowledgement true.
	s.sendHelloOK(conn)
	s.notifyPeerOnline(pair, conn)

	s.pump(ctx, pair, httpPair, conn)

	// See serveAgent: during a shutdown, Shutdown() already owns notifying
	// and closing every tracked connection, and detaching here would race
	// it on both registries.
	if s.shuttingDown.Load() {
		return
	}

	if httpPair != nil {
		// Read the hash back rather than reusing the one registered with:
		// a rekey (§11.3) may have re-indexed this entry since.
		cur := httpPair.TokenHash()
		if s.httpReg.DetachAgent(cur, conn) {
			s.log.Info("dual agent http lane detached", "conn", conn.ID(), "token", logging.TokenTag(cur))
		}
	}
	s.retireAgent(id, conn)
}

func (s *Server) serveClient(ctx context.Context, id hub.PairID, conn *hub.Conn) {
	// Sent before the lookup, unlike the agent paths: a client's own
	// attachment is what the *agent* waits on, and `notifyPeerOnline`
	// already handles either order, so there is no window to close here.
	// Keeping it first also preserves the sequence existing clients see
	// when no agent is attached — hello_ok, then error, then 4404.
	s.sendHelloOK(conn)

	pair, ok := s.hub.Lookup(id)
	if !ok {
		s.sendControl(conn, wire.NewError(wire.ErrAgentOffline))
		s.closeProto(conn, wire.CloseAgentOffline, "agent_offline")
		return
	}

	displaced := pair.SetClient(conn)
	if displaced != nil {
		s.closeDisplaced(displaced)
	}
	s.m.ConnectionsActive.WithLabelValues("client", conn.Grant().Tier).Inc()
	defer s.m.ConnectionsActive.WithLabelValues("client", conn.Grant().Tier).Dec()

	s.notifyPeerOnline(pair, conn)

	s.pump(ctx, pair, nil, conn)

	// See the matching comment in serveAgent: during a shutdown, Shutdown()
	// already owns notifying and closing every connection, so the ordinary
	// "client disappeared, tell the agent peer_offline" path is both
	// redundant and racy here.
	if s.shuttingDown.Load() {
		return
	}

	if pair.ClearClient(conn) {
		if peer := pair.Peer(wire.RoleClient); peer != nil {
			s.sendControl(peer, wire.PeerOffline())
		}
	}
}

// notifyPeerOnline tells both sides peer_online once both are attached.
// It is a no-op if the peer hasn't connected yet — in that case, the peer
// itself will call this (and find self) when it attaches, regardless of
// which side connects first (spec §4.6).
func (s *Server) notifyPeerOnline(pair *hub.Pair, self *hub.Conn) {
	peer := pair.Peer(self.Role())
	if peer == nil {
		return
	}
	s.sendControl(peer, wire.PeerOnline())
	s.sendControl(self, wire.PeerOnline())
}

func (s *Server) closeDisplaced(c *hub.Conn) {
	s.closeProto(c, wire.CloseDisplaced, "displaced")
}

// pump is the single read loop for every WebSocket the relay serves,
// routing each frame by its channel byte:
//
//   - 0x01/0x02 are forwarded verbatim to self's peer (the E2E lane).
//     Requires p; an http-only connection has no session and no peer.
//   - 0x03 is demultiplexed to the HTTP request that owns its stream_id
//     (the plain lane). Requires hp.
//
// Either lane may be absent: a client or plain E2E agent passes hp == nil,
// an http-only agent passes p == nil, and a dual agent passes both. A
// frame for an absent lane is a protocol violation and closes the
// connection — which is also what now makes the "0x03 is only ever valid
// on a connection that asked for it" rule true of the server and not just
// of the endpoints.
//
// The two lanes are charged against separate byte buckets on purpose. One
// socket must not mean one budget: a third-party client hammering
// inference would otherwise exhaust the pair's bucket and drop the socket
// the user's browser depends on.
//
// It deliberately does no buffering of its own — the next Read does not
// happen until the current frame's Write to the peer (or Deliver to a
// stream) has completed or timed out, which is what makes backpressure
// propagate all the way from a slow consumer back to Ollama's response
// stream (see the build plan's Design reference, "Backpressure:
// serialized forwarding, zero buffering").
func (s *Server) pump(ctx context.Context, p *hub.Pair, hp *hub.HTTPPair, self *hub.Conn) {
	self.SetReadLimit(int64(s.cfg.MaxFrameBytes) + 1024)

	pingCtx, cancelPing := context.WithCancel(ctx)
	defer cancelPing()
	go s.pingLoop(pingCtx, self)

	for {
		typ, data, err := self.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			s.closeProto(self, wire.CloseBadFrame, "binary_only")
			return
		}
		if len(data) > s.cfg.MaxFrameBytes {
			s.closeProto(self, wire.CloseFrameTooLarge, "frame_too_large")
			return
		}

		// Parsed before the byte bucket is charged, because which bucket
		// this frame belongs to depends on its channel. A malformed frame
		// therefore goes uncharged, which costs nothing: it closes the
		// connection on the spot rather than repeating.
		hdr, payload, err := wire.ParseOuter(data)
		if err != nil {
			s.closeProto(self, wire.CloseBadFrame, "bad_frame")
			return
		}

		switch hdr.Channel {
		case wire.ChannelCiphertext, wire.ChannelHandshake:
			if p == nil {
				s.closeProto(self, wire.CloseBadFrame, "unexpected_session_frame")
				return
			}
			if !p.Bucket().AllowN(len(data)) {
				s.m.RateLimitedTotal.WithLabelValues("pair_bytes").Inc()
				s.closeProto(self, wire.CloseRateLimited, "rate_limited")
				return
			}
			s.m.FramesTotal.WithLabelValues(channelLabel(hdr.Channel), "in").Inc()
			s.m.BytesTotal.WithLabelValues("in").Add(float64(len(data)))

			peer := p.Peer(self.Role())
			if peer == nil {
				s.sendControl(self, wire.NewError(wire.ErrPeerOffline))
				continue
			}

			writeStart := time.Now()
			wctx, cancel := context.WithTimeout(ctx, s.cfg.WriteTimeout)
			err = peer.Write(wctx, data)
			cancel()
			s.m.WriteStall.Observe(time.Since(writeStart).Seconds())
			if err != nil {
				// The PEER failed to keep up or is gone — close the peer,
				// not self. Self is healthy and keeps reading; if/when a
				// new peer attaches (reconnect/displacement), forwarding
				// resumes.
				s.closeProto(peer, wire.CloseWriteTimeout, "write_timeout")
				continue
			}
			s.m.FramesTotal.WithLabelValues(channelLabel(hdr.Channel), "out").Inc()
			s.m.BytesTotal.WithLabelValues("out").Add(float64(len(data)))

		case wire.ChannelPlain:
			if hp == nil {
				s.closeProto(self, wire.CloseBadFrame, "unexpected_plain_frame")
				return
			}
			if !hp.Bucket().AllowN(len(data)) {
				s.m.RateLimitedTotal.WithLabelValues("pair_bytes").Inc()
				s.closeProto(self, wire.CloseRateLimited, "rate_limited")
				return
			}
			frames, err := wire.DecodeInnerAll(payload)
			if err != nil {
				s.closeProto(self, wire.CloseBadFrame, "bad_frame")
				return
			}
			s.m.FramesTotal.WithLabelValues("plain", "in").Inc()
			s.m.BytesTotal.WithLabelValues("in").Add(float64(len(data)))
			for _, f := range frames {
				stream, ok := hp.Route(f.StreamID)
				if !ok {
					// Unknown stream_id: a frame that was already in flight
					// when the request was cancelled or completed. Spec
					// §6.1 requires dropping these silently.
					continue
				}
				stream.Deliver(hub.StreamEvent{Type: f.Type, Payload: f.Payload})
			}

		case wire.ChannelControl:
			// `rekey` (§11.3) is the one control message allowed after
			// hello, and only from an agent. A client sending control is
			// still a protocol violation.
			if self.Role() != wire.RoleAgent {
				s.closeProto(self, wire.CloseBadFrame, "unexpected_control_frame")
				return
			}
			s.handleAgentControl(hp, self, payload)

		default:
			// v1 defines nothing above 0x03.
			s.closeProto(self, wire.CloseBadFrame, "unexpected_channel")
			return
		}
	}
}

// handleAgentControl processes a post-hello control message from an agent.
//
// Deliberately never closes the connection. An agent that sends a control
// this build does not understand — a newer amallo against an older relay,
// or a rekey arriving on a connection whose HTTP lane was degraded away —
// must not lose its pairing over it, which is the same leniency the mode
// switch in handleUpgrade applies for the same reason.
func (s *Server) handleAgentControl(hp *hub.HTTPPair, self *hub.Conn, payload []byte) {
	var ct wire.ControlType
	if err := json.Unmarshal(payload, &ct); err != nil {
		s.log.Warn("agent sent unparseable control", "conn", self.ID())
		return
	}
	if ct.T != "rekey" {
		s.log.Warn("agent sent unknown control", "conn", self.ID(), "t", ct.T)
		return
	}
	if hp == nil {
		// No HTTP lane on this connection (plain E2E agent, or a dual one
		// that degraded). Nothing to re-index.
		s.log.Info("ignoring rekey: connection has no http lane", "conn", self.ID())
		return
	}

	var rk wire.Rekey
	if err := json.Unmarshal(payload, &rk); err != nil {
		s.log.Warn("agent sent malformed rekey", "conn", self.ID())
		return
	}
	if rk.TokenHash == "" {
		s.httpReg.Unregister(hp)
		s.log.Info("http lane unregistered by rekey", "conn", self.ID())
		return
	}
	th, err := hub.ParseTokenHash(rk.TokenHash)
	if err != nil {
		s.log.Warn("agent sent rekey with a malformed token hash", "conn", self.ID())
		return
	}
	if err := s.httpReg.Rekey(hp, th); err != nil {
		s.log.Warn("rekey refused", "conn", self.ID(), "err", err)
		return
	}
	s.log.Info("http lane rekeyed", "conn", self.ID(), "token", logging.TokenTag(th))
}

func channelLabel(ch wire.Channel) string {
	switch ch {
	case wire.ChannelCiphertext:
		return "ciphertext"
	case wire.ChannelHandshake:
		return "handshake"
	case wire.ChannelPlain:
		return "plain"
	default:
		return "control"
	}
}

// pingLoop sends RFC 6455 pings on cfg.PingInterval and closes the
// connection if a pong isn't observed within cfg.PongTimeout — the
// WebSocket-layer liveness check spec §7 relies on independent of any
// application-level signal.
func (s *Server) pingLoop(ctx context.Context, c *hub.Conn) {
	t := time.NewTicker(s.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, s.cfg.PongTimeout)
			err := c.Ping(pctx)
			cancel()
			if err != nil {
				s.closeProto(c, int(websocket.StatusPolicyViolation), "ping_timeout")
				return
			}
		}
	}
}

func (s *Server) closeProto(c *hub.Conn, code int, reason string) {
	s.m.CloseTotal.WithLabelValues(strconv.Itoa(code)).Inc()
	_ = c.Close(websocket.StatusCode(code), reason)
}

func (s *Server) sendControl(c *hub.Conn, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	frame := wire.EncodeOuter(wire.ChannelControl, b)
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.WriteTimeout)
	defer cancel()
	_ = c.Write(ctx, frame) // best-effort: a failed control send means the
	// conn is already dying, and its own read/pump loop will observe that
	// independently and clean up.
}

func (s *Server) sendHelloOK(c *hub.Conn) {
	s.sendControl(c, wire.HelloOK{
		T:      "hello_ok",
		Conn:   strconv.FormatUint(c.ID(), 10),
		PingMS: int(s.cfg.PingInterval.Milliseconds()),
	})
}

func readHello(ctx context.Context, c *hub.Conn) (wire.Hello, error) {
	typ, data, err := c.Read(ctx)
	if err != nil {
		return wire.Hello{}, err
	}
	if typ != websocket.MessageBinary {
		return wire.Hello{}, errNotBinary
	}
	hdr, payload, err := wire.ParseOuter(data)
	if err != nil {
		return wire.Hello{}, err
	}
	if hdr.Channel != wire.ChannelControl {
		return wire.Hello{}, errNotControl
	}
	var h wire.Hello
	if err := json.Unmarshal(payload, &h); err != nil {
		return wire.Hello{}, err
	}
	if h.T != "hello" {
		return wire.Hello{}, errNotHello
	}
	return h, nil
}

func decodePairID(s string) (hub.PairID, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 16 {
		return hub.PairID{}, errBadPairID
	}
	var id hub.PairID
	copy(id[:], b)
	return id, nil
}

// clientIP extracts the caller's address, preferring the first
// X-Forwarded-For hop when trustProxy is set (the deploy topology in Step
// 3 always sits behind Caddy) and falling back to the raw connection's
// remote address otherwise. Never returns an error — an unparseable
// address degrades to the unspecified address, which the IP rate limiter
// still functions against (conservatively, as a single shared bucket).
func clientIP(r *http.Request, trustProxy bool) netip.Addr {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
			if ip, err := netip.ParseAddr(first); err == nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip
	}
	return netip.IPv4Unspecified()
}
