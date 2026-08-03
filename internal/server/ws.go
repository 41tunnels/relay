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

	sessionStart := time.Now()
	s.sendHelloOK(conn)

	switch role {
	case wire.RoleAgent:
		s.serveAgent(r.Context(), pairID, conn)
	case wire.RoleClient:
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

	s.notifyPeerOnline(pair, conn)

	s.pump(ctx, pair, conn)

	client, removed := s.hub.RemoveIfAgent(id, conn)
	if removed {
		s.m.PairsActive.Set(float64(s.hub.Len()))
		if client != nil {
			s.sendControl(client, wire.PeerOffline())
			s.closeProto(client, wire.CloseAgentGone, "agent_gone")
		}
	}
}

func (s *Server) serveClient(ctx context.Context, id hub.PairID, conn *hub.Conn) {
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

	s.pump(ctx, pair, conn)

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

// pump is the forwarding loop: read one outer frame from self, hand it to
// self's peer. It deliberately does no buffering of its own — the next
// Read does not happen until the current frame's Write to the peer has
// completed or timed out, which is what makes backpressure propagate all
// the way from a slow browser's TCP receive window back to Ollama's
// response stream (see the build plan's Design reference, "Backpressure:
// serialized forwarding, zero buffering").
func (s *Server) pump(ctx context.Context, p *hub.Pair, self *hub.Conn) {
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
		if !p.Bucket().AllowN(len(data)) {
			s.m.RateLimitedTotal.WithLabelValues("pair_bytes").Inc()
			s.closeProto(self, wire.CloseRateLimited, "rate_limited")
			return
		}

		hdr, _, err := wire.ParseOuter(data)
		if err != nil {
			s.closeProto(self, wire.CloseBadFrame, "bad_frame")
			return
		}
		if hdr.Channel == wire.ChannelControl {
			// No control-channel messages are expected from either side
			// after the initial hello — everything past that point is
			// opaque ciphertext/handshake data the relay only forwards.
			s.closeProto(self, wire.CloseBadFrame, "unexpected_control_frame")
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
			// The PEER failed to keep up or is gone — close the peer, not
			// self. Self is healthy and keeps reading; if/when a new peer
			// attaches (reconnect/displacement), forwarding resumes.
			s.closeProto(peer, wire.CloseWriteTimeout, "write_timeout")
			continue
		}
		s.m.FramesTotal.WithLabelValues(channelLabel(hdr.Channel), "out").Inc()
		s.m.BytesTotal.WithLabelValues("out").Add(float64(len(data)))
	}
}

func channelLabel(ch wire.Channel) string {
	switch ch {
	case wire.ChannelCiphertext:
		return "ciphertext"
	case wire.ChannelHandshake:
		return "handshake"
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
