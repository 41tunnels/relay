package server

// The agent side of the OpenAI-compatible endpoint (spec §11) for an agent
// that declared mode:"http" — the HTTP lane alone, with no pairing. It has
// no peer socket to be spliced with (the relay's own HTTP handlers in
// openai.go play the client role), so it gets its own register/detach
// path, but it shares the one pump in ws.go.
//
// amallo opens mode:"dual" instead (see Server.serveDualAgent); this mode
// remains for agents that want the endpoint without a pairing at all.

import (
	"context"
	"time"

	"github.com/OpenCharUI/relay/internal/hub"
	"github.com/OpenCharUI/relay/internal/logging"
	"github.com/OpenCharUI/relay/internal/wire"
)

func (s *Server) serveHTTPAgent(ctx context.Context, id hub.PairID, conn *hub.Conn, tokenHashB64 string) {
	th, err := hub.ParseTokenHash(tokenHashB64)
	if err != nil {
		s.m.ConnectionsTotal.WithLabelValues("agent_http", "rejected").Inc()
		s.closeProto(conn, wire.CloseBadFrame, "bad_frame")
		return
	}

	pair, displaced, err := s.httpReg.RegisterAgent(th, id, conn)
	if err != nil {
		s.closeProto(conn, wire.CloseCapacity, "capacity")
		return
	}
	if displaced != nil {
		s.closeDisplaced(displaced)
	}

	s.m.ConnectionsActive.WithLabelValues("agent_http", conn.Grant().Tier).Inc()
	defer s.m.ConnectionsActive.WithLabelValues("agent_http", conn.Grant().Tier).Dec()

	s.log.Info("http agent registered",
		"conn", conn.ID(),
		"token", logging.TokenTag(th),
		"live", s.httpReg.Len(),
	)

	// Registered: the key resolves, so an HTTP request arriving the
	// instant the agent sees this acknowledgement is routable rather than
	// answered with a spurious "incorrect API key".
	s.sendHelloOK(conn)

	// Shares the one pump with every other connection kind; passing a nil
	// Pair is what makes a session frame (0x01/0x02) a protocol violation
	// here, since this connection has no peer and no session.
	s.pump(ctx, nil, pair, conn)

	// Shutdown() owns notification and close for every tracked connection
	// during a shutdown; detaching here too would race it, exactly as it
	// would in serveAgent.
	if s.shuttingDown.Load() {
		return
	}
	// Read the hash back rather than reusing the one registered with: a
	// rekey (§11.3) may have re-indexed this entry since.
	cur := pair.TokenHash()
	if s.httpReg.DetachAgent(cur, conn) {
		s.log.Info("http agent detached", "conn", conn.ID(), "token", logging.TokenTag(cur))
	}
}

// sweepHTTPTombstones evicts expired offline entries on a ticker, so a key
// whose agent has been gone longer than the TTL stops resolving (and reads
// as unknown) instead of accumulating forever.
func (s *Server) sweepHTTPTombstones(ctx context.Context) {
	interval := s.cfg.HTTPTombstoneTTL / 4
	if interval < time.Minute {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if n := s.httpReg.Sweep(now); n > 0 {
				s.log.Info("swept http tombstones", "evicted", n, "remaining", s.httpReg.TotalLen())
			}
		}
	}
}
