package hub

import (
	"sync"
	"time"

	"github.com/41tunnels/relay/internal/limits"
	"github.com/41tunnels/relay/internal/wire"
)

// Pair is one agent/client slot pair. Its mutex guards only the two
// pointer fields below — it is never held across a network write. To
// forward a frame: take the lock, copy the peer pointer, release, then
// write outside the lock (see Peer). This is invariant #2 from the build
// plan's locking discipline.
type Pair struct {
	id      PairID
	created time.Time
	bucket  *limits.Bucket

	mu     sync.Mutex
	agent  *Conn
	client *Conn
	// Incremented every time the agent slot is cleared, so each park can
	// be told apart from the one before it. A grace timer carries the
	// number of the park it was armed for and does nothing if that park
	// has already ended — otherwise an agent that leaves, returns and
	// leaves again would have its second park cut short by the first
	// park's timer, which sees an agentless pair and cannot tell that it
	// is looking at a different one.
	parkSeq uint64
}

func newPair(id PairID, bytesPerSec int64) *Pair {
	return &Pair{
		id:      id,
		created: time.Now(),
		bucket:  limits.NewBucket(bytesPerSec),
	}
}

func (p *Pair) ID() PairID          { return p.id }
func (p *Pair) Bucket() *limits.Bucket { return p.bucket }

// Peer returns the other side's current connection for self's role, or
// nil if that side isn't attached right now. Safe to call from any
// goroutine; the returned pointer may become stale immediately after
// return (the peer could disconnect a moment later) — callers must treat
// a subsequent Write error as "the peer is gone", not as a bug.
func (p *Pair) Peer(self wire.Role) *Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if self == wire.RoleAgent {
		return p.client
	}
	return p.agent
}

// SetAgent installs c as the pair's agent connection, returning whatever
// was there before (nil if nothing was). The caller is responsible for
// closing a non-nil return value with CloseDisplaced — both roles
// displace rather than reject, per the build plan (a stale connection
// shouldn't lock out a reconnecting device for up to the ping-timeout
// window).
func (p *Pair) SetAgent(c *Conn) (displaced *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	displaced = p.agent
	p.agent = c
	return displaced
}

// SetClient installs c as the pair's client connection, displacing any
// previous one (see SetAgent).
func (p *Pair) SetClient(c *Conn) (displaced *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	displaced = p.client
	p.client = c
	return displaced
}

// ClearClient removes c from the client slot, but only if c is still the
// current occupant — this guards against a stale cleanup racing a newer
// connection's SetClient (e.g. old client's pump exits right as a new
// client already displaced it; the old pump's cleanup must not evict the
// new one). Returns true if it actually cleared the slot.
func (p *Pair) ClearClient(c *Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client == c {
		p.client = nil
		return true
	}
	return false
}

// ClearAgent nils the agent slot, but only if it is still occupied by c
// (the same staleness guard as ClearClient), and leaves the client slot
// alone. Returns the client that was attached at the moment of clearing,
// if any, so the caller can tell it the agent went away.
//
// It deliberately does NOT evict the client. An agent restarting, waking
// from sleep or flipping networks is the common case, not an exceptional
// one, and taking the browser's socket down with it turned a two-second
// blip into a full reconnect on both sides — with backoff, a fresh TLS
// handshake and a fresh E2E handshake, all to arrive back where it
// started. The pair is instead parked agentless for a grace window (see
// the server's retireAgent): the client stays attached and simply gets
// peer_offline, and the returning agent's peer_online starts a new
// session on the socket that never went away.
func (p *Pair) ClearAgent(c *Conn) (client *Conn, park uint64, cleared bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.agent != c {
		return nil, 0, false
	}
	p.agent = nil
	p.parkSeq++
	return p.client, p.parkSeq, true
}

// endPark reports whether the pair is still sitting in the park numbered
// `park` — no agent has come back, and no later park has replaced this
// one — and returns the client still waiting on it, if any.
func (p *Pair) endPark(park uint64) (client *Conn, ended bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.agent != nil || p.parkSeq != park {
		return nil, false
	}
	return p.client, true
}

// isIdle reports whether neither side is attached.
func (p *Pair) isIdle() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.agent == nil && p.client == nil
}

// Client returns the currently attached client connection, or nil. Same
// staleness caveat as Peer: the pointer may go stale the moment it is
// returned.
func (p *Pair) Client() *Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.client
}

// HasAgent reports whether an agent is currently attached — used by
// metrics/diagnostics, not by the hot forwarding path.
func (p *Pair) HasAgent() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.agent != nil
}
