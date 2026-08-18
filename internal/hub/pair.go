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

// ClearAgentAndClient nils both slots, but only if the agent slot is
// still occupied by c (the same staleness guard as ClearClient). Returns
// the client connection that was attached at the moment of clearing, if
// any, so the caller can notify and close it — an agent disconnecting
// takes the whole pair down (spec §8: close code 4410 agent_gone).
func (p *Pair) ClearAgentAndClient(c *Conn) (client *Conn, cleared bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.agent != c {
		return nil, false
	}
	client = p.client
	p.agent = nil
	p.client = nil
	return client, true
}

// HasAgent reports whether an agent is currently attached — used by
// metrics/diagnostics, not by the hot forwarding path.
func (p *Pair) HasAgent() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.agent != nil
}
