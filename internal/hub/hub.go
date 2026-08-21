package hub

import (
	"errors"
	"sync"
)

// ErrCapacity is returned by RegisterAgent when creating a new pair would
// exceed the configured maximum — see Hub.maxPairs and the
// RELAY_MAX_PAIRS config knob. Existing pairs are never affected by this;
// only new-pair creation is capacity-gated (a displaced agent
// reconnecting to its own pair never counts against the limit twice).
var ErrCapacity = errors.New("hub: at capacity")

// Hub owns the pair_id -> Pair map. Its mutex guards only the map itself
// (invariant #1 from the build plan's locking discipline): never held
// across I/O, and never held across a Pair's own mutex. A pair is created
// only when an agent registers it — never by a client attach — which is
// what bounds map growth to real agents rather than every unauthenticated
// upgrade attempt.
type Hub struct {
	mu                  sync.RWMutex
	pairs               map[PairID]*Pair
	maxPairs            int
	pairRateBytesPerSec int64
}

func New(maxPairs int, pairRateBytesPerSec int64) *Hub {
	return &Hub{
		pairs:               make(map[PairID]*Pair),
		maxPairs:            maxPairs,
		pairRateBytesPerSec: pairRateBytesPerSec,
	}
}

// RegisterAgent attaches c as the agent for id, creating the pair if it
// doesn't exist yet. If the pair already exists, any previous agent
// connection is displaced (see Pair.SetAgent) rather than rejected — both
// roles displace, per the build plan, so a reconnecting agent is never
// locked out behind the old connection's ping-timeout window.
//
// Capacity (RELAY_MAX_PAIRS) is checked only on new-pair creation: an
// agent reconnecting to its own already-registered pair never counts
// against the limit a second time.
func (h *Hub) RegisterAgent(id PairID, c *Conn) (pair *Pair, displaced *Conn, err error) {
	h.mu.Lock()
	p, exists := h.pairs[id]
	if !exists {
		if len(h.pairs) >= h.maxPairs {
			h.mu.Unlock()
			return nil, nil, ErrCapacity
		}
		p = newPair(id, h.pairRateBytesPerSec)
		h.pairs[id] = p
	}
	h.mu.Unlock()

	displaced = p.SetAgent(c)
	return p, displaced, nil
}

// Lookup returns the pair for id without creating one — used by the
// client-side upgrade path, where an unregistered pair means "agent
// offline" (spec close code 4404), not "create an empty pair and wait".
func (h *Hub) Lookup(id PairID) (*Pair, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	p, ok := h.pairs[id]
	return p, ok
}

// DetachAgent removes c from the agent slot. It only acts if c is still
// the pair's current agent connection; if c was already displaced by a
// newer connection (see Pair.SetAgent), this is a no-op and the live pair
// is left untouched — a stale cleanup goroutine from the old connection
// must never disturb a pair a reconnect has already taken over.
//
// What happens to the pair depends on whether anyone is still using it:
//
//   - a client is attached: the pair is KEPT, agentless, and returned as
//     kept=true. The caller sends the client peer_offline and arms a
//     grace window; a returning agent inside that window re-registers
//     into this same pair and the client never notices more than a pause.
//   - nobody else is attached: the pair is dropped immediately, because
//     nothing would be preserved by keeping it.
//
// Returns the client attached at the moment of detaching (nil if none),
// and — when the pair was kept — the park number to arm the grace timer
// with, which DropIfParked uses to tell this park from any later one.
func (h *Hub) DetachAgent(id PairID, c *Conn) (client *Conn, park uint64, kept bool, ok bool) {
	h.mu.RLock()
	p, exists := h.pairs[id]
	h.mu.RUnlock()
	if !exists {
		return nil, 0, false, false
	}

	client, park, cleared := p.ClearAgent(c)
	if !cleared {
		return nil, 0, false, false
	}
	if client != nil {
		return client, park, true, true
	}

	h.mu.Lock()
	if h.pairs[id] == p {
		delete(h.pairs, id)
	}
	h.mu.Unlock()
	return nil, 0, false, true
}

// DropIfParked removes a pair once the park numbered `park` has run out of
// grace without the agent coming back, returning the client that was still
// waiting on it (nil if it gave up first) so the caller can close it with
// 4410 agent_gone.
//
// A no-op if an agent has since reattached, or if a *later* park has
// replaced this one — which is why the grace timer never needs
// cancelling. It fires, finds that the park it was armed for is over, and
// leaves the pair alone.
func (h *Hub) DropIfParked(id PairID, park uint64) (client *Conn, dropped bool) {
	h.mu.RLock()
	p, exists := h.pairs[id]
	h.mu.RUnlock()
	if !exists {
		return nil, false
	}

	client, ended := p.endPark(park)
	if !ended {
		return nil, false
	}

	h.mu.Lock()
	if h.pairs[id] == p {
		delete(h.pairs, id)
	}
	h.mu.Unlock()
	return client, true
}

// DropIfIdle removes a pair nobody is attached to any more — the case
// where a parked pair's client gives up before the agent returns, leaving
// an entry with nothing on either side and no reason to keep waiting for
// its grace timer.
func (h *Hub) DropIfIdle(id PairID) (dropped bool) {
	h.mu.RLock()
	p, exists := h.pairs[id]
	h.mu.RUnlock()
	if !exists || !p.isIdle() {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pairs[id] != p {
		return false
	}
	delete(h.pairs, id)
	return true
}

// Len reports the number of currently registered pairs — used for the
// relay_pairs_active gauge and tests.
func (h *Hub) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.pairs)
}
