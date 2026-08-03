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

// RemoveIfAgent tears the pair down entirely — spec §8: an agent
// disconnecting closes the whole pair, taking any attached client with it
// (close code 4410 agent_gone). It only acts if c is still the pair's
// current agent connection; if c was already displaced by a newer
// connection (see Pair.SetAgent), this is a no-op and the live pair is
// left untouched — a stale cleanup goroutine from the old connection must
// never tear down a pair a reconnect has already taken over.
//
// Returns the client connection that was attached at the moment of
// removal (nil if none), for the caller to notify (peer_offline) and
// close (4410).
func (h *Hub) RemoveIfAgent(id PairID, c *Conn) (client *Conn, removed bool) {
	h.mu.RLock()
	p, ok := h.pairs[id]
	h.mu.RUnlock()
	if !ok {
		return nil, false
	}

	client, cleared := p.ClearAgentAndClient(c)
	if !cleared {
		return nil, false
	}

	h.mu.Lock()
	if h.pairs[id] == p {
		delete(h.pairs, id)
	}
	h.mu.Unlock()

	return client, true
}

// Len reports the number of currently registered pairs — used for the
// relay_pairs_active gauge and tests.
func (h *Hub) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.pairs)
}
