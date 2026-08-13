package hub

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/OpenCharUI/relay/internal/limits"
	"github.com/OpenCharUI/relay/internal/wire"
)

// TokenHash is the SHA-256 of an API key issued by an agent for the
// OpenAI-compatible HTTP endpoint (spec §11.2). The relay indexes hashes,
// never keys: a heap dump or leaked index yields nothing directly usable,
// even though the relay unavoidably sees the key in flight on every
// request. This is hardening against an offline leak, not against a live
// relay compromise — that threat is out of scope for this path by
// construction, since the relay also sees plaintext prompts here.
type TokenHash [32]byte

// HashToken derives the index key for a raw API key.
func HashToken(raw string) TokenHash {
	return TokenHash(sha256.Sum256([]byte(raw)))
}

// ParseTokenHash decodes the base64url form an agent sends in its hello.
func ParseTokenHash(s string) (TokenHash, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return TokenHash{}, ErrBadTokenHash
	}
	var th TokenHash
	copy(th[:], b)
	return th, nil
}

// Equal compares in constant time. Callers look tokens up via a map (which
// is not constant-time), so this exists for the paths that compare a
// candidate against a known value directly.
func (t TokenHash) Equal(other TokenHash) bool {
	return subtle.ConstantTimeCompare(t[:], other[:]) == 1
}

func (t TokenHash) String() string { return base64.RawURLEncoding.EncodeToString(t[:]) }

var (
	ErrBadTokenHash   = errors.New("hub: invalid token hash")
	ErrStreamsExhaust = errors.New("hub: stream ids exhausted")
	ErrTooManyInFlight = errors.New("hub: too many concurrent requests for this pair")
	ErrAgentOffline   = errors.New("hub: agent offline")
	ErrTokenTaken     = errors.New("hub: token hash already belongs to another agent")
)

// StreamEvent is one inner frame routed back to the HTTP request that owns
// its stream_id: RESP, then zero or more RESP_BODY, then RESP_END — or
// ERROR at any point.
type StreamEvent struct {
	Type    wire.InnerType
	Payload []byte
}

// Stream is the response side of one in-flight HTTP request.
//
// events is deliberately bounded and never dropped: when an HTTP client
// stops reading, this channel fills, which blocks the agent connection's
// reader goroutine, which stops draining the WebSocket, which propagates
// backpressure through the relay all the way to Ollama's response stream.
// That is the same "serialized forwarding, zero buffering" property the
// E2E pump has, and the reason a large buffer here would be a bug rather
// than an optimization.
//
// The cost is head-of-line blocking across streams sharing one agent
// socket: a stalled client delays other requests on the same connection.
// The E2E path has the identical property, and spec §6's 16 KiB RESP_BODY
// guidance is what bounds the resulting latency; the server additionally
// applies a write deadline so a dead client cannot wedge the connection
// indefinitely.
type Stream struct {
	id     uint32
	events chan StreamEvent
	// done, not a close of events: the agent's reader goroutine can be
	// blocked in Deliver at the exact moment the HTTP handler tears the
	// stream down, and closing a channel out from under a blocked sender
	// panics. Signalling completion on a second channel makes both sides
	// race-free, at the cost of one extra select arm in the receiver.
	done chan struct{}
	once sync.Once
}

func (s *Stream) ID() uint32                 { return s.id }
func (s *Stream) Events() <-chan StreamEvent { return s.events }

// Done is closed when the stream is torn down — by the handler finishing,
// or by the agent detaching mid-request.
func (s *Stream) Done() <-chan struct{} { return s.done }

// Deliver hands one event to the owning request, blocking while the
// buffer is full (that block is the backpressure — see the type comment).
// Returns false once the stream is torn down, which is the ordinary fate
// of a late frame arriving after CANCEL; spec §6.1 requires the sender to
// tolerate exactly this and drop it silently.
func (s *Stream) Deliver(ev StreamEvent) bool {
	select {
	case s.events <- ev:
		return true
	case <-s.done:
		return false
	}
}

// close marks the stream dead and wakes both any blocked sender and the
// receiver. Idempotent.
func (s *Stream) close() {
	s.once.Do(func() { close(s.done) })
}

// HTTPPair is one agent connected in mode:"http" (spec §11). Unlike Pair
// it has no client socket — the relay's own HTTP handler plays the client
// role, so this type owns the stream-id allocator and the response router
// that a web client would otherwise own itself.
type HTTPPair struct {
	tokenHash TokenHash
	pairID    PairID
	created   time.Time
	bucket    *limits.Bucket
	maxInFlight int
	streamBuf   int

	mu         sync.Mutex
	agent      *Conn
	nextStream uint32
	streams    map[uint32]*Stream
	inFlight   int
	// offlineAt is zero while an agent is attached. Once set, this entry
	// is a tombstone: the token is still known (so the HTTP handler can
	// answer 503 "agent offline" instead of 401, which is the difference
	// between a user seeing "your PC is asleep" and "your API key is
	// wrong") but no request can be served until an agent reattaches.
	offlineAt time.Time
}

func newHTTPPair(th TokenHash, pairID PairID, bytesPerSec int64, maxInFlight, streamBuf int) *HTTPPair {
	return &HTTPPair{
		tokenHash:   th,
		pairID:      pairID,
		created:     time.Now(),
		bucket:      limits.NewBucket(bytesPerSec),
		maxInFlight: maxInFlight,
		streamBuf:   streamBuf,
		// Odd stream ids only: spec §6 reserves even ones for
		// agent-initiated streams, which do not exist in v1.
		nextStream: 1,
		streams:    make(map[uint32]*Stream),
	}
}

func (p *HTTPPair) PairID() PairID         { return p.pairID }
func (p *HTTPPair) Bucket() *limits.Bucket { return p.bucket }

// TokenHash reports the hash this entry is currently indexed under. Read
// under the lock because a rekey (§11.3) can change it mid-connection.
func (p *HTTPPair) TokenHash() TokenHash {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenHash
}

// dropStreamsLocked tears down every in-flight stream and returns them for
// the caller to close outside the lock. Used on detach and on rekey: in
// both cases the requests can never be answered, and on rekey they were
// authorised under a key that no longer exists.
func (p *HTTPPair) dropStreamsLocked() []*Stream {
	streams := make([]*Stream, 0, len(p.streams))
	for id, s := range p.streams {
		streams = append(streams, s)
		delete(p.streams, id)
	}
	p.inFlight = 0
	return streams
}

// Agent returns the currently attached agent connection, or nil if this
// entry is a tombstone.
func (p *HTTPPair) Agent() *Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.agent
}

// OpenStream allocates a stream id and registers a response route for it.
// Returns ErrAgentOffline if no agent is attached, and ErrTooManyInFlight
// once the per-pair concurrency cap is reached — a shared key pointed at
// one consumer GPU queues badly, so shedding with 429 beats thrashing.
func (p *HTTPPair) OpenStream() (*Stream, *Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.agent == nil {
		return nil, nil, ErrAgentOffline
	}
	if p.inFlight >= p.maxInFlight {
		return nil, nil, ErrTooManyInFlight
	}
	// Spec §6: a stream_id is never reused within a session, and wrapping
	// closes the connection rather than recycling ids. Detect the wrap
	// before it happens; the server turns this into a connection teardown
	// so the agent reconnects with a fresh id space.
	if p.nextStream > 0xFFFFFFFD {
		return nil, nil, ErrStreamsExhaust
	}

	s := &Stream{
		id:     p.nextStream,
		events: make(chan StreamEvent, p.streamBuf),
		done:   make(chan struct{}),
	}
	p.nextStream += 2
	p.streams[s.id] = s
	p.inFlight++
	return s, p.agent, nil
}

// CloseStream removes a stream's route and releases its concurrency slot.
// Safe to call more than once for the same stream.
func (p *HTTPPair) CloseStream(s *Stream) {
	p.mu.Lock()
	if _, ok := p.streams[s.id]; ok {
		delete(p.streams, s.id)
		p.inFlight--
	}
	p.mu.Unlock()
	s.close()
}

// Route finds the stream owning an inbound inner frame's stream_id.
func (p *HTTPPair) Route(streamID uint32) (*Stream, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.streams[streamID]
	return s, ok
}

// detachAgent turns this entry into a tombstone and tears down every
// in-flight stream — their requests can never be answered now, and
// leaving them blocked would hang the HTTP handlers until their own
// timeouts.
func (p *HTTPPair) detachAgent(c *Conn) bool {
	p.mu.Lock()
	if p.agent != c {
		p.mu.Unlock()
		return false
	}
	p.agent = nil
	p.offlineAt = time.Now()
	streams := p.dropStreamsLocked()
	p.mu.Unlock()

	for _, s := range streams {
		s.close()
	}
	return true
}

// attachAgent installs c, returning any previous agent to be displaced.
// Reattaching clears the tombstone but deliberately does NOT reset
// nextStream: ids stay unique for the lifetime of the registry entry, so
// a late frame from a previous connection can never be mistaken for a
// live stream.
func (p *HTTPPair) attachAgent(c *Conn) (displaced *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	displaced = p.agent
	p.agent = c
	p.offlineAt = time.Time{}
	return displaced
}

// HTTPRegistry owns the token_hash -> HTTPPair map. It is entirely
// separate from Hub's pair_id map: an agent in http mode never occupies
// an E2E pair slot, so enabling the OpenAI endpoint can neither displace
// nor interfere with the web PWA's pairing, even for the same install.
type HTTPRegistry struct {
	mu           sync.RWMutex
	byToken      map[TokenHash]*HTTPPair
	maxPairs     int
	tombstoneTTL time.Duration
	rateBytes    int64
	maxInFlight  int
	streamBuf    int
}

func NewHTTPRegistry(maxPairs int, rateBytes int64, tombstoneTTL time.Duration, maxInFlight, streamBuf int) *HTTPRegistry {
	// Clamp rather than reject: a caller constructing a Config literal
	// without these fields (tests, mostly) should get a working registry,
	// not an unbuffered channel that deadlocks in a way that looks like a
	// protocol bug. Config.Validate is where bad deploy values are caught.
	if maxInFlight <= 0 {
		maxInFlight = 1
	}
	if streamBuf <= 0 {
		streamBuf = 1
	}
	if tombstoneTTL <= 0 {
		tombstoneTTL = time.Hour
	}
	return &HTTPRegistry{
		byToken:      make(map[TokenHash]*HTTPPair),
		maxPairs:     maxPairs,
		tombstoneTTL: tombstoneTTL,
		rateBytes:    rateBytes,
		maxInFlight:  maxInFlight,
		streamBuf:    streamBuf,
	}
}

// RegisterAgent attaches c for th, creating the entry if needed (or
// reviving a tombstone). Capacity is charged only on creation, matching
// Hub.RegisterAgent: a reconnecting agent never counts twice.
//
// Tombstones deliberately do not count toward maxPairs — otherwise an
// agent restart loop would exhaust the budget with entries that serve no
// traffic.
func (r *HTTPRegistry) RegisterAgent(th TokenHash, pairID PairID, c *Conn) (*HTTPPair, *Conn, error) {
	r.mu.Lock()
	p, exists := r.byToken[th]
	if !exists {
		if r.liveCountLocked() >= r.maxPairs {
			r.mu.Unlock()
			return nil, nil, ErrCapacity
		}
		p = newHTTPPair(th, pairID, r.rateBytes, r.maxInFlight, r.streamBuf)
		r.byToken[th] = p
	}
	r.mu.Unlock()

	displaced := p.attachAgent(c)
	return p, displaced, nil
}

// Rekey re-indexes p under newTH, in place and without disturbing the
// connection (spec §11.3). Every in-flight stream is torn down: those
// requests were authorised under the previous key, which the user has
// just revoked, so answering them would outlive the revocation.
//
// Refuses if newTH already belongs to a different entry. A hash
// collision on a 256-bit key is not a real scenario, but without this an
// agent could publish another agent's hash and take over routing for a
// key it does not hold.
func (r *HTTPRegistry) Rekey(p *HTTPPair, newTH TokenHash) error {
	r.mu.Lock()
	if existing, ok := r.byToken[newTH]; ok && existing != p {
		r.mu.Unlock()
		return ErrTokenTaken
	}
	old := p.TokenHash()
	if old != newTH {
		// Only drop the old mapping if it still points at this entry — a
		// concurrent re-register may already have replaced it.
		if existing, ok := r.byToken[old]; ok && existing == p {
			delete(r.byToken, old)
		}
		r.byToken[newTH] = p
	}
	r.mu.Unlock()

	p.mu.Lock()
	p.tokenHash = newTH
	streams := p.dropStreamsLocked()
	p.mu.Unlock()
	for _, s := range streams {
		s.close()
	}
	return nil
}

// Unregister removes p from the token index without touching its
// connection, so the agent's other lane (a paired browser sharing the
// same socket) keeps running. Used when the OpenAI endpoint is switched
// off. The entry stops resolving immediately; a later Rekey re-indexes it.
func (r *HTTPRegistry) Unregister(p *HTTPPair) {
	r.mu.Lock()
	old := p.TokenHash()
	if existing, ok := r.byToken[old]; ok && existing == p {
		delete(r.byToken, old)
	}
	r.mu.Unlock()

	p.mu.Lock()
	streams := p.dropStreamsLocked()
	p.mu.Unlock()
	for _, s := range streams {
		s.close()
	}
}

// Lookup returns the entry for a token hash whether or not an agent is
// currently attached — the caller distinguishes those cases via
// HTTPPair.Agent(), which is what makes 503-vs-401 possible.
func (r *HTTPRegistry) Lookup(th TokenHash) (*HTTPPair, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byToken[th]
	return p, ok
}

// DetachAgent marks the entry offline if c is still its agent. The entry
// itself survives as a tombstone until Sweep evicts it.
func (r *HTTPRegistry) DetachAgent(th TokenHash, c *Conn) bool {
	r.mu.RLock()
	p, ok := r.byToken[th]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	return p.detachAgent(c)
}

// Sweep evicts tombstones older than the configured TTL. Returns how many
// entries it removed. The server runs this on a ticker.
func (r *HTTPRegistry) Sweep(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	evicted := 0
	for th, p := range r.byToken {
		p.mu.Lock()
		expired := p.agent == nil && !p.offlineAt.IsZero() && now.Sub(p.offlineAt) > r.tombstoneTTL
		p.mu.Unlock()
		if expired {
			delete(r.byToken, th)
			evicted++
		}
	}
	return evicted
}

// Len reports live (agent-attached) entries, for the pairs_active gauge.
func (r *HTTPRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.liveCountLocked()
}

// TotalLen reports live entries plus tombstones, for diagnostics.
func (r *HTTPRegistry) TotalLen() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byToken)
}

func (r *HTTPRegistry) liveCountLocked() int {
	n := 0
	for _, p := range r.byToken {
		p.mu.Lock()
		if p.agent != nil {
			n++
		}
		p.mu.Unlock()
	}
	return n
}
