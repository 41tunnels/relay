// Package limits implements the relay's two rate controls: a per-pair byte
// budget (protects one pair's bandwidth from starving others sharing the
// host) and a per-IP connection-attempt budget (bounds the cost of
// unauthenticated upgrade attempts before a pair even exists). See the
// build plan's Step 2 — these are deliberately simple token buckets, not a
// distributed rate limiter; the relay is a single process per deploy.
package limits

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Bucket is a per-pair byte-rate limiter. Burst is set to one second's
// worth of the configured rate, which is generous enough not to choke a
// single large NDJSON chunk while still bounding sustained throughput.
type Bucket struct {
	lim *rate.Limiter
}

// NewBucket builds a Bucket allowing bytesPerSec sustained, bursting up to
// bytesPerSec in one go (i.e. a single very large frame at MaxFrameBytes
// still gets through as long as it's under the burst, rather than being
// rejected outright).
func NewBucket(bytesPerSec int64) *Bucket {
	if bytesPerSec <= 0 {
		bytesPerSec = 1 // never construct a limiter that permits nothing
	}
	return &Bucket{lim: rate.NewLimiter(rate.Limit(bytesPerSec), int(bytesPerSec))}
}

// AllowN reports whether n bytes may be admitted right now. It does not
// block — the relay's forwarding pump treats a rate-limit hit as a
// protocol violation (close the connection), not something to queue
// behind, per the "no buffering" backpressure design.
func (b *Bucket) AllowN(n int) bool {
	return b.lim.AllowN(time.Now(), n)
}

// IPLimiter bounds new-connection attempts per source IP, independent of
// whether a pair ends up existing — this is what keeps an unauthenticated
// flood of upgrade requests cheap to reject.
type IPLimiter struct {
	perMin int
	mu     sync.Mutex
	byIP   map[netip.Addr]*entry
}

type entry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// NewIPLimiter builds a limiter allowing perMin connection attempts per
// minute per source IP, with a burst equal to perMin (so a legitimate
// client reconnecting a few times in quick succession after a network
// blip isn't punished).
func NewIPLimiter(perMin int) *IPLimiter {
	if perMin <= 0 {
		perMin = 1
	}
	return &IPLimiter{
		perMin: perMin,
		byIP:   make(map[netip.Addr]*entry),
	}
}

// Allow reports whether ip may attempt a new connection now, lazily
// creating that IP's bucket on first sight.
func (l *IPLimiter) Allow(ip netip.Addr) bool {
	l.mu.Lock()
	e, ok := l.byIP[ip]
	if !ok {
		e = &entry{lim: rate.NewLimiter(rate.Limit(float64(l.perMin)/60.0), l.perMin)}
		l.byIP[ip] = e
	}
	e.lastSeen = time.Now()
	l.mu.Unlock()

	return e.lim.Allow()
}

// Sweep removes entries not seen for longer than maxAge, bounding memory
// growth from a churn of distinct source IPs over a long-running process.
// Call periodically (e.g. every few minutes) from a janitor goroutine —
// not on every request, to keep Allow() cheap.
func (l *IPLimiter) Sweep(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, e := range l.byIP {
		if e.lastSeen.Before(cutoff) {
			delete(l.byIP, ip)
		}
	}
}

// Len reports the number of tracked IPs — exposed for tests and metrics.
func (l *IPLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.byIP)
}
