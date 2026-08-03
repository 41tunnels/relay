// Package metrics defines the relay's Prometheus collectors. Served on a
// separate, loopback-only listener (see the deploy compose in Step 3) —
// the failure modes this relay actually has ("pairs leak", "one pair eats
// all bandwidth", "everyone's reconnecting at once") are the ones these
// metrics are chosen to surface.
package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	PairsActive       prometheus.Gauge
	ConnectionsActive *prometheus.GaugeVec
	ConnectionsTotal  *prometheus.CounterVec
	FramesTotal       *prometheus.CounterVec
	BytesTotal        *prometheus.CounterVec
	CloseTotal        *prometheus.CounterVec
	HandshakeDuration prometheus.Histogram
	SessionDuration   prometheus.Histogram
	WriteStall        prometheus.Histogram
	RateLimitedTotal  *prometheus.CounterVec
}

// New registers every collector against reg and returns the bundle. Pass
// a fresh prometheus.NewRegistry() in tests to avoid the global default
// registry's "duplicate registration" panic across parallel test runs.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		PairsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "relay_pairs_active",
			Help: "Number of pairs currently registered (agent connected).",
		}),
		ConnectionsActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "relay_connections_active",
			Help: "Number of currently open WebSocket connections.",
		}, []string{"role", "tier"}),
		ConnectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_connections_total",
			Help: "Total connection attempts, labeled by outcome.",
		}, []string{"role", "result"}), // result: ok|rejected|displaced
		FramesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_frames_total",
			Help: "Total outer frames processed, labeled by channel and direction.",
		}, []string{"channel", "direction"}),
		BytesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_bytes_total",
			Help: "Total bytes forwarded, labeled by direction.",
		}, []string{"direction"}),
		CloseTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_close_total",
			Help: "Total connection closes, labeled by close code.",
		}, []string{"code"}),
		HandshakeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "relay_handshake_duration_seconds",
			Help:    "Time from WebSocket upgrade to a validated hello.",
			Buckets: prometheus.DefBuckets,
		}),
		SessionDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "relay_session_duration_seconds",
			Help:    "Time from hello_ok to connection close.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 16), // 1s .. ~18h
		}),
		WriteStall: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "relay_write_stall_seconds",
			Help:    "Time spent blocked writing a frame to a peer — the backpressure signal.",
			Buckets: prometheus.DefBuckets,
		}),
		RateLimitedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_rate_limited_total",
			Help: "Total rate-limit rejections, labeled by kind.",
		}, []string{"kind"}), // kind: ip_connect|pair_bytes
	}

	reg.MustRegister(
		m.PairsActive, m.ConnectionsActive, m.ConnectionsTotal, m.FramesTotal,
		m.BytesTotal, m.CloseTotal, m.HandshakeDuration, m.SessionDuration,
		m.WriteStall, m.RateLimitedTotal,
	)
	return m
}

// NewUnregistered builds a Metrics bundle backed by its own private
// registry — for tests and tools (fakeagent/fakeclient) that want the
// collectors' side effects without a real /metrics endpoint or any risk of
// colliding with another test's registrations.
func NewUnregistered() *Metrics {
	return New(prometheus.NewRegistry())
}
