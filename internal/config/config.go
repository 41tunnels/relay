// Package config loads and validates the relay's runtime configuration
// from environment variables (see the build plan's Step 2 and the deploy
// compose files). Every field has a default, so an empty environment
// produces a usable, if not internet-facing-appropriate, configuration —
// but Load fails loudly on a malformed value rather than silently falling
// back, so a bad deploy config is caught at startup, not at 3am under
// load.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr           string // e.g. ":8080"
	MetricsAddr    string // e.g. ":9091" — bind to loopback only in deploy
	AllowedOrigins []string

	MaxFrameBytes int
	MaxPairs      int

	PingInterval  time.Duration
	PongTimeout   time.Duration
	HelloTimeout  time.Duration
	WriteTimeout  time.Duration
	ShutdownGrace time.Duration

	PairRateBytesPerSec int64
	IPConnPerMin        int
	TrustProxy          bool

	// OpenAI-compatible HTTP endpoint (spec §11). Serving the route costs
	// nothing when no agent opts in — an agent must connect in mode:"http"
	// with a token hash before any key resolves — but HTTPEnabled exists so
	// a deploy can refuse the whole surface outright.
	HTTPEnabled bool
	// HTTPMaxInFlight caps concurrent requests per key. One consumer GPU
	// thrashes badly past a handful of parallel generations, so shedding
	// with 429 beats queueing without bound.
	HTTPMaxInFlight int
	// HTTPTombstoneTTL is how long a key stays resolvable after its agent
	// disconnects, so the endpoint can answer 503 "offline" instead of 401
	// "bad key". Past this, the entry is evicted and the key reads as
	// unknown until the agent reconnects.
	HTTPTombstoneTTL time.Duration
	// HTTPFirstByteTimeout bounds the wait for the agent's RESP. Generous
	// by default: a cold model load on a sleeping laptop is slow, and the
	// failure mode of being too tight is a confusing 504 on a request that
	// would have succeeded.
	HTTPFirstByteTimeout time.Duration
	// HTTPKeepaliveInterval is the gap after which an SSE response emits a
	// comment line to keep intermediaries and client read timeouts from
	// giving up during a long pause. Zero disables it.
	HTTPKeepaliveInterval time.Duration
	// HTTPStreamBuffer is the per-request response-frame buffer. Small on
	// purpose — see hub.Stream on why buffering here would defeat
	// backpressure rather than improve throughput.
	HTTPStreamBuffer int

	LogLevel  string // "debug"|"info"|"warn"|"error"
	LogFormat string // "json"|"text"
}

// Defaults returns the configuration used when no environment variable
// overrides a field — the values named throughout spec/PROTOCOL.md and the
// build plan.
func Defaults() Config {
	return Config{
		Addr:                ":8080",
		MetricsAddr:         ":9091",
		AllowedOrigins:      []string{"opencharui.github.io", "localhost:*", "127.0.0.1:*"},
		MaxFrameBytes:       1 << 20, // 1 MiB
		MaxPairs:            10000,
		PingInterval:        30 * time.Second,
		PongTimeout:         15 * time.Second,
		HelloTimeout:        5 * time.Second,
		WriteTimeout:        30 * time.Second,
		ShutdownGrace:       20 * time.Second,
		PairRateBytesPerSec: 8 << 20, // 8 MiB/s
		IPConnPerMin:        60,
		TrustProxy:          true,

		HTTPEnabled:           true,
		HTTPMaxInFlight:       8,
		HTTPTombstoneTTL:      24 * time.Hour,
		HTTPFirstByteTimeout:  180 * time.Second,
		HTTPKeepaliveInterval: 15 * time.Second,
		HTTPStreamBuffer:      8,

		LogLevel:  "info",
		LogFormat: "json",
	}
}

// Load reads Defaults() and applies RELAY_* environment overrides,
// returning a descriptive error on the first invalid value rather than a
// partially-applied config.
func Load() (Config, error) {
	c := Defaults()

	if v, ok := lookup("RELAY_ADDR"); ok {
		c.Addr = v
	}
	if v, ok := lookup("RELAY_METRICS_ADDR"); ok {
		c.MetricsAddr = v
	}
	if v, ok := lookup("RELAY_ALLOWED_ORIGINS"); ok {
		c.AllowedOrigins = splitCSV(v)
	}
	if err := setInt("RELAY_MAX_FRAME_BYTES", &c.MaxFrameBytes); err != nil {
		return Config{}, err
	}
	if err := setInt("RELAY_MAX_PAIRS", &c.MaxPairs); err != nil {
		return Config{}, err
	}
	if err := setDuration("RELAY_PING_INTERVAL", &c.PingInterval); err != nil {
		return Config{}, err
	}
	if err := setDuration("RELAY_PONG_TIMEOUT", &c.PongTimeout); err != nil {
		return Config{}, err
	}
	if err := setDuration("RELAY_HELLO_TIMEOUT", &c.HelloTimeout); err != nil {
		return Config{}, err
	}
	if err := setDuration("RELAY_WRITE_TIMEOUT", &c.WriteTimeout); err != nil {
		return Config{}, err
	}
	if err := setDuration("RELAY_SHUTDOWN_GRACE", &c.ShutdownGrace); err != nil {
		return Config{}, err
	}
	if err := setInt64("RELAY_PAIR_RATE_BYTES_PER_SEC", &c.PairRateBytesPerSec); err != nil {
		return Config{}, err
	}
	if err := setInt("RELAY_IP_CONN_PER_MIN", &c.IPConnPerMin); err != nil {
		return Config{}, err
	}
	if err := setBool("RELAY_TRUST_PROXY", &c.TrustProxy); err != nil {
		return Config{}, err
	}
	if err := setBool("RELAY_HTTP_ENABLED", &c.HTTPEnabled); err != nil {
		return Config{}, err
	}
	if err := setInt("RELAY_HTTP_MAX_INFLIGHT", &c.HTTPMaxInFlight); err != nil {
		return Config{}, err
	}
	if err := setDuration("RELAY_HTTP_TOMBSTONE_TTL", &c.HTTPTombstoneTTL); err != nil {
		return Config{}, err
	}
	if err := setDuration("RELAY_HTTP_FIRST_BYTE_TIMEOUT", &c.HTTPFirstByteTimeout); err != nil {
		return Config{}, err
	}
	if err := setDuration("RELAY_HTTP_KEEPALIVE_INTERVAL", &c.HTTPKeepaliveInterval); err != nil {
		return Config{}, err
	}
	if err := setInt("RELAY_HTTP_STREAM_BUFFER", &c.HTTPStreamBuffer); err != nil {
		return Config{}, err
	}
	if v, ok := lookup("RELAY_LOG_LEVEL"); ok {
		c.LogLevel = v
	}
	if v, ok := lookup("RELAY_LOG_FORMAT"); ok {
		c.LogFormat = v
	}

	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate rejects configurations that would either fail immediately or
// silently misbehave (e.g. a zero timeout that turns every write into an
// instant failure).
func (c Config) Validate() error {
	if c.Addr == "" {
		return fmt.Errorf("config: RELAY_ADDR must not be empty")
	}
	if c.MaxFrameBytes <= 0 {
		return fmt.Errorf("config: RELAY_MAX_FRAME_BYTES must be positive, got %d", c.MaxFrameBytes)
	}
	if c.MaxPairs <= 0 {
		return fmt.Errorf("config: RELAY_MAX_PAIRS must be positive, got %d", c.MaxPairs)
	}
	if c.PingInterval <= 0 {
		return fmt.Errorf("config: RELAY_PING_INTERVAL must be positive, got %s", c.PingInterval)
	}
	if c.PongTimeout <= 0 {
		return fmt.Errorf("config: RELAY_PONG_TIMEOUT must be positive, got %s", c.PongTimeout)
	}
	if c.HelloTimeout <= 0 {
		return fmt.Errorf("config: RELAY_HELLO_TIMEOUT must be positive, got %s", c.HelloTimeout)
	}
	if c.WriteTimeout <= 0 {
		return fmt.Errorf("config: RELAY_WRITE_TIMEOUT must be positive, got %s", c.WriteTimeout)
	}
	if c.PairRateBytesPerSec <= 0 {
		return fmt.Errorf("config: RELAY_PAIR_RATE_BYTES_PER_SEC must be positive, got %d", c.PairRateBytesPerSec)
	}
	if c.IPConnPerMin <= 0 {
		return fmt.Errorf("config: RELAY_IP_CONN_PER_MIN must be positive, got %d", c.IPConnPerMin)
	}
	if c.HTTPMaxInFlight <= 0 {
		return fmt.Errorf("config: RELAY_HTTP_MAX_INFLIGHT must be positive, got %d", c.HTTPMaxInFlight)
	}
	if c.HTTPTombstoneTTL <= 0 {
		return fmt.Errorf("config: RELAY_HTTP_TOMBSTONE_TTL must be positive, got %s", c.HTTPTombstoneTTL)
	}
	if c.HTTPFirstByteTimeout <= 0 {
		return fmt.Errorf("config: RELAY_HTTP_FIRST_BYTE_TIMEOUT must be positive, got %s", c.HTTPFirstByteTimeout)
	}
	if c.HTTPStreamBuffer <= 0 {
		return fmt.Errorf("config: RELAY_HTTP_STREAM_BUFFER must be positive, got %d", c.HTTPStreamBuffer)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: RELAY_LOG_LEVEL must be one of debug|info|warn|error, got %q", c.LogLevel)
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		return fmt.Errorf("config: RELAY_LOG_FORMAT must be one of json|text, got %q", c.LogFormat)
	}
	return nil
}

func lookup(name string) (string, bool) {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func setInt(name string, dst *int) error {
	v, ok := lookup(name)
	if !ok {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("config: %s=%q is not a valid integer: %w", name, v, err)
	}
	*dst = n
	return nil
}

func setInt64(name string, dst *int64) error {
	v, ok := lookup(name)
	if !ok {
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fmt.Errorf("config: %s=%q is not a valid integer: %w", name, v, err)
	}
	*dst = n
	return nil
}

func setDuration(name string, dst *time.Duration) error {
	v, ok := lookup(name)
	if !ok {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("config: %s=%q is not a valid duration (e.g. \"30s\"): %w", name, v, err)
	}
	*dst = d
	return nil
}

func setBool(name string, dst *bool) error {
	v, ok := lookup(name)
	if !ok {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("config: %s=%q is not a valid boolean: %w", name, v, err)
	}
	*dst = b
	return nil
}
