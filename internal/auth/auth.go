// Package auth defines the relay's pluggable authorization seam. v1 ships
// a single implementation — OpenAuthorizer, which admits every pair
// unconditionally — but every connection already flows through this
// interface and every hello already carries a (currently-empty) Token
// field (spec/PROTOCOL.md §3, §9), so a future subscription-gated
// implementation is a new file and a config switch, not a protocol change.
package auth

import (
	"context"
	"net/netip"
	"time"
)

// Role mirrors wire.Role without importing the wire package, keeping auth
// dependency-free (it's the seam other packages depend on, not the other
// way around).
type Role string

const (
	RoleAgent  Role = "agent"
	RoleClient Role = "client"
)

// ConnMeta is everything about a connection attempt an Authorizer might
// want to base a decision on.
type ConnMeta struct {
	Role      Role
	RemoteIP  netip.Addr
	UserAgent string
	Token     string // from hello.token; "" in v1 — see spec §9
	Version   int
}

// Grant is what an Authorizer hands back: the limits this connection
// operates under. OpenAuthorizer returns the same Grant for everyone;
// threading it through Pair/Conn from day one (rather than adding the
// plumbing later) is what makes a future tiered authorizer a drop-in
// replacement.
type Grant struct {
	MaxBytesPerSec int64
	MaxFrameBytes  int
	MaxSessionDur  time.Duration
	Tier           string // "open" in v1; becomes a metrics label once tiers exist
}

// Authorizer decides whether a connection may proceed and under what
// limits. Errors from Authorize are treated as a hard rejection — the
// caller closes the connection with code 4503 (capacity) or an
// implementation-specific code; Authorize itself does not touch the
// network.
type Authorizer interface {
	Authorize(ctx context.Context, pair [16]byte, meta ConnMeta) (Grant, error)
}

// OpenAuthorizer is the v1 authorizer: every pair is admitted, every
// connection gets Default.
type OpenAuthorizer struct {
	Default Grant
}

func (a OpenAuthorizer) Authorize(_ context.Context, _ [16]byte, _ ConnMeta) (Grant, error) {
	return a.Default, nil
}
