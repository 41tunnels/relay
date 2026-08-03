// Package logging sets up structured slog logging and provides PairTag,
// the one function every log call site touching a pair_id MUST go
// through. spec/PROTOCOL.md §3 requires logs never carry the raw pair_id
// (it's a bearer capability); PairTag is what makes "never" enforceable by
// convention rather than by remembering to hash it correctly every time.
package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"

	"github.com/OpenCharUI/relay/internal/config"
)

// New builds the process-wide logger per cfg.LogLevel/LogFormat.
func New(cfg config.Config) *slog.Logger {
	level := parseLevel(cfg.LogLevel)
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.LogFormat == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// PairTag returns the correlation id logged in place of a raw pair_id:
// the first 4 bytes of SHA-256(pair_id), hex-encoded. Short enough to skim
// in logs, long enough (32 bits) that distinct pairs essentially never
// collide in a single deploy's log stream, and — the actual point —
// computationally infeasible to invert back to the pair_id, which is a
// bearer capability for reaching someone's desktop agent.
func PairTag(pairID [16]byte) string {
	sum := sha256.Sum256(pairID[:])
	return hex.EncodeToString(sum[:4])
}
