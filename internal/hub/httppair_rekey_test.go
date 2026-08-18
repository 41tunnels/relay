package hub

import (
	"errors"
	"testing"
	"time"

	"github.com/41tunnels/relay/internal/wire"
)

func testRegistry() *HTTPRegistry {
	return NewHTTPRegistry(10, 1<<20, time.Hour, 4, 4)
}

// openStream is the "a request is in flight" setup every rekey test needs:
// a live stream that must not survive the key it was authorised under.
func openStream(t *testing.T, p *HTTPPair) *Stream {
	t.Helper()
	s, _, err := p.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	return s
}

func assertClosed(t *testing.T, s *Stream, what string) {
	t.Helper()
	select {
	case <-s.Done():
	default:
		t.Fatalf("%s: expected the in-flight stream to be torn down", what)
	}
}

func TestRekeyReindexesInPlace(t *testing.T) {
	r := testRegistry()
	c := fakeConn(wire.RoleAgent)
	oldTH := HashToken("41t_old")
	newTH := HashToken("41t_new")

	p, _, err := r.RegisterAgent(oldTH, testPairID(1), c)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	stream := openStream(t, p)

	if err := r.Rekey(p, newTH); err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	if _, ok := r.Lookup(oldTH); ok {
		t.Fatal("the old key still resolves after a rekey")
	}
	got, ok := r.Lookup(newTH)
	if !ok || got != p {
		t.Fatal("the new key does not resolve to the rekeyed entry")
	}
	if p.TokenHash() != newTH {
		t.Fatal("the entry did not record its new hash")
	}
	// The connection itself is untouched — that is the whole point of
	// rekeying in place rather than reconnecting.
	if p.Agent() != c {
		t.Fatal("rekey detached the agent")
	}
	assertClosed(t, stream, "rekey")
}

func TestRekeyRefusesAnotherAgentsToken(t *testing.T) {
	r := testRegistry()
	mine, _, err := r.RegisterAgent(HashToken("41t_mine"), testPairID(1), fakeConn(wire.RoleAgent))
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	theirTH := HashToken("41t_theirs")
	theirs, _, err := r.RegisterAgent(theirTH, testPairID(2), fakeConn(wire.RoleAgent))
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	if err := r.Rekey(mine, theirTH); !errors.Is(err, ErrTokenTaken) {
		t.Fatalf("expected ErrTokenTaken, got %v", err)
	}
	if got, _ := r.Lookup(theirTH); got != theirs {
		t.Fatal("a refused rekey still stole the other agent's routing")
	}
	if p, ok := r.Lookup(HashToken("41t_mine")); !ok || p != mine {
		t.Fatal("a refused rekey disturbed the caller's own mapping")
	}
}

func TestRekeyToSameHashIsANoop(t *testing.T) {
	r := testRegistry()
	th := HashToken("41t_same")
	p, _, err := r.RegisterAgent(th, testPairID(1), fakeConn(wire.RoleAgent))
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	if err := r.Rekey(p, th); err != nil {
		t.Fatalf("rekey to the current hash should succeed, got %v", err)
	}
	if got, ok := r.Lookup(th); !ok || got != p {
		t.Fatal("rekeying to the same hash dropped the mapping")
	}
}

func TestUnregisterStopsResolvingButKeepsTheConnection(t *testing.T) {
	r := testRegistry()
	c := fakeConn(wire.RoleAgent)
	th := HashToken("41t_off")
	p, _, err := r.RegisterAgent(th, testPairID(1), c)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	stream := openStream(t, p)

	r.Unregister(p)

	if _, ok := r.Lookup(th); ok {
		t.Fatal("the key still resolves after unregistering")
	}
	// Switching the endpoint off must not disturb the browser session
	// sharing this socket, so the agent stays attached.
	if p.Agent() != c {
		t.Fatal("unregister detached the agent")
	}
	assertClosed(t, stream, "unregister")
}

func TestRekeyAfterUnregisterReindexes(t *testing.T) {
	r := testRegistry()
	p, _, err := r.RegisterAgent(HashToken("41t_first"), testPairID(1), fakeConn(wire.RoleAgent))
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	r.Unregister(p)

	// Switching the endpoint back on without reconnecting.
	again := HashToken("41t_again")
	if err := r.Rekey(p, again); err != nil {
		t.Fatalf("Rekey after Unregister: %v", err)
	}
	if got, ok := r.Lookup(again); !ok || got != p {
		t.Fatal("the entry did not come back after being re-keyed")
	}
}

func TestRekeyReleasesInFlightSlots(t *testing.T) {
	r := NewHTTPRegistry(10, 1<<20, time.Hour, 1, 4) // maxInFlight = 1
	p, _, err := r.RegisterAgent(HashToken("41t_a"), testPairID(1), fakeConn(wire.RoleAgent))
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	openStream(t, p)

	if err := r.Rekey(p, HashToken("41t_b")); err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	// Tearing the stream down has to free its concurrency slot too, or the
	// pair would be permanently wedged at its in-flight cap after a rekey.
	if _, _, err := p.OpenStream(); err != nil {
		t.Fatalf("expected a free in-flight slot after rekey, got %v", err)
	}
}
