package hub

import (
	"net/netip"
	"testing"

	"github.com/OpenCharUI/relay/internal/auth"
	"github.com/OpenCharUI/relay/internal/wire"
)

// fakeConn builds a Conn usable for identity/locking tests — these never
// touch the underlying WebSocket, so a nil *websocket.Conn is safe. Real
// I/O is exercised in server_test.go against actual connections.
func fakeConn(role wire.Role) *Conn {
	return NewConn(nil, role, nextID(), netip.MustParseAddr("127.0.0.1"), auth.Grant{})
}

var idCounter uint64

func nextID() uint64 {
	idCounter++
	return idCounter
}

func testPairID(b byte) PairID {
	var id PairID
	id[0] = b
	return id
}

func TestRegisterAgentCreatesPair(t *testing.T) {
	h := New(10, 1<<20)
	agent := fakeConn(wire.RoleAgent)

	pair, displaced, err := h.RegisterAgent(testPairID(1), agent)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if displaced != nil {
		t.Error("first registration should not displace anything")
	}
	if pair.Peer(wire.RoleClient) != agent {
		t.Error("pair's agent slot should be the registered conn")
	}
	if h.Len() != 1 {
		t.Errorf("Len() = %d, want 1", h.Len())
	}
}

func TestRegisterAgentDisplacesPrevious(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	first, _, err := h.RegisterAgent(id, fakeConn(wire.RoleAgent))
	if err != nil {
		t.Fatal(err)
	}
	firstAgent := first.Peer(wire.RoleClient) // the agent conn we just set

	second := fakeConn(wire.RoleAgent)
	pair, displaced, err := h.RegisterAgent(id, second)
	if err != nil {
		t.Fatal(err)
	}
	if pair != first {
		t.Error("re-registering the same pair_id must reuse the existing Pair, not create a new one")
	}
	if displaced != firstAgent {
		t.Error("displaced should be the first agent connection")
	}
	if pair.Peer(wire.RoleClient) != second {
		t.Error("pair's agent slot should now be the second conn")
	}
	if h.Len() != 1 {
		t.Errorf("displacement must not grow the pair count; Len() = %d, want 1", h.Len())
	}
}

func TestRegisterAgentCapacity(t *testing.T) {
	h := New(1, 1<<20)
	if _, _, err := h.RegisterAgent(testPairID(1), fakeConn(wire.RoleAgent)); err != nil {
		t.Fatal(err)
	}
	// A second, *different* pair_id must be rejected once at capacity.
	if _, _, err := h.RegisterAgent(testPairID(2), fakeConn(wire.RoleAgent)); err != ErrCapacity {
		t.Errorf("err = %v, want ErrCapacity", err)
	}
	// But re-registering the *same* pair_id (a reconnect) must still work —
	// capacity only gates new-pair creation.
	if _, _, err := h.RegisterAgent(testPairID(1), fakeConn(wire.RoleAgent)); err != nil {
		t.Errorf("re-registering an existing pair under capacity pressure: %v", err)
	}
}

func TestLookupUnknownPair(t *testing.T) {
	h := New(10, 1<<20)
	if _, ok := h.Lookup(testPairID(99)); ok {
		t.Error("Lookup of an unregistered pair_id must report false")
	}
}

func TestClientAttachAndDisplace(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	agent := fakeConn(wire.RoleAgent)
	pair, _, _ := h.RegisterAgent(id, agent)

	client1 := fakeConn(wire.RoleClient)
	if displaced := pair.SetClient(client1); displaced != nil {
		t.Error("first client attach should not displace anything")
	}
	if pair.Peer(wire.RoleAgent) != client1 {
		t.Error("agent's peer should be client1")
	}

	client2 := fakeConn(wire.RoleClient)
	displaced := pair.SetClient(client2)
	if displaced != client1 {
		t.Error("second client attach should displace client1")
	}
	if pair.Peer(wire.RoleAgent) != client2 {
		t.Error("agent's peer should now be client2")
	}
}

func TestClearClientStalenessGuard(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	pair, _, _ := h.RegisterAgent(id, fakeConn(wire.RoleAgent))

	client1 := fakeConn(wire.RoleClient)
	pair.SetClient(client1)
	client2 := fakeConn(wire.RoleClient)
	pair.SetClient(client2) // displaces client1

	// client1's own cleanup goroutine runs after being displaced — it must
	// NOT clear client2's slot.
	if cleared := pair.ClearClient(client1); cleared {
		t.Error("ClearClient(client1) must be a no-op once client1 has been displaced")
	}
	if pair.Peer(wire.RoleAgent) != client2 {
		t.Error("client2 must still be attached after client1's stale cleanup")
	}

	if cleared := pair.ClearClient(client2); !cleared {
		t.Error("ClearClient(client2) should succeed — it's the current occupant")
	}
	if pair.Peer(wire.RoleAgent) != nil {
		t.Error("agent's peer should be nil after the current client clears")
	}
}

func TestRemoveIfAgentTearsDownPair(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	agent := fakeConn(wire.RoleAgent)
	pair, _, _ := h.RegisterAgent(id, agent)
	client := fakeConn(wire.RoleClient)
	pair.SetClient(client)

	gotClient, removed := h.RemoveIfAgent(id, agent)
	if !removed {
		t.Fatal("RemoveIfAgent should succeed for the current agent")
	}
	if gotClient != client {
		t.Error("RemoveIfAgent should return the attached client conn for notification/close")
	}
	if _, ok := h.Lookup(id); ok {
		t.Error("the pair must be gone from the hub after its agent is removed")
	}
	if h.Len() != 0 {
		t.Errorf("Len() = %d, want 0", h.Len())
	}
}

func TestRemoveIfAgentStalenessGuard(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	staleAgent := fakeConn(wire.RoleAgent)
	h.RegisterAgent(id, staleAgent)

	newAgent := fakeConn(wire.RoleAgent)
	pair, displaced, _ := h.RegisterAgent(id, newAgent) // displaces staleAgent
	if displaced != staleAgent {
		t.Fatal("setup: expected staleAgent to be displaced")
	}

	// staleAgent's own cleanup goroutine now runs — it must NOT tear down
	// the pair the reconnect already took over.
	_, removed := h.RemoveIfAgent(id, staleAgent)
	if removed {
		t.Error("RemoveIfAgent(staleAgent) must be a no-op once displaced by a newer agent")
	}
	if _, ok := h.Lookup(id); !ok {
		t.Error("the live pair (with newAgent) must survive the stale agent's cleanup")
	}
	if pair.Peer(wire.RoleClient) != newAgent {
		t.Error("newAgent must still be the pair's agent")
	}
}

func TestRemoveIfAgentUnknownPair(t *testing.T) {
	h := New(10, 1<<20)
	_, removed := h.RemoveIfAgent(testPairID(1), fakeConn(wire.RoleAgent))
	if removed {
		t.Error("RemoveIfAgent on a never-registered pair_id must report false")
	}
}
