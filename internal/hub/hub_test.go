package hub

import (
	"net/netip"
	"testing"

	"github.com/41tunnels/relay/internal/auth"
	"github.com/41tunnels/relay/internal/wire"
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

func TestDetachAgentParksPairWhileAClientIsAttached(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	agent := fakeConn(wire.RoleAgent)
	pair, _, _ := h.RegisterAgent(id, agent)
	client := fakeConn(wire.RoleClient)
	pair.SetClient(client)

	gotClient, _, kept, ok := h.DetachAgent(id, agent)
	if !ok {
		t.Fatal("DetachAgent should succeed for the current agent")
	}
	if gotClient != client {
		t.Error("DetachAgent should return the attached client conn so it can be told peer_offline")
	}
	if !kept {
		t.Error("a pair with a client still attached must be kept, not dropped")
	}
	if _, found := h.Lookup(id); !found {
		t.Error("the parked pair must still resolve, so the returning agent lands in it")
	}
	if pair.HasAgent() {
		t.Error("the agent slot must be empty while parked")
	}

	// The whole point of parking: the agent comes back and finds its own
	// pair, with the same client still sitting in it.
	agent2 := fakeConn(wire.RoleAgent)
	pair2, displaced, err := h.RegisterAgent(id, agent2)
	if err != nil {
		t.Fatalf("RegisterAgent after a park: %v", err)
	}
	if displaced != nil {
		t.Error("nothing to displace — the previous agent already detached")
	}
	if pair2 != pair {
		t.Error("the returning agent must land in the same pair, not a fresh one")
	}
	if pair2.Peer(wire.RoleAgent) != client {
		t.Error("the client must still be attached after the agent's round trip")
	}
}

func TestDetachAgentDropsPairWithNoClient(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	agent := fakeConn(wire.RoleAgent)
	h.RegisterAgent(id, agent)

	client, _, kept, ok := h.DetachAgent(id, agent)
	if !ok {
		t.Fatal("DetachAgent should succeed for the current agent")
	}
	if client != nil || kept {
		t.Error("with nobody attached there is nothing to park for — the pair should just go")
	}
	if _, found := h.Lookup(id); found {
		t.Error("the pair must be gone from the hub")
	}
	if h.Len() != 0 {
		t.Errorf("Len() = %d, want 0", h.Len())
	}
}

func TestDropIfAgentlessEndsAPark(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	agent := fakeConn(wire.RoleAgent)
	pair, _, _ := h.RegisterAgent(id, agent)
	client := fakeConn(wire.RoleClient)
	pair.SetClient(client)
	_, park, _, _ := h.DetachAgent(id, agent)

	gotClient, dropped := h.DropIfParked(id, park)
	if !dropped {
		t.Fatal("a parked pair whose grace ran out must be dropped")
	}
	if gotClient != client {
		t.Error("the still-waiting client must be returned so it can be closed 4410")
	}
	if h.Len() != 0 {
		t.Errorf("Len() = %d, want 0", h.Len())
	}
}

func TestDropIfAgentlessLeavesAReturnedAgentAlone(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	agent := fakeConn(wire.RoleAgent)
	pair, _, _ := h.RegisterAgent(id, agent)
	pair.SetClient(fakeConn(wire.RoleClient))
	_, park, _, _ := h.DetachAgent(id, agent)

	// The agent beat the grace timer back. The timer still fires — it is
	// never cancelled — and must do nothing.
	h.RegisterAgent(id, fakeConn(wire.RoleAgent))

	if _, dropped := h.DropIfParked(id, park); dropped {
		t.Error("DropIfParked must be a no-op once an agent has reattached")
	}
	if _, found := h.Lookup(id); !found {
		t.Error("the live pair must survive its own expired grace timer")
	}
}

func TestAnOldParksTimerCannotCutShortALaterPark(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	client := fakeConn(wire.RoleClient)

	agent1 := fakeConn(wire.RoleAgent)
	pair, _, _ := h.RegisterAgent(id, agent1)
	pair.SetClient(client)
	_, firstPark, _, _ := h.DetachAgent(id, agent1)

	// The agent flaps: back, then gone again. The second departure opens a
	// park of its own, with its own full grace window.
	agent2 := fakeConn(wire.RoleAgent)
	h.RegisterAgent(id, agent2)
	_, secondPark, _, _ := h.DetachAgent(id, agent2)
	if secondPark == firstPark {
		t.Fatal("each park must be distinguishable from the one before it")
	}

	// The first park's timer now fires. The pair is agentless, so a check
	// that only looked at the agent slot would drop it — taking away most
	// of the second park's grace, and the client with it.
	if _, dropped := h.DropIfParked(id, firstPark); dropped {
		t.Error("a stale park's timer must not end the park that replaced it")
	}
	if _, found := h.Lookup(id); !found {
		t.Fatal("the pair must survive its previous park's timer")
	}

	// The current park's own timer still works.
	gotClient, dropped := h.DropIfParked(id, secondPark)
	if !dropped || gotClient != client {
		t.Error("the current park's timer must end it and hand back the waiting client")
	}
}

func TestDropIfIdleClearsAParkNobodyIsWaitingOn(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	agent := fakeConn(wire.RoleAgent)
	pair, _, _ := h.RegisterAgent(id, agent)
	client := fakeConn(wire.RoleClient)
	pair.SetClient(client)
	h.DetachAgent(id, agent)

	if h.DropIfIdle(id) {
		t.Error("a parked pair with a client still waiting must not be dropped")
	}

	pair.ClearClient(client)
	if !h.DropIfIdle(id) {
		t.Error("once nobody is attached there is nothing left to park for")
	}
	if h.Len() != 0 {
		t.Errorf("Len() = %d, want 0", h.Len())
	}
}

func TestDetachAgentStalenessGuard(t *testing.T) {
	h := New(10, 1<<20)
	id := testPairID(1)
	staleAgent := fakeConn(wire.RoleAgent)
	h.RegisterAgent(id, staleAgent)

	newAgent := fakeConn(wire.RoleAgent)
	pair, displaced, _ := h.RegisterAgent(id, newAgent) // displaces staleAgent
	if displaced != staleAgent {
		t.Fatal("setup: expected staleAgent to be displaced")
	}

	// staleAgent's own cleanup goroutine now runs — it must NOT disturb
	// the pair the reconnect already took over.
	_, _, _, ok := h.DetachAgent(id, staleAgent)
	if ok {
		t.Error("DetachAgent(staleAgent) must be a no-op once displaced by a newer agent")
	}
	if _, found := h.Lookup(id); !found {
		t.Error("the live pair (with newAgent) must survive the stale agent's cleanup")
	}
	if pair.Peer(wire.RoleClient) != newAgent {
		t.Error("newAgent must still be the pair's agent")
	}
}

func TestDetachAgentUnknownPair(t *testing.T) {
	h := New(10, 1<<20)
	_, _, _, ok := h.DetachAgent(testPairID(1), fakeConn(wire.RoleAgent))
	if ok {
		t.Error("DetachAgent on a never-registered pair_id must report false")
	}
}
