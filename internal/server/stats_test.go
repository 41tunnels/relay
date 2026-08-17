package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestStatsHTML(t *testing.T) {
	_, ts := newTestServer(t, testConfig())

	resp, err := http.Get(ts.URL + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestStatsJSONEmpty(t *testing.T) {
	_, ts := newTestServer(t, testConfig())

	resp, err := http.Get(ts.URL + "/stats?format=json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var stats statsSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if stats.PairsActive != 0 || stats.AgentsConnected != 0 || stats.ClientsConnected != 0 {
		t.Errorf("stats = %+v, want all-zero counts on a fresh server", stats)
	}
}

func TestStatsCountsLiveConnections(t *testing.T) {
	_, ts := newTestServer(t, testConfig())
	pairID := randPairID(t)
	agentConn, clientConn := handshakeAgentAndClient(t, ts, pairID)
	defer agentConn.CloseNow()
	defer clientConn.CloseNow()

	resp, err := http.Get(ts.URL + "/stats?format=json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var stats statsSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if stats.PairsActive != 1 {
		t.Errorf("PairsActive = %d, want 1", stats.PairsActive)
	}
	if stats.AgentsConnected != 1 {
		t.Errorf("AgentsConnected = %d, want 1", stats.AgentsConnected)
	}
	if stats.ClientsConnected != 1 {
		t.Errorf("ClientsConnected = %d, want 1", stats.ClientsConnected)
	}
}

// TestStatsNeverLeaksIdentifiers guards the whole point of the endpoint:
// whatever it returns must not let a scraper reconstruct which pairs are
// live. It only asserts on the JSON view's keys since that is the
// machine-readable contract; the HTML view renders from the same
// statsSnapshot struct, so there is no separate field list to drift.
func TestStatsNeverLeaksIdentifiers(t *testing.T) {
	_, ts := newTestServer(t, testConfig())
	pairID := randPairID(t)
	agentConn, clientConn := handshakeAgentAndClient(t, ts, pairID)
	defer agentConn.CloseNow()
	defer clientConn.CloseNow()

	resp, err := http.Get(ts.URL + "/stats?format=json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := map[string]bool{
		"pairs_active": true, "agents_connected": true,
		"clients_connected": true, "uptime_seconds": true,
	}
	for k := range raw {
		if !want[k] {
			t.Errorf("unexpected field %q in /stats response — only aggregate counts are allowed", k)
		}
	}
}
