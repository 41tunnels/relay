package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/OpenCharUI/relay/internal/wire"
)

// statsSnapshot is the entire public surface of /stats: aggregate counts
// only. Pair IDs, tokens and IP addresses never flow into this struct, so
// there is nothing confidential for the endpoint to leak by being
// unauthenticated.
type statsSnapshot struct {
	PairsActive      int   `json:"pairs_active"`
	AgentsConnected  int   `json:"agents_connected"`
	ClientsConnected int   `json:"clients_connected"`
	UptimeSeconds    int64 `json:"uptime_seconds"`
}

func (s *Server) snapshotStats() statsSnapshot {
	s.connsMu.Lock()
	var agents, clients int
	for c := range s.conns {
		switch c.Role() {
		case wire.RoleAgent:
			agents++
		case wire.RoleClient:
			clients++
		}
	}
	s.connsMu.Unlock()

	return statsSnapshot{
		PairsActive:      s.hub.Len(),
		AgentsConnected:  agents,
		ClientsConnected: clients,
		UptimeSeconds:    int64(time.Since(s.startedAt).Seconds()),
	}
}

// handleStats serves a public, unauthenticated dashboard of aggregate
// relay load — how many pairs/agents/clients are connected right now, and
// for how long the process has been up. It renders HTML by default and
// JSON for either ?format=json or an Accept header that prefers it, which
// is what lets this double as a machine-readable status check without a
// second endpoint.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := s.snapshotStats()

	if wantsJSONStats(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(stats)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, statsPageHTML,
		stats.PairsActive, stats.AgentsConnected, stats.ClientsConnected,
		formatUptime(stats.UptimeSeconds),
	)
}

func wantsJSONStats(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}

func formatUptime(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	default:
		return fmt.Sprintf("%dm", minutes)
	}
}

// statsPageHTML has no external requests (fonts, scripts, stylesheets) —
// the same "no CDN calls" posture as the rest of the relay's public
// surface — and prints only the four integers/strings from statsSnapshot,
// so there is no user input to escape.
const statsPageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relay Stats</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1.5rem; line-height: 1.5; }
  h1 { font-size: 1.25rem; margin-bottom: 0.25rem; }
  p.sub { color: #767676; margin-top: 0; margin-bottom: 2rem; font-size: 0.9rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; }
  .card { border: 1px solid #8884; border-radius: 10px; padding: 1rem 1.25rem; }
  .card .n { font-size: 2rem; font-weight: 600; display: block; }
  .card .l { font-size: 0.85rem; color: #767676; }
  footer { margin-top: 2.5rem; font-size: 0.8rem; color: #767676; }
  a { color: inherit; }
</style>
</head>
<body>
<h1>Relay</h1>
<p class="sub">Live connection counts. No pairing IDs, tokens, or IP addresses are ever shown here.</p>
<div class="grid">
  <div class="card"><span class="n">%d</span><span class="l">active pairs</span></div>
  <div class="card"><span class="n">%d</span><span class="l">agents connected</span></div>
  <div class="card"><span class="n">%d</span><span class="l">clients connected</span></div>
  <div class="card"><span class="n">%s</span><span class="l">uptime</span></div>
</div>
<footer>JSON: <a href="/stats?format=json">/stats?format=json</a></footer>
</body>
</html>
`
