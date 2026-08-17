# Relay

Relay is the Go server that lets the OpenCharUI web app talk to a user's
own **Amallo** desktop agent over the open internet — without a VPN, and
without the relay ever seeing plaintext.

## Why this exists

OpenCharUI is three pieces, developed as separate repos:

| Component | What it is |
|---|---|
| `web` | The OpenCharUI PWA — public, served from GitHub Pages |
| `amallo` | A Rust desktop agent that runs Ollama-backed inference on the user's own machine |
| `relay` (this repo) | A Go server that lets the two find and reach each other |

`amallo` runs on a machine that's usually behind NAT/CGNAT with no inbound
ports open, and `web` runs in a browser that can't dial into it directly.
Something has to sit in the middle.

The obvious answer, a VPN mesh like Tailscale/Headscale, doesn't fit: seat
pricing charges per authenticated device on an app with many end users, and
the actual problem is narrower than "join these two devices to one
network" — it's just NAT traversal for one streamed connection. Relay is
that narrower thing: a plain WebSocket relay, the same shape as the
ngrok/Cloudflare Tunnel pattern, with none of the VPN machinery.

## How it works

1. `amallo` opens an outbound WebSocket to Relay on startup and keeps it
   parked — no inbound ports required, works behind CGNAT.
2. The user pairs their browser to their agent once, by scanning a QR code
   `amallo` displays. That QR code carries a pairing ID and a shared
   secret; both sides derive an encryption key from it locally.
3. `web` opens its own WebSocket to Relay, authenticated for that same
   pairing ID.
4. Relay splices the two sockets together and forwards frames blindly.
   Past the handshake, everything it forwards is AES-GCM ciphertext — the
   relay is a byte pipe, not a party to the conversation.

If `amallo`'s machine is asleep or offline, there's nothing to splice to;
Relay reports that honestly (`agent_offline`) rather than hanging.

Relay also exposes an optional OpenAI-compatible HTTP endpoint (see
`spec/PROTOCOL.md` §11) so a third-party client can call a paired agent's
model directly, keyed by a per-agent token rather than the pairing secret.

The wire format — outer frame, control channel, pairing handshake, the
OpenAI-compatible HTTP lane — is specified in full, with test vectors, in
[`spec/PROTOCOL.md`](spec/PROTOCOL.md). That document is normative: `web`
and `amallo` each implement it independently against the same
`testdata/vectors/`, and where an implementation disagrees with the spec,
the spec wins.

## Repository layout

```
cmd/
  relay/       the server binary (config → wiring → listen → graceful shutdown)
  fakeagent/   a scriptable stand-in for amallo, for load/manual testing
  fakeclient/  a scriptable stand-in for web, for load/manual testing
  genvectors/  regenerates testdata/vectors/ from the reference implementation

internal/
  config/      env-var configuration, defaults, validation
  auth/        pairing/token authorization
  hub/         pair_id -> Pair bookkeeping; the agent/client socket splice
  wire/        outer frame + control/inner frame encoding
  proto/       handshake and session framing above the wire layer
  limits/      per-IP connection limiting, per-pair byte-rate limiting
  metrics/     Prometheus collectors
  logging/     structured logging setup
  server/      HTTP handlers: /v1/agent, /v1/client, /healthz, /stats,
               and the OpenAI-compatible HTTP endpoint
  testclient/  shared test-only WebSocket client used by cmd/fake*

spec/          spec/PROTOCOL.md, the normative wire protocol
testdata/      cross-implementation test vectors referenced by the spec
```

## Running it

```bash
go run ./cmd/relay
```

Defaults are usable out of the box (see `internal/config/config.go`);
override with `RELAY_*` environment variables for anything
internet-facing. A few of the more consequential ones:

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_ADDR` | `:8080` | Public listener |
| `RELAY_METRICS_ADDR` | `:9091` | Prometheus listener — bind to loopback only |
| `RELAY_ALLOWED_ORIGINS` | `opencharui.github.io,localhost:*,127.0.0.1:*` | WebSocket origin allowlist |
| `RELAY_MAX_PAIRS` | `10000` | Capacity cap on new pair creation |
| `RELAY_TRUST_PROXY` | `true` | Trust `X-Forwarded-For` from the reverse proxy in front |
| `RELAY_HTTP_ENABLED` | `true` | Serve the OpenAI-compatible HTTP endpoint |

`config.Load()` fails loudly on a malformed value rather than silently
falling back — a bad deploy config is caught at startup, not at 3am under
load.

### Tests

```bash
go vet ./...
go test -race ./...
```

## Endpoints

| Path | Purpose |
|---|---|
| `GET /v1/agent`, `GET /v1/client` | WebSocket upgrade endpoints for the two roles |
| `GET /healthz` | Liveness probe, `200 ok` |
| `GET /stats` | Public dashboard of aggregate load — see below |
| `GET /{token}/v1/...` or `Authorization: Bearer` | The OpenAI-compatible HTTP lane (§11), when `RELAY_HTTP_ENABLED` |
| Prometheus metrics | Served on the separate `RELAY_METRICS_ADDR` listener — never public |

### `/stats`

A public, unauthenticated page showing how busy the relay currently is:
active pairs, agents connected, clients connected, and process uptime.
It's deliberately aggregate-only — no pairing IDs, tokens, or IP addresses
are ever computed anywhere the handler can reach, so there's nothing
confidential to expose by leaving it open. Add `?format=json` (or send
`Accept: application/json`) for a machine-readable version of the same
numbers.

## Deployment

Relay ships as a Docker image (`Dockerfile`, multi-arch, distroless) and is
meant to sit behind a reverse proxy that terminates TLS and proxies
WebSocket upgrades transparently — see `Caddyfile.example`, which also
notes the two things a different proxy (nginx, Traefik) needs to get
right: no idle-timeout on the public listener (agent sockets stay parked
for hours), and no response buffering (SSE streaming depends on it).

`docker-compose.yml` shows the production shape: read-only root
filesystem, all capabilities dropped, raised `nofile` for the socket
count, and the Prometheus port bound to loopback only.

Non-negotiables baked into the design, regardless of deploy target: 30s
pings with a bounded pong timeout, exponential backoff with jitter
expected on both clients, bounded server-side buffering per connection
(no backlog that outlives a slow consumer), and per-pair byte-rate limits
so one noisy pairing can't starve another.

## License

AGPL-3.0 — see [`LICENSE`](LICENSE).
