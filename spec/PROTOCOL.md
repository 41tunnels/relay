# OpenCharUI Relay Protocol — v1

This document is normative. The relay (Go), `amallo` (Rust) and `web`
(TypeScript) each implement this spec independently, cross-checked against
the shared test vectors in `testdata/vectors/`. Where this document and an
implementation disagree, this document wins and the implementation has a
bug.

All multi-byte integers are big-endian unless stated otherwise. All byte
strings in examples are hex.

## 1. Transport

Each side (`agent` = amallo, `client` = web) opens one WebSocket to the
relay:

```
GET /v1/agent   (role = agent)
GET /v1/client  (role = client)
```

No query parameters carry secrets — `pair_id` is never placed in the URL.
A capability in a query string ends up in access logs, browser history and
`Referer` headers; it belongs in the control-channel `hello` instead (§3).

After the WebSocket upgrade, the connection MUST send a `hello` control
frame within `RELAY_HELLO_TIMEOUT` (default 5s) or the relay closes it with
code `4400`.

All application messages are **binary** WebSocket frames. Text frames are
protocol errors (close `4400`).

## 2. Outer frame

Every binary WS message is one outer frame:

```
[channel:1][flags:1] ( [conn_id:8] if flags & 0x01 ) [payload...]
```

| Field | Meaning |
|---|---|
| `channel` | `0x00` = control (JSON, relay-visible), `0x01` = ciphertext (opaque to relay), `0x02` = handshake (plaintext, still opaque to relay), `0x03` = plain inner frames (relay-visible, §11 only) |
| `flags` | bit 0 = `conn_id` present. **RESERVED, MUST be 0 in v1.** Bits 1-7 reserved, MUST be 0. |
| `conn_id` | Reserved for a future multi-peer extension (§9). Absent in v1. |

Receivers MUST reject any message with non-zero reserved flag bits (close
`4400 bad_frame`), and any channel above `0x03`, which v1 does not define.
The relay parses only the `channel` and `flags` bytes; it never inspects
the payload of channel `0x01` or `0x02`. It does read `0x03`, which is the
whole reason that channel is separate — see §11.1.

Which channels are valid on a given connection depends on what its hello
asked for (§11.3); a frame for a lane the connection does not carry is
`4400`.

Maximum outer frame size: `RELAY_MAX_FRAME_BYTES` (default 1 MiB, relay-
enforced). Oversize → close `4413 frame_too_large`.

## 3. Control channel (0x00)

JSON, UTF-8, one object per outer frame. The relay both consumes and
produces these.

### Client/agent → relay

```json
{"t":"hello","v":1,"role":"agent"|"client","pair":"<base64url,16 bytes>","token":""}
{"t":"rekey","token_hash":"<base64url,32 bytes>"|""}
```

`token` is reserved for future subscription gating (§9) and MUST be sent as
`""` in v1. `pair` is the pairing ID from the QR/manual code, base64url
without padding.

`hello` MUST be the first frame on every connection. `rekey` is the only
control message either side may send after it, it is **agent-only**, and
it belongs entirely to §11.3 — a relay that does not implement §11 MUST
ignore it rather than close. Any other post-hello control frame is a
protocol violation (`4400`); a client sending `rekey` is likewise `4400`.

### Relay → client/agent

```json
{"t":"hello_ok","conn":"<opaque>","ping_ms":30000}
{"t":"peer_online"}
{"t":"peer_offline"}
{"t":"error","code":"agent_offline"|"peer_offline"|"capacity"|"rate_limited"|"bad_frame"}
{"t":"going_away","retry_after_ms":2000}
```

`hello_ok` means **attached and reachable**, not merely "your hello
parsed". A relay MUST NOT send it to an agent until that agent is
registered — under its `pair` for the E2E lane, its `token_hash` for the
HTTP lane, and both for `mode:"dual"` (§11.3). Everything an agent does
next assumes it: a request arriving in the window between a premature
acknowledgement and the registration landing would be answered as though
the pair were gone (`4404`) or the key were wrong (`401`), for a
connection that is in fact healthy. An agent that cannot be attached is
closed instead, without `hello_ok`.

A client is acknowledged as soon as its hello is accepted, before the pair
lookup: nothing the client does depends on its own registration, and
`peer_online` already resolves either attachment order.

`peer_online`/`peer_offline` are required triggers, not just UX — see §5
(session lifecycle). A relay that withholds `peer_online` causes a stalled
connection, never a compromise; the E2E handshake (§4) is what actually
gates data flow.

## 4. End-to-end handshake (channel 0x02)

Channel `0x02` carries the plaintext handshake. The relay forwards these
bytes verbatim and never parses them — they are "opaque" only in the sense
that the relay doesn't need to understand them, not that they're secret.

### 4.1 Primitives

- Curve: **P-256** (not X25519 — see rationale in the plan; WebCrypto X25519
  support is too new for a phone-first client).
- Cipher: **AES-256-GCM**.
- KDF: **HKDF-SHA256** (RFC 5869).
- MAC: **HMAC-SHA256**.

### 4.2 Pairing material

Generated once by the agent: `pair_id` (16 random bytes), `psk` (32 random
bytes). Encoded as:

```
opencharui://pair?v=1&r=<relay_url>&i=<pair_id_b64url>&k=<psk_b64url>
```

### 4.3 HELLO

```
k_mac = HKDF-Expand(HKDF-Extract(salt="", ikm=psk), info="opencharui/v1 hello-mac", len=32)

HELLO = [ver:1][role:1][pair_id:16][epk:65][nonce:32][mac:32]     // 147 bytes
  ver     = 0x01
  role    = 0x01 (agent) | 0x02 (client)
  epk     = uncompressed SEC1 P-256 public key (0x04 || X:32 || Y:32)
  nonce   = 32 random bytes
  mac     = HMAC-SHA256(k_mac, "opencharui/v1 hello" || ver || role || pair_id || epk || nonce)
```

Each side generates a fresh ephemeral P-256 key pair for every session —
never persisted, never reused across reconnects.

On receipt of a peer HELLO:
1. Verify `mac` (constant-time compare).
2. Reject if `pair_id` does not match your own.
3. Reject if `role` equals your own role (reflection defence).
4. Reject if `epk` does not decode to a valid point on P-256 (both WebCrypto
   `importKey` and `aws-lc-rs::agree_ephemeral` perform this check as part
   of key agreement).

Any failure → close `4400 bad_frame` (do not distinguish failure reasons in
the close reason string; that would help an attacker calibrate).

### 4.4 Key derivation

```
transcript = SHA-256("opencharui/v1 transcript" || HELLO_agent || HELLO_web)
```

`HELLO_agent` always precedes `HELLO_web` in the transcript, regardless of
which side observed which HELLO first — canonical ordering by role, not by
arrival time, or the two sides can compute different transcripts.

```
psk_ikm = HKDF-Expand(HKDF-Extract(salt="", ikm=psk), info="opencharui/v1 psk-ikm" || transcript, len=32)
ecdh_x  = X-coordinate of ECDH(my_ephemeral_priv, peer_ephemeral_pub)
prk     = HKDF-Extract(salt=transcript, ikm=ecdh_x || psk_ikm)

k_a2w   = HKDF-Expand(prk, "opencharui/v1 key-a2w", 32)   // agent -> web direction key
k_w2a   = HKDF-Expand(prk, "opencharui/v1 key-w2a", 32)   // web -> agent direction key
np_a2w  = HKDF-Expand(prk, "opencharui/v1 np-a2w", 4)     // nonce prefix, agent -> web
np_w2a  = HKDF-Expand(prk, "opencharui/v1 np-w2a", 4)     // nonce prefix, web -> agent
```

`k_mac` MUST NOT be used for anything except the HELLO MAC. Using one key
for two primitives is the mistake this design specifically avoids — it is
also what makes it possible for a client to import the PSK as a
non-extractable, single-purpose `CryptoKey`.

Mixing `psk_ikm` into the `prk` extraction is what prevents relay MITM: a
relay can swap ephemeral keys in transit, but without `psk` it cannot
compute `psk_ikm` and therefore cannot derive `prk`.

### 4.5 CONFIRM

```
CONFIRM = [ver:1][role:1][tag:32]     // 34 bytes
  tag_agent = HKDF-Expand(prk, "opencharui/v1 confirm-agent", 32)
  tag_web   = HKDF-Expand(prk, "opencharui/v1 confirm-web", 32)
```

Each side sends its own `CONFIRM` after deriving `prk`, and verifies the
peer's `CONFIRM` tag (constant-time) against the expected value for the
peer's role.

**CONFIRM is mandatory.** No channel `0x01` frame may be sent, and none may
be accepted, before the peer's CONFIRM has been received and verified. This
costs one extra round trip per session and eliminates an entire class of
"talking to an unauthenticated peer" bugs.

### 4.6 Session lifecycle

```
agent:  connect -> hello -> hello_ok -> (wait)
client: connect -> hello -> hello_ok
relay:  -> peer_online to BOTH
both:   send HELLO (0x02) immediately
both:   on receiving+verifying peer HELLO -> compute prk -> send CONFIRM (0x02)
both:   on receiving+verifying peer CONFIRM -> session established
        -> channel 0x01 frames may now be sent AND accepted
```

`peer_offline` (either side drops) → zero all session key material, abort
every open stream (§6), return to the wait state. Keys are never reused
across sessions — a fresh HELLO/CONFIRM runs every time.

**A session's lifetime is not the connection's.** `peer_offline` ends the
session; it does not end the connection, and an agent MUST NOT reconnect
in response to one. The wait state is an ordinary steady state: the next
`peer_online` starts a fresh handshake on the same socket, and on a
`mode:"dual"` connection (§11.3) the HTTP lane keeps serving throughout —
including before any browser has ever attached.

Two consequences for implementers:

- Ciphertext MAY arrive before the local side has finished installing its
  session, because a peer sends its first request as soon as it has
  verified the last CONFIRM. A receiver MUST NOT treat that as an error;
  hold such frames and open them, in arrival order, once the session is
  installed. Dropping them strands a request the peer considers sent, and
  §5's exact-counter rule leaves no freedom about the order.
- Ciphertext arriving with no session established *and none in progress*
  MUST NOT be acted on — there is no key to authenticate it with. It is
  not, however, grounds for closing the connection: a peer sending
  ciphertext believes a session exists, so the useful response is to start
  a handshake (send a HELLO) and let the two sides agree again.
- The same applies to a frame that fails to open, or that opens to
  undecodable inner frames: retire the session, offer a fresh HELLO, and
  keep the connection. See §5.

**A HELLO always begins a new handshake**, whatever state the receiver was
in — including `established`. That is what makes recovery possible without
a reconnect, and it is why a `peer_online` that overtakes or replaces a
HELLO (or is lost entirely) cannot strand a connection: either notification
alone is enough to start again.

## 5. Ciphertext channel (0x01)

```
payload = [counter:8][ciphertext || tag:16]

nonce = nonce_prefix(4) || counter(8)      // 12 bytes, AES-GCM standard
AAD   = outer_header_bytes || counter(8)   // outer_header_bytes = [channel][flags]([conn_id])
```

`nonce_prefix` is `np_a2w` or `np_w2a` depending on direction; direction is
otherwise bound entirely by which key (`k_a2w` / `k_w2a`) successfully
decrypts, so no explicit direction byte is needed.

The `counter` is transmitted explicitly (not implicit/tracked-only) so that
replay and gap detection are simple integer comparisons and test vectors
are exact. **The receiver's expected counter MUST equal the received
counter exactly** — no window, no reordering tolerance. Any gap or repeat
invalidates the session (§4.6): the receiver MUST NOT act on the frame,
and MUST retire its session rather than continue against a counter
sequence it no longer agrees on.

Retiring the session is the whole of the required response. Closing the
connection with `4401 nonce_violation` is permitted but discouraged, and
no implementation in this repo does it any more: the connection outlives
the session by design, and on a `mode:"dual"` agent (§11.3) it is also
carrying the OpenAI endpoint's plain lane and the agent's registration.
Hanging up takes all of that down and costs both ends a full reconnect,
where a fresh handshake costs one round trip. An implementation MAY bound
how many times it will rebuild a session on one connection before giving
up and reconnecting — a persistent failure is not recoverable in place,
and retrying it forever is an invisible handshake loop.

Per-frame overhead: `2 (outer header) + 8 (counter) + 16 (GCM tag) = 26
bytes`, plus the plaintext length.

### 5.1 Nonce discipline (non-negotiable)

Because multiple concurrent streams (§6) share one direction's key and
counter, **there MUST be exactly one sealing point per direction** in every
implementation: a single task/goroutine/writer owns the key and the
counter, and nothing else may invoke the seal operation. Concurrent access
to the counter (e.g. two tasks each doing read-increment-write) can produce
two frames encrypted under the same nonce, which breaks AES-GCM
catastrophically — it leaks the authentication key and reveals the XOR of
the two plaintexts. This is not a performance-tuning suggestion; it is a
correctness requirement.

This binds *every* implementation, including ones with no threads. A
sealing routine that reads the counter, awaits its cipher, and increments
afterwards has two sealing points the moment two callers overlap across
that await — which is the normal state of a client with several requests
in flight. Both frames then go out under one nonce. Two defences, and
both are cheap:

- serialise the calls, so there is one sealing point in fact and not just
  in intent (a promise chain, a channel to a single writer task, a mutex);
- claim the counter *before* the await, never after, so an unserialised
  caller produces a gap — which the peer rejects — rather than a repeat,
  which is catastrophic.

- Counter exhaustion (would exceed 2^64-1, in practice: never, but treat
  overflow as fatal) ends the session, never wraps. On a connection that
  outlives its session (§4.6) an implementation MAY retire just the
  session and keep the socket; it MUST NOT continue sealing.
- Session keys are never reused across sessions, including two successive
  sessions on one connection.
- The sealing point is per *session*, not per connection: when a session
  is installed, the new key and a counter starting at zero replace the
  previous pair atomically, so no frame can be sealed with a key its
  counter did not start under.

## 6. Inner frames (carried inside decrypted channel-0x01 payloads)

One or more inner frames may be concatenated inside a single decrypted
payload — this is what makes opportunistic batching free (see the relay
implementation notes; not part of the wire contract itself).

```
[type:1][stream_id:4][len:3][payload:len]
```

`len` is a 3-byte unsigned integer (max 16,777,215), always present even
for empty payloads (`len=0`).

`stream_id`: monotonically increasing per initiator. Odd = client-
initiated, even = agent-initiated. Only the client initiates streams in
v1 (agent-initiated streams are reserved for a future push-notification
style extension). A `stream_id` is never reused within a session; wrapping
closes the connection.

| `type` | Name | Payload |
|---|---|---|
| `0x01` | `REQ` | JSON `{"m":"POST","p":"/api/chat","h":[["content-type","application/json"]]}` |
| `0x02` | `REQ_BODY` | raw request body bytes |
| `0x03` | `REQ_END` | empty |
| `0x04` | `RESP` | JSON `{"s":200,"h":[["content-type","application/x-ndjson"]]}` |
| `0x05` | `RESP_BODY` | raw response body bytes |
| `0x06` | `RESP_END` | empty |
| `0x07` | `CANCEL` | JSON `{"code":"user_abort"}` or empty |
| `0x08` | `ERROR` | JSON `{"code":"upstream_unreachable","message":"..."}` |
| `0x09` | `WINDOW_UPDATE` | **reserved. MUST NOT be sent in v1.** |
| `0x0A` | `PING` | **reserved. MUST NOT be sent in v1.** |
| `0x0B` | `PONG` | **reserved. MUST NOT be sent in v1.** |

Application-level ping/pong is deliberately omitted from v1: both WebSocket
legs already carry RFC 6455 ping/pong (§7), and an E2E-level ping would
only ever distinguish "peer really alive" from "relay claims peer alive" —
a lying relay can cause a UI error, never a compromise. The type is
reserved in case that judgement changes.

`REQ_BODY` chunks SHOULD be ≤256 KiB (keeps outer frames comfortably under
`RELAY_MAX_FRAME_BYTES` while still supporting amallo's 64 MiB sync
uploads across many chunks). `RESP_BODY` chunks SHOULD be ≤16 KiB, to keep
any single frame from monopolizing the backpressure-serialized relay pump
for too long.

### 6.1 CANCEL semantics

- The sender of `CANCEL` MUST tolerate frames for that `stream_id` that were
  already in flight when it sent `CANCEL`, and silently drop them.
- The receiver of `CANCEL` MUST send nothing further for that `stream_id` —
  no `ERROR`, no `RESP_END`, nothing.
- A cancelled `stream_id` is never reused.

## 7. WebSocket-layer liveness

Both legs run standard RFC 6455 ping/pong: relay pings every
`RELAY_PING_INTERVAL` (default 30s), and a missing pong within
`RELAY_PONG_TIMEOUT` (default 15s) closes the connection. No
protocol-level ping is layered on top (§6).

That covers the relay's view. It does not cover the endpoint's, and an
endpoint that only waits to be told is the reason a pairing can appear to
survive long after it has died: a half-open TCP socket — laptop slept,
Wi-Fi flipped, CGNAT dropped the mapping — reports nothing at all until
something is written to it, so a parked agent sits in its read forever
believing it is online while the relay has long since dropped it.

`hello_ok` therefore carries `ping_ms`, and **an endpoint SHOULD treat
prolonged silence as a dead connection and redial.** The relay's pings
arrive unprompted, so any healthy connection produces traffic every
`ping_ms` even with nothing else happening; several intervals of complete
silence (this repo's agent uses three, floored at 45s) means the path is
gone. Received ping and pong frames count as traffic for this purpose —
they are exactly the signal being relied on.

## 8. Close codes

| Code | Meaning |
|---|---|
| `1001` | `going_away` — relay is shutting down/restarting; reconnect after `retry_after_ms` with **no** backoff escalation |
| `4400` | `bad_frame` — malformed outer frame, bad HELLO/CONFIRM, reserved bits set |
| `4401` | `nonce_violation` — counter gap or repeat |
| `4404` | `agent_offline` — client connected for a `pair_id` that has never registered an agent (a pair whose agent has merely gone away is parked instead, see below) |
| `4408` | `write_timeout` — relay could not write to this socket within `RELAY_WRITE_TIMEOUT` |
| `4409` | `displaced` — another connection for the same role took this slot; do NOT auto-reconnect, surface "opened on another device" |
| `4410` | `agent_gone` — the agent side of this pair went away and did not come back within `RELAY_AGENT_GRACE` |
| `4413` | `frame_too_large` |
| `4429` | `rate_limited` |
| `4503` | `capacity` — `RELAY_MAX_PAIRS` reached |

### 8.1 Parking: what happens when an agent disconnects

An agent disconnecting does **not** immediately close the client attached
to it. The relay keeps the pair, agentless, for `RELAY_AGENT_GRACE`
(default 90s) and sends the client `peer_offline`. Three things can end
that park:

- **the agent comes back** — it registers into the very same pair, both
  sides get `peer_online`, and a fresh handshake (§4.6) runs on the
  client socket that never went anywhere;
- **the grace window expires** — the client is closed `4410 agent_gone`,
  which is what it would have received immediately before parking existed,
  and the pair is dropped;
- **the client gives up first** — nothing is left to park for, so the pair
  is dropped at once rather than lingering.

The reason is that an agent restarting, waking from sleep or changing
network is the ordinary case rather than an exceptional one, and it is
back within seconds. Closing the client sent it into backoff; if it then
redialled before the agent had finished reconnecting it got `4404` and
backed off further, so a two-second blip routinely cost a minute of
apparent downtime. Parking makes that cost one handshake.

A client attaching during a park is accepted and waits, exactly as one
whose agent left would. `4404` is reserved for a `pair_id` with no pair at
all — a client cannot bring a pair into existence, which is what keeps the
pair map bounded by real agents rather than by connection attempts.

## 9. Forward-compatibility seams (present in v1, unused)

These exist specifically so that later changes do not require a protocol
version bump:

- **`conn_id` flag bit** (§2): reserved for a future "one agent, N web
  peers" model, where each peer gets its own `(pair_id, psk)` and its own
  `conn_id`. A symmetric PSK today means any holder can impersonate either
  role to a third party sharing the same PSK — the long-term fix is one
  PSK per paired device, and this bit is what makes that a non-breaking
  extension.
- **`token` field in `hello`** (§3): empty in v1. A future subscription-
  gating authorizer reads this field; the wire format does not change.
- **`WINDOW_UPDATE` / `PING` / `PONG` inner frame types** (§6): reserved,
  unused. If per-stream flow control or E2E liveness ever becomes
  necessary, these types are already carved out.

## 10. Versioning

`ver=1` appears in the pairing URI and inside every HELLO's MAC input. A
future incompatible change increments this and both the MAC and transcript
computation are versioned along with it — old and new versions MUST NOT be
mutually intelligible past the HELLO stage (this is a feature, not a gap:
downgrade attacks are defeated by binding `ver` into the MAC).

## 11. OpenAI-compatible HTTP endpoint

A second, **optional** agent protocol that makes an agent's Ollama
reachable by any OpenAI-compatible client (Open WebUI, Cursor, Continue,
LibreChat, an SDK) with nothing but a base URL and an API key.

### 11.1 Why this path is not end-to-end encrypted

Everything in §4-§5 depends on both peers holding the PSK. An unmodified
third-party OpenAI client holds nothing. There is therefore no key to
derive a session from, and no arrangement of this protocol in which the
relay both routes such a request and is unable to read it.

So on this path the relay sees plaintext prompts and completions. That is
a deliberate trade, not an oversight, and it is why:

- the agent-side setting that enables it **defaults to off**;
- the agent MUST state the trade-off where the user enables it, since the
  URL itself cannot: this endpoint shares the relay's hostname (one
  origin, one certificate, and the agent derives the HTTP base URL from
  the relay URL by swapping the scheme), so nothing about the address
  distinguishes it from the encrypted path;
- §11.5's allowlist is strictly smaller than the E2E path's.

An agent that never enables this has no HTTP registry entry, and the
entire section is inert for it.

**The E2E path's guarantees are unchanged by this section.** The two lanes
use different channels, different registries, and different allowlists,
and an agent MAY carry both on one socket (`mode:"dual"`, §11.3). Sharing
a socket means sharing a fate — one drops, both drop — and nothing else:
no plaintext frame is ever opened with a session key, no §11.5 request
ever reaches the E2E allowlist, and the lanes are charged against separate
rate budgets so traffic on one cannot close the other.

### 11.2 Keys and their hashes

The agent generates an API key (`41t_` ‖ base64url of 32 random bytes) and
publishes only `base64url(SHA-256(key))` to the relay. The relay indexes
hashes and never stores a usable key.

This bounds what an offline leak of the relay's index is worth. It does
**not** protect against a live relay compromise — the key arrives in
cleartext on every request, as does the prompt. Do not oversell it.

Rotation is in place: the agent issues a new key and republishes its hash
with `rekey` (§11.3), the relay re-indexes, and the previous key stops
resolving. The relay stays stateless — the agent is the source of truth
for which keys exist.

Rotation MUST NOT require a reconnect. On a `mode:"dual"` connection the
socket also carries a paired browser's session, and revoking an API key is
no reason to interrupt someone's chat.

### 11.3 Agent connection

Same endpoint as any agent (`GET /v1/agent`), distinguished by the hello:

```json
{"t":"hello","v":1,"role":"agent","pair":"<base64url,16 bytes>",
 "token":"","mode":"dual","token_hash":"<base64url,32 bytes>"}
```

`mode` selects which lanes the connection carries:

| `mode` | E2E lane (0x01/0x02) | HTTP lane (0x03) | Registered under |
|---|---|---|---|
| absent / `"e2e"` | yes | no | `pair` |
| `"http"` | no | yes | `token_hash` |
| `"dual"` | yes | yes | both |

- `"http"` and `"dual"` are **agent-only**. A client declaring either is
  closed with `4400`.
- A relay MUST treat an unrecognised `mode` as `"e2e"` rather than
  rejecting it. That leniency is what lets a newer agent roll out against
  an older relay and still get its pairing, losing only the lane the old
  relay cannot route.
- `token_hash` is required for `"http"` and `"dual"`, and meaningless
  otherwise.

For `"http"`, `pair` is only a correlation id for logs and metrics —
routing is by `token_hash` alone and the connection is never registered in
the pair_id map. For `"dual"` it is both: the connection occupies its
pair_id slot *and* its token_hash slot, and displacement in one does not
imply displacement in the other.

`"dual"` is the mode an agent that serves both a paired browser and the
OpenAI endpoint SHOULD use. Opening two sockets that reuse one `pair_id`
is a defect, not an alternative: both register as the agent for that pair
and displace each other in a loop.

A relay that cannot provide the HTTP lane for a `"dual"` connection — the
endpoint is disabled, the token hash is malformed, the token registry is
full — MUST degrade it to `"e2e"` and serve the pairing, not close the
connection. The pairing is the socket's primary job; the HTTP lane is an
add-on, and a user must not lose their browser session to an operator
setting or a bad hash. (`"http"` has nothing to degrade to and is closed
with `4503`.)

For the E2E lane, §4.6's session lifecycle applies unchanged. The HTTP
lane has no HELLO/CONFIRM exchange and generates no
`peer_online`/`peer_offline`: its peer is the relay's own HTTP handler,
which exists per request rather than as a socket. On a `"dual"`
connection the peer notifications therefore refer only to the browser.

**Rekey.** An agent republishes the hash it currently accepts without
reconnecting:

```json
{"t":"rekey","token_hash":"<base64url,32 bytes>"}
{"t":"rekey","token_hash":""}
```

- The relay re-indexes the connection's registry entry under the new hash.
  The previous hash stops resolving immediately.
- An empty `token_hash` removes the entry from the index entirely, which
  is how the endpoint is switched off. A later `rekey` restores it.
- Every in-flight request on the HTTP lane MUST be torn down, in both
  cases. Those requests were authorised under a key that no longer exists,
  and answering them would outlive the revocation.
- The E2E lane MUST be untouched: no session teardown, no `peer_offline`,
  no reconnect.
- A relay MUST refuse a `token_hash` already held by a *different* entry,
  and leave both entries as they were. Computing another agent's hash
  requires already holding its key, so this is not much of an escalation —
  but without the check, publishing one would take over its routing.
- A `rekey` on a connection with no HTTP lane (a plain E2E agent, or a
  degraded `"dual"` one) MUST be ignored, not closed.

### 11.4 Channel 0x03

Inner frames (§6) with no AEAD wrapping:

```
[channel=0x03][flags=0x00][inner frames...]
```

Inner frame semantics, stream-id parity, and CANCEL rules are exactly §6
and §6.1. The relay allocates odd stream ids, one per in-flight HTTP
request, and demultiplexes the RESP family back to the request that owns
each id.

A frame is valid only on a connection that carries its lane (§11.3's
table); anything else is `4400`. Concretely: 0x03 MUST NOT appear on an
`"e2e"` connection, 0x01/0x02 MUST NOT appear on an `"http"` one, and a
`"dual"` connection accepts all three. This is enforced by the relay and
by both endpoints, not by the endpoints alone.

The lanes are charged against **separate byte budgets**. One socket must
not mean one budget: a rate limit shared between them would let a
third-party client hammering inference exhaust the pair's allowance and
close the socket the user's browser depends on.

On a `"dual"` connection the receiver decides how to treat a frame from
its channel alone, before parsing the payload — a 0x03 frame is dispatched
against §11.5's allowlist and a 0x01 frame against the E2E one, and no
input can move a frame from one to the other.

Because there is no AEAD, §5.1's nonce discipline does not apply here —
there is no counter and no sealing point. The single-writer requirement
still holds for ordinary WebSocket framing reasons.

### 11.5 Request surface

The agent MUST enforce a smaller allowlist than the E2E path's:

| Method | Path |
|---|---|
| `POST` | `/v1/chat/completions` |
| `POST` | `/v1/completions` |
| `POST` | `/v1/embeddings` |
| `GET`  | `/v1/models` |
| `GET`  | `/v1/models/{id}` |

Ollama serves all of these natively; nothing needs translating.

Note what is absent. `/api/pull` and `/api/delete` are on the E2E
allowlist, and a leaked key that reached them could make the machine
download a 70B model or destroy its model library. A leaked key must cost
the user inference cycles and nothing more.

The caller's `Authorization` header authenticates them to the *relay* and
MUST NOT be forwarded; the agent stamps its own bearer token for its local
router, exactly as on the E2E path.

### 11.6 Client-facing URL

Both forms resolve the same key, and a relay MUST accept both:

```
https://<host>/<key>/v1/chat/completions      # key as first path segment
https://<host>/v1/chat/completions            # key as Authorization: Bearer
```

The path form exists because some clients accept only a base URL. It has a
real cost — a key in a URL reaches access logs, `Referer` headers, and
browser history — so a deploy MUST redact keys from its access logs, and
browser-based clients SHOULD be pointed at the bearer form.

Redaction MUST match the key prefix (`^/41t_[^/?]+`) rather than "any
first path segment": the same hostname serves `/v1/agent`, `/v1/client`
and `/healthz`, whose first segment is meaningful and must stay readable.
The bearer form carries no secret in the URL and needs no redaction.

A first path segment of `v1`, `healthz`, or `metrics` is reserved and is
never interpreted as a key.

Relays SHOULD normalize a doubled `/v1/v1/` and repeated slashes rather
than 404: both are routine artifacts of clients concatenating a base URL.

### 11.7 Error mapping

Responses MUST use the OpenAI error envelope, or clients surface an opaque
parse failure instead of the reason:

```json
{"error":{"message":"...","type":"...","code":"..."}}
```

| Condition | Status | `code` |
|---|---|---|
| No key supplied, or key not in the index | `401` | `invalid_api_key` |
| Key known, agent not connected | `503` | `agent_offline` |
| Per-key concurrency cap reached | `429` | `rate_limit_exceeded` |
| Agent rejected the path (§11.5) | `403` | `forbidden` |
| Agent did not send RESP in time | `504` | `agent_timeout` |
| Agent detached mid-request | `503` | `agent_offline` |

The `401`/`503` split is required, not cosmetic: "your machine is asleep"
and "your API key is wrong" are different problems and a user cannot act
on the wrong one. It obliges the relay to keep a key resolvable for a
grace period after its agent disconnects (a tombstone). This does leak a
small oracle — an attacker can distinguish a real-but-offline key from a
nonexistent one — which is an accepted trade for the UX, not an oversight.

### 11.8 Streaming

`RESP_BODY` frames MUST be flushed to the HTTP response as they arrive;
buffering collapses a token stream into one blob at the end and defeats
the endpoint's purpose. Any proxy in front MUST have response buffering
and compression disabled.

A cold model load routinely exceeds a client's default read timeout. Once
headers are sent and the response is `text/event-stream`, a relay MAY emit
`: keepalive\n\n` comment lines during gaps — legal no-ops to every SSE
parser. Before headers there is nothing legal to send, so that window is
bounded by a timeout instead (§11.7's `agent_timeout`).
