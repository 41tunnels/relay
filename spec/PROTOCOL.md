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
| `channel` | `0x00` = control (JSON, relay-visible), `0x01` = ciphertext (opaque to relay), `0x02` = handshake (plaintext, still opaque to relay) |
| `flags` | bit 0 = `conn_id` present. **RESERVED, MUST be 0 in v1.** Bits 1-7 reserved, MUST be 0. |
| `conn_id` | Reserved for a future multi-peer extension (§9). Absent in v1. |

Receivers MUST reject any message with non-zero reserved flag bits (close
`4400 bad_frame`). The relay parses only the `channel` and `flags` bytes; it
never inspects the payload of channel `0x01` or `0x02`.

Maximum outer frame size: `RELAY_MAX_FRAME_BYTES` (default 1 MiB, relay-
enforced). Oversize → close `4413 frame_too_large`.

## 3. Control channel (0x00)

JSON, UTF-8, one object per outer frame. The relay both consumes and
produces these.

### Client/agent → relay

```json
{"t":"hello","v":1,"role":"agent"|"client","pair":"<base64url,16 bytes>","token":""}
```

`token` is reserved for future subscription gating (§9) and MUST be sent as
`""` in v1. `pair` is the pairing ID from the QR/manual code, base64url
without padding.

### Relay → client/agent

```json
{"t":"hello_ok","conn":"<opaque>","ping_ms":30000}
{"t":"peer_online"}
{"t":"peer_offline"}
{"t":"error","code":"agent_offline"|"peer_offline"|"capacity"|"rate_limited"|"bad_frame"}
{"t":"going_away","retry_after_ms":2000}
```

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
across a reconnect — a fresh HELLO/CONFIRM runs every time.

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
counter exactly** — no window, no reordering tolerance. Any gap or repeat →
close `4401 nonce_violation`.

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

- Counter exhaustion (would exceed 2^64-1, in practice: never, but treat
  overflow as fatal) is a hard connection close, never a wrap.
- Session keys are never reused across a reconnect.

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
`RELAY_PONG_TIMEOUT` (default 15s) closes the connection. This is
independent of and sufficient for liveness detection — no protocol-level
ping is layered on top (§6).

## 8. Close codes

| Code | Meaning |
|---|---|
| `1001` | `going_away` — relay is shutting down/restarting; reconnect after `retry_after_ms` with **no** backoff escalation |
| `4400` | `bad_frame` — malformed outer frame, bad HELLO/CONFIRM, reserved bits set |
| `4401` | `nonce_violation` — counter gap or repeat |
| `4404` | `agent_offline` — client connected for a `pair_id` with no registered agent |
| `4408` | `write_timeout` — relay could not write to this socket within `RELAY_WRITE_TIMEOUT` |
| `4409` | `displaced` — another connection for the same role took this slot; do NOT auto-reconnect, surface "opened on another device" |
| `4410` | `agent_gone` — the agent side of this pair disconnected |
| `4413` | `frame_too_large` |
| `4429` | `rate_limited` |
| `4503` | `capacity` — `RELAY_MAX_PAIRS` reached |

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
