package wire

// Control-channel (0x00) JSON message shapes — spec §3. These are the only
// messages the relay itself reads and writes; everything else it forwards
// blindly.

// Role is the connecting side's declared role in the hello message.
type Role string

const (
	RoleAgent  Role = "agent"
	RoleClient Role = "client"
)

// Hello is sent by both agent and client immediately after the WebSocket
// upgrade. Token is reserved for future subscription gating (spec §9) and
// MUST be "" in v1.
type Hello struct {
	T     string `json:"t"` // "hello"
	V     int    `json:"v"`
	Role  Role   `json:"role"`
	Pair  string `json:"pair"`  // base64url, no padding, 16 raw bytes
	Token string `json:"token"` // reserved, "" in v1

	// Mode selects which agent protocol this connection speaks (§11).
	// "" and ModeE2E are the ordinary PSK-handshake pairing that serves
	// the web PWA; ModeHTTP is the OpenAI-compatible endpoint alone;
	// ModeDual is both at once over a single socket, which is what amallo
	// opens. Clients never set this.
	Mode Mode `json:"mode,omitempty"`
	// TokenHash is the base64url SHA-256 of the API key the agent is
	// currently accepting, sent with ModeHTTP and ModeDual. The relay
	// indexes the hash and never holds a usable key at rest — see §11.2.
	TokenHash string `json:"token_hash,omitempty"`
}

// Mode distinguishes the agent connection protocols (§11).
type Mode string

const (
	ModeE2E  Mode = "e2e"
	ModeHTTP Mode = "http"
	// ModeDual carries both lanes on one socket: sealed session traffic on
	// 0x01/0x02 and the OpenAI endpoint's plaintext on 0x03. The agent is
	// registered in both the pair map and the token-hash map, and the two
	// lanes keep their own rate budgets — see Server.serveDualAgent.
	ModeDual Mode = "dual"
)

// WantsHTTPLane reports whether this mode asks for OpenAI-endpoint
// routing, i.e. whether the hello's TokenHash is meaningful.
func (m Mode) WantsHTTPLane() bool {
	return m == ModeHTTP || m == ModeDual
}

// Normalized reports the effective mode, treating an absent field as the
// E2E default so pre-§11 agents keep working unchanged.
func (m Mode) Normalized() Mode {
	if m == "" {
		return ModeE2E
	}
	return m
}

func NewHello(role Role, pairB64 string) Hello {
	return Hello{T: "hello", V: 1, Role: role, Pair: pairB64, Token: ""}
}

// HelloOK is the relay's acknowledgement of a valid Hello.
type HelloOK struct {
	T       string `json:"t"` // "hello_ok"
	Conn    string `json:"conn"`
	PingMS  int    `json:"ping_ms"`
}

// PeerStatus notifies a connection that its peer became reachable or
// unreachable. This is a required trigger for the E2E handshake (spec §4.6
// / §6 of the design), not cosmetic UI state.
type PeerStatus struct {
	T string `json:"t"` // "peer_online" | "peer_offline"
}

func PeerOnline() PeerStatus  { return PeerStatus{T: "peer_online"} }
func PeerOffline() PeerStatus { return PeerStatus{T: "peer_offline"} }

// Rekey is the one control message an agent may send after its hello
// (§11.3). It republishes the API-key hash the agent is now accepting so
// the relay can re-index the connection in place, without the reconnect
// that publishing a new hash in a fresh hello would otherwise require.
//
// An empty TokenHash removes the connection from the token index
// entirely — that is how switching the OpenAI endpoint off stops
// resolving keys without disturbing the paired browser session sharing
// the same socket.
type Rekey struct {
	T         string `json:"t"` // "rekey"
	TokenHash string `json:"token_hash"`
}

// ControlType peeks at just the `t` field, so a reader can dispatch a
// control message without committing to a concrete shape first.
type ControlType struct {
	T string `json:"t"`
}

// ErrorCode enumerates the control-channel error codes (spec §3).
type ErrorCode string

const (
	ErrAgentOffline ErrorCode = "agent_offline"
	ErrPeerOffline  ErrorCode = "peer_offline"
	ErrCapacity     ErrorCode = "capacity"
	ErrRateLimited  ErrorCode = "rate_limited"
	ErrBadFrame     ErrorCode = "bad_frame"
)

type ErrorMsg struct {
	T    string    `json:"t"` // "error"
	Code ErrorCode `json:"code"`
}

func NewError(code ErrorCode) ErrorMsg { return ErrorMsg{T: "error", Code: code} }

// GoingAway announces a graceful relay shutdown (spec §3, §8). Clients
// treat this close as "reconnect after RetryAfterMS with no backoff
// escalation" — distinct from an error close.
type GoingAway struct {
	T             string `json:"t"` // "going_away"
	RetryAfterMS  int    `json:"retry_after_ms"`
}

func NewGoingAway(retryAfterMS int) GoingAway {
	return GoingAway{T: "going_away", RetryAfterMS: retryAfterMS}
}

// Close codes (spec §8). WebSocket close codes in the 4000-4999 range are
// reserved for private use per RFC 6455 §7.4.2.
const (
	CloseGoingAway       = 1001
	CloseBadFrame        = 4400
	CloseNonceViolation  = 4401
	CloseAgentOffline    = 4404
	CloseWriteTimeout    = 4408
	CloseDisplaced       = 4409
	CloseAgentGone       = 4410
	CloseFrameTooLarge   = 4413
	CloseRateLimited     = 4429
	CloseCapacity        = 4503
)
