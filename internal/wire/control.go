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
