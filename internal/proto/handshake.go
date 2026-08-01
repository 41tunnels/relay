// Package proto is a reference implementation of the OpenCharUI E2E
// handshake and AEAD session (spec/PROTOCOL.md §4-§6). The relay itself
// never calls this package — channel 0x01/0x02 payloads are opaque to it.
// It exists so the Go side can (a) generate cross-checked test vectors and
// (b) drive the fakeagent/fakeclient test harnesses used to validate the
// server and, later, amallo and web against a real peer.
package proto

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Role mirrors spec §4.3 (agent=0x01, client=0x02) — deliberately not the
// wire.Role string type, since this is the single-byte form that goes
// inside HMAC/transcript input.
type Role byte

const (
	RoleAgent  Role = 0x01
	RoleClient Role = 0x02
)

const (
	protoVersion = 0x01

	pairIDLen = 16
	pskLen    = 32
	epkLen    = 65 // uncompressed SEC1 P-256 point: 0x04 || X(32) || Y(32)
	nonceLen  = 32
	macLen    = 32
	tagLen    = 32

	helloLen   = 1 + 1 + pairIDLen + epkLen + nonceLen + macLen // 147
	confirmLen = 1 + 1 + tagLen                                  // 34
)

var (
	ErrBadLength       = errors.New("proto: wrong-length input")
	ErrBadMAC          = errors.New("proto: HELLO MAC verification failed")
	ErrPairMismatch    = errors.New("proto: HELLO pair_id does not match")
	ErrRoleReflection  = errors.New("proto: peer HELLO has the same role as us")
	ErrBadVersion      = errors.New("proto: unsupported protocol version")
	ErrBadPoint        = errors.New("proto: ephemeral public key is not a valid P-256 point")
	ErrConfirmMismatch = errors.New("proto: CONFIRM tag verification failed")
	ErrConfirmRole     = errors.New("proto: CONFIRM role does not match expected peer")
)

// --- Ephemeral keys -------------------------------------------------------

// Ephemeral wraps one P-256 ECDH key pair, used for exactly one handshake
// and never persisted or reused across reconnects (spec §4.2).
type Ephemeral struct {
	priv *ecdh.PrivateKey
}

// GenerateEphemeral creates a fresh, random ephemeral key pair.
func GenerateEphemeral() (*Ephemeral, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ephemeral{priv: priv}, nil
}

// EphemeralFromScalar constructs a deterministic key pair from a raw
// 32-byte big-endian scalar. This exists solely so test vectors can make
// the handshake a pure function: the vector supplies the "random" input
// instead of the implementation generating it. Every implementation of
// this spec MUST expose an equivalent seam — see testdata/vectors and the
// build plan's note that this seam must not be retrofitted later.
func EphemeralFromScalar(scalar []byte) (*Ephemeral, error) {
	priv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	return &Ephemeral{priv: priv}, nil
}

// PublicKeyBytes returns the uncompressed SEC1 encoding (65 bytes) used as
// `epk` in HELLO.
func (e *Ephemeral) PublicKeyBytes() []byte {
	return e.priv.PublicKey().Bytes()
}

// EphemeralRawScalar returns the raw 32-byte P-256 private scalar backing
// e. Production handshake code never needs this — session key material is
// always derived through ECDH — but cmd/genvectors publishes it so other
// implementations can reconstruct the exact same key pair from a vector
// input via EphemeralFromScalar.
func EphemeralRawScalar(e *Ephemeral) []byte {
	return e.priv.Bytes()
}

// ECDH performs the key agreement against a peer's HELLO-carried public
// key and returns the shared X-coordinate (spec §4.4's ecdh_x). peerEpk is
// the raw 65-byte uncompressed point from the peer's HELLO; ErrBadPoint if
// it is not a valid point on P-256 (this is also where invalid-curve
// attacks are rejected — crypto/ecdh validates on import).
func (e *Ephemeral) ECDH(peerEpk []byte) ([]byte, error) {
	peerPub, err := ecdh.P256().NewPublicKey(peerEpk)
	if err != nil {
		return nil, ErrBadPoint
	}
	return e.priv.ECDH(peerPub)
}

// --- HELLO -----------------------------------------------------------------

// kMac derives the HELLO-MAC key from the PSK (spec §4.3). This key is used
// for nothing else — see the "one key, one purpose" rule in PROTOCOL.md.
func kMac(psk []byte) []byte {
	return hkdfExpand(hkdfExtract(nil, psk), []byte("opencharui/v1 hello-mac"), 32)
}

// KMac and PSKIKM re-export the two intermediate HKDF values used inside
// BuildHello/VerifyHello and DeriveSession. Normal handshake code never
// needs these directly; they exist so cmd/genvectors can publish
// intermediate values in the shared test vectors, letting the Rust and
// TypeScript implementations cross-check each derivation step
// independently rather than only the final session keys.
func KMac(psk []byte) []byte { return kMac(psk) }

func PSKIKM(psk []byte, transcript [32]byte) []byte {
	return hkdfExpand(hkdfExtract(nil, psk), append([]byte("opencharui/v1 psk-ikm"), transcript[:]...), 32)
}

// HelloFields is a parsed, not-yet-verified HELLO.
type HelloFields struct {
	Ver    byte
	Role   Role
	PairID [pairIDLen]byte
	Epk    []byte // 65 bytes
	Nonce  [nonceLen]byte
	Mac    []byte // 32 bytes
	Raw    []byte // the exact 147 bytes, needed verbatim for the transcript
}

// BuildHello encodes and MACs a HELLO message (spec §4.3). nonce must be
// exactly 32 bytes — callers pass a fresh random nonce in production and a
// vector-fixed nonce when generating test vectors.
func BuildHello(psk []byte, role Role, pairID [pairIDLen]byte, epk []byte, nonce [nonceLen]byte) ([]byte, error) {
	if len(psk) != pskLen {
		return nil, ErrBadLength
	}
	if len(epk) != epkLen {
		return nil, ErrBadLength
	}
	buf := make([]byte, 0, helloLen)
	buf = append(buf, protoVersion, byte(role))
	buf = append(buf, pairID[:]...)
	buf = append(buf, epk...)
	buf = append(buf, nonce[:]...)

	mac := hmac.New(sha256.New, kMac(psk))
	mac.Write([]byte("opencharui/v1 hello"))
	mac.Write(buf) // ver || role || pair_id || epk || nonce, in encoding order
	tag := mac.Sum(nil)

	return append(buf, tag...), nil
}

// ParseHello splits a raw HELLO without verifying it — use VerifyHello for
// the authenticated path. Exposed separately because negative test vectors
// need to observe "parses fine, fails verification" distinctly.
func ParseHello(raw []byte) (HelloFields, error) {
	if len(raw) != helloLen {
		return HelloFields{}, ErrBadLength
	}
	var f HelloFields
	f.Raw = append([]byte(nil), raw...)
	f.Ver = raw[0]
	f.Role = Role(raw[1])
	copy(f.PairID[:], raw[2:2+pairIDLen])
	off := 2 + pairIDLen
	f.Epk = append([]byte(nil), raw[off:off+epkLen]...)
	off += epkLen
	copy(f.Nonce[:], raw[off:off+nonceLen])
	off += nonceLen
	f.Mac = append([]byte(nil), raw[off:off+macLen]...)
	return f, nil
}

// VerifyHello parses raw and applies every check from spec §4.3: MAC,
// pair_id match, role-reflection defence, and point validity. ownRole is
// the verifier's own role, used to reject a reflected HELLO with the same
// role as the verifier — a peer's HELLO must always have the *other* role.
func VerifyHello(psk []byte, raw []byte, expectPairID [pairIDLen]byte, ownRole Role) (HelloFields, error) {
	f, err := ParseHello(raw)
	if err != nil {
		return HelloFields{}, err
	}
	if f.Ver != protoVersion {
		return HelloFields{}, ErrBadVersion
	}
	if f.PairID != expectPairID {
		return HelloFields{}, ErrPairMismatch
	}
	if f.Role == ownRole {
		return HelloFields{}, ErrRoleReflection
	}

	mac := hmac.New(sha256.New, kMac(psk))
	mac.Write([]byte("opencharui/v1 hello"))
	mac.Write(raw[:2+pairIDLen+epkLen+nonceLen])
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(expected, f.Mac) != 1 {
		return HelloFields{}, ErrBadMAC
	}

	// Point validity: NewPublicKey rejects invalid-curve points.
	if _, err := ecdh.P256().NewPublicKey(f.Epk); err != nil {
		return HelloFields{}, ErrBadPoint
	}

	return f, nil
}

// --- Transcript and session key derivation ---------------------------------

// Transcript computes spec §4.4's canonical, role-ordered transcript hash.
// helloAgent and helloWeb are the exact 147-byte HELLO wire encodings —
// agent's HELLO always precedes web's in the hash input, regardless of
// which one either side observed first.
func Transcript(helloAgent, helloWeb []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("opencharui/v1 transcript"))
	h.Write(helloAgent)
	h.Write(helloWeb)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionKeys holds everything derived from one handshake (spec §4.4).
type SessionKeys struct {
	PRK   []byte // 32 bytes; kept only to derive CONFIRM tags
	KA2W  []byte // 32 bytes, AES-256 key for agent->web
	KW2A  []byte // 32 bytes, AES-256 key for web->agent
	NPA2W []byte // 4 bytes, nonce prefix agent->web
	NPW2A []byte // 4 bytes, nonce prefix web->agent
}

// DeriveSession computes the session keys from the PSK, the transcript,
// and the raw ECDH shared secret (spec §4.4). psk_ikm is folded into the
// PRK extraction specifically so that a relay without the PSK — even one
// that swapped both ephemeral public keys in transit — cannot derive
// anything past this point.
func DeriveSession(psk []byte, transcript [32]byte, ecdhX []byte) (SessionKeys, error) {
	if len(psk) != pskLen {
		return SessionKeys{}, ErrBadLength
	}
	pskIKM := hkdfExpand(hkdfExtract(nil, psk), append([]byte("opencharui/v1 psk-ikm"), transcript[:]...), 32)

	ikm := append(append([]byte{}, ecdhX...), pskIKM...)
	prk := hkdfExtract(transcript[:], ikm)

	return SessionKeys{
		PRK:   prk,
		KA2W:  hkdfExpand(prk, []byte("opencharui/v1 key-a2w"), 32),
		KW2A:  hkdfExpand(prk, []byte("opencharui/v1 key-w2a"), 32),
		NPA2W: hkdfExpand(prk, []byte("opencharui/v1 np-a2w"), 4),
		NPW2A: hkdfExpand(prk, []byte("opencharui/v1 np-w2a"), 4),
	}, nil
}

// --- CONFIRM -----------------------------------------------------------------

func confirmTag(prk []byte, role Role) []byte {
	label := "opencharui/v1 confirm-agent"
	if role == RoleClient {
		label = "opencharui/v1 confirm-web"
	}
	return hkdfExpand(prk, []byte(label), tagLen)
}

// BuildConfirm encodes this side's CONFIRM (spec §4.5). role is the
// sender's own role.
func BuildConfirm(prk []byte, role Role) []byte {
	buf := make([]byte, 0, confirmLen)
	buf = append(buf, protoVersion, byte(role))
	buf = append(buf, confirmTag(prk, role)...)
	return buf
}

// VerifyConfirm checks a peer's CONFIRM. expectRole is the *peer's*
// expected role (i.e. the role opposite to the verifier). No channel-0x01
// frame may be sent or accepted before this succeeds (spec §4.5) —
// enforced by callers, not by this function.
func VerifyConfirm(prk []byte, raw []byte, expectRole Role) error {
	if len(raw) != confirmLen {
		return ErrBadLength
	}
	if raw[0] != protoVersion {
		return ErrBadVersion
	}
	role := Role(raw[1])
	if role != expectRole {
		return ErrConfirmRole
	}
	expected := confirmTag(prk, role)
	if subtle.ConstantTimeCompare(expected, raw[2:2+tagLen]) != 1 {
		return ErrConfirmMismatch
	}
	return nil
}

// --- HKDF helpers ------------------------------------------------------------
//
// Thin wrappers around golang.org/x/crypto/hkdf's RFC 5869 primitives —
// deliberately not hand-rolled, so a salt/IKM argument-order mistake can't
// silently produce self-consistent-but-wrong vectors.

func hkdfExtract(salt, ikm []byte) []byte {
	return hkdf.Extract(sha256.New, ikm, salt)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	r := hkdf.Expand(sha256.New, prk, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		// hkdf.Expand only fails for a requested length that's too long
		// for the hash (255*32 bytes for SHA-256); every call site here
		// requests <=32 bytes, so this is unreachable in practice.
		panic(err)
	}
	return out
}
