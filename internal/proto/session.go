package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	directionKeyLen  = 32 // AES-256
	noncePrefixLen   = 4
	nonceCounterLen  = 8
	nonceLen12       = noncePrefixLen + nonceCounterLen
	gcmTagLen        = 16
)

var (
	ErrCounterMismatch = errors.New("proto: ciphertext counter does not match expected value (spec §5: no gap, no reorder tolerance)")
	ErrCounterExhausted = errors.New("proto: direction counter exhausted; session MUST be torn down, never wrapped")
	ErrAuthFailed       = errors.New("proto: AEAD authentication failed (tampered ciphertext or AAD)")
)

// Sealer encrypts one direction of a session (spec §5). It owns the
// counter exclusively.
//
// spec §5.1 is not a suggestion: exactly one Sealer must exist per
// direction, and it must not be shared across goroutines/tasks without an
// external mutex serializing every call to Seal. Concurrent unsynchronized
// use produces two frames encrypted under the same nonce, which breaks
// AES-GCM catastrophically (authentication key recovery, plaintext XOR
// disclosure). This type's zero built-in synchronization is deliberate: it
// pushes implementers toward the "one owning task, fed by a channel"
// pattern described in the plan, rather than a mutex that invites sharing
// the Sealer across call sites "for convenience".
type Sealer struct {
	aead    cipher.AEAD
	prefix  [noncePrefixLen]byte
	counter uint64
	closed  bool
}

// NewSealerAt builds a Sealer whose counter starts at startCounter rather
// than 0. Test/vector-generation only: normal sessions always start a
// fresh Sealer at counter 0 (spec §5.1 — keys are never reused across
// reconnects, so there is never a legitimate production reason to resume a
// counter). It exists so cmd/genvectors can publish AEAD vectors at
// specific counter values, including the 2^32 boundary, without a real
// implementation exposing a public "set counter" foot-gun.
func NewSealerAt(key, prefix []byte, startCounter uint64) *Sealer {
	s, err := NewSealer(key, prefix)
	if err != nil {
		panic(err) // tooling-only call site; a bad key/prefix here is a genvectors bug, not a runtime condition
	}
	s.counter = startCounter
	return s
}

// NewSealer builds a Sealer for a 32-byte AES-256 key and 4-byte nonce
// prefix (one of SessionKeys.KA2W/KW2A paired with NPA2W/NPW2A).
func NewSealer(key, prefix []byte) (*Sealer, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(prefix) != noncePrefixLen {
		return nil, ErrBadLength
	}
	s := &Sealer{aead: aead}
	copy(s.prefix[:], prefix)
	return s, nil
}

// Seal encrypts plaintext for the given outer-frame header bytes
// (spec §5: AAD = outer_header_bytes || counter) and returns the full
// channel-0x01 payload: [counter:8][ciphertext||tag]. It advances the
// internal counter by one. Returns ErrCounterExhausted — a hard failure,
// never a silent wrap — if the counter would overflow.
func (s *Sealer) Seal(headerBytes, plaintext []byte) ([]byte, error) {
	if s.closed {
		return nil, ErrCounterExhausted
	}
	counter := s.counter
	if counter == ^uint64(0) {
		s.closed = true
		return nil, ErrCounterExhausted
	}
	nonce := makeNonce(s.prefix, counter)
	aad := makeAAD(headerBytes, counter)

	sealed := s.aead.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, nonceCounterLen+len(sealed))
	binary.BigEndian.PutUint64(out[:nonceCounterLen], counter)
	copy(out[nonceCounterLen:], sealed)

	s.counter++
	return out, nil
}

// Opener decrypts and authenticates one direction of a session. It rejects
// any payload whose counter is not exactly the next expected value — no
// window, no reordering (spec §5).
type Opener struct {
	aead     cipher.AEAD
	prefix   [noncePrefixLen]byte
	expected uint64
	closed   bool
}

// NewOpener builds an Opener for a 32-byte AES-256 key and 4-byte nonce
// prefix. Use the *other* direction's key/prefix than the paired Sealer —
// e.g. an agent's Opener uses KW2A/NPW2A while its Sealer uses KA2W/NPA2W.
func NewOpener(key, prefix []byte) (*Opener, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(prefix) != noncePrefixLen {
		return nil, ErrBadLength
	}
	o := &Opener{aead: aead}
	copy(o.prefix[:], prefix)
	return o, nil
}

// Open verifies and decrypts a channel-0x01 payload. headerBytes must be
// the exact outer-frame header bytes that accompanied this payload on the
// wire (see wire.OuterHeader.HeaderBytes).
func (o *Opener) Open(headerBytes, payload []byte) ([]byte, error) {
	if o.closed {
		return nil, ErrCounterExhausted
	}
	if len(payload) < nonceCounterLen+gcmTagLen {
		return nil, ErrBadLength
	}
	counter := binary.BigEndian.Uint64(payload[:nonceCounterLen])
	if counter != o.expected {
		return nil, ErrCounterMismatch
	}
	sealed := payload[nonceCounterLen:]

	nonce := makeNonce(o.prefix, counter)
	aad := makeAAD(headerBytes, counter)

	plaintext, err := o.aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}

	if o.expected == ^uint64(0) {
		o.closed = true
	} else {
		o.expected++
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != directionKeyLen {
		return nil, ErrBadLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func makeNonce(prefix [noncePrefixLen]byte, counter uint64) []byte {
	nonce := make([]byte, nonceLen12)
	copy(nonce[:noncePrefixLen], prefix[:])
	binary.BigEndian.PutUint64(nonce[noncePrefixLen:], counter)
	return nonce
}

// makeAAD builds [outer_header_bytes][counter:8] per spec §5. The header
// bytes are taken verbatim from the wire, not re-serialized, so a
// serialization bug elsewhere can never silently change what was
// authenticated.
func makeAAD(headerBytes []byte, counter uint64) []byte {
	aad := make([]byte, len(headerBytes)+nonceCounterLen)
	copy(aad, headerBytes)
	binary.BigEndian.PutUint64(aad[len(headerBytes):], counter)
	return aad
}
