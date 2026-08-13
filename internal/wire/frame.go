// Package wire implements the OpenCharUI relay wire format: the outer
// frame (relay-visible) and the inner frame (carried inside decrypted
// channel-0x01 payloads). See spec/PROTOCOL.md — this package is a direct
// transcription of §2 and §6 and must be kept in sync with it.
package wire

import (
	"encoding/binary"
	"errors"
)

// Channel identifies the outer-frame payload kind (spec §2).
type Channel byte

const (
	ChannelControl   Channel = 0x00
	ChannelCiphertext Channel = 0x01
	ChannelHandshake Channel = 0x02
	// ChannelPlain carries inner frames (§6) with no AEAD wrapping, and
	// exists solely for the OpenAI-compatible HTTP endpoint (§11): there,
	// the caller is an arbitrary third-party client with no PSK, so the
	// relay itself originates requests and necessarily sees plaintext.
	// It is only ever valid on a connection that declared mode:"http" in
	// its hello — an E2E session (0x01) must never accept or emit it, and
	// the server rejects it on any other connection with close 4400.
	ChannelPlain Channel = 0x03
)

const (
	// flagConnID marks that an 8-byte conn_id follows the flags byte.
	// Reserved for a future multi-peer extension (spec §9); MUST be 0 in v1.
	flagConnID = 0x01
	// flagsReservedMask covers every bit that must be zero in v1.
	flagsReservedMask = 0xFE // bits 1-7
)

var (
	ErrFrameTooShort    = errors.New("wire: outer frame too short")
	ErrReservedFlagsSet = errors.New("wire: reserved flag bits set")
	ErrConnIDNotV1      = errors.New("wire: conn_id present but not supported in v1")
)

// OuterHeader is the parsed [channel][flags]([conn_id]) prefix of an outer
// frame, exactly as transmitted. Session.Seal/Open uses HeaderBytes as part
// of the AEAD associated data (spec §5).
type OuterHeader struct {
	Channel Channel
	Flags   byte
	// HeaderBytes is the exact byte sequence of channel+flags(+conn_id) as
	// it appeared on the wire — this is what goes into the AAD, not a
	// re-serialization, so a re-serialization bug can never silently
	// change what was authenticated.
	HeaderBytes []byte
}

// ParseOuter splits a raw WebSocket binary message into its header and
// payload. It validates the reserved-bits rule (spec §2) but does not
// interpret the payload — that is the caller's job, based on Channel.
func ParseOuter(msg []byte) (OuterHeader, []byte, error) {
	if len(msg) < 2 {
		return OuterHeader{}, nil, ErrFrameTooShort
	}
	channel := Channel(msg[0])
	flags := msg[1]
	if flags&flagsReservedMask != 0 {
		return OuterHeader{}, nil, ErrReservedFlagsSet
	}
	if flags&flagConnID != 0 {
		// Defined by the spec's wire format but not a valid v1 message:
		// no implementation may send it yet.
		return OuterHeader{}, nil, ErrConnIDNotV1
	}
	hdr := OuterHeader{
		Channel:     channel,
		Flags:       flags,
		HeaderBytes: msg[:2:2],
	}
	return hdr, msg[2:], nil
}

// EncodeOuter builds a v1 outer frame (no conn_id — that field does not
// exist yet). Channel and payload are caller-supplied; flags is always 0.
func EncodeOuter(channel Channel, payload []byte) []byte {
	out := make([]byte, 2+len(payload))
	out[0] = byte(channel)
	out[1] = 0
	copy(out[2:], payload)
	return out
}

// PutUint24 writes a 3-byte big-endian length. v must fit in 24 bits.
func PutUint24(b []byte, v uint32) {
	_ = b[2]
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

// Uint24 reads a 3-byte big-endian length.
func Uint24(b []byte) uint32 {
	_ = b[2]
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

// PutUint64 / Uint64 are re-exported for callers that want the same
// endianness convention without importing encoding/binary directly.
func PutUint64(b []byte, v uint64) { binary.BigEndian.PutUint64(b, v) }
func Uint64(b []byte) uint64       { return binary.BigEndian.Uint64(b) }
