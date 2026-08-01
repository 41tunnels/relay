package wire

import "errors"

// InnerType identifies an inner frame (spec §6). Carried inside decrypted
// channel-0x01 payloads only — never seen by the relay itself.
type InnerType byte

const (
	InnerReq      InnerType = 0x01
	InnerReqBody  InnerType = 0x02
	InnerReqEnd   InnerType = 0x03
	InnerResp     InnerType = 0x04
	InnerRespBody InnerType = 0x05
	InnerRespEnd  InnerType = 0x06
	InnerCancel   InnerType = 0x07
	InnerError    InnerType = 0x08

	// Reserved — MUST NOT be sent in v1 (spec §6, §9).
	InnerWindowUpdate InnerType = 0x09
	InnerPing         InnerType = 0x0A
	InnerPong         InnerType = 0x0B
)

// MaxInnerPayload is the largest payload representable in the 3-byte
// length field (spec §6): 2^24 - 1.
const MaxInnerPayload = 1<<24 - 1

const innerHeaderLen = 1 + 4 + 3 // type + stream_id + len

var (
	ErrInnerFrameTooShort  = errors.New("wire: inner frame header truncated")
	ErrInnerPayloadTooLong = errors.New("wire: inner payload exceeds 24-bit length")
	ErrInnerTruncated      = errors.New("wire: inner frame payload truncated")
	ErrInnerReservedType   = errors.New("wire: reserved inner frame type used in v1")
)

// InnerFrame is one decoded [type][stream_id][len][payload] record.
type InnerFrame struct {
	Type     InnerType
	StreamID uint32
	Payload  []byte
}

// EncodeInner appends the wire encoding of f to dst and returns the
// extended slice, so callers can concatenate multiple frames into one
// ciphertext payload cheaply (spec §6 batching).
func EncodeInner(dst []byte, f InnerFrame) ([]byte, error) {
	if len(f.Payload) > MaxInnerPayload {
		return nil, ErrInnerPayloadTooLong
	}
	if isReservedInnerType(f.Type) {
		return nil, ErrInnerReservedType
	}
	hdr := make([]byte, innerHeaderLen)
	hdr[0] = byte(f.Type)
	PutUint32(hdr[1:5], f.StreamID)
	PutUint24(hdr[5:8], uint32(len(f.Payload)))
	dst = append(dst, hdr...)
	dst = append(dst, f.Payload...)
	return dst, nil
}

// DecodeInnerAll parses every inner frame concatenated in buf. It is used
// on both sides of a session, since a single decrypted ciphertext payload
// may carry more than one inner frame (opportunistic batching — see the
// design notes in the plan; batching is a sender-side optimization with no
// wire-format footprint beyond "frames may be concatenated").
func DecodeInnerAll(buf []byte) ([]InnerFrame, error) {
	var frames []InnerFrame
	for len(buf) > 0 {
		f, rest, err := decodeInnerOne(buf)
		if err != nil {
			return nil, err
		}
		if isReservedInnerType(f.Type) {
			return nil, ErrInnerReservedType
		}
		frames = append(frames, f)
		buf = rest
	}
	return frames, nil
}

func decodeInnerOne(buf []byte) (InnerFrame, []byte, error) {
	if len(buf) < innerHeaderLen {
		return InnerFrame{}, nil, ErrInnerFrameTooShort
	}
	typ := InnerType(buf[0])
	streamID := Uint32(buf[1:5])
	length := Uint24(buf[5:8])
	buf = buf[innerHeaderLen:]
	if uint32(len(buf)) < length {
		return InnerFrame{}, nil, ErrInnerTruncated
	}
	payload := buf[:length:length]
	return InnerFrame{Type: typ, StreamID: streamID, Payload: payload}, buf[length:], nil
}

func isReservedInnerType(t InnerType) bool {
	switch t {
	case InnerWindowUpdate, InnerPing, InnerPong:
		return true
	default:
		return false
	}
}

// PutUint32 / Uint32: big-endian, re-exported for the same reason as
// PutUint64/Uint64 in frame.go.
func PutUint32(b []byte, v uint32) {
	_ = b[3]
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func Uint32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// IsClientInitiated reports whether a stream_id was allocated by the web
// client (odd, per spec §6). Agent-initiated (even) streams are reserved
// for a future push-style extension and unused in v1.
func IsClientInitiated(streamID uint32) bool { return streamID%2 == 1 }
