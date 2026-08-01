package wire

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeInnerSingle(t *testing.T) {
	frames := []InnerFrame{
		{Type: InnerReq, StreamID: 1, Payload: []byte(`{"m":"GET","p":"/api/tags"}`)},
		{Type: InnerReqEnd, StreamID: 1, Payload: nil},
		{Type: InnerRespBody, StreamID: 1, Payload: bytes.Repeat([]byte{0xAB}, 1000)},
	}
	for _, f := range frames {
		buf, err := EncodeInner(nil, f)
		if err != nil {
			t.Fatalf("EncodeInner(%+v): %v", f, err)
		}
		got, err := DecodeInnerAll(buf)
		if err != nil {
			t.Fatalf("DecodeInnerAll: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d frames, want 1", len(got))
		}
		if got[0].Type != f.Type || got[0].StreamID != f.StreamID || !bytes.Equal(got[0].Payload, f.Payload) {
			t.Errorf("round trip mismatch: got %+v, want %+v", got[0], f)
		}
	}
}

func TestEncodeDecodeInnerConcatenated(t *testing.T) {
	// The batching path: multiple inner frames inside one payload.
	in := []InnerFrame{
		{Type: InnerReq, StreamID: 3, Payload: []byte("req-head")},
		{Type: InnerReqBody, StreamID: 3, Payload: []byte("chunk-1")},
		{Type: InnerReqBody, StreamID: 3, Payload: []byte("chunk-2")},
		{Type: InnerReqEnd, StreamID: 3, Payload: nil},
	}
	var buf []byte
	var err error
	for _, f := range in {
		buf, err = EncodeInner(buf, f)
		if err != nil {
			t.Fatalf("EncodeInner: %v", err)
		}
	}
	got, err := DecodeInnerAll(buf)
	if err != nil {
		t.Fatalf("DecodeInnerAll: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("got %d frames, want %d", len(got), len(in))
	}
	for i := range in {
		if got[i].Type != in[i].Type || got[i].StreamID != in[i].StreamID || !bytes.Equal(got[i].Payload, in[i].Payload) {
			t.Errorf("frame %d mismatch: got %+v, want %+v", i, got[i], in[i])
		}
	}
}

func TestDecodeInnerTruncated(t *testing.T) {
	full, err := EncodeInner(nil, InnerFrame{Type: InnerReq, StreamID: 1, Payload: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInnerAll(full[:len(full)-2]); err != ErrInnerTruncated {
		t.Errorf("truncated payload: err = %v, want ErrInnerTruncated", err)
	}
	if _, err := DecodeInnerAll(full[:5]); err != ErrInnerFrameTooShort {
		t.Errorf("truncated header: err = %v, want ErrInnerFrameTooShort", err)
	}
}

func TestEncodeInnerPayloadTooLong(t *testing.T) {
	f := InnerFrame{Type: InnerReqBody, StreamID: 1, Payload: make([]byte, MaxInnerPayload+1)}
	if _, err := EncodeInner(nil, f); err != ErrInnerPayloadTooLong {
		t.Errorf("err = %v, want ErrInnerPayloadTooLong", err)
	}
}

func TestReservedInnerTypesRejected(t *testing.T) {
	for _, typ := range []InnerType{InnerWindowUpdate, InnerPing, InnerPong} {
		if _, err := EncodeInner(nil, InnerFrame{Type: typ, StreamID: 1}); err != ErrInnerReservedType {
			t.Errorf("encode type %v: err = %v, want ErrInnerReservedType", typ, err)
		}
		// Also must be rejected on decode, in case a non-conformant peer
		// sends one anyway.
		raw := make([]byte, innerHeaderLen)
		raw[0] = byte(typ)
		if _, err := DecodeInnerAll(raw); err != ErrInnerReservedType {
			t.Errorf("decode type %v: err = %v, want ErrInnerReservedType", typ, err)
		}
	}
}

func TestIsClientInitiated(t *testing.T) {
	if !IsClientInitiated(1) || !IsClientInitiated(3) {
		t.Error("odd stream IDs should be client-initiated")
	}
	if IsClientInitiated(0) || IsClientInitiated(2) {
		t.Error("even stream IDs should not be client-initiated")
	}
}
