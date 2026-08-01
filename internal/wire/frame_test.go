package wire

import (
	"bytes"
	"testing"
)

func TestEncodeParseOuterRoundTrip(t *testing.T) {
	for _, ch := range []Channel{ChannelControl, ChannelCiphertext, ChannelHandshake} {
		payload := []byte("hello world")
		msg := EncodeOuter(ch, payload)
		hdr, gotPayload, err := ParseOuter(msg)
		if err != nil {
			t.Fatalf("channel %v: ParseOuter: %v", ch, err)
		}
		if hdr.Channel != ch {
			t.Errorf("channel = %v, want %v", hdr.Channel, ch)
		}
		if hdr.Flags != 0 {
			t.Errorf("flags = %v, want 0", hdr.Flags)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Errorf("payload = %q, want %q", gotPayload, payload)
		}
		if !bytes.Equal(hdr.HeaderBytes, msg[:2]) {
			t.Errorf("HeaderBytes = %x, want %x", hdr.HeaderBytes, msg[:2])
		}
	}
}

func TestParseOuterTooShort(t *testing.T) {
	for _, msg := range [][]byte{{}, {0x00}} {
		if _, _, err := ParseOuter(msg); err != ErrFrameTooShort {
			t.Errorf("ParseOuter(%x) = %v, want ErrFrameTooShort", msg, err)
		}
	}
}

func TestParseOuterReservedFlags(t *testing.T) {
	for bit := 1; bit < 8; bit++ {
		msg := []byte{0x00, 1 << uint(bit), 0xAA}
		if _, _, err := ParseOuter(msg); err != ErrReservedFlagsSet {
			t.Errorf("bit %d: ParseOuter = %v, want ErrReservedFlagsSet", bit, err)
		}
	}
}

func TestParseOuterConnIDRejectedInV1(t *testing.T) {
	msg := []byte{0x01, flagConnID, 1, 2, 3, 4, 5, 6, 7, 8, 0xAA}
	if _, _, err := ParseOuter(msg); err != ErrConnIDNotV1 {
		t.Errorf("ParseOuter = %v, want ErrConnIDNotV1", err)
	}
}

func TestUint24RoundTrip(t *testing.T) {
	cases := []uint32{0, 1, 255, 65535, 16777215}
	for _, v := range cases {
		b := make([]byte, 3)
		PutUint24(b, v)
		got := Uint24(b)
		if got != v {
			t.Errorf("Uint24(PutUint24(%d)) = %d", v, got)
		}
	}
}
