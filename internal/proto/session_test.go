package proto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func mustDirKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, directionKeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func mustPrefix(t *testing.T) []byte {
	t.Helper()
	p := make([]byte, noncePrefixLen)
	if _, err := rand.Read(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := mustDirKey(t)
	prefix := mustPrefix(t)
	sealer, err := NewSealer(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := NewOpener(key, prefix)
	if err != nil {
		t.Fatal(err)
	}

	header := []byte{0x01, 0x00} // channel=ciphertext, flags=0
	plaintexts := [][]byte{
		[]byte(""),
		[]byte("a"),
		bytes.Repeat([]byte{0x42}, 16*1024),
	}
	for _, pt := range plaintexts {
		ct, err := sealer.Seal(header, pt)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		got, err := opener.Open(header, ct)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("round trip mismatch: got %q, want %q", got, pt)
		}
	}
}

func TestSealOverheadIs26Bytes(t *testing.T) {
	key := mustDirKey(t)
	prefix := mustPrefix(t)
	sealer, _ := NewSealer(key, prefix)

	header := []byte{0x01, 0x00}
	pt := []byte("hello")
	ct, err := sealer.Seal(header, pt)
	if err != nil {
		t.Fatal(err)
	}
	// spec §5: 8 (counter) + 16 (GCM tag) = 24 bytes overhead on the
	// ciphertext payload itself (the outer 2-byte header is separate and
	// not part of this payload).
	want := len(pt) + nonceCounterLen + gcmTagLen
	if len(ct) != want {
		t.Errorf("ciphertext payload length = %d, want %d", len(ct), want)
	}
}

func TestOpenRejectsCounterGap(t *testing.T) {
	key := mustDirKey(t)
	prefix := mustPrefix(t)
	sealer, _ := NewSealer(key, prefix)
	opener, _ := NewOpener(key, prefix)
	header := []byte{0x01, 0x00}

	ct0, _ := sealer.Seal(header, []byte("frame 0"))
	ct1, _ := sealer.Seal(header, []byte("frame 1"))

	// Skip ct0, present ct1 first — must be rejected (no reordering
	// tolerance per spec §5).
	if _, err := opener.Open(header, ct1); err != ErrCounterMismatch {
		t.Errorf("err = %v, want ErrCounterMismatch", err)
	}
	_ = ct0
}

func TestOpenRejectsReplay(t *testing.T) {
	key := mustDirKey(t)
	prefix := mustPrefix(t)
	sealer, _ := NewSealer(key, prefix)
	opener, _ := NewOpener(key, prefix)
	header := []byte{0x01, 0x00}

	ct, _ := sealer.Seal(header, []byte("only frame"))
	if _, err := opener.Open(header, ct); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := opener.Open(header, ct); err != ErrCounterMismatch {
		t.Errorf("replay: err = %v, want ErrCounterMismatch", err)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	key := mustDirKey(t)
	prefix := mustPrefix(t)
	sealer, _ := NewSealer(key, prefix)
	opener, _ := NewOpener(key, prefix)
	header := []byte{0x01, 0x00}

	ct, _ := sealer.Seal(header, []byte("authentic"))
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0x01 // flip a bit in the GCM tag region

	if _, err := opener.Open(header, tampered); err != ErrAuthFailed {
		t.Errorf("err = %v, want ErrAuthFailed", err)
	}
}

func TestOpenRejectsTamperedAAD(t *testing.T) {
	key := mustDirKey(t)
	prefix := mustPrefix(t)
	sealer, _ := NewSealer(key, prefix)
	opener, _ := NewOpener(key, prefix)
	header := []byte{0x01, 0x00}

	ct, _ := sealer.Seal(header, []byte("authentic"))
	tamperedHeader := []byte{0x00, 0x00} // different channel byte in the AAD

	if _, err := opener.Open(tamperedHeader, ct); err != ErrAuthFailed {
		t.Errorf("err = %v, want ErrAuthFailed", err)
	}
}

func TestSealDirectionKeysAreIndependent(t *testing.T) {
	keyA := mustDirKey(t)
	keyB := mustDirKey(t)
	prefix := mustPrefix(t)

	sealerA, _ := NewSealer(keyA, prefix)
	openerB, _ := NewOpener(keyB, prefix)
	header := []byte{0x01, 0x00}

	ct, _ := sealerA.Seal(header, []byte("secret"))
	if _, err := openerB.Open(header, ct); err != ErrAuthFailed {
		t.Errorf("opening with the wrong direction key: err = %v, want ErrAuthFailed", err)
	}
}

func TestNewSealerRejectsWrongKeyLength(t *testing.T) {
	if _, err := NewSealer(make([]byte, 16), mustPrefix(t)); err != ErrBadLength {
		t.Errorf("err = %v, want ErrBadLength", err)
	}
}

func TestOpenRejectsShortPayload(t *testing.T) {
	opener, _ := NewOpener(mustDirKey(t), mustPrefix(t))
	if _, err := opener.Open([]byte{0x01, 0x00}, []byte{1, 2, 3}); err != ErrBadLength {
		t.Errorf("err = %v, want ErrBadLength", err)
	}
}

func TestCounterExhaustionIsHardClose(t *testing.T) {
	key := mustDirKey(t)
	prefix := mustPrefix(t)
	sealer, _ := NewSealer(key, prefix)
	sealer.counter = ^uint64(0) // force the next Seal to hit the max value

	header := []byte{0x01, 0x00}
	if _, err := sealer.Seal(header, []byte("x")); err != ErrCounterExhausted {
		t.Fatalf("first exhausting Seal: err = %v, want ErrCounterExhausted", err)
	}
	// Must stay closed — never silently wrap back to counter 0.
	if _, err := sealer.Seal(header, []byte("y")); err != ErrCounterExhausted {
		t.Errorf("second Seal after exhaustion: err = %v, want ErrCounterExhausted", err)
	}
}
