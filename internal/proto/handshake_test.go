package proto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func mustPSK(t *testing.T) []byte {
	t.Helper()
	psk := make([]byte, pskLen)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	return psk
}

func mustPairID(t *testing.T) [pairIDLen]byte {
	t.Helper()
	var id [pairIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func mustNonce(t *testing.T) [nonceLen]byte {
	t.Helper()
	var n [nonceLen]byte
	if _, err := rand.Read(n[:]); err != nil {
		t.Fatal(err)
	}
	return n
}

// fullHandshake runs a complete two-sided handshake and returns both
// sides' derived SessionKeys, which must be identical.
func fullHandshake(t *testing.T) (psk []byte, pairID [pairIDLen]byte, agentKeys, webKeys SessionKeys) {
	t.Helper()
	psk = mustPSK(t)
	pairID = mustPairID(t)

	agentEph, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	webEph, err := GenerateEphemeral()
	if err != nil {
		t.Fatal(err)
	}

	agentNonce := mustNonce(t)
	webNonce := mustNonce(t)

	helloAgent, err := BuildHello(psk, RoleAgent, pairID, agentEph.PublicKeyBytes(), agentNonce)
	if err != nil {
		t.Fatal(err)
	}
	helloWeb, err := BuildHello(psk, RoleClient, pairID, webEph.PublicKeyBytes(), webNonce)
	if err != nil {
		t.Fatal(err)
	}

	// Agent verifies web's hello, and vice versa.
	if _, err := VerifyHello(psk, helloWeb, pairID, RoleAgent); err != nil {
		t.Fatalf("agent verifying web hello: %v", err)
	}
	if _, err := VerifyHello(psk, helloAgent, pairID, RoleClient); err != nil {
		t.Fatalf("web verifying agent hello: %v", err)
	}

	transcript := Transcript(helloAgent, helloWeb)

	agentX, err := agentEph.ECDH(webEph.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	webX, err := webEph.ECDH(agentEph.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(agentX, webX) {
		t.Fatal("ECDH shared secrets disagree")
	}

	agentKeys, err = DeriveSession(psk, transcript, agentX)
	if err != nil {
		t.Fatal(err)
	}
	webKeys, err = DeriveSession(psk, transcript, webX)
	if err != nil {
		t.Fatal(err)
	}
	return psk, pairID, agentKeys, webKeys
}

func TestHandshakeKeysAgree(t *testing.T) {
	_, _, agentKeys, webKeys := fullHandshake(t)

	if !bytes.Equal(agentKeys.PRK, webKeys.PRK) {
		t.Error("PRK mismatch")
	}
	if !bytes.Equal(agentKeys.KA2W, webKeys.KA2W) {
		t.Error("KA2W mismatch")
	}
	if !bytes.Equal(agentKeys.KW2A, webKeys.KW2A) {
		t.Error("KW2A mismatch")
	}
	if !bytes.Equal(agentKeys.NPA2W, webKeys.NPA2W) {
		t.Error("NPA2W mismatch")
	}
	if !bytes.Equal(agentKeys.NPW2A, webKeys.NPW2A) {
		t.Error("NPW2A mismatch")
	}
	if bytes.Equal(agentKeys.KA2W, agentKeys.KW2A) {
		t.Error("the two direction keys must not be equal")
	}
}

func TestConfirmRoundTrip(t *testing.T) {
	_, _, agentKeys, webKeys := fullHandshake(t)

	agentConfirm := BuildConfirm(agentKeys.PRK, RoleAgent)
	webConfirm := BuildConfirm(webKeys.PRK, RoleClient)

	if err := VerifyConfirm(webKeys.PRK, agentConfirm, RoleAgent); err != nil {
		t.Errorf("web verifying agent confirm: %v", err)
	}
	if err := VerifyConfirm(agentKeys.PRK, webConfirm, RoleClient); err != nil {
		t.Errorf("agent verifying web confirm: %v", err)
	}
}

func TestVerifyHelloBadMAC(t *testing.T) {
	psk := mustPSK(t)
	pairID := mustPairID(t)
	eph, _ := GenerateEphemeral()
	hello, _ := BuildHello(psk, RoleAgent, pairID, eph.PublicKeyBytes(), mustNonce(t))

	tampered := append([]byte(nil), hello...)
	tampered[len(tampered)-1] ^= 0xFF // flip a bit in the MAC

	if _, err := VerifyHello(psk, tampered, pairID, RoleClient); err != ErrBadMAC {
		t.Errorf("err = %v, want ErrBadMAC", err)
	}
}

func TestVerifyHelloWrongPSK(t *testing.T) {
	psk := mustPSK(t)
	otherPSK := mustPSK(t)
	pairID := mustPairID(t)
	eph, _ := GenerateEphemeral()
	hello, _ := BuildHello(psk, RoleAgent, pairID, eph.PublicKeyBytes(), mustNonce(t))

	if _, err := VerifyHello(otherPSK, hello, pairID, RoleClient); err != ErrBadMAC {
		t.Errorf("err = %v, want ErrBadMAC", err)
	}
}

func TestVerifyHelloPairMismatch(t *testing.T) {
	psk := mustPSK(t)
	pairID := mustPairID(t)
	otherPairID := mustPairID(t)
	eph, _ := GenerateEphemeral()
	hello, _ := BuildHello(psk, RoleAgent, pairID, eph.PublicKeyBytes(), mustNonce(t))

	if _, err := VerifyHello(psk, hello, otherPairID, RoleClient); err != ErrPairMismatch {
		t.Errorf("err = %v, want ErrPairMismatch", err)
	}
}

func TestVerifyHelloReflection(t *testing.T) {
	psk := mustPSK(t)
	pairID := mustPairID(t)
	eph, _ := GenerateEphemeral()
	hello, _ := BuildHello(psk, RoleAgent, pairID, eph.PublicKeyBytes(), mustNonce(t))

	// A verifier with role=Agent receiving a role=Agent HELLO (i.e. its own
	// HELLO reflected back) must reject it.
	if _, err := VerifyHello(psk, hello, pairID, RoleAgent); err != ErrRoleReflection {
		t.Errorf("err = %v, want ErrRoleReflection", err)
	}
}

func TestVerifyHelloBadVersion(t *testing.T) {
	psk := mustPSK(t)
	pairID := mustPairID(t)
	eph, _ := GenerateEphemeral()
	hello, _ := BuildHello(psk, RoleAgent, pairID, eph.PublicKeyBytes(), mustNonce(t))
	hello[0] = 0x02 // corrupt version — this also invalidates the MAC,
	// but the version check must fire regardless of check ordering.

	_, err := VerifyHello(psk, hello, pairID, RoleClient)
	if err != ErrBadVersion && err != ErrBadMAC {
		t.Errorf("err = %v, want ErrBadVersion or ErrBadMAC", err)
	}
}

func TestVerifyHelloMalformedPoint(t *testing.T) {
	psk := mustPSK(t)
	pairID := mustPairID(t)
	eph, _ := GenerateEphemeral()
	hello, _ := BuildHello(psk, RoleAgent, pairID, eph.PublicKeyBytes(), mustNonce(t))

	// Corrupt one byte of the epk field. This breaks the MAC too (the epk
	// is covered by it), so we expect ErrBadMAC — MAC verification must
	// happen before point parsing, since an unauthenticated point should
	// never reach curve arithmetic.
	off := 2 + pairIDLen
	hello[off] ^= 0xFF
	if _, err := VerifyHello(psk, hello, pairID, RoleClient); err != ErrBadMAC {
		t.Errorf("err = %v, want ErrBadMAC (MAC must be checked before point validity)", err)
	}
}

func TestVerifyHelloWrongLength(t *testing.T) {
	psk := mustPSK(t)
	pairID := mustPairID(t)
	if _, err := VerifyHello(psk, []byte("too short"), pairID, RoleClient); err != ErrBadLength {
		t.Errorf("err = %v, want ErrBadLength", err)
	}
}

func TestTranscriptOrderMatters(t *testing.T) {
	psk := mustPSK(t)
	pairID := mustPairID(t)
	agentEph, _ := GenerateEphemeral()
	webEph, _ := GenerateEphemeral()
	helloAgent, _ := BuildHello(psk, RoleAgent, pairID, agentEph.PublicKeyBytes(), mustNonce(t))
	helloWeb, _ := BuildHello(psk, RoleClient, pairID, webEph.PublicKeyBytes(), mustNonce(t))

	t1 := Transcript(helloAgent, helloWeb)
	t2 := Transcript(helloWeb, helloAgent)
	if t1 == t2 {
		t.Error("transcript must not be order-independent (spec requires agent-first canonical order)")
	}
}
