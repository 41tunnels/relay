package proto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// See internal/wire/vectors_test.go for the rationale: this package's own
// handshake/session code is checked against the same committed vectors
// that amallo (Rust) and web (TypeScript) vendor and check themselves
// against.

const vectorsDir = "../../testdata/vectors"

func loadVectors(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(vectorsDir + "/" + name)
	if err != nil {
		t.Fatalf("reading %s: %v (run `go run ./cmd/genvectors` from the repo root first)", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
}

func h(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func h16(t *testing.T, s string) [16]byte {
	t.Helper()
	var out [16]byte
	copy(out[:], h(t, s))
	return out
}

func h32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	copy(out[:], h(t, s))
	return out
}

func hexEq(t *testing.T, label string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s = %x, want %s", label, got, want)
	}
}

type handshakeVector struct {
	Name   string `json:"name"`
	Inputs struct {
		PairIDHex         string `json:"pair_id_hex"`
		PSKHex            string `json:"psk_hex"`
		AgentEphScalarHex string `json:"agent_eph_priv_raw_hex"`
		WebEphScalarHex   string `json:"web_eph_priv_raw_hex"`
		AgentNonceHex     string `json:"agent_nonce_hex"`
		WebNonceHex       string `json:"web_nonce_hex"`
	} `json:"inputs"`
	Expected *struct {
		KMacHex         string `json:"k_mac_hex"`
		AgentEpkHex     string `json:"agent_epk_hex"`
		WebEpkHex       string `json:"web_epk_hex"`
		HelloAgentHex   string `json:"hello_agent_hex"`
		HelloWebHex     string `json:"hello_web_hex"`
		TranscriptHex   string `json:"transcript_hex"`
		EcdhXHex        string `json:"ecdh_x_hex"`
		PskIkmHex       string `json:"psk_ikm_hex"`
		KA2WHex         string `json:"k_a2w_hex"`
		KW2AHex         string `json:"k_w2a_hex"`
		NpA2WHex        string `json:"np_a2w_hex"`
		NpW2AHex        string `json:"np_w2a_hex"`
		ConfirmAgentHex string `json:"confirm_agent_hex"`
		ConfirmWebHex   string `json:"confirm_web_hex"`
	} `json:"expected"`
	ExpectError       string `json:"expect_error"`
	VerifyRawHelloHex string `json:"verify_raw_hello_hex"`
	VerifyOwnRoleHex  string `json:"verify_own_role_hex"`
	VerifyPairIDHex   string `json:"verify_pair_id_hex"`
}

func TestVectorsHandshake(t *testing.T) {
	var cases []handshakeVector
	loadVectors(t, "handshake.json", &cases)

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			psk := h(t, c.Inputs.PSKHex)

			if c.VerifyRawHelloHex != "" {
				// Verify-only (negative or targeted-positive) case.
				pairID := h16(t, c.VerifyPairIDHex)
				ownRole := Role(h(t, c.VerifyOwnRoleHex)[0])
				_, err := VerifyHello(psk, h(t, c.VerifyRawHelloHex), pairID, ownRole)
				if c.ExpectError != "" {
					if err == nil {
						t.Fatalf("expected error %q, got success", c.ExpectError)
					}
					if got := ErrorCode(err); got != c.ExpectError {
						t.Errorf("error code = %q, want %q", got, c.ExpectError)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			// Full positive derivation case.
			pairID := h16(t, c.Inputs.PairIDHex)
			agentEph, err := EphemeralFromScalar(h(t, c.Inputs.AgentEphScalarHex))
			if err != nil {
				t.Fatalf("agent ephemeral: %v", err)
			}
			webEph, err := EphemeralFromScalar(h(t, c.Inputs.WebEphScalarHex))
			if err != nil {
				t.Fatalf("web ephemeral: %v", err)
			}
			agentNonce := h32(t, c.Inputs.AgentNonceHex)
			webNonce := h32(t, c.Inputs.WebNonceHex)

			hexEq(t, "k_mac", KMac(psk), c.Expected.KMacHex)
			hexEq(t, "agent_epk", agentEph.PublicKeyBytes(), c.Expected.AgentEpkHex)
			hexEq(t, "web_epk", webEph.PublicKeyBytes(), c.Expected.WebEpkHex)

			helloAgent, err := BuildHello(psk, RoleAgent, pairID, agentEph.PublicKeyBytes(), agentNonce)
			if err != nil {
				t.Fatalf("BuildHello agent: %v", err)
			}
			helloWeb, err := BuildHello(psk, RoleClient, pairID, webEph.PublicKeyBytes(), webNonce)
			if err != nil {
				t.Fatalf("BuildHello web: %v", err)
			}
			hexEq(t, "hello_agent", helloAgent, c.Expected.HelloAgentHex)
			hexEq(t, "hello_web", helloWeb, c.Expected.HelloWebHex)

			if _, err := VerifyHello(psk, helloWeb, pairID, RoleAgent); err != nil {
				t.Errorf("agent verifying web hello: %v", err)
			}
			if _, err := VerifyHello(psk, helloAgent, pairID, RoleClient); err != nil {
				t.Errorf("web verifying agent hello: %v", err)
			}

			transcript := Transcript(helloAgent, helloWeb)
			hexEq(t, "transcript", transcript[:], c.Expected.TranscriptHex)

			ecdhX, err := agentEph.ECDH(webEph.PublicKeyBytes())
			if err != nil {
				t.Fatalf("ECDH: %v", err)
			}
			hexEq(t, "ecdh_x", ecdhX, c.Expected.EcdhXHex)

			hexEq(t, "psk_ikm", PSKIKM(psk, transcript), c.Expected.PskIkmHex)

			keys, err := DeriveSession(psk, transcript, ecdhX)
			if err != nil {
				t.Fatalf("DeriveSession: %v", err)
			}
			hexEq(t, "k_a2w", keys.KA2W, c.Expected.KA2WHex)
			hexEq(t, "k_w2a", keys.KW2A, c.Expected.KW2AHex)
			hexEq(t, "np_a2w", keys.NPA2W, c.Expected.NpA2WHex)
			hexEq(t, "np_w2a", keys.NPW2A, c.Expected.NpW2AHex)

			confirmAgent := BuildConfirm(keys.PRK, RoleAgent)
			confirmWeb := BuildConfirm(keys.PRK, RoleClient)
			hexEq(t, "confirm_agent", confirmAgent, c.Expected.ConfirmAgentHex)
			hexEq(t, "confirm_web", confirmWeb, c.Expected.ConfirmWebHex)

			if err := VerifyConfirm(keys.PRK, confirmAgent, RoleAgent); err != nil {
				t.Errorf("verifying agent confirm: %v", err)
			}
			if err := VerifyConfirm(keys.PRK, confirmWeb, RoleClient); err != nil {
				t.Errorf("verifying web confirm: %v", err)
			}
		})
	}
}

type aeadVector struct {
	Name                 string `json:"name"`
	KeyHex               string `json:"key_hex"`
	PrefixHex            string `json:"prefix_hex"`
	HeaderHex            string `json:"header_hex"`
	Counter              uint64 `json:"counter"`
	PlaintextHex         string `json:"plaintext_hex"`
	CiphertextPayloadHex string `json:"ciphertext_payload_hex"`
	ExpectError          string `json:"expect_error"`
}

func TestVectorsAEAD(t *testing.T) {
	var cases []aeadVector
	loadVectors(t, "aead.json", &cases)

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			key := h(t, c.KeyHex)
			prefix := h(t, c.PrefixHex)
			header := h(t, c.HeaderHex)

			if c.ExpectError != "" {
				// Negative case: attempt to Open the supplied (possibly
				// tampered, possibly out-of-order) payload. Counter starts
				// at the vector's Counter so a "counter_gap" case (which
				// supplies a payload's counter beyond what the Opener
				// expects) is exercised against a freshly-reset Opener,
				// not one advanced by unrelated prior calls.
				opener := newOpenerAt(t, key, prefix, 0)
				_, err := opener.Open(header, h(t, c.CiphertextPayloadHex))
				if err == nil {
					t.Fatalf("expected error %q, got success", c.ExpectError)
				}
				if got := ErrorCode(err); got != c.ExpectError {
					t.Errorf("error code = %q, want %q", got, c.ExpectError)
				}
				return
			}

			// Positive case: seal at the vector's counter, compare bytes,
			// then open it back and compare plaintext.
			sealer := NewSealerAt(key, prefix, c.Counter)
			ct, err := sealer.Seal(header, h(t, c.PlaintextHex))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			hexEq(t, "ciphertext_payload", ct, c.CiphertextPayloadHex)

			opener := newOpenerAt(t, key, prefix, c.Counter)
			pt, err := opener.Open(header, ct)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			hexEq(t, "plaintext", pt, c.PlaintextHex)
		})
	}
}

// newOpenerAt builds an Opener (via the package's own NewOpener) whose
// expected counter starts at start rather than 0, mirroring NewSealerAt —
// needed because vectors exercise counters other than 0, and Opener
// enforces exact sequencing from its own start point.
func newOpenerAt(t *testing.T, key, prefix []byte, start uint64) *Opener {
	t.Helper()
	o, err := NewOpener(key, prefix)
	if err != nil {
		t.Fatalf("NewOpener: %v", err)
	}
	o.expected = start
	return o
}
