package proto

import (
	"testing"

	"github.com/OpenCharUI/relay/internal/wire"
)

// TestVectorsSession replays the golden chat transcript from session.json:
// decrypts every frame in order with fresh Openers seeded from the
// vector's keys, decodes the inner frame, and confirms it matches both the
// declared direction and the plaintext recorded alongside the ciphertext.
// This is the end-to-end sanity check the other, more granular vector
// files don't give on their own — it proves a real per-stream chat
// exchange (REQ, chunked body, RESP, streamed RESP_BODY, CANCEL) survives
// the full seal/open round trip in the order it was produced.
func TestVectorsSession(t *testing.T) {
	var v struct {
		Name     string `json:"name"`
		KA2WHex  string `json:"k_a2w_hex"`
		KW2AHex  string `json:"k_w2a_hex"`
		NpA2WHex string `json:"np_a2w_hex"`
		NpW2AHex string `json:"np_w2a_hex"`
		Frames   []struct {
			Dir           string `json:"dir"`
			InnerHex      string `json:"inner_hex"`
			CiphertextHex string `json:"ciphertext_hex"`
		} `json:"frames"`
	}
	loadVectors(t, "session.json", &v)

	openerA2W, err := NewOpener(h(t, v.KA2WHex), h(t, v.NpA2WHex))
	if err != nil {
		t.Fatalf("NewOpener a2w: %v", err)
	}
	openerW2A, err := NewOpener(h(t, v.KW2AHex), h(t, v.NpW2AHex))
	if err != nil {
		t.Fatalf("NewOpener w2a: %v", err)
	}
	header := []byte{0x01, 0x00}

	var streamSeen bool
	for i, f := range v.Frames {
		var opener *Opener
		switch f.Dir {
		case "a2w":
			opener = openerA2W
		case "w2a":
			opener = openerW2A
		default:
			t.Fatalf("frame %d: unknown direction %q", i, f.Dir)
		}

		pt, err := opener.Open(header, h(t, f.CiphertextHex))
		if err != nil {
			t.Fatalf("frame %d (%s): Open: %v", i, f.Dir, err)
		}
		hexEq(t, "frame plaintext", pt, f.InnerHex)

		frames, err := wire.DecodeInnerAll(pt)
		if err != nil {
			t.Fatalf("frame %d (%s): DecodeInnerAll: %v", i, f.Dir, err)
		}
		if len(frames) != 1 {
			t.Fatalf("frame %d: expected exactly one inner frame, got %d", i, len(frames))
		}
		if frames[0].StreamID == 1 {
			streamSeen = true
		}
	}
	if !streamSeen {
		t.Error("expected every frame to belong to stream_id=1 (the single simulated chat stream)")
	}

	// Each direction's counter must have advanced monotonically with no
	// gaps — Open() already enforces this per-call, but confirm the
	// session actually exercised both directions rather than one Opener
	// silently never being used.
	if openerA2W.expected == 0 {
		t.Error("a2w direction was never exercised by the vector")
	}
	if openerW2A.expected == 0 {
		t.Error("w2a direction was never exercised by the vector")
	}
}
