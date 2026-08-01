package wire

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// These tests read the shared cross-language vectors from
// testdata/vectors/ (repo root) and confirm this package's own encoder/
// decoder agrees with them — the same files amallo and web vendor and
// check themselves against. If this test fails after editing frame.go or
// inner.go, either the code has a bug or the vectors are stale and need
// regenerating via `go run ./cmd/genvectors`.

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
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestVectorsFrameOuter(t *testing.T) {
	var v struct {
		Encode []struct {
			Name       string `json:"name"`
			ChannelHex string `json:"channel_hex"`
			PayloadHex string `json:"payload_hex"`
			WantHex    string `json:"want_hex"`
		} `json:"encode"`
		Parse []struct {
			Name           string `json:"name"`
			RawHex         string `json:"raw_hex"`
			WantChannelHex string `json:"want_channel_hex"`
			WantPayloadHex string `json:"want_payload_hex"`
			ExpectError    string `json:"expect_error"`
		} `json:"parse"`
	}
	loadVectors(t, "frame_outer.json", &v)

	for _, c := range v.Encode {
		t.Run(c.Name, func(t *testing.T) {
			channel := Channel(h(t, c.ChannelHex)[0])
			got := EncodeOuter(channel, h(t, c.PayloadHex))
			if hex.EncodeToString(got) != c.WantHex {
				t.Errorf("EncodeOuter = %x, want %s", got, c.WantHex)
			}
		})
	}

	for _, c := range v.Parse {
		t.Run(c.Name, func(t *testing.T) {
			hdr, payload, err := ParseOuter(h(t, c.RawHex))
			if c.ExpectError != "" {
				if err == nil {
					t.Fatalf("expected error %q, got success", c.ExpectError)
				}
				if got := DecodeErrorCode(err); got != c.ExpectError {
					t.Errorf("error code = %q, want %q", got, c.ExpectError)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hex.EncodeToString([]byte{byte(hdr.Channel)}) != c.WantChannelHex {
				t.Errorf("channel = %x, want %s", hdr.Channel, c.WantChannelHex)
			}
			if hex.EncodeToString(payload) != c.WantPayloadHex {
				t.Errorf("payload = %x, want %s", payload, c.WantPayloadHex)
			}
		})
	}
}

func TestVectorsFrameInner(t *testing.T) {
	var v struct {
		Encode []struct {
			Name        string `json:"name"`
			TypeHex     string `json:"type_hex"`
			StreamID    uint32 `json:"stream_id"`
			PayloadHex  string `json:"payload_hex"`
			WantHex     string `json:"want_hex"`
			ExpectError string `json:"expect_error"`
		} `json:"encode"`
		Decode []struct {
			Name       string `json:"name"`
			BufHex     string `json:"buf_hex"`
			WantFrames []struct {
				TypeHex    string `json:"type_hex"`
				StreamID   uint32 `json:"stream_id"`
				PayloadHex string `json:"payload_hex"`
			} `json:"want_frames"`
			ExpectError string `json:"expect_error"`
		} `json:"decode"`
	}
	loadVectors(t, "frame_inner.json", &v)

	for _, c := range v.Encode {
		t.Run(c.Name, func(t *testing.T) {
			f := InnerFrame{Type: InnerType(h(t, c.TypeHex)[0]), StreamID: c.StreamID, Payload: h(t, c.PayloadHex)}
			got, err := EncodeInner(nil, f)
			if c.ExpectError != "" {
				if err == nil {
					t.Fatalf("expected error %q, got success", c.ExpectError)
				}
				if got := DecodeErrorCode(err); got != c.ExpectError {
					t.Errorf("error code = %q, want %q", got, c.ExpectError)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hex.EncodeToString(got) != c.WantHex {
				t.Errorf("EncodeInner = %x, want %s", got, c.WantHex)
			}
		})
	}

	for _, c := range v.Decode {
		t.Run(c.Name, func(t *testing.T) {
			got, err := DecodeInnerAll(h(t, c.BufHex))
			if c.ExpectError != "" {
				if err == nil {
					t.Fatalf("expected error %q, got success", c.ExpectError)
				}
				if got := DecodeErrorCode(err); got != c.ExpectError {
					t.Errorf("error code = %q, want %q", got, c.ExpectError)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(c.WantFrames) {
				t.Fatalf("got %d frames, want %d", len(got), len(c.WantFrames))
			}
			for i, wf := range c.WantFrames {
				if hex.EncodeToString([]byte{byte(got[i].Type)}) != wf.TypeHex {
					t.Errorf("frame %d: type = %x, want %s", i, got[i].Type, wf.TypeHex)
				}
				if got[i].StreamID != wf.StreamID {
					t.Errorf("frame %d: stream_id = %d, want %d", i, got[i].StreamID, wf.StreamID)
				}
				if hex.EncodeToString(got[i].Payload) != wf.PayloadHex {
					t.Errorf("frame %d: payload = %x, want %s", i, got[i].Payload, wf.PayloadHex)
				}
			}
		})
	}
}
