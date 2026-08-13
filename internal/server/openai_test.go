package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/OpenCharUI/relay/internal/config"
	"github.com/OpenCharUI/relay/internal/hub"
	"github.com/OpenCharUI/relay/internal/wire"
)

// --- fake http-mode agent ----------------------------------------------------

type recordedReq struct {
	Method  string
	Path    string
	Headers [][2]string
	Body    []byte
}

// fakeHTTPAgent is the agent half of spec §11: it connects declaring
// mode:"http", then answers every REQ with a canned response. It speaks
// exactly what amallo's run_once_http does, so these tests drive the real
// relay-side path rather than a mock of it.
type fakeHTTPAgent struct {
	t     *testing.T
	conn  *websocket.Conn
	wmu   sync.Mutex
	reqs  chan recordedReq
	reply func(streamID uint32, a *fakeHTTPAgent)
}

func httpTestConfig() config.Config {
	c := testConfig()
	// Keep failures fast; the production defaults are minutes.
	c.HTTPFirstByteTimeout = 2 * time.Second
	c.HTTPKeepaliveInterval = 200 * time.Millisecond
	c.HTTPTombstoneTTL = time.Hour
	c.HTTPMaxInFlight = 4
	c.HTTPStreamBuffer = 4
	return c
}

func startFakeHTTPAgent(t *testing.T, ts *httptest.Server, apiKey string, reply func(uint32, *fakeHTTPAgent)) *fakeHTTPAgent {
	t.Helper()
	c := dial(t, ts, "/v1/agent")
	pairID := randPairID(t)

	hello := wire.Hello{
		T: "hello", V: 1, Role: wire.RoleAgent,
		Pair:      base64.RawURLEncoding.EncodeToString(pairID[:]),
		Mode:      wire.ModeHTTP,
		TokenHash: hub.HashToken(apiKey).String(),
	}
	b, err := json.Marshal(hello)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageBinary, wire.EncodeOuter(wire.ChannelControl, b)); err != nil {
		t.Fatalf("send http hello: %v", err)
	}
	expectControlType(t, c, "hello_ok", 5*time.Second)

	a := &fakeHTTPAgent{t: t, conn: c, reqs: make(chan recordedReq, 8), reply: reply}
	go a.run()
	t.Cleanup(func() { _ = c.CloseNow() })
	return a
}

func (a *fakeHTTPAgent) run() {
	type head struct {
		M string      `json:"m"`
		P string      `json:"p"`
		H [][2]string `json:"h"`
	}
	heads := map[uint32]head{}
	bodies := map[uint32][]byte{}

	for {
		_, data, err := a.conn.Read(context.Background())
		if err != nil {
			return
		}
		hdr, payload, err := wire.ParseOuter(data)
		if err != nil || hdr.Channel != wire.ChannelPlain {
			continue
		}
		frames, err := wire.DecodeInnerAll(payload)
		if err != nil {
			return
		}
		for _, f := range frames {
			switch f.Type {
			case wire.InnerReq:
				var h head
				_ = json.Unmarshal(f.Payload, &h)
				heads[f.StreamID] = h
			case wire.InnerReqBody:
				bodies[f.StreamID] = append(bodies[f.StreamID], f.Payload...)
			case wire.InnerReqEnd:
				h := heads[f.StreamID]
				select {
				case a.reqs <- recordedReq{Method: h.M, Path: h.P, Headers: h.H, Body: bodies[f.StreamID]}:
				default:
				}
				delete(heads, f.StreamID)
				delete(bodies, f.StreamID)
				a.reply(f.StreamID, a)
			}
		}
	}
}

func (a *fakeHTTPAgent) send(streamID uint32, typ wire.InnerType, payload []byte) {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	inner, err := wire.EncodeInner(nil, wire.InnerFrame{Type: typ, StreamID: streamID, Payload: payload})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = a.conn.Write(ctx, websocket.MessageBinary, wire.EncodeOuter(wire.ChannelPlain, inner))
}

func (a *fakeHTTPAgent) respond(streamID uint32, status int, headers [][2]string, chunks ...string) {
	h, _ := json.Marshal(struct {
		S int         `json:"s"`
		H [][2]string `json:"h"`
	}{S: status, H: headers})
	a.send(streamID, wire.InnerResp, h)
	for _, c := range chunks {
		a.send(streamID, wire.InnerRespBody, []byte(c))
	}
	a.send(streamID, wire.InnerRespEnd, nil)
}

func (a *fakeHTTPAgent) nextReq(t *testing.T) recordedReq {
	t.Helper()
	select {
	case r := <-a.reqs:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("agent never received a request")
		return recordedReq{}
	}
}

// okJSON is the default responder: 200 with a small JSON body.
func okJSON(streamID uint32, a *fakeHTTPAgent) {
	a.respond(streamID, http.StatusOK,
		[][2]string{{"content-type", "application/json"}},
		`{"id":"chatcmpl-1","object":"chat.completion"}`)
}

func postChat(t *testing.T, ts *httptest.Server, path, bearer, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decodeOAIError(t *testing.T, resp *http.Response) oaiError {
	t.Helper()
	var e oaiError
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("response body is not an OpenAI error envelope: %v", err)
	}
	return e
}

// --- path handling -----------------------------------------------------------

func TestSplitTokenAndNormalize(t *testing.T) {
	cases := []struct {
		in        string
		wantToken string
		wantPath  string
	}{
		{"/41t_abc/v1/chat/completions", "41t_abc", "/v1/chat/completions"},
		{"/v1/chat/completions", "", "/v1/chat/completions"},
		{"/41t_abc/v1/models", "41t_abc", "/v1/models"},
		// Clients that concatenate a base URL ending in /v1 with "/v1/..".
		{"/41t_abc/v1/v1/chat/completions", "41t_abc", "/v1/chat/completions"},
		// Clients that join with a stray slash.
		{"/41t_abc//v1//chat/completions", "41t_abc", "/v1/chat/completions"},
		{"/41t_abc/v1/models/", "41t_abc", "/v1/models"},
		// Reserved first segments are never read as a token.
		{"/healthz", "", "/healthz"},
	}
	for _, c := range cases {
		gotToken, gotPath := splitToken(c.in)
		if gotToken != c.wantToken || gotPath != c.wantPath {
			t.Errorf("splitToken(%q) = (%q, %q), want (%q, %q)",
				c.in, gotToken, gotPath, c.wantToken, c.wantPath)
		}
	}
}

// --- auth and availability ---------------------------------------------------

func TestOpenAIUnknownKeyIs401(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	startFakeHTTPAgent(t, ts, "41t_real", okJSON)

	resp := postChat(t, ts, "/41t_wrong/v1/chat/completions", "", `{}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := decodeOAIError(t, resp).Error.Code; got != "invalid_api_key" {
		t.Errorf("error code = %q, want invalid_api_key", got)
	}
}

func TestOpenAIMissingKeyIs401(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	startFakeHTTPAgent(t, ts, "41t_real", okJSON)

	resp := postChat(t, ts, "/v1/chat/completions", "", `{}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// The distinction this test protects is the whole reason tombstones exist:
// "your machine is asleep" and "your API key is wrong" must not look the
// same to a user.
func TestOpenAIOfflineAgentIs503NotUnauthorized(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	a := startFakeHTTPAgent(t, ts, "41t_real", okJSON)

	// Prove it works, then take the agent away.
	if resp := postChat(t, ts, "/41t_real/v1/chat/completions", "", `{}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("precondition: status = %d, want 200", resp.StatusCode)
	}
	_ = a.conn.CloseNow()

	deadline := time.Now().Add(5 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp = postChat(t, ts, "/41t_real/v1/chat/completions", "", `{}`)
		if resp.StatusCode != http.StatusOK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if got := decodeOAIError(t, resp).Error.Code; got != "agent_offline" {
		t.Errorf("error code = %q, want agent_offline", got)
	}
}

// --- request forwarding ------------------------------------------------------

func TestOpenAIForwardsViaPathToken(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	a := startFakeHTTPAgent(t, ts, "41t_real", okJSON)

	resp := postChat(t, ts, "/41t_real/v1/chat/completions", "", `{"model":"llama3.2"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := a.nextReq(t)
	if got.Method != "POST" || got.Path != "/v1/chat/completions" {
		t.Errorf("agent saw %s %s, want POST /v1/chat/completions", got.Method, got.Path)
	}
	if string(got.Body) != `{"model":"llama3.2"}` {
		t.Errorf("agent saw body %q", got.Body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "chatcmpl-1") {
		t.Errorf("response body = %q", body)
	}
}

func TestOpenAIForwardsViaBearerToken(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	a := startFakeHTTPAgent(t, ts, "41t_real", okJSON)

	resp := postChat(t, ts, "/v1/chat/completions", "41t_real", `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := a.nextReq(t); got.Path != "/v1/chat/completions" {
		t.Errorf("agent saw path %q", got.Path)
	}
}

// The caller's key authenticates them to the relay and must never be
// forwarded — amallo stamps its own bearer token for the local router.
func TestOpenAIDoesNotForwardCallerAuthorization(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	a := startFakeHTTPAgent(t, ts, "41t_real", okJSON)

	postChat(t, ts, "/v1/chat/completions", "41t_real", `{}`)
	for _, kv := range a.nextReq(t).Headers {
		if strings.EqualFold(kv[0], "authorization") {
			t.Fatalf("caller Authorization header reached the agent: %q", kv[1])
		}
	}
}

func TestOpenAIStreamsBodyIncrementally(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	startFakeHTTPAgent(t, ts, "41t_real", func(id uint32, a *fakeHTTPAgent) {
		a.respond(id, http.StatusOK,
			[][2]string{{"content-type", "text/event-stream"}},
			"data: {\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n",
			"data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n",
			"data: [DONE]\n\n")
	})

	resp := postChat(t, ts, "/41t_real/v1/chat/completions", "", `{"stream":true}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content-type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "[DONE]") || !strings.Contains(string(body), "llo") {
		t.Errorf("stream body = %q", body)
	}
	// Content-Length must not survive: the body is re-framed here.
	if resp.Header.Get("Content-Length") != "" {
		t.Errorf("Content-Length was echoed from upstream")
	}
}

func TestOpenAINormalizesDoubledV1(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	a := startFakeHTTPAgent(t, ts, "41t_real", okJSON)

	resp := postChat(t, ts, "/41t_real/v1/v1/chat/completions", "", `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := a.nextReq(t); got.Path != "/v1/chat/completions" {
		t.Errorf("agent saw path %q, want the doubled /v1 collapsed", got.Path)
	}
}

func TestOpenAIPropagatesAgentError(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	startFakeHTTPAgent(t, ts, "41t_real", func(id uint32, a *fakeHTTPAgent) {
		a.send(id, wire.InnerError, []byte(`{"code":"forbidden","message":"not on the relay allowlist"}`))
	})

	resp := postChat(t, ts, "/41t_real/v1/chat/completions", "", `{}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	e := decodeOAIError(t, resp)
	if e.Error.Code != "forbidden" || !strings.Contains(e.Error.Message, "allowlist") {
		t.Errorf("error = %+v", e.Error)
	}
}

func TestOpenAIFirstByteTimeout(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	// Never replies at all.
	startFakeHTTPAgent(t, ts, "41t_real", func(uint32, *fakeHTTPAgent) {})

	resp := postChat(t, ts, "/41t_real/v1/chat/completions", "", `{}`)
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
}

// --- CORS --------------------------------------------------------------------

func TestOpenAICORSPreflightNeedsNoKey(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())

	req, err := http.NewRequest(http.MethodOptions, ts.URL+"/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("allow-origin = %q", got)
	}
	// The Fetch spec does not let `*` cover Authorization, so it has to be
	// named explicitly or every browser-based client fails its preflight.
	if got := resp.Header.Get("Access-Control-Allow-Headers"); !strings.Contains(strings.ToLower(got), "authorization") {
		t.Errorf("allow-headers = %q, must name Authorization", got)
	}
}

// --- mode isolation ----------------------------------------------------------

// An http-mode agent must not occupy an E2E pair slot, or enabling the
// OpenAI endpoint would break the user's paired browser.
func TestHTTPAgentDoesNotOccupyE2EPairSlot(t *testing.T) {
	s, ts := newTestServer(t, httpTestConfig())
	startFakeHTTPAgent(t, ts, "41t_real", okJSON)

	if n := s.hub.Len(); n != 0 {
		t.Errorf("E2E hub has %d pairs, want 0", n)
	}
	if n := s.httpReg.Len(); n != 1 {
		t.Errorf("http registry has %d live entries, want 1", n)
	}
}

// A client claiming mode:"http" is rejected: the client half of that path
// is the relay's own handler, never a WebSocket peer.
func TestClientCannotClaimHTTPMode(t *testing.T) {
	_, ts := newTestServer(t, httpTestConfig())
	c := dial(t, ts, "/v1/client")
	pairID := randPairID(t)

	hello := wire.Hello{
		T: "hello", V: 1, Role: wire.RoleClient,
		Pair:      base64.RawURLEncoding.EncodeToString(pairID[:]),
		Mode:      wire.ModeHTTP,
		TokenHash: hub.HashToken("41t_real").String(),
	}
	b, _ := json.Marshal(hello)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageBinary, wire.EncodeOuter(wire.ChannelControl, b)); err != nil {
		t.Fatal(err)
	}
	expectClose(t, c, websocket.StatusCode(wire.CloseBadFrame), 5*time.Second)
}
