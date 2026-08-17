package server

// The OpenAI-compatible HTTP endpoint (spec §11).
//
// This is the one place the relay stops being a byte-forwarder and becomes
// a protocol participant: an arbitrary third-party client has no PSK, so
// nobody else can originate the inner frames on its behalf. Everything
// here therefore runs against channel 0x03 (plaintext) and NEVER touches
// an E2E session — see hub.HTTPRegistry for why the two registries are
// deliberately disjoint.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/OpenCharUI/relay/internal/hub"
	"github.com/OpenCharUI/relay/internal/wire"
)

// reqBodyChunk is the REQ_BODY chunk size. Spec §6 permits up to 256 KiB;
// 64 KiB keeps a single frame well under RELAY_MAX_FRAME_BYTES even with
// the outer/inner headers, and bounds how long one upload frame occupies
// the agent's write path.
const reqBodyChunk = 64 * 1024

// reservedFirstSegment are path prefixes that can never be a token, so a
// request to the ordinary API (with the key in the Authorization header
// instead of the path) is never mistaken for a token-prefixed one.
var reservedFirstSegment = map[string]bool{
	"v1":      true,
	"healthz": true,
	"metrics": true,
	"stats":   true,
}

// oaiError is the error envelope every OpenAI-compatible client knows how
// to parse. Returning a bare status with a plain-text body makes clients
// surface an opaque parse failure instead of the actual reason, so every
// failure path here goes through this shape.
type oaiError struct {
	Error oaiErrorBody `json:"error"`
}

type oaiErrorBody struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
}

func writeOAIError(w http.ResponseWriter, status int, typ, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(oaiError{Error: oaiErrorBody{
		Message: msg,
		Type:    typ,
		Code:    code,
	}})
}

// setCORS allows any origin. The credential here is a bearer token or a
// path segment, never a cookie, so a wildcard origin grants nothing a
// caller could not already do with curl — and many OpenAI-compatible UIs
// are pure frontends that will preflight this endpoint.
func setCORS(h http.Header) {
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	// Authorization must be listed explicitly: per the Fetch spec the `*`
	// wildcard does not cover it.
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	h.Set("Access-Control-Max-Age", "86400")
}

// splitToken separates an optional leading token segment from the upstream
// path. Returns the raw token ("" if none) and the normalized path.
func splitToken(rawPath string) (token, upstream string) {
	trimmed := strings.TrimPrefix(rawPath, "/")
	first, rest, _ := strings.Cut(trimmed, "/")
	if first == "" || reservedFirstSegment[first] {
		return "", normalizeUpstream(rawPath)
	}
	return first, normalizeUpstream("/" + rest)
}

// normalizeUpstream collapses the two mistakes clients reliably make when
// they build a base URL by string concatenation: duplicated slashes, and a
// doubled /v1 from appending "/v1" to a base that already ended in it.
// Both are cheaper to absorb here than to explain in a support thread.
func normalizeUpstream(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for strings.HasPrefix(p, "/v1/v1/") {
		p = strings.TrimPrefix(p, "/v1")
	}
	return strings.TrimSuffix(p, "/")
}

// extractAPIKey prefers the path token, falling back to the Authorization
// header. Supporting both is what makes "paste your key into both fields"
// advice that always works, across clients that only take a base URL and
// clients that only take an API key.
func extractAPIKey(r *http.Request) (key, upstream string) {
	pathToken, upstream := splitToken(r.URL.Path)
	if pathToken != "" {
		return pathToken, upstream
	}
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:]), upstream
	}
	return "", upstream
}

func (s *Server) handleOpenAI(w http.ResponseWriter, r *http.Request) {
	setCORS(w.Header())
	if r.Method == http.MethodOptions {
		// Preflights carry no Authorization header by design, so this must
		// answer before any auth check.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if s.shuttingDown.Load() {
		writeOAIError(w, http.StatusServiceUnavailable, "server_error", "shutting_down",
			"The relay is restarting. Retry in a moment.")
		return
	}

	ip := clientIP(r, s.cfg.TrustProxy)
	if !s.ipLim.Allow(ip) {
		s.m.RateLimitedTotal.WithLabelValues("ip_connect").Inc()
		writeOAIError(w, http.StatusTooManyRequests, "rate_limit_error", "rate_limit_exceeded",
			"Too many requests from this address.")
		return
	}

	key, upstream := extractAPIKey(r)
	if key == "" {
		writeOAIError(w, http.StatusUnauthorized, "invalid_request_error", "invalid_api_key",
			"No API key provided. Pass it as a bearer token or as the first path segment.")
		return
	}

	pair, found := s.httpReg.Lookup(hub.HashToken(key))
	if !found {
		writeOAIError(w, http.StatusUnauthorized, "invalid_request_error", "invalid_api_key",
			"Incorrect API key provided.")
		return
	}

	stream, agent, err := pair.OpenStream()
	switch {
	case errors.Is(err, hub.ErrAgentOffline):
		// The token is real but its agent is not connected. Distinguishing
		// this from an unknown key is the whole reason tombstones exist —
		// see hub.HTTPPair.offlineAt.
		writeOAIError(w, http.StatusServiceUnavailable, "server_error", "agent_offline",
			"The machine serving this key is offline. Wake it and try again.")
		return
	case errors.Is(err, hub.ErrTooManyInFlight):
		writeOAIError(w, http.StatusTooManyRequests, "rate_limit_error", "rate_limit_exceeded",
			"Too many concurrent requests for this key.")
		return
	case err != nil:
		writeOAIError(w, http.StatusServiceUnavailable, "server_error", "stream_unavailable",
			"Could not open a request stream to the agent.")
		return
	}
	defer pair.CloseStream(stream)

	s.m.FramesTotal.WithLabelValues("plain", "out").Inc()
	s.serveOpenAIStream(w, r, pair, agent, stream, upstream)
}

// serveOpenAIStream runs one request: send the REQ family on the agent's
// socket, then pump RESP frames back to the HTTP response.
func (s *Server) serveOpenAIStream(
	w http.ResponseWriter,
	r *http.Request,
	pair *hub.HTTPPair,
	agent *hub.Conn,
	stream *hub.Stream,
	upstream string,
) {
	ctx := r.Context()

	head, err := json.Marshal(struct {
		M string      `json:"m"`
		P string      `json:"p"`
		H [][2]string `json:"h"`
	}{
		M: r.Method,
		P: upstream + queryOf(r),
		H: forwardableHeaders(r),
	})
	if err != nil {
		writeOAIError(w, http.StatusInternalServerError, "server_error", "encode_failed",
			"Could not encode the request.")
		return
	}

	if err := s.sendInner(ctx, agent, pair, wire.InnerFrame{
		Type: wire.InnerReq, StreamID: stream.ID(), Payload: head,
	}); err != nil {
		writeOAIError(w, http.StatusBadGateway, "server_error", "agent_unreachable",
			"Could not reach the agent.")
		return
	}

	// The request body goes out on its own goroutine so a large upload can
	// never deadlock against an agent that answers (or errors) early —
	// the response pump below stays live throughout.
	sendErr := make(chan error, 1)
	go func() { sendErr <- s.sendRequestBody(ctx, agent, pair, stream, r.Body) }()

	// A client that hangs up mid-generation must free the GPU rather than
	// leave the model running to completion: CANCEL is what aborts the
	// dispatch task on the agent (spec §6.1).
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.sendInner(context.Background(), agent, pair, wire.InnerFrame{
				Type:     wire.InnerCancel,
				StreamID: stream.ID(),
				Payload:  []byte(`{"code":"client_disconnected"}`),
			})
		case <-done:
		}
	}()

	s.pumpResponse(w, pair, stream, sendErr)
}

// pumpResponse translates the RESP family back into an HTTP response.
func (s *Server) pumpResponse(w http.ResponseWriter, pair *hub.HTTPPair, stream *hub.Stream, sendErr <-chan error) {
	flusher, _ := w.(http.Flusher)
	headerWritten := false
	sse := false

	// Cold model loads on a sleeping laptop routinely exceed a client's
	// default read timeout. Once headers are out and the response is SSE,
	// a comment line is a legal no-op to every parser, so it keeps the
	// connection warm through the gap before the first token without
	// affecting the stream's content.
	var keepalive *time.Ticker
	var keepaliveC <-chan time.Time
	defer func() {
		if keepalive != nil {
			keepalive.Stop()
		}
	}()

	firstByte := time.NewTimer(s.cfg.HTTPFirstByteTimeout)
	defer firstByte.Stop()

	for {
		select {
		case <-stream.Done():
			// The agent detached mid-request (detachAgent tears down every
			// live stream). Nothing more is coming.
			if !headerWritten {
				writeOAIError(w, http.StatusServiceUnavailable, "server_error", "agent_offline",
					"The machine serving this key went offline mid-request.")
			}
			return

		case ev := <-stream.Events():
			switch ev.Type {
			case wire.InnerResp:
				if headerWritten {
					continue
				}
				ct := s.writeRespHead(w, ev.Payload)
				headerWritten = true
				sse = strings.HasPrefix(ct, "text/event-stream")
				if sse && s.cfg.HTTPKeepaliveInterval > 0 {
					keepalive = time.NewTicker(s.cfg.HTTPKeepaliveInterval)
					keepaliveC = keepalive.C
				}
				if flusher != nil {
					flusher.Flush()
				}

			case wire.InnerRespBody:
				if !headerWritten {
					// An agent that streams a body without a RESP head is
					// protocol-violating; treat the body as the response
					// rather than dropping it silently.
					w.WriteHeader(http.StatusOK)
					headerWritten = true
				}
				if _, err := w.Write(ev.Payload); err != nil {
					// Client hung up. The CANCEL goroutine in the caller
					// handles telling the agent; just stop pumping.
					return
				}
				// Flush per frame or streaming collapses into one blob at
				// the end, which defeats the entire point of this endpoint.
				if flusher != nil {
					flusher.Flush()
				}
				if keepalive != nil {
					keepalive.Reset(s.cfg.HTTPKeepaliveInterval)
				}
				firstByte.Stop()

			case wire.InnerRespEnd:
				return

			case wire.InnerError:
				s.writeAgentError(w, ev.Payload, headerWritten)
				return
			}

		case <-keepaliveC:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}

		case <-firstByte.C:
			if !headerWritten {
				writeOAIError(w, http.StatusGatewayTimeout, "server_error", "agent_timeout",
					"The agent did not start responding in time.")
				return
			}

		case err := <-sendErr:
			if err != nil && !headerWritten {
				writeOAIError(w, http.StatusBadGateway, "server_error", "agent_unreachable",
					"Failed while sending the request to the agent.")
				return
			}
			// A successful send is not an end condition — keep pumping the
			// response. Nil out the channel so this case stops firing.
			sendErr = nil
		}
	}
}

// writeRespHead copies the agent's status and headers onto the HTTP
// response, returning the content-type it applied (the caller needs it to
// decide whether SSE keepalives are legal).
func (s *Server) writeRespHead(w http.ResponseWriter, payload []byte) string {
	var head struct {
		S int         `json:"s"`
		H [][2]string `json:"h"`
	}
	if err := json.Unmarshal(payload, &head); err != nil {
		writeOAIError(w, http.StatusBadGateway, "server_error", "bad_response",
			"The agent sent a malformed response header.")
		return ""
	}
	ct := ""
	for _, kv := range head.H {
		name := kv[0]
		if skipResponseHeader(name) {
			continue
		}
		if strings.EqualFold(name, "content-type") {
			ct = kv[1]
		}
		w.Header().Add(name, kv[1])
	}
	if head.S == 0 {
		head.S = http.StatusOK
	}
	w.WriteHeader(head.S)
	return ct
}

// skipResponseHeader drops hop-by-hop and length headers the relay must
// not echo: the body is re-framed here, so an upstream Content-Length is
// wrong, and Go owns Transfer-Encoding itself.
func skipResponseHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "transfer-encoding", "connection", "keep-alive",
		"access-control-allow-origin", "access-control-allow-headers",
		"access-control-allow-methods":
		return true
	default:
		return false
	}
}

func (s *Server) writeAgentError(w http.ResponseWriter, payload []byte, headerWritten bool) {
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(payload, &e)

	if headerWritten {
		// Too late for a status code; the client sees a truncated stream,
		// which is the only honest signal left.
		return
	}
	status, typ := http.StatusBadGateway, "server_error"
	switch e.Code {
	case "forbidden":
		status, typ = http.StatusForbidden, "invalid_request_error"
	case "bad_request":
		status, typ = http.StatusBadRequest, "invalid_request_error"
	case "upstream_unreachable":
		status, typ = http.StatusBadGateway, "server_error"
	}
	msg := e.Message
	if msg == "" {
		msg = "The agent could not complete the request."
	}
	writeOAIError(w, status, typ, e.Code, msg)
}

// sendRequestBody streams the HTTP request body out as REQ_BODY frames,
// terminated by REQ_END.
func (s *Server) sendRequestBody(ctx context.Context, agent *hub.Conn, pair *hub.HTTPPair, stream *hub.Stream, body io.ReadCloser) error {
	defer func() { _ = body.Close() }()

	buf := make([]byte, reqBodyChunk)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if serr := s.sendInner(ctx, agent, pair, wire.InnerFrame{
				Type: wire.InnerReqBody, StreamID: stream.ID(), Payload: chunk,
			}); serr != nil {
				return serr
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	return s.sendInner(ctx, agent, pair, wire.InnerFrame{
		Type: wire.InnerReqEnd, StreamID: stream.ID(), Payload: nil,
	})
}

// sendInner encodes one inner frame onto channel 0x03 and writes it to the
// agent, charging the pair's byte bucket.
func (s *Server) sendInner(ctx context.Context, agent *hub.Conn, pair *hub.HTTPPair, f wire.InnerFrame) error {
	inner, err := wire.EncodeInner(nil, f)
	if err != nil {
		return err
	}
	outer := wire.EncodeOuter(wire.ChannelPlain, inner)
	if len(outer) > s.cfg.MaxFrameBytes {
		return fmt.Errorf("server: outbound frame %d exceeds max %d", len(outer), s.cfg.MaxFrameBytes)
	}
	if !pair.Bucket().AllowN(len(outer)) {
		s.m.RateLimitedTotal.WithLabelValues("pair_bytes").Inc()
		return errors.New("server: pair rate limit exceeded")
	}
	wctx, cancel := context.WithTimeout(ctx, s.cfg.WriteTimeout)
	defer cancel()
	if err := agent.Write(wctx, outer); err != nil {
		return err
	}
	s.m.BytesTotal.WithLabelValues("out").Add(float64(len(outer)))
	return nil
}

func queryOf(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	return "?" + r.URL.RawQuery
}

// forwardableHeaders is a strict allowlist. Authorization is deliberately
// absent: the caller's key authenticates them to the RELAY, and must never
// reach the agent, which stamps its own bearer token for the local router
// (see amallo's relay/policy.rs, which drops it again on arrival).
func forwardableHeaders(r *http.Request) [][2]string {
	out := make([][2]string, 0, 2)
	for _, name := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(name); v != "" {
			out = append(out, [2]string{strings.ToLower(name), v})
		}
	}
	return out
}
