// Package hub implements pair registration and the two-connection
// splice: which agent socket and which client socket belong together, and
// the locking discipline that keeps that bookkeeping safe under
// concurrent connects/disconnects. It does not touch frame contents —
// channel 0x01/0x02 payloads pass through untouched; only channel 0x00
// (control) is ever inspected by the server package that sits on top of
// this one.
package hub

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"

	"github.com/OpenCharUI/relay/internal/auth"
	"github.com/OpenCharUI/relay/internal/wire"
)

// PairID is the 16-byte pairing capability from the QR/manual code (spec
// §3, §4.2).
type PairID [16]byte

// Conn wraps one accepted WebSocket connection with the bookkeeping the
// hub and server packages need: a single writer lock (coder/websocket
// permits one concurrent Write, so control-frame sends from the hub and
// forwarded frames from the pump must serialize through the same lock),
// idempotent close, and byte counters for metrics/quota.
type Conn struct {
	ws       *websocket.Conn
	role     wire.Role
	id       uint64
	remoteIP netip.Addr
	grant    auth.Grant

	wmu    sync.Mutex
	closed atomic.Bool
	rx     atomic.Int64
	tx     atomic.Int64
}

// NewConn wraps an already-upgraded *websocket.Conn. id should be a
// process-unique, monotonically increasing value (see Server.connSeq) —
// used only for log correlation, never as a security boundary.
func NewConn(ws *websocket.Conn, role wire.Role, id uint64, remoteIP netip.Addr, grant auth.Grant) *Conn {
	return &Conn{ws: ws, role: role, id: id, remoteIP: remoteIP, grant: grant}
}

func (c *Conn) Role() wire.Role      { return c.role }
func (c *Conn) ID() uint64           { return c.id }
func (c *Conn) RemoteIP() netip.Addr { return c.remoteIP }
func (c *Conn) Grant() auth.Grant    { return c.grant }
func (c *Conn) IsClosed() bool       { return c.closed.Load() }
func (c *Conn) BytesSent() int64     { return c.tx.Load() }
func (c *Conn) BytesReceived() int64 { return c.rx.Load() }

// SetGrant records the Authorizer's decision for this connection. Called
// once, after Authorize succeeds and before the forwarding pump starts —
// the connection has to exist (to read the hello) before it can be
// authorized, so this can't be a constructor parameter.
func (c *Conn) SetGrant(g auth.Grant) { c.grant = g }

// Read blocks for the next binary/text message. The read side has no
// internal lock — coder/websocket permits exactly one concurrent Read,
// and this codebase only ever reads from a connection's own pump
// goroutine, so no second caller can exist.
func (c *Conn) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	typ, data, err := c.ws.Read(ctx)
	if err == nil {
		c.rx.Add(int64(len(data)))
	}
	return typ, data, err
}

// Write serializes against Ping and any other Write via wmu — this is
// what lets the server package send a control frame (e.g. peer_online)
// from one goroutine while the pump forwards data frames from another,
// safely.
func (c *Conn) Write(ctx context.Context, data []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	err := c.ws.Write(ctx, websocket.MessageBinary, data)
	if err == nil {
		c.tx.Add(int64(len(data)))
	}
	return err
}

// Ping serializes against Write for the same reason.
func (c *Conn) Ping(ctx context.Context) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.ws.Ping(ctx)
}

// SetReadLimit caps the largest message coder/websocket will accept
// before returning an error, in bytes. Call once before the read loop
// starts.
func (c *Conn) SetReadLimit(n int64) { c.ws.SetReadLimit(n) }

// Close is idempotent: only the first call actually closes the underlying
// connection, so cleanup code in multiple goroutines (e.g. a peer's pump
// closing this conn on write-timeout, racing this conn's own pump exiting)
// never double-closes or panics.
//
// coder/websocket's Close performs a full RFC 6455 closing handshake: it
// writes our close frame (carrying the code the peer needs — spec §8)
// immediately, but then waits up to a hardcoded 5s, internal to the
// library and not caller-configurable, for the peer's reciprocal close
// frame before tearing down the raw connection. A cooperative peer
// responds almost immediately, but every close in this codebase (protocol
// violations, displacement, ping timeout, shutdown broadcast) is exactly
// the situation where the peer might be gone, wedged, or actively
// misbehaving — the one case that 5s wait is guaranteed to hit. Run the
// call in its own goroutine so a single unresponsive peer's slow teardown
// is isolated to that one connection and never blocks the caller (the
// forwarding pump, ping loop, or a shutdown broadcast over many
// connections). The close frame with our code still reaches a
// well-behaved peer immediately, since that write happens before the
// wait; only the fully-synchronous cleanup of a misbehaving peer is
// delayed, invisibly to everyone else.
func (c *Conn) Close(code websocket.StatusCode, reason string) error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	go func() {
		_ = c.ws.Close(code, reason)
	}()
	return nil
}

// CloseNow forcibly tears down the connection without a clean WebSocket
// close handshake — used as a last-resort defer in the upgrade handler so
// a panicking or early-returning code path never leaks a socket.
func (c *Conn) CloseNow() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.ws.CloseNow()
}
