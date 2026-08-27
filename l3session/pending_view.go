package l3session

import (
	"net"
	"sync/atomic"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

// PendingSessionView is an immutable snapshot passed to Manager.OnStart.
// It deliberately does not expose the manager-owned Session object or its
// lifecycle hooks. Request returns a defensive copy on every call.
type PendingSessionView struct {
	request    l3ingress.SessionRequest
	conn       rendr.Conn
	packetConn rendr.PacketConn
}

// Request returns the request that created the pending session.
func (v PendingSessionView) Request() l3ingress.SessionRequest {
	return cloneSessionRequest(v.request)
}

// Conn returns the pending stream connection, or nil for packet sessions.
// Closing this view closes the candidate and prevents Manager from publishing
// it even when OnStart returns nil.
func (v PendingSessionView) Conn() rendr.Conn { return v.conn }

// PacketConn returns the pending packet connection, or nil for stream
// sessions. Closing this view prevents the candidate from being published.
func (v PendingSessionView) PacketConn() rendr.PacketConn { return v.packetConn }

type pendingSessionAccess struct {
	closed  atomic.Bool
	revoked atomic.Bool
}

func (a *pendingSessionAccess) usable() bool {
	return a != nil && !a.revoked.Load()
}

func (a *pendingSessionAccess) revoke() {
	if a != nil {
		a.revoked.Store(true)
	}
}

func newPendingSessionView(sess *Session) (PendingSessionView, *pendingSessionAccess) {
	access := &pendingSessionAccess{}
	view := PendingSessionView{request: cloneSessionRequest(sess.request)}
	if sess.conn != nil {
		view.conn = &pendingStreamConn{session: sess, conn: sess.conn, access: access}
	}
	if sess.packetConn != nil {
		view.packetConn = &pendingPacketConn{session: sess, conn: sess.packetConn, access: access}
	}
	return view, access
}

type pendingStreamConn struct {
	session *Session
	conn    rendr.Conn
	access  *pendingSessionAccess
}

func (c *pendingStreamConn) Read(p []byte) (int, error) {
	if c == nil || !c.access.usable() {
		return 0, net.ErrClosed
	}
	return c.conn.Read(p)
}
func (c *pendingStreamConn) Write(p []byte) (int, error) {
	if c == nil || !c.access.usable() {
		return 0, net.ErrClosed
	}
	return c.conn.Write(p)
}
func (c *pendingStreamConn) Close() error {
	if c == nil || !c.access.usable() {
		return net.ErrClosed
	}
	c.access.closed.Store(true)
	return c.session.Close()
}
func (c *pendingStreamConn) LocalAddr() net.Addr {
	if c == nil || !c.access.usable() {
		return nil
	}
	return c.conn.LocalAddr()
}
func (c *pendingStreamConn) RemoteAddr() net.Addr {
	if c == nil || !c.access.usable() {
		return nil
	}
	return c.conn.RemoteAddr()
}
func (c *pendingStreamConn) SetDeadline(t time.Time) error {
	if c == nil || !c.access.usable() {
		return net.ErrClosed
	}
	return c.conn.SetDeadline(t)
}
func (c *pendingStreamConn) SetReadDeadline(t time.Time) error {
	if c == nil || !c.access.usable() {
		return net.ErrClosed
	}
	return c.conn.SetReadDeadline(t)
}
func (c *pendingStreamConn) SetWriteDeadline(t time.Time) error {
	if c == nil || !c.access.usable() {
		return net.ErrClosed
	}
	return c.conn.SetWriteDeadline(t)
}
func (c *pendingStreamConn) Paths() []rendr.PathInfo {
	if c == nil || !c.access.usable() {
		return nil
	}
	return c.conn.Paths()
}
func (c *pendingStreamConn) FlowID() [16]byte {
	if c == nil || !c.access.usable() {
		return [16]byte{}
	}
	return c.conn.FlowID()
}
func (c *pendingStreamConn) Status() rendr.Status {
	if c == nil || !c.access.usable() {
		return rendr.Status{}
	}
	return c.conn.Status()
}

type pendingPacketConn struct {
	session *Session
	conn    rendr.PacketConn
	access  *pendingSessionAccess
}

func (c *pendingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c == nil || !c.access.usable() {
		return 0, nil, net.ErrClosed
	}
	return c.conn.ReadFrom(p)
}
func (c *pendingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c == nil || !c.access.usable() {
		return 0, net.ErrClosed
	}
	return c.conn.WriteTo(p, addr)
}
func (c *pendingPacketConn) Close() error {
	if c == nil || !c.access.usable() {
		return net.ErrClosed
	}
	c.access.closed.Store(true)
	return c.session.Close()
}
func (c *pendingPacketConn) LocalAddr() net.Addr {
	if c == nil || !c.access.usable() {
		return nil
	}
	return c.conn.LocalAddr()
}
func (c *pendingPacketConn) SetDeadline(t time.Time) error {
	if c == nil || !c.access.usable() {
		return net.ErrClosed
	}
	return c.conn.SetDeadline(t)
}
func (c *pendingPacketConn) SetReadDeadline(t time.Time) error {
	if c == nil || !c.access.usable() {
		return net.ErrClosed
	}
	return c.conn.SetReadDeadline(t)
}
func (c *pendingPacketConn) SetWriteDeadline(t time.Time) error {
	if c == nil || !c.access.usable() {
		return net.ErrClosed
	}
	return c.conn.SetWriteDeadline(t)
}
func (c *pendingPacketConn) Paths() []rendr.PathInfo {
	if c == nil || !c.access.usable() {
		return nil
	}
	return c.conn.Paths()
}
func (c *pendingPacketConn) FlowID() [16]byte {
	if c == nil || !c.access.usable() {
		return [16]byte{}
	}
	return c.conn.FlowID()
}
func (c *pendingPacketConn) Status() rendr.Status {
	if c == nil || !c.access.usable() {
		return rendr.Status{}
	}
	return c.conn.Status()
}

// Keep the wrappers explicit about satisfying the complete public data-plane
// contracts. Embedded interfaces supply all methods except Close.
var (
	_ rendr.Conn       = (*pendingStreamConn)(nil)
	_ rendr.PacketConn = (*pendingPacketConn)(nil)
	_ net.Conn         = (*pendingStreamConn)(nil)
	_ net.PacketConn   = (*pendingPacketConn)(nil)
)
