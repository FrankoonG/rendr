package quic

import (
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	qgo "github.com/quic-go/quic-go"
)

// streamConn is one QUIC stream as the net.Conn of a rendr stream carrier.
// The read that reaches the peer's FIN may return bytes and io.EOF
// together; rendr's reader consumes the bytes first.
type streamConn struct {
	qc      *qgo.Conn
	st      *qgo.Stream
	local   net.Addr
	remote  net.Addr                       // captured: quic-go's changes after a NAT rebinding
	release func(qgo.ApplicationErrorCode) // closes the connection once

	wmu    sync.Mutex // quic-go forbids Stream.Close concurrent with Write
	closed atomic.Bool
	once   sync.Once
}

func newStreamConn(qc *qgo.Conn, st *qgo.Stream, release func(qgo.ApplicationErrorCode)) *streamConn {
	return &streamConn{qc: qc, st: st, local: qc.LocalAddr(), remote: copyAddr(qc.RemoteAddr()), release: release}
}

// copyAddr returns a copy of a *net.UDPAddr that nothing else changes.
func copyAddr(a net.Addr) net.Addr {
	if u, ok := a.(*net.UDPAddr); ok {
		return &net.UDPAddr{IP: slices.Clone(u.IP), Port: u.Port, Zone: u.Zone}
	}
	return a
}

func (c *streamConn) Read(p []byte) (int, error) {
	n, err := c.st.Read(p)
	return n, c.err(err)
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.st.Write(p)
	return n, c.err(err)
}

func (c *streamConn) err(err error) error {
	if err != nil && c.closed.Load() {
		return net.ErrClosed
	}
	return connErr(err)
}

// Close returns at once with Read and Write unblocked (deadline first,
// L52), sends FIN after what was written, and closes the connection after
// a linger of clamp(2·srtt + 50 ms, 50 ms, 500 ms) or at the peer's own
// close: a CONNECTION_CLOSE discards the receiver's unread data, so the
// linger lets the peer read rendr's last frames (L05; what was delivered
// is decided by rendr's own CLOSE exchange, never by QUIC).
func (c *streamConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		_ = c.st.SetDeadline(time.Now())
		c.wmu.Lock() // the woken Write has returned; no Write starts any more
		_ = c.st.Close()
		c.wmu.Unlock()
		go c.linger()
	})
	return nil
}

func (c *streamConn) linger() {
	t := time.NewTimer(min(max(2*c.qc.ConnectionStats().SmoothedRTT+50*time.Millisecond, 50*time.Millisecond), 500*time.Millisecond))
	select {
	case <-t.C:
	case <-c.qc.Context().Done():
	}
	t.Stop()
	c.release(codeClosed)
}

func (c *streamConn) LocalAddr() net.Addr                { return c.local }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }
