package engine

import (
	"errors"
	"io"
	"net"
	"time"
)

// Conn is an engineConn: it implements net.Conn on top of an Engine,
// and is what the public rendr.Conn type wraps.
type Conn struct {
	E *Engine

	// Local / remote addresses for the application's view. They are
	// not used by the engine itself.
	LAddr net.Addr
	RAddr net.Addr
}

// Read pulls bytes from the engine's recv buffer.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.E.Recv(p)
	if err != nil {
		// io.EOF and ErrMigrationBudgetExceeded propagate as-is.
		if errors.Is(err, io.EOF) {
			return n, io.EOF
		}
		return n, err
	}
	return n, nil
}

// Write pushes bytes through the engine.
func (c *Conn) Write(p []byte) (int, error) {
	return c.E.SendData(p)
}

// Close tears down the engine.
func (c *Conn) Close() error { return c.E.Close() }

// LocalAddr / RemoteAddr report the application-facing addresses.
func (c *Conn) LocalAddr() net.Addr  { return c.LAddr }
func (c *Conn) RemoteAddr() net.Addr { return c.RAddr }

// SetDeadline / SetReadDeadline / SetWriteDeadline are required by
// net.Conn. M1 implements them as no-ops; future commits will plumb
// them through the recv condvar. Applications that rely on deadlines
// during M1 should not depend on cancellation precision.
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }
