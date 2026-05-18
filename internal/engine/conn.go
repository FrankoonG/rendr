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

// SetDeadline sets both the read and write deadlines. The write
// deadline is currently a no-op; the read deadline is honored by
// Recv/RecvPacket and returns ErrReadDeadlineExceeded when elapsed.
func (c *Conn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

// SetReadDeadline routes through to the engine's deadline tracker.
// The zero time clears the deadline. Returned errors come from the
// engine; the call itself currently never fails.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.E.SetReadDeadline(t) }

// SetWriteDeadline is a no-op: rendr Writes never block on receive
// data, only on path availability inside the migration budget, which
// is a separate timeout. Honoring an application-level write deadline
// would require interleaving with the dispatch loop and is deferred
// until a concrete use case shows up.
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }
