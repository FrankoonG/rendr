package rendrtest

import (
	"net"
	"time"
)

// DatagramPipeConfig configures NewDatagramPipe; zero values take defaults.
type DatagramPipeConfig struct {
	Queue        int           // datagrams buffered per direction (256); more are dropped and counted, as a socket buffer drops
	Trunc        TruncMode     // a Read into a shorter buffer: TruncLinux (n = len(b), the rest discarded) or TruncWindows (ErrMsgSize, buffer filled)
	Loss, Dup    float64       // per datagram and direction, from Seed
	Delay        time.Duration // one-way, both directions
	Seed         uint64
	AddrA, AddrB net.Addr // what each end reports as LocalAddr (documentation addresses by default)
}

// TruncMode is how a DatagramConn's Read reports a datagram longer than
// its buffer.
type TruncMode uint8

// Truncation modes.
const (
	TruncLinux   TruncMode = iota // n = len(b), nil error, the rest discarded (a Linux UDP socket)
	TruncWindows                  // n = len(b), ErrMsgSize, the rest discarded (a Windows UDP socket)
)

// ErrMsgSize is the running OS's "message too long" errno (EMSGSIZE;
// WSAEMSGSIZE on Windows), as TruncWindows returns it.
var ErrMsgSize error = errMsgSize

// DatagramConnCounts are a DatagramConn's counters (DatagramCounts, the
// older type, counts the carriers of a DatagramLink or DatagramHub).
type DatagramConnCounts struct {
	In        uint64 // datagrams this end's Reads returned
	Out       uint64 // datagrams this end's Writes sent
	Dropped   uint64 // datagrams toward this end dropped: a full queue, Loss
	Truncated uint64 // Reads that returned a datagram longer than their buffer
	Injected  uint64 // Reads and Writes that returned an injected error
}

// NewDatagramPipe returns the two ends of an in-memory connected datagram
// conn: each Write is one datagram delivered whole to the other end's next
// Read; deadlines as net.Conn; Close makes both ends' later calls return
// net.ErrClosed.
//
// Skeleton (M6 wave 0): not implemented yet; it panics.
func NewDatagramPipe(cfg DatagramPipeConfig) (a, b *DatagramConn) {
	panic("rendrtest: NewDatagramPipe not implemented")
}

// DatagramConn is one end of a DatagramPipe, or a UDPSocketHub client: a
// connected datagram net.Conn.
type DatagramConn struct{}

var _ net.Conn = (*DatagramConn)(nil)

// Read returns the next datagram (TruncMode decides a shorter buffer).
func (c *DatagramConn) Read(b []byte) (int, error) { panic("rendrtest: DatagramConn not implemented") }

// Write sends b as one datagram.
func (c *DatagramConn) Write(b []byte) (int, error) { panic("rendrtest: DatagramConn not implemented") }

// Close closes the conn; later calls of both ends return net.ErrClosed.
func (c *DatagramConn) Close() error { panic("rendrtest: DatagramConn not implemented") }

// LocalAddr returns this end's address.
func (c *DatagramConn) LocalAddr() net.Addr { panic("rendrtest: DatagramConn not implemented") }

// RemoteAddr returns the other end's address.
func (c *DatagramConn) RemoteAddr() net.Addr { panic("rendrtest: DatagramConn not implemented") }

// SetDeadline sets both deadlines, as net.Conn.
func (c *DatagramConn) SetDeadline(t time.Time) error {
	panic("rendrtest: DatagramConn not implemented")
}

// SetReadDeadline sets the read deadline, as net.Conn.
func (c *DatagramConn) SetReadDeadline(t time.Time) error {
	panic("rendrtest: DatagramConn not implemented")
}

// SetWriteDeadline sets the write deadline, as net.Conn.
func (c *DatagramConn) SetWriteDeadline(t time.Time) error {
	panic("rendrtest: DatagramConn not implemented")
}

// Inject makes the next Read (every later one if persistent) return err.
func (c *DatagramConn) Inject(err error, persistent bool) {
	panic("rendrtest: DatagramConn not implemented")
}

// InjectWrite makes the next n Writes return err and send nothing.
func (c *DatagramConn) InjectWrite(err error, n int) {
	panic("rendrtest: DatagramConn not implemented")
}

// Counts returns the conn's counters.
func (c *DatagramConn) Counts() DatagramConnCounts { panic("rendrtest: DatagramConn not implemented") }
