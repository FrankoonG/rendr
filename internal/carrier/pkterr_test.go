package carrier

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// pktErrRow is one ClassifyPacketErr case: the error, the side and the
// class expected on it.
type pktErrRow struct {
	name  string
	err   error
	write bool
	want  PacketErrClass
}

// pktTemporary is an embedder error that reports itself transient.
type pktTemporary struct{}

func (pktTemporary) Error() string   { return "transient" }
func (pktTemporary) Temporary() bool { return true }
func (pktTemporary) Timeout() bool   { return false }

// pktDeadConn is a dead connection's error that claims Timeout() without
// being a deadline (quic-go's idle timeout before the quic module wraps it).
type pktDeadConn struct{}

func (pktDeadConn) Error() string   { return "no recent network activity" }
func (pktDeadConn) Temporary() bool { return false }
func (pktDeadConn) Timeout() bool   { return true }

// pktOpErr wraps err as net.UDPConn returns it from a read or a write.
func pktOpErr(op string, err error) error {
	call := "recvmsg"
	if op == "write" {
		call = "sendmsg"
	}
	return &net.OpError{Op: op, Net: "udp", Err: os.NewSyscallError(call, err)}
}

// TestClassifyPacketErr_L58: the one error table of embedder datagram conns
// (M2 design §A6.4, Revision 1, R1-28; EPERM on a write since integration
// 1). A deadline is the caller's only by os.ErrDeadlineExceeded — a dead
// conn's Timeout() is death — and comes before Temporary(); ErrNoise and
// Temporary() errors are noise on both sides; a too-large error refuses a
// write; anything else is death. The errno rows (POSIX and the Windows
// numbers, on every OS) come from pktErrnoRows.
func TestClassifyPacketErr_L58(t *testing.T) {
	deadline := &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
	rows := []pktErrRow{
		{"read deadline", deadline, false, PacketErrDeadline},
		{"write deadline", &net.OpError{Op: "write", Net: "udp", Err: os.ErrDeadlineExceeded}, true, PacketErrDeadline},
		{"bare deadline", os.ErrDeadlineExceeded, false, PacketErrDeadline},
		{"wrapped deadline", fmt.Errorf("conn: %w", deadline), true, PacketErrDeadline},
		{"ErrNoise on a read", ErrNoise, false, PacketErrNoise},
		{"ErrNoise on a write", fmt.Errorf("wrapped: %w", ErrNoise), true, PacketErrNoise},
		{"Temporary() on a read", pktTemporary{}, false, PacketErrNoise},
		{"Temporary() on a write", &net.OpError{Op: "write", Err: pktTemporary{}}, true, PacketErrNoise},
		{"Timeout() of a dead conn on a read", pktDeadConn{}, false, PacketErrDeath},
		{"Timeout() of a dead conn on a write", fmt.Errorf("x: %w", pktDeadConn{}), true, PacketErrDeath},
		{"too large on a write", &wire.DatagramTooLargeError{Max: 1152}, true, PacketErrSize},
		{"ErrDatagramTooLarge on a write", wire.ErrDatagramTooLarge, true, PacketErrSize},
		{"too large on a read", &wire.DatagramTooLargeError{Max: 1152}, false, PacketErrDeath},
		{"closed", net.ErrClosed, false, PacketErrDeath},
		{"closed write", &net.OpError{Op: "write", Err: net.ErrClosed}, true, PacketErrDeath},
		{"EOF", io.EOF, false, PacketErrDeath},
		{"other", errors.New("broken"), true, PacketErrDeath},
	}
	rows = append(rows, pktErrnoRows()...)
	for _, r := range rows {
		if got := ClassifyPacketErr(r.err, r.write); got != r.want {
			t.Errorf("%s (write %v): class %d, want %d (%v)", r.name, r.write, got, r.want, r.err)
		}
	}
}
