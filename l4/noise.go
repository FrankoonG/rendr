package l4

import (
	"errors"
	"io"
	"time"
)

// localClass is the class of an error from an l4 socket — ForwardPacket's
// local conn, the passive's egress socket, the ingress socket (M6-D15,
// R1-2, R1-16; m6-design W1.3).
type localClass uint8

const (
	// classNoise: every syscall.Errno outside the fatal set (ICMP-derived
	// and send-path errors): counted and ignored; a run of read errors
	// backs off; the flow continues.
	classNoise localClass = iota + 1
	// classSize: EMSGSIZE or WSAEMSGSIZE on a read, or io.ErrShortBuffer:
	// a datagram above MaxPayload, dropped and counted TooLarge — an errno
	// only when the read filled its buffer; without, ForwardPacket's pump
	// counts it as noise (an ICMP fragmentation-needed or packet-too-big
	// of an earlier send). On a write the caller counts it as noise (a
	// datagram the local socket refused to send).
	classSize
	// classFatal: the fatal errno set (a closed, invalid or unconnected
	// socket and their WSA twins), net.ErrClosed, io.EOF, a timeout and
	// every error that is not a syscall.Errno: the forward ends.
	classFatal
)

// errClass classifies err (non-nil) by M6-D15's tables, in this order:
// io.ErrShortBuffer anywhere in its chain is the size class (R1-16: a
// rendr PacketConn adapter as the local conn of a chained deployment); a
// syscall.Errno in its chain decides by its value (errnoClass: the size
// errno, the fatal set, else noise — ETIMEDOUT included, a network event,
// not a deadline); everything else is fatal: net.ErrClosed, io.EOF, a
// deadline (os.ErrDeadlineExceeded or another error whose Timeout is
// true) and an embedder conn's own errors. On plan9, which has no
// syscall.Errno, every error but io.ErrShortBuffer is fatal (m4:R3-34).
func errClass(err error) localClass {
	if errors.Is(err, io.ErrShortBuffer) {
		return classSize
	}
	if c, ok := errnoClass(err); ok {
		return c
	}
	return classFatal
}

// The back-off of a reader through a run of noise-class read errors
// (M6-D15, M6-D25; L58): the first noiseRunFree errors of a run are read
// past at once, then each further one waits noiseBackoffMin, doubling up
// to noiseBackoffMax, so a socket that reports an error on every read (an
// ICMP storm, a broken embedder conn) costs at most ten reads a second
// instead of a spinning core. A read that returns a datagram ends the run.
const (
	noiseRunFree    = 64
	noiseBackoffMin = 5 * time.Millisecond
	noiseBackoffMax = 100 * time.Millisecond
)

// noiseRun counts one reader's consecutive noise-class read errors
// (shared by ForwardPacket's pump and the PortForward reader). The zero
// value is a reader with no error behind it; one goroutine uses it.
type noiseRun struct {
	n    int           // errors in the current run
	wait time.Duration // the last back-off of the run (0 before the first)
}

// fail records one more noise error and returns how long the reader waits
// before its next read: 0 for the first noiseRunFree errors of a run, then
// noiseBackoffMin doubling up to noiseBackoffMax.
func (r *noiseRun) fail() time.Duration {
	if r.n++; r.n <= noiseRunFree {
		return 0
	}
	r.wait = min(max(2*r.wait, noiseBackoffMin), noiseBackoffMax)
	return r.wait
}

// ok ends the run: a read returned a datagram (or a size-class error,
// which is one).
func (r *noiseRun) ok() { r.n, r.wait = 0, 0 }
