package l4

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
	// a datagram above MaxPayload, dropped and counted TooLarge.
	classSize
	// classFatal: the fatal errno set (a closed, invalid or unconnected
	// socket and their WSA twins), net.ErrClosed, io.EOF, a timeout and
	// every error that is not a syscall.Errno: the forward ends.
	classFatal
)

// errClass classifies err (non-nil) by M6-D15's tables; the per-OS fatal
// set lives beside M4's errno tables (errno_*.go; plan9: every error but
// the size class is fatal).
//
// Skeleton (M6 wave 0): every error is fatal.
func errClass(err error) localClass { return classFatal }
