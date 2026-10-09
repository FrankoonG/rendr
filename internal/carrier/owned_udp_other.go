//go:build !unix && !windows

package carrier

// udpMsgTrunc: no truncation flag is read on this platform; the max+1
// buffer alone detects a datagram longer than the receive limit.
const udpMsgTrunc = 0

// udpErrnoClass: no errno table on this platform (compile-only, M2 design
// §A6.1); deadlines and Temporary() errors are still classified.
func udpErrnoClass(error) udpClass { return udpOther }
