package udpsocket

// SetSendCount makes every sendmmsg of the process report lie(cnt, want)
// instead of cnt, the count the kernel returned for a call given want
// messages, after the kernel sent what it sent: a socket that misreports
// its count (L42). It returns the function that restores the true count.
// It is a test seam, the one through which the tests of the packages above
// this one produce an invalid sendmmsg count on a real socket
// (internal/carrier's TestDgramUnsentNotReturnedOnSendmmsgCount_L42, Linux
// amd64/arm64; the call does not exist elsewhere), and it is not
// synchronised: production code never calls it, and a test calls it before
// the sockets it concerns start writing, restores the count after they
// stopped, and never runs it beside tests that write through sockets in
// parallel (t.Parallel).
func SetSendCount(lie func(cnt, want int) int) (restore func()) {
	prev := sendmmsgFn
	sendmmsgFn = func(fd uintptr, b *Batch, k, n int) (int, error) {
		cnt, err := prev(fd, b, k, n)
		if err != nil {
			return cnt, err
		}
		return lie(cnt, n), nil
	}
	return func() { sendmmsgFn = prev }
}
