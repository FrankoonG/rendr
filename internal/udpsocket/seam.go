package udpsocket

// SetSendCount makes every sendmmsg of the process report lie(cnt, want)
// instead of cnt, the count the kernel returned for a call given want
// messages, after the kernel sent what it sent: a socket that misreports
// its count (L42). It returns the function that restores the true count.
// It is the seam through which the tests of the packages above this one
// produce an invalid sendmmsg count on a real socket (internal/carrier's
// TestDgramUnsentNotReturnedOnSendmmsgCount_L42, Linux amd64/arm64; the
// call does not exist elsewhere). Production code never calls it; a test
// calls it before the sockets it concerns start writing and restores it
// after they stopped.
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
