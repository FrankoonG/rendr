//go:build !plan9

package udpsocket

import (
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
)

// The errno helpers of the package's fake-call tests: the fake fd −1 probe
// answers with errnos, which plan9 lacks (a Conn there is always plain,
// errno_plan9.go), so the tests that drive ModeBatch build everywhere else.

// probeAnswer is a fake fd −1 probe that counts its runs per call.
type probeAnswer struct {
	sends, recvs     atomic.Int64 // probes of sendmmsg and of recvmmsg
	sendErr, recvErr atomic.Value // error (syscall.Errno)
}

func newProbe(sendErr, recvErr syscall.Errno) *probeAnswer {
	p := &probeAnswer{}
	p.set(sendErr, recvErr)
	return p
}

func (p *probeAnswer) set(sendErr, recvErr syscall.Errno) {
	p.sendErr.Store(sendErr)
	p.recvErr.Store(recvErr)
}

func (p *probeAnswer) fn(call int) error {
	if call == callRecv {
		p.recvs.Add(1)
		return p.recvErr.Load().(syscall.Errno)
	}
	p.sends.Add(1)
	return p.sendErr.Load().(syscall.Errno)
}

// forceBatch makes New put sockets in ModeBatch on this target, with a
// fake probe answering p.
func forceBatch(t *testing.T, p *probeAnswer) {
	t.Helper()
	seams(t)
	batchTarget = true
	probeFn = p.fn
}

// errno returns err's errno (0 if none).
func errno(err error) syscall.Errno {
	var e syscall.Errno
	if errors.As(err, &e) {
		return e
	}
	return 0
}
