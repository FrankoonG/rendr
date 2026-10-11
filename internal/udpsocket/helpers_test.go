package udpsocket

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Helpers of the package's tests. The fake-call tests drive ModeBatch on
// every target (the Windows host included) through the package's seams:
// batchTarget forces the batch path, probeFn answers the fd −1 probe, and
// sendmmsgFn/recvmmsgFn replace the system calls, reading and filling the
// call's messages through Batch.ms. Conn.rawWrite/rawRead are replaced by
// a fake netpoller where a test needs EAGAIN (Windows' RawConn.Write
// cannot wait for writability). The real-socket rows of the Linux file
// (mmsg_linux_test.go) use the real calls.

// seams saves the package's seams and restores them, and re-arms the
// process probe, when the test ends: a test that fakes the probe never
// leaves its answer to the next test.
func seams(t *testing.T) {
	t.Helper()
	send, recv, pr, target, ifs := sendmmsgFn, recvmmsgFn, probeFn, batchTarget, interfacesFn
	resetProbe()
	t.Cleanup(func() {
		sendmmsgFn, recvmmsgFn, probeFn, batchTarget, interfacesFn = send, recv, pr, target, ifs
		resetProbe()
	})
}

// resetProbe re-arms the process probe and empties the zone table.
func resetProbe() {
	probeOnce = sync.Once{}
	probeOK = false
	zones.Store(nil)
	zoneFetch.Store(0)
}

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

// listen4 opens a rendr-like IPv4 loopback socket.
func listen4(t *testing.T) *net.UDPConn {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	if err := u.SetReadBuffer(4 << 20); err != nil {
		t.Logf("SetReadBuffer: %v", err)
	}
	return u
}

func addrOf(u *net.UDPConn) netip.AddrPort {
	return u.LocalAddr().(*net.UDPAddr).AddrPort()
}

func newConn(t *testing.T, u *net.UDPConn, maxBatch int, ctr *Counters) *Conn {
	t.Helper()
	c, err := New(u, maxBatch, ctr)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// payload is datagram i of a test: its decimal index.
func payload(i int) []byte { return []byte(strconv.Itoa(i)) }

// msgs returns n messages to dst carrying payloads first … first+n−1.
func msgs(dst netip.AddrPort, first, n int) []Msg {
	ms := make([]Msg, n)
	for i := range ms {
		ms[i] = Msg{Buf: payload(first + i), Addr: dst}
	}
	return ms
}

// slots returns n receive slots of size bytes.
func slots(n, size int) []Msg {
	ms := make([]Msg, n)
	for i := range ms {
		ms[i].Buf = make([]byte, size)
	}
	return ms
}

// collect reads datagrams from u until want arrived or the read times out
// (a missing datagram fails the caller's assertion, never hangs).
func collect(t *testing.T, u *net.UDPConn, want int) []string {
	t.Helper()
	var got []string
	buf := make([]byte, 2048)
	for len(got) < want {
		u.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := u.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Errorf("after %d of %d datagrams: %v", len(got), want, err)
			break
		}
		got = append(got, string(buf[:n]))
	}
	u.SetReadDeadline(time.Time{})
	return got
}

// expectNone fails if a datagram is queued on u within d.
func expectNone(t *testing.T, u *net.UDPConn, d time.Duration) {
	t.Helper()
	buf := make([]byte, 2048)
	u.SetReadDeadline(time.Now().Add(d))
	defer u.SetReadDeadline(time.Time{})
	if n, _, err := u.ReadFromUDPAddrPort(buf); err == nil {
		t.Errorf("unexpected datagram %q", buf[:n])
	}
}

// fakeSend is a fake sendmmsg: script decides each call's outcome; the
// datagrams a call reports sent are recorded in order (sent) and, if tx
// is set, really sent from tx to their destination.
type fakeSend struct {
	mu     sync.Mutex
	calls  []int // n asked of each call
	sent   []string
	tx     *net.UDPConn
	script func(call int, n int) (int, error) // nil: send all
}

func (f *fakeSend) fn(fd uintptr, b *Batch, k, n int) (int, error) {
	f.mu.Lock()
	call := len(f.calls)
	f.calls = append(f.calls, n)
	cnt, err := n, error(nil)
	if f.script != nil {
		cnt, err = f.script(call, n)
	}
	for i := 0; i < cnt && i < n; i++ {
		m := &b.ms[b.base+k+i]
		f.sent = append(f.sent, string(m.Buf))
		if f.tx != nil {
			f.tx.WriteToUDPAddrPort(m.Buf, m.Addr)
		}
	}
	f.mu.Unlock()
	return cnt, err
}

func (f *fakeSend) snapshot() (calls []int, sent []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.calls...), append([]string(nil), f.sent...)
}

// fakePoller replaces a Conn's RawConn calls by a netpoller that re-runs
// the callback at once after it returned false, counting the waits.
type fakePoller struct{ waits atomic.Int64 }

func (p *fakePoller) run(f func(uintptr) bool) error {
	for !f(0) {
		p.waits.Add(1)
	}
	return nil
}

// seq returns the payloads first … first+n−1.
func seq(first, n int) []string {
	s := make([]string, n)
	for i := range s {
		s[i] = string(payload(first + i))
	}
	return s
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func eqInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// errno returns err's errno (0 if none).
func errno(err error) syscall.Errno {
	var e syscall.Errno
	if errors.As(err, &e) {
		return e
	}
	return 0
}

func counters(c *Counters) string {
	sc, s, rc, r, f := c.Load()
	return fmt.Sprintf("SendCalls %d SentDatagrams %d RecvCalls %d RecvDatagrams %d BatchFallbacks %d", sc, s, rc, r, f)
}
