//go:build !plan9

package udpsocket

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// TestBatchLoopPlain (§A10.1 WP1; every target, the Windows host
// included): the per-datagram loop — one WriteToUDPAddrPort per datagram,
// stopping at the first error with ms[:n] sent; one ReadMsgUDPAddrPort per
// ReadBatch — and its counters (one call per datagram, R1-2).
func TestBatchLoopPlain(t *testing.T) {
	seams(t)
	rx, txu := listen4(t), listen4(t)
	var ctr Counters
	c := newConn(t, txu, 1, &ctr)
	if c.Mode() != ModePlain || c.MaxBatch() != 1 {
		t.Fatalf("MaxBatch 1: mode %v, MaxBatch %d; want plain, 1", c.Mode(), c.MaxBatch())
	}
	if !accelerated {
		if c32 := newConn(t, listen4(t), 32, nil); c32.Mode() != ModePlain {
			t.Fatalf("MaxBatch 32 on a plain target: mode %v", c32.Mode())
		}
	}
	dst := addrOf(rx)
	ms := msgs(dst, 0, 5)
	ms[2].Addr = netip.MustParseAddrPort("[::1]:9") // not sendable on an IPv4 socket
	n, err := c.WriteBatch(NewBatch(8), ms)
	if n != 2 || err == nil {
		t.Fatalf("WriteBatch with ms[2] unsendable: n %d, err %v; want 2 and ms[2]'s error", n, err)
	}
	if sc, s, _, _, _ := ctr.Load(); sc != 2 || s != 2 {
		t.Fatalf("after the stopped loop: %s; want 2 calls, 2 datagrams", counters(&ctr))
	}
	if n, err := c.WriteBatch(nil, ms[3:]); n != 2 || err != nil {
		t.Fatalf("WriteBatch of the rest: %d, %v", n, err)
	}
	if got, want := collect(t, rx, 4), []string{"0", "1", "3", "4"}; !eqStrings(got, want) {
		t.Fatalf("received %q; want %q", got, want)
	}
	if sc, s, _, _, _ := ctr.Load(); sc != 4 || s != 4 {
		t.Fatalf("after 4 datagrams: %s", counters(&ctr))
	}

	var rctr Counters
	r := newConn(t, rx, 1, &rctr)
	if _, err := r.ReadBatch(nil, nil); err == nil {
		t.Fatal("ReadBatch without a slot: no error")
	}
	if _, err := txu.WriteToUDPAddrPort([]byte("hello"), dst); err != nil {
		t.Fatal(err)
	}
	rs := slots(4, 64)
	n, err = r.ReadBatch(NewBatch(4), rs)
	if n != 1 || err != nil || string(rs[0].Buf[:rs[0].N]) != "hello" || rs[0].Addr != addrOf(txu) || rs[0].Trunc {
		t.Fatalf("plain read: n %d err %v %+v; want one datagram \"hello\" from %v", n, err, rs[0], addrOf(txu))
	}
	if _, _, rc, rd, _ := rctr.Load(); rc != 1 || rd != 1 {
		t.Fatalf("after one read: %s", counters(&rctr))
	}
	// M2's truncation rule: a datagram longer than the slot.
	if _, err := txu.WriteToUDPAddrPort(make([]byte, 100), dst); err != nil {
		t.Fatal(err)
	}
	rs[0].Buf = make([]byte, 50)
	n, err = r.ReadBatch(nil, rs[:1])
	if runtime.GOOS == "windows" {
		if n != 0 || errno(err) != 10040 { // WSAEMSGSIZE: the caller's truncation drop
			t.Fatalf("Windows truncated read: n %d err %v; want WSAEMSGSIZE", n, err)
		}
	} else if n != 1 || err != nil || !rs[0].Trunc || rs[0].N != 50 {
		t.Fatalf("truncated read: n %d err %v %+v; want Trunc with N 50", n, err, rs[0])
	}
}

// TestBatchProbeTable_L56 (M5-D15): the process probe runs once; only
// EBADF from both fd −1 calls puts sockets in ModeBatch; ENOSYS or EPERM
// (absent, or a sandbox policy) — from either call — keeps every socket
// plain from the start, and MaxBatch 1 is plain whatever the probe says.
func TestBatchProbeTable_L56(t *testing.T) {
	rows := []struct {
		send, recv syscall.Errno
		want       Mode
	}{
		{syscall.EBADF, syscall.EBADF, ModeBatch},
		{syscall.ENOSYS, syscall.ENOSYS, ModePlain},
		{syscall.EPERM, syscall.EPERM, ModePlain},
		{syscall.EPERM, syscall.EBADF, ModePlain},
		{syscall.EBADF, syscall.EPERM, ModePlain},
		{syscall.EBADF, syscall.ENOSYS, ModePlain},
		{syscall.ENOSYS, syscall.EBADF, ModePlain},
	}
	for _, row := range rows {
		t.Run(row.send.Error()+"/"+row.recv.Error(), func(t *testing.T) {
			p := newProbe(row.send, row.recv)
			forceBatch(t, p)
			for i := range 3 {
				if c := newConn(t, listen4(t), 32, nil); c.Mode() != row.want {
					t.Fatalf("socket %d: mode %v; want %v", i, c.Mode(), row.want)
				}
			}
			if c := newConn(t, listen4(t), 1, nil); c.Mode() != ModePlain {
				t.Fatalf("MaxBatch 1: mode %v", c.Mode())
			}
			if s, r := p.sends.Load(), p.recvs.Load(); s != 1 || r != 1 {
				t.Fatalf("the process probe ran %d/%d times for 4 sockets; want once", s, r)
			}
		})
	}
}

// TestBatchKeepOnFilterDrop_L56 (R1-3): sendmmsg reports EPERM at message
// 3 of 8 and the re-probe finds the call permitted (EBADF): a netfilter
// drop of one datagram. WriteBatch returns n = 3 with EPERM for message 3
// (the caller's udpFiltered: Dropped, continue at 4), the socket stays in
// ModeBatch with no fallback, and the caller's next call sends 4 … 7 as
// one batch.
func TestBatchKeepOnFilterDrop_L56(t *testing.T) {
	p := newProbe(syscall.EBADF, syscall.EBADF)
	forceBatch(t, p)
	var ctr Counters
	c := newConn(t, listen4(t), 32, &ctr)
	fs := &fakeSend{script: func(call, n int) (int, error) {
		switch call {
		case 0:
			return 3, nil // 0 … 2 left; the kernel reports the count, the error comes next
		case 1:
			return 0, syscall.EPERM
		}
		return n, nil
	}}
	sendmmsgFn = fs.fn
	ms := msgs(addrOf(listen4(t)), 0, 8)
	b := NewBatch(32)
	n, err := c.WriteBatch(b, ms)
	if n != 3 || errno(err) != syscall.EPERM {
		t.Fatalf("WriteBatch: n %d, err %v; want 3 and EPERM for message 3", n, err)
	}
	var oe *net.OpError
	if !errors.As(err, &oe) || oe.Op != "write" {
		t.Fatalf("error %#v is not wrapped as a write's *net.OpError", err)
	}
	if c.Mode() != ModeBatch || p.sends.Load() != 2 || p.recvs.Load() != 1 {
		t.Fatalf("after a filter drop: mode %v, probes %d/%d; want batch, 2/1 (the process probe and one re-probe of sendmmsg only)", c.Mode(), p.sends.Load(), p.recvs.Load())
	}
	if n, err := c.WriteBatch(b, ms[n+1:]); n != 4 || err != nil {
		t.Fatalf("WriteBatch of 4 … 7: %d, %v", n, err)
	}
	calls, sent := fs.snapshot()
	if !eqInts(calls, []int{8, 5, 4}) || !eqStrings(sent, []string{"0", "1", "2", "4", "5", "6", "7"}) {
		t.Fatalf("calls %v sent %q; want calls [8 5 4] and 0 1 2 4 5 6 7 (4 … 7 in one call)", calls, sent)
	}
	if sc, s, _, _, f := ctr.Load(); sc != 2 || s != 7 || f != 0 {
		t.Fatalf("%s; want 2 calls, 7 datagrams, no fallback", counters(&ctr))
	}
}

// TestBatchFallbackOnDenied_L56 (R1-3): the same EPERM, but the re-probe
// is refused too (a sandbox policy denies sendmmsg): exactly one
// transition to ModePlain, and messages 3 … 7 are redone plainly within
// the same WriteBatch, which returns 8. Later writes never use sendmmsg.
func TestBatchFallbackOnDenied_L56(t *testing.T) {
	p := newProbe(syscall.EBADF, syscall.EBADF)
	forceBatch(t, p)
	var ctr Counters
	rx := listen4(t)
	c := newConn(t, listen4(t), 32, &ctr)
	fs := &fakeSend{script: func(call, n int) (int, error) {
		if call == 0 {
			return 3, nil
		}
		return 0, syscall.EPERM
	}}
	sendmmsgFn = fs.fn
	p.set(syscall.EPERM, syscall.EPERM)
	ms := msgs(addrOf(rx), 0, 8)
	if n, err := c.WriteBatch(NewBatch(32), ms); n != 8 || err != nil {
		t.Fatalf("WriteBatch: %d, %v; want 8 (3 … 7 redone plainly)", n, err)
	}
	if got := collect(t, rx, 5); !eqStrings(got, seq(3, 5)) {
		t.Fatalf("plain redo delivered %q; want 3 … 7", got)
	}
	if c.Mode() != ModePlain {
		t.Fatalf("mode %v after a denied EPERM", c.Mode())
	}
	if n, err := c.WriteBatch(NewBatch(32), ms); n != 8 || err != nil {
		t.Fatalf("WriteBatch after the fallback: %d, %v", n, err)
	}
	collect(t, rx, 8)
	calls, _ := fs.snapshot()
	if len(calls) != 2 {
		t.Fatalf("sendmmsg calls %v; want 2, none after the fallback", calls)
	}
	// 1 batch call (3 datagrams), 5 + 8 plain calls.
	if sc, s, _, _, f := ctr.Load(); sc != 14 || s != 16 || f != 1 {
		t.Fatalf("%s; want 14 calls, 16 datagrams, 1 fallback", counters(&ctr))
	}
}

// TestBatchReadFallback_L56 (R1-3, M5-D15 on the receive side): an EPERM
// from recvmmsg that the re-probe does not confirm is returned as the
// read's error (M2: death on a read) with the mode kept; ENOSYS moves the
// socket to ModePlain once and the same ReadBatch reads the datagram
// plainly.
func TestBatchReadFallback_L56(t *testing.T) {
	p := newProbe(syscall.EBADF, syscall.EBADF)
	forceBatch(t, p)
	var ctr Counters
	rx, txu := listen4(t), listen4(t)
	c := newConn(t, rx, 32, &ctr)
	var rerr syscall.Errno = syscall.EPERM
	recvmmsgFn = func(fd uintptr, b *Batch, n int) (int, error) { return 0, rerr }
	rs := slots(8, 64)
	b := NewBatch(8)
	n, err := c.ReadBatch(b, rs)
	var oe *net.OpError
	if n != 0 || errno(err) != syscall.EPERM || !errors.As(err, &oe) || oe.Op != "read" {
		t.Fatalf("permitted EPERM: n %d, err %v; want the read's EPERM", n, err)
	}
	if c.Mode() != ModeBatch || p.sends.Load() != 1 || p.recvs.Load() != 2 {
		t.Fatalf("mode %v, probes %d/%d; want batch, 1/2 (one re-probe of recvmmsg only)", c.Mode(), p.sends.Load(), p.recvs.Load())
	}
	rerr = syscall.ENOSYS
	if _, err := txu.WriteToUDPAddrPort([]byte("x1"), addrOf(rx)); err != nil {
		t.Fatal(err)
	}
	n, err = c.ReadBatch(b, rs)
	if n != 1 || err != nil || string(rs[0].Buf[:rs[0].N]) != "x1" || rs[0].Addr != addrOf(txu) {
		t.Fatalf("ENOSYS: n %d, err %v, %+v; want x1 read plainly", n, err, rs[0])
	}
	if c.Mode() != ModePlain {
		t.Fatalf("mode %v after ENOSYS", c.Mode())
	}
	if _, _, rc, rd, f := ctr.Load(); rc != 1 || rd != 1 || f != 1 {
		t.Fatalf("%s; want 1 call, 1 datagram, 1 fallback", counters(&ctr))
	}
}

// TestBatchFallbackOnce64_L56 (M5-D15, R1-3): 64 writers share one socket
// (a listening socket's flows), each with its own Batch, and every one's
// sendmmsg is refused. The row's stimulus is R1-3's denied path: EPERM
// with a re-probe that answers EPERM too (a sandbox policy), so each
// writer runs the concurrent re-probe and none may take a denial for a
// filter drop; a second subtest refuses with ENOSYS. Exactly one
// transition is counted, every writer redoes its messages plainly, every
// datagram arrives exactly once, and the mode never moves back — not even
// when the calls would succeed again.
func TestBatchFallbackOnce64_L56(t *testing.T) {
	for _, refusal := range []syscall.Errno{syscall.EPERM, syscall.ENOSYS} {
		t.Run(refusal.Error(), func(t *testing.T) { fallbackOnce64(t, refusal) })
	}
}

func fallbackOnce64(t *testing.T, refusal syscall.Errno) {
	p := newProbe(syscall.EBADF, syscall.EBADF)
	forceBatch(t, p)
	var ctr Counters
	rx := listen4(t)
	c := newConn(t, listen4(t), 32, &ctr)
	fs := &fakeSend{script: func(call, n int) (int, error) { return 0, refusal }}
	sendmmsgFn = fs.fn
	p.set(syscall.EPERM, syscall.EPERM) // the policy denies the calls: the re-probe confirms an EPERM
	const writers, each = 64, 8
	dst := addrOf(rx)
	// Gate: every writer passed the mode check and reached the RawConn
	// call before any sendmmsg runs, so all 64 see the same refusal and
	// race on the transition (the fd's write lock serialises the calls).
	var arrived sync.WaitGroup
	arrived.Add(writers)
	raw := c.rawWrite
	c.rawWrite = func(f func(uintptr) bool) error {
		arrived.Done()
		arrived.Wait()
		return raw(f)
	}
	var start, done sync.WaitGroup
	start.Add(1)
	errs := make(chan error, writers)
	for w := range writers {
		done.Add(1)
		go func() {
			defer done.Done()
			ms := msgs(dst, w*each, each)
			b := NewBatch(32)
			start.Wait()
			if n, err := c.WriteBatch(b, ms); n != each || err != nil {
				errs <- err
			}
		}()
	}
	start.Done()
	got := collect(t, rx, writers*each)
	done.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("writer: %v", err)
	}
	sort.Strings(got)
	want := seq(0, writers*each)
	sort.Strings(want)
	if !eqStrings(got, want) {
		t.Fatalf("received %d datagrams, not each of the %d exactly once", len(got), writers*each)
	}
	expectNone(t, rx, 50*time.Millisecond)
	if _, _, _, _, f := ctr.Load(); f != 1 || c.Mode() != ModePlain {
		t.Fatalf("%s, mode %v; want exactly one fallback to plain", counters(&ctr), c.Mode())
	}
	calls, _ := fs.snapshot()
	if len(calls) != writers {
		t.Fatalf("%d sendmmsg calls; want one per writer (each saw ModeBatch)", len(calls))
	}
	if refusal == syscall.EPERM {
		// Every writer's EPERM was re-probed (a denial is never cached).
		if n := p.sends.Load(); n != 1+writers {
			t.Fatalf("%d sendmmsg probes; want the process probe and one re-probe per writer", n)
		}
	}
	c.rawWrite = raw
	before := len(calls)
	fs.mu.Lock()
	fs.script = nil // the calls would succeed now
	fs.mu.Unlock()
	p.set(syscall.EBADF, syscall.EBADF)
	if n, err := c.WriteBatch(NewBatch(32), msgs(dst, 0, 4)); n != 4 || err != nil {
		t.Fatalf("WriteBatch after the fallback: %d, %v", n, err)
	}
	collect(t, rx, 4)
	if calls, _ := fs.snapshot(); len(calls) != before || c.Mode() != ModePlain {
		t.Fatalf("after the fallback: sendmmsg ran %d more times, mode %v; a mode never moves back", len(calls)-before, c.Mode())
	}
	if _, _, _, _, f := ctr.Load(); f != 1 {
		t.Fatalf("fallbacks %d", f)
	}
}

// TestBatchFilterProbeCached_L56 (R1-3 rule 3, synctest): a permitted
// re-probe is trusted for 1 s, so a storm of filter drops costs one probe
// per second per socket; a policy installed mid-run is seen at the first
// EPERM after the cache expired, and then the socket falls back.
func TestBatchFilterProbeCached_L56(t *testing.T) {
	p := newProbe(syscall.EBADF, syscall.EBADF)
	forceBatch(t, p)
	var ctr Counters
	c := newConn(t, listen4(t), 32, &ctr)
	sendmmsgFn = func(fd uintptr, b *Batch, k, n int) (int, error) { return 0, syscall.EPERM }
	ms := msgs(addrOf(listen4(t)), 0, 4)
	b := NewBatch(32)
	drop := func(when string) {
		t.Helper()
		if n, err := c.WriteBatch(b, ms); n != 0 || errno(err) != syscall.EPERM || c.Mode() != ModeBatch {
			t.Fatalf("%s: n %d, err %v, mode %v; want a filter drop of message 0", when, n, err, c.Mode())
		}
	}
	synctest.Test(t, func(t *testing.T) {
		for range 100 {
			drop("storm")
		}
		if n := p.sends.Load(); n != 2 {
			t.Fatalf("100 drops within 1 s ran the probe %d times; want 1 (+1 process probe)", n)
		}
		time.Sleep(probeCache - time.Nanosecond)
		drop("just before expiry")
		if n := p.sends.Load(); n != 2 {
			t.Fatalf("probe runs %d before the cache expired", n)
		}
		time.Sleep(time.Nanosecond)
		drop("after expiry")
		if n := p.sends.Load(); n != 3 || p.recvs.Load() != 1 {
			t.Fatalf("probe runs %d/%d after the cache expired; want 3/1", n, p.recvs.Load())
		}
		p.set(syscall.EPERM, syscall.EPERM) // a policy is installed
		drop("policy cached")
		time.Sleep(probeCache)
		sendmmsgFn = func(fd uintptr, b *Batch, k, n int) (int, error) {
			if c.Mode() != ModeBatch {
				t.Error("sendmmsg after the fallback")
			}
			return 0, syscall.EPERM
		}
		n, err := c.WriteBatch(b, ms)
		if n != 4 || err != nil || c.Mode() != ModePlain {
			t.Fatalf("after the policy: n %d, err %v, mode %v; want a plain redo of 4", n, err, c.Mode())
		}
	})
	if _, _, _, _, f := ctr.Load(); f != 1 {
		t.Fatalf("fallbacks %d", f)
	}
}

// TestBatchCountsMovedCalls_R1_2: the counters count the system calls that
// moved at least one datagram and the datagrams they moved; EINTR, EAGAIN
// and an error before the first datagram are not counted (R1-2 rule 1),
// and a partial sendmmsg is one call with its count.
func TestBatchCountsMovedCalls_R1_2(t *testing.T) {
	p := newProbe(syscall.EBADF, syscall.EBADF)
	forceBatch(t, p)
	var ctr Counters
	c := newConn(t, listen4(t), 32, &ctr)
	var poll fakePoller
	c.rawWrite, c.rawRead = poll.run, poll.run
	script := []struct {
		cnt int
		err error
	}{{0, syscall.EINTR}, {2, nil}, {0, syscall.EAGAIN}, {0, syscall.EINTR}, {4, nil}, {0, syscall.ENOBUFS}}
	fs := &fakeSend{script: func(call, n int) (int, error) { return script[call].cnt, script[call].err }}
	sendmmsgFn = fs.fn
	dst := addrOf(listen4(t))
	b := NewBatch(32)
	if n, err := c.WriteBatch(b, msgs(dst, 0, 6)); n != 6 || err != nil {
		t.Fatalf("WriteBatch: %d, %v", n, err)
	}
	if sc, s, _, _, _ := ctr.Load(); sc != 2 || s != 6 || poll.waits.Load() != 1 {
		t.Fatalf("%s, %d waits; want 2 calls, 6 datagrams, 1 wait", counters(&ctr), poll.waits.Load())
	}
	if n, err := c.WriteBatch(b, msgs(dst, 6, 3)); n != 0 || errno(err) != syscall.ENOBUFS {
		t.Fatalf("WriteBatch with ENOBUFS at its first datagram: %d, %v", n, err)
	}
	if sc, s, _, _, _ := ctr.Load(); sc != 2 || s != 6 {
		t.Fatalf("after an error before the first datagram: %s", counters(&ctr))
	}

	rscript := []struct {
		cnt int
		err error
	}{{0, syscall.EAGAIN}, {0, syscall.EINTR}, {0, syscall.EAGAIN}, {3, nil}, {0, syscall.ECONNREFUSED}}
	call := 0
	recvmmsgFn = func(fd uintptr, b *Batch, n int) (int, error) {
		s := rscript[call]
		call++
		for i := range s.cnt {
			b.ms[i].N = 1
		}
		return s.cnt, s.err
	}
	rs := slots(8, 16)
	if n, err := c.ReadBatch(b, rs); n != 3 || err != nil {
		t.Fatalf("ReadBatch: %d, %v", n, err)
	}
	if n, err := c.ReadBatch(b, rs); n != 0 || errno(err) != syscall.ECONNREFUSED {
		t.Fatalf("ReadBatch with an error: %d, %v", n, err)
	}
	if _, _, rc, rd, _ := ctr.Load(); rc != 1 || rd != 3 || poll.waits.Load() != 3 {
		t.Fatalf("%s, %d waits; want 1 receive call, 3 datagrams, 3 waits in all", counters(&ctr), poll.waits.Load())
	}
}

// TestBatchPartialSeam (the fake-call twin of the Linux row
// TestMmsgPartialEAGAIN, R1-9): sendmmsg writes 7 of 16, then reports
// EAGAIN once, then writes the rest. WriteBatch waits once and returns 16,
// every datagram left exactly once and in order, in 2 counted calls.
func TestBatchPartialSeam(t *testing.T) {
	p := newProbe(syscall.EBADF, syscall.EBADF)
	forceBatch(t, p)
	var ctr Counters
	c := newConn(t, listen4(t), 32, &ctr)
	var poll fakePoller
	c.rawWrite = poll.run
	eagain := 0
	fs := &fakeSend{script: func(call, n int) (int, error) {
		switch call {
		case 0:
			return 7, nil
		case 1:
			eagain++
			return 0, syscall.EAGAIN
		}
		return n, nil
	}}
	sendmmsgFn = fs.fn
	n, err := c.WriteBatch(NewBatch(32), msgs(addrOf(listen4(t)), 0, 16))
	calls, sent := fs.snapshot()
	if n != 16 || err != nil || !eqStrings(sent, seq(0, 16)) || !eqInts(calls, []int{16, 9, 9}) {
		t.Fatalf("n %d err %v, calls %v, sent %q; want 16, calls [16 9 9], 0 … 15 once in order", n, err, calls, sent)
	}
	if sc, s, _, _, _ := ctr.Load(); sc != 2 || s != 16 || eagain != 1 || poll.waits.Load() != 1 {
		t.Fatalf("%s, %d EAGAIN, %d waits; want 2 calls, 16 datagrams, 1, 1", counters(&ctr), eagain, poll.waits.Load())
	}
}

// TestBatchErrorIndexSeam_L42 (the fake-call twin of the Linux row
// TestMmsgErrorIndex_L42): sendmmsg sends messages 0 … 3 and then fails
// message 4 with EMSGSIZE: WriteBatch returns n = 4 with EMSGSIZE, the
// error of message 4. A count outside the range a call was asked for is
// ErrInvalidCount at the message the call started from (L42).
func TestBatchErrorIndexSeam_L42(t *testing.T) {
	p := newProbe(syscall.EBADF, syscall.EBADF)
	forceBatch(t, p)
	var ctr Counters
	c := newConn(t, listen4(t), 32, &ctr)
	dst := addrOf(listen4(t))
	b := NewBatch(32)
	fs := &fakeSend{script: func(call, n int) (int, error) {
		if call == 0 {
			return 4, nil
		}
		return 0, syscall.EMSGSIZE
	}}
	sendmmsgFn = fs.fn
	if n, err := c.WriteBatch(b, msgs(dst, 0, 8)); n != 4 || errno(err) != syscall.EMSGSIZE {
		t.Fatalf("WriteBatch: n %d, err %v; want 4 and EMSGSIZE for message 4", n, err)
	}
	for _, bad := range []struct {
		name string
		cnt  func(n int) int
	}{
		{"above n", func(n int) int { return n + 1 }},
		{"negative", func(int) int { return -1 }},
		{"zero without an error", func(int) int { return 0 }},
	} {
		sendmmsgFn = (&fakeSend{script: func(call, n int) (int, error) {
			if call == 0 {
				return 2, nil
			}
			return bad.cnt(n), nil
		}}).fn
		if n, err := c.WriteBatch(b, msgs(dst, 0, 8)); n != 2 || !errors.Is(err, ErrInvalidCount) {
			t.Errorf("count %s: n %d, err %v; want 2 and ErrInvalidCount", bad.name, n, err)
		}
	}
	if c.Mode() != ModeBatch {
		t.Fatalf("mode %v: an invalid count is the caller's fatal error, not a fallback", c.Mode())
	}
}

// TestBatchOneDatagramPlain (R1-5 rule 2): a one-datagram write and a
// one-slot read use the single-datagram calls even in ModeBatch, and are
// counted as calls.
func TestBatchOneDatagramPlain(t *testing.T) {
	p := newProbe(syscall.EBADF, syscall.EBADF)
	forceBatch(t, p)
	var ctr Counters
	rx, txu := listen4(t), listen4(t)
	c := newConn(t, txu, 32, &ctr)
	sendmmsgFn = func(fd uintptr, b *Batch, k, n int) (int, error) {
		t.Error("sendmmsg for one datagram")
		return 0, syscall.EINVAL
	}
	recvmmsgFn = func(fd uintptr, b *Batch, n int) (int, error) {
		t.Error("recvmmsg for one slot")
		return 0, syscall.EINVAL
	}
	b := NewBatch(32)
	if n, err := c.WriteBatch(b, msgs(addrOf(rx), 0, 1)); n != 1 || err != nil {
		t.Fatalf("WriteBatch of one: %d, %v", n, err)
	}
	r := newConn(t, rx, 32, &ctr)
	rs := slots(1, 64)
	if n, err := r.ReadBatch(b, rs); n != 1 || err != nil || string(rs[0].Buf[:rs[0].N]) != "0" {
		t.Fatalf("ReadBatch of one: %d, %v", n, err)
	}
	if sc, s, rc, rd, _ := ctr.Load(); sc != 1 || s != 1 || rc != 1 || rd != 1 {
		t.Fatalf("%s", counters(&ctr))
	}
}

// TestBatchChunks: a WriteBatch longer than its Batch runs one call per
// Batch-sized chunk, in order; a ReadBatch reads at most Cap() datagrams.
func TestBatchChunks(t *testing.T) {
	forceBatch(t, newProbe(syscall.EBADF, syscall.EBADF))
	var ctr Counters
	c := newConn(t, listen4(t), 32, &ctr)
	fs := &fakeSend{}
	sendmmsgFn = fs.fn
	if n, err := c.WriteBatch(NewBatch(4), msgs(addrOf(listen4(t)), 0, 10)); n != 10 || err != nil {
		t.Fatalf("WriteBatch: %d, %v", n, err)
	}
	if calls, sent := fs.snapshot(); !eqInts(calls, []int{4, 4, 2}) || !eqStrings(sent, seq(0, 10)) {
		t.Fatalf("calls %v sent %q; want [4 4 2] and 0 … 9", calls, sent)
	}
	var asked []int
	recvmmsgFn = func(fd uintptr, b *Batch, n int) (int, error) {
		asked = append(asked, n)
		return n, nil
	}
	if n, err := c.ReadBatch(NewBatch(4), slots(10, 8)); n != 4 || err != nil || !eqInts(asked, []int{4}) {
		t.Fatalf("ReadBatch: %d, %v, asked %v; want 4 of a Batch of 4", n, err, asked)
	}
	if sc, s, rc, rd, _ := ctr.Load(); sc != 3 || s != 10 || rc != 1 || rd != 4 {
		t.Fatalf("%s", counters(&ctr))
	}
}
