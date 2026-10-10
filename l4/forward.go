package l4

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// ForwardResult reports how a Forward ended.
type ForwardResult struct {
	ToSession, ToLocal int64 // bytes moved in each direction
	Clean              bool  // both directions ended with a FIN
	SessionErr         error // the session's error when not clean, as Read or Write returned it (ctx.Err() when ctx ended it)
	LocalErr           error // local's read or write error when not clean
}

// Err returns nil after a clean exchange, else SessionErr or LocalErr.
func (r ForwardResult) Err() error {
	switch {
	case r.Clean:
		return nil
	case r.SessionErr != nil:
		return r.SessionErr
	}
	return r.LocalErr
}

// Forward moves bytes between the session c and local until both
// directions ended, the session ended, or ctx is done, then closes both. A
// FIN from local becomes c.CloseWrite; the session's io.EOF becomes
// CloseWrite on local when local has one (else local stays open for the
// reverse direction); any other end of either side resets the other
// (c.Abort(AbortReset, …); local: SetLinger(0) where offered, then Close).
// When the session ends uncleanly while local still has a direction open (a
// peer that ignores FIN or never reads), local is reset at once; after a
// clean end the last bytes and the FIN are written first, within a bound.
// (Pending, R1-15: a Conn still opening (EarlyReturn) is read at once
// until the first-read hold lands; with it, such a Conn is read only after
// local's first bytes were written to it, or after 20 ms.) ctx ending
// aborts the session (AbortShutdown) and resets local. Forward owns c and
// local from the call on, sets no deadlines on them during the transfer,
// and starts two goroutines that end before it returns.
//
// After local's FIN, Forward reads nothing more from local, so a later
// close of local is not observable (TCP sends nothing for it): such a
// session ends when the far side ends it, at its idle limit, or when ctx
// ends; an embedder that learns of the close by other means closes the
// Conn. A deadline set on local by its owner that expires is a failure of
// local (a reset both ways): hand Forward conns without deadlines. So
// are a local Read count outside [0, len(p)] and 100 Reads in a row that
// return neither bytes nor an error (io.ErrNoProgress). A local
// conn without CloseWrite is closed fully at the end; one without
// SetLinger is closed plainly where a reset is due. Forward calls only the
// net.Conn methods, CloseWrite and SetLinger of local.
func Forward(ctx context.Context, c *rendr.Conn, local net.Conn) ForwardResult {
	f := &forwarder{c: c, local: local, done: make(chan struct{}, 2)}
	go f.pumpA()
	go f.pumpB()
	f.reap(ctx)
	return f.result()
}

// Forward's internals (M4 design §A7; WP4 owns them, WP5 calls them).
var (
	// cleanJoinMax bounds the wait for the pumps after a clean session end
	// (R1-1): Linger's default; l4's tests lower it.
	cleanJoinMax = 30 * time.Second
	// earlyFirstWriteWait bounds pump B's hold of its first Read on a
	// Conn still opening (R1-15, M4-D57); l4's tests change it.
	earlyFirstWriteWait = 20 * time.Millisecond
	// bufPool holds the pumps' 32 KiB buffers (M4-D36: one per pump, no
	// allocation per chunk in steady state).
	bufPool = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}
)

// Errors Forward records as LocalErr.
var (
	// errBadCount: local's Read or Write returned a count outside
	// [0, len(p)] (L42); the call is a failure of local.
	errBadCount = errors.New("l4: forwarded conn returned an invalid byte count")
	// errNoDrain: the session ended cleanly but local did not take the last
	// bytes and the FIN within cleanJoinMax (R1-1).
	errNoDrain = errors.New("l4: local did not drain after the session ended")
)

// maxEmptyReads is the number of consecutive local Reads returning (0, nil)
// after which local has failed with io.ErrNoProgress (L42: a conn that
// neither delivers nor fails must not make a pump spin; bufio's limit).
const maxEmptyReads = 100

// The messages of Forward's RSTs (fixed class texts).
const (
	msgLocalRead  = "forwarded socket read failed"
	msgLocalWrite = "forwarded socket write failed"
	msgSession    = "forwarded session failed"
	msgCancelled  = "forward cancelled"
)

// resetConn resets local: SetDeadline(now), SetLinger(0) where offered,
// then Close (M4-D37, M4-D40; L52).
func resetConn(local net.Conn) {
	local.SetDeadline(time.Now()) // a blocked call returns even where Close does not interrupt it
	if l, ok := local.(interface{ SetLinger(sec int) error }); ok {
		l.SetLinger(0)
	}
	local.Close()
}

// forwarder is one Forward call: the two pumps' state and the end record.
// The pumps write their own fields only (pump A: toSession, eofA; pump B:
// toLocal, eofB) and signal done once each; the reaper reads them after
// both signalled. The first failure is the cause (fail); a failure that
// follows from the teardown it started (a read of a reset local, a write
// to an aborted session) is not recorded.
type forwarder struct {
	c     *rendr.Conn
	local net.Conn
	done  chan struct{} // one signal per pump

	toSession, toLocal int64
	eofA, eofB         bool // pump A ended with local's FIN; pump B with the session's io.EOF

	mu                sync.Mutex
	failed            bool  // a cause was recorded: the end is not clean
	sessErr, localErr error // the cause
	localDone         bool  // local was closed or reset (exactly once)
}

// fail records the cause of an unclean end unless one was recorded; it
// reports whether this call recorded it.
func (f *forwarder) fail(sessErr, localErr error) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed {
		return false
	}
	f.failed = true
	f.sessErr, f.localErr = sessErr, localErr
	return true
}

// closeLocal closes local once: a reset (resetConn) or, after a clean
// exchange, a plain Close.
func (f *forwarder) closeLocal(reset bool) {
	f.mu.Lock()
	if f.localDone {
		f.mu.Unlock()
		return
	}
	f.localDone = true
	f.mu.Unlock()
	if reset {
		resetConn(f.local)
		return
	}
	f.local.Close()
}

// failLocal ends the forward on a failure of local: the session is reset
// toward the peer (AbortReset; never a FIN), then local.
func (f *forwarder) failLocal(err error, msg string) {
	f.fail(nil, err)
	f.c.Abort(AbortReset, msg)
	f.closeLocal(true)
}

// failSession ends the forward on a failure of the session: local is
// reset; the session is reset too where it still lives (a deadline its
// owner set), so no failure reaches the far end as a FIN.
func (f *forwarder) failSession(err error) {
	f.fail(err, nil)
	f.c.Abort(AbortReset, msgSession)
	f.closeLocal(true)
}

// pumpA moves local → session: local's FIN becomes c.CloseWrite.
func (f *forwarder) pumpA() {
	defer func() { f.done <- struct{}{} }()
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	empty := 0
	for {
		n, err := f.local.Read(buf)
		if n < 0 || n > len(buf) {
			f.failLocal(errBadCount, msgLocalRead)
			return
		}
		if n == 0 && err == nil {
			if empty++; empty >= maxEmptyReads {
				f.failLocal(io.ErrNoProgress, msgLocalRead)
				return
			}
			continue
		}
		empty = 0
		if n > 0 {
			w, werr := f.c.Write(buf[:n])
			f.toSession += int64(w)
			if werr == nil && w != n {
				werr = io.ErrShortWrite
			}
			if werr != nil {
				f.failSession(werr)
				return
			}
		}
		switch {
		case err == io.EOF:
			if cerr := f.c.CloseWrite(); cerr != nil {
				f.failSession(cerr)
				return
			}
			f.eofA = true
			return
		case err != nil:
			f.failLocal(err, msgLocalRead)
			return
		}
	}
}

// pumpB moves session → local: the session's io.EOF becomes CloseWrite on
// local where offered; without it local stays open for the reverse
// direction (M4-D39).
func (f *forwarder) pumpB() {
	defer func() { f.done <- struct{}{} }()
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	for {
		n, err := f.c.Read(buf)
		if n > 0 {
			w, werr := writeFull(f.local, buf[:n])
			f.toLocal += int64(w)
			if werr != nil {
				f.failLocal(werr, msgLocalWrite)
				return
			}
		}
		switch {
		case err == io.EOF:
			if cw, ok := f.local.(interface{ CloseWrite() error }); ok {
				if cerr := cw.CloseWrite(); cerr != nil {
					f.failLocal(cerr, msgLocalWrite)
					return
				}
			}
			f.eofB = true
			return
		case err != nil:
			f.failSession(err)
			return
		}
	}
}

// writeFull writes p to w (L42): a short write without an error that made
// progress is continued; no progress, an invalid count or an error ends it
// with an error.
func writeFull(w io.Writer, p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		k, err := w.Write(p)
		if k < 0 || k > len(p) {
			return written, errBadCount
		}
		written += k
		p = p[k:]
		switch {
		case err != nil:
			return written, err
		case k == 0:
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// reap waits for both pumps, the session's end and ctx (M4-D38, R1-1):
// an unclean session end resets local at once (a peer that ignores FIN or
// never reads is released); a clean one lets pump B write the last bytes
// and the FIN within cleanJoinMax; ctx aborts the session (AbortShutdown)
// and resets local. It returns once both pumps ended.
func (f *forwarder) reap(ctx context.Context) {
	ended, cancelled := f.c.Done(), ctx.Done()
	var join *time.Timer
	var joinC <-chan time.Time
	for pending := 2; pending > 0; {
		select {
		case <-f.done:
			pending--
		case <-ended:
			ended = nil
			pending -= drain(f.done)
			if pending == 0 {
				break
			}
			if err := f.c.Status().Err; err != io.EOF {
				f.fail(err, nil)
				f.closeLocal(true)
				break
			}
			join = time.NewTimer(cleanJoinMax)
			joinC = join.C
		case <-joinC:
			joinC = nil
			f.fail(nil, errNoDrain)
			f.closeLocal(true)
		case <-cancelled:
			cancelled = nil
			f.fail(ctx.Err(), nil)
			f.c.Abort(AbortShutdown, msgCancelled)
			f.closeLocal(true)
		}
	}
	if join != nil {
		join.Stop()
	}
	f.mu.Lock()
	clean := !f.failed && f.eofA && f.eofB
	f.mu.Unlock()
	if !clean {
		// An end that is not both FINs never reaches either far end as a
		// FIN (no-op where the session already ended or was reset).
		f.c.Abort(AbortReset, msgSession)
	}
	f.c.Close()
	f.closeLocal(!clean)
}

// drain takes the pump signals already sent and returns their count.
func drain(done chan struct{}) int {
	n := 0
	for {
		select {
		case <-done:
			n++
		default:
			return n
		}
	}
}

// result is the ForwardResult after reap.
func (f *forwarder) result() ForwardResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := ForwardResult{ToSession: f.toSession, ToLocal: f.toLocal}
	if !f.failed && f.eofA && f.eofB {
		r.Clean = true
		return r
	}
	r.SessionErr, r.LocalErr = f.sessErr, f.localErr
	return r
}
