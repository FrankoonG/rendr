package l4

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// PacketResult reports how a ForwardPacket ended.
type PacketResult struct {
	ToSession, ToLocal uint64 // datagrams moved in each direction
	TooLarge           uint64 // local datagrams above pc.MaxPayload(), dropped
	LocalNoise         uint64 // local read and write errors of the noise classes, counted and ignored
	Stream             bool   // the flow became a stream
	// SessionErr is the session's end: io.EOF (the peer closed),
	// rendr.ErrIdleTimeout, *rendr.AbortError, rendr.ErrNoPath,
	// rendr.ErrSessionLost, net.ErrClosed (closed on this side after a
	// local failure), or ctx.Err().
	SessionErr error
	LocalErr   error // the local error that ended the forward, else nil
}

// ForwardPacket moves datagrams between the packet session pc and local, a
// connected datagram conn (each Read returns one datagram from local's far
// end, each Write sends one: a connected *net.UDPConn), until the session
// ends, a fatal local error occurs or ctx is done, and then closes both.
// Boundaries are kept; zero-length datagrams are forwarded. A local
// datagram longer than pc.MaxPayload() is dropped and counted (TooLarge),
// never split (an io.ErrShortBuffer from local counts as TooLarge too).
// Local system-call errors — a port or host unreachable, an
// administratively prohibited destination, a message too long, no buffer
// space: every syscall.Errno except a small fatal set (a closed or invalid
// descriptor, an unconnected socket) — are counted and ignored; a run of
// them backs off up to 100 ms; they never end the flow. Other errors end
// it, and so does a count local must not return (L42: a Read count outside
// its buffer, or a Write count other than the datagram's length, without
// an error).
// ForwardPacket applies idle's classes to pc with SetIdleTimeout (Short at
// once, Stream once the flow is a stream). When the session ends while a
// local Write is still running, ForwardPacket sets local's deadline one
// second later, so a local that never takes a datagram cannot hold the
// flow (a Write that returns within the second still delivers its
// datagram). It sets no other deadlines during the transfer, owns pc and
// local from the call on, and starts two goroutines that end before it
// returns. Carrier changes are invisible to local.
func ForwardPacket(ctx context.Context, pc *rendr.PacketConn, local net.Conn, idle FlowIdle) PacketResult {
	return forwardPacket(ctx, pc, local, idle, flowSeed{}, nil)
}

// packetSession is what a forward uses of its packet session: the methods
// of *rendr.PacketConn it calls (tests wrap one to observe the calls).
type packetSession interface {
	ReadFrom(p []byte) (int, net.Addr, error)
	WriteTo(p []byte, addr net.Addr) (int, error)
	MaxPayload() int
	SetIdleTimeout(d time.Duration) error
	Close() error
	Done() <-chan struct{}
}

// endWriteGrace bounds a local Write still running when the session ended
// (L52): then local's deadline is set. The core releases every queued
// datagram at the end, so only the datagram of that Write is at stake.
// l4's tests read it.
var endWriteGrace = time.Second

// flowSeed is a datagram that moved before a forward started (R1-10): the
// first datagram HandleUDP wrote to the target before Confirm (dir
// towardLocal, at its write). The zero value is none.
type flowSeed struct {
	at  time.Time
	dir flowDir
}

// packetTally receives a forward's counts as they happen, for an owner
// whose status reports live figures (the Server's UDPServerStatus). nil:
// none. Several forwards may share one.
type packetTally struct {
	toSession, toLocal, tooLarge, noise atomic.Uint64
}

// tallyKind names one of packetTally's counters.
type tallyKind uint8

const (
	tallyToSession tallyKind = iota
	tallyToLocal
	tallyTooLarge
	tallyNoise
)

// add counts one event of kind k (nothing when t is nil).
func (t *packetTally) add(k tallyKind) {
	if t == nil {
		return
	}
	switch k {
	case tallyToSession:
		t.toSession.Add(1)
	case tallyToLocal:
		t.toLocal.Add(1)
	case tallyTooLarge:
		t.tooLarge.Add(1)
	default:
		t.noise.Add(1)
	}
}

// errBadDatagramCount: local's Read returned a count outside [0, len(p)],
// or its Write a count other than len(p) without an error (L42: a datagram
// write is exactly complete); the call is a failure of local.
var errBadDatagramCount = errors.New("l4: forwarded datagram conn returned an invalid byte count")

// forwardPacket is ForwardPacket with the passive's seed (R1-10: the class
// tracker counts the first datagram HandleUDP wrote) and an optional live
// tally. The caller's goroutine moves session → local; one pump goroutine
// moves local → session (M6 design §A7.1); one watcher ends the forward
// from outside both loops (ctx, the session's end).
func forwardPacket(ctx context.Context, pc packetSession, local net.Conn, idle FlowIdle, seed flowSeed, tally *packetTally) PacketResult {
	mp := pc.MaxPayload()
	f := &pfwd{pc: pc, local: local, tally: tally, stop: make(chan struct{})}
	f.short, f.stream = idle.limits()
	pc.SetIdleTimeout(f.short) // net.ErrClosed only: the session already ended, which ReadFrom reports
	if seed.dir != 0 && f.class.seed(seed.at, seed.dir) {
		f.promote()
	}
	buf := make([]byte, 2*mp+1) // session → local: mp; local → session: mp + 1, so an oversize datagram shows on every OS
	pumpDone, watchDone := make(chan struct{}), make(chan struct{})
	go f.pump(buf[mp:], pumpDone)
	go f.watch(ctx, watchDone)

	var r PacketResult
	var readErr error
	rb := buf[:mp]
	for {
		n, _, err := pc.ReadFrom(rb)
		if err != nil {
			if errors.Is(err, io.ErrShortBuffer) {
				// Cannot happen (no session delivers more than MaxPayload):
				// dropped and counted, defensively.
				r.TooLarge++
				f.tally.add(tallyTooLarge)
				continue
			}
			readErr = err
			break
		}
		w, werr := local.Write(rb[:n])
		if werr == nil && w != n {
			werr = errBadDatagramCount // a datagram write is exactly complete (L42)
		}
		if werr != nil {
			if f.stopping.Load() {
				// The watcher's deadline, not local's failure: ctx closed
				// the session or the session ended, so the next ReadFrom
				// returns at once with that end.
				continue
			}
			if errClass(werr) != classFatal {
				// A write's size-class error is a datagram local refused
				// to send: noise like the rest.
				r.LocalNoise++
				f.tally.add(tallyNoise)
				continue
			}
			f.failLocal(werr) // pc closed: the next ReadFrom ends the loop
			continue
		}
		r.ToLocal++
		f.tally.add(tallyToLocal)
		if !f.class.isStream() && f.class.in(time.Now()) {
			f.promote()
		}
	}

	// Teardown (L52): local's deadline first, so a call blocked where Close
	// does not interrupt returns too, then local's Close (exactly once),
	// the session's Close (a no-op once it ended), the joins of the pump
	// and of the watcher (which may still be touching pc and local). The
	// watcher stays live until the joins: a ctx done meanwhile finds
	// stopping set and changes nothing (the end already happened).
	f.stopping.Store(true)
	local.SetDeadline(time.Now())
	local.Close()
	pc.Close()
	close(f.stop)
	<-pumpDone
	<-watchDone

	r.ToSession, r.TooLarge, r.LocalNoise = f.toSession, r.TooLarge+f.tooLarge, r.LocalNoise+f.noise
	r.Stream = f.class.isStream()
	r.LocalErr = f.localError()
	r.SessionErr = readErr
	if f.cancelled.Load() && errors.Is(readErr, net.ErrClosed) {
		r.SessionErr = ctx.Err() // ctx's halt closed pc: ctx ended the flow
	}
	return r
}

// pfwd is one forwardPacket call. The pump writes toSession, tooLarge and
// noise only, and the caller reads them after the join.
type pfwd struct {
	pc            packetSession
	local         net.Conn
	short, stream time.Duration // the SetIdleTimeout values of the classes (0: off)
	class         flowClass
	tally         *packetTally

	stop      chan struct{} // closed at the teardown: a back-off wait and the watcher end
	stopping  atomic.Bool   // the teardown or the watcher's halt began: local's errors are not failures
	cancelled atomic.Bool   // the watcher's halt ran for ctx

	toSession, tooLarge, noise uint64 // the pump's counts

	mu       sync.Mutex
	localErr error // the first fatal local error
}

// promote applies the stream class: one SetIdleTimeout call, none when
// both classes have the same limit (the clock is not restarted either
// way). The tracker reports a promotion at most once.
func (f *pfwd) promote() {
	if f.stream != f.short {
		f.pc.SetIdleTimeout(f.stream) // net.ErrClosed after the end: the flow ends normally
	}
}

// failLocal ends the forward on a fatal local error: the first one is
// recorded and the session is closed (the peer reads io.EOF after the
// datagrams already sent), which ends the caller's ReadFrom.
func (f *pfwd) failLocal(err error) {
	f.mu.Lock()
	if f.localErr == nil {
		f.localErr = err
	}
	f.mu.Unlock()
	f.pc.Close()
}

func (f *pfwd) localError() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.localErr
}

// watch ends the forward from outside its two loops until the teardown
// (L52, M4-D38's reap for packets): ctx done halts it at once (the session
// closed, SessionErr ctx.Err()); the session's end halts it endWriteGrace
// later unless the caller's loop ended first — that loop reads the end at
// once unless a local Write holds it, and the halt's deadline ends that
// Write.
func (f *pfwd) watch(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ended := f.pc.Done()
	var grace *time.Timer
	var graceC <-chan time.Time
	defer func() {
		if grace != nil {
			grace.Stop()
		}
	}()
	for {
		select {
		case <-f.stop:
			return
		case <-ctx.Done():
			f.halt(ended != nil) // after the session's end, that end is the result
			return
		case <-ended:
			ended = nil
			grace = time.NewTimer(endWriteGrace)
			graceC = grace.C
		case <-graceC:
			f.halt(false)
			return
		}
	}
}

// halt is the watcher's end of the forward, unless the teardown began:
// local's errors from now on are not failures, the session is closed for
// ctx (the caller's ReadFrom returns), and local's deadline is set (a
// Write blocked in local returns).
func (f *pfwd) halt(cancel bool) {
	if !f.stopping.CompareAndSwap(false, true) {
		return
	}
	if cancel {
		f.cancelled.Store(true)
		f.pc.Close()
	}
	f.local.SetDeadline(time.Now())
}

// pump moves local → session until the session refuses a datagram with
// its end, a fatal local error, or the teardown (M6 design §A7.2).
func (f *pfwd) pump(buf []byte, done chan<- struct{}) {
	defer close(done)
	var run noiseRun
	var wait *time.Timer
	defer func() {
		if wait != nil {
			wait.Stop()
		}
	}()
	for {
		n, err := f.local.Read(buf)
		if f.stopping.Load() {
			return
		}
		if n < 0 || n > len(buf) {
			f.failLocal(errBadDatagramCount)
			return
		}
		if err != nil {
			c := errClass(err)
			if c == classSize && n < len(buf) && !errors.Is(err, io.ErrShortBuffer) {
				// A size errno without a filled buffer is no datagram that
				// arrived: Windows reports a longer one as WSAEMSGSIZE with
				// the buffer filled, Unix truncates it silently (n =
				// len(buf), no error), and a connected socket reports an
				// ICMP fragmentation-needed or packet-too-big of an earlier
				// send as EMSGSIZE on its next call: noise (L58).
				c = classNoise
			}
			switch c {
			case classSize: // WSAEMSGSIZE with the buffer filled, io.ErrShortBuffer
				run.ok()
				f.tooLarge++
				f.tally.add(tallyTooLarge)
			case classNoise:
				f.noise++
				f.tally.add(tallyNoise)
				if d := run.fail(); d > 0 {
					if wait == nil {
						wait = time.NewTimer(d)
					} else {
						wait.Reset(d)
					}
					select {
					case <-wait.C:
					case <-f.stop:
						return
					}
				}
			default:
				f.failLocal(err)
				return
			}
			continue
		}
		run.ok()
		if n == len(buf) { // MaxPayload + 1: a longer datagram, truncated (Linux)
			f.tooLarge++
			f.tally.add(tallyTooLarge)
			continue
		}
		if _, werr := f.pc.WriteTo(buf[:n], nil); werr != nil {
			if errors.Is(werr, rendr.ErrPacketTooLarge) { // cannot happen: n ≤ MaxPayload
				f.tooLarge++
				f.tally.add(tallyTooLarge)
				continue
			}
			if !errors.Is(werr, net.ErrClosed) {
				// The session's end error (Close is a no-op then), or a
				// deadline someone else set: the flow cannot go on one way.
				// net.ErrClosed is this side's Close or the peer's: the
				// caller still reads what the peer sent before it.
				f.pc.Close()
			}
			return
		}
		f.toSession++
		f.tally.add(tallyToSession)
		if !f.class.isStream() && f.class.out(time.Now()) {
			f.promote()
		}
	}
}

// flowDir is the direction in which a datagram moved through a forward.
type flowDir uint8

const (
	towardSession flowDir = iota + 1 // from local (the client at the ingress, the target at the passive) to the session
	towardLocal                      // from the session to local
)

// flowClass is one end's class tracker of a UDP flow, shared by
// ForwardPacket, the passive's seeded forward and the PortForward ingress
// (M6-D9, R1-7, R1-10, R1-23; m6-design W1.3). It applies activeRule():
// seed records a datagram that moved before the tracker's owner started
// (HandleUDP's first datagram, written to the target before Confirm:
// towardLocal), out one that moved toward the session at now, in one that
// moved toward local at now. Each reports whether the flow became a stream
// with that datagram — true at most once in the tracker's life — and the
// caller then calls pc.SetIdleTimeout(Stream) once. At most three time
// comparisons per datagram until the promotion (promoteActive: the gap,
// the latest instant, the period's length), none after; no allocation.
// The zero value is ready; the methods may be called from two goroutines
// at once (each direction's mover). The rule is read at the first call and
// kept for the tracker's life.
type flowClass struct {
	streamed atomic.Bool // the promotion happened: every later call returns false at once

	mu    sync.Mutex
	rule  promoteMode // fixed at the first call
	seen  uint8       // the directions seen (bit dir−1): the whole flow (promoteOnReply), the current activity period (promoteActive)
	start time.Time   // promoteActive: the current period's first datagram
	last  time.Time   // promoteActive: the latest datagram
}

func (c *flowClass) seed(at time.Time, d flowDir) bool { return c.note(at, d) }
func (c *flowClass) out(now time.Time) bool            { return c.note(now, towardSession) }
func (c *flowClass) in(now time.Time) bool             { return c.note(now, towardLocal) }

// isStream reports whether the flow became a stream (FlowInfo.Stream,
// PacketResult.Stream; the movers' fast path).
func (c *flowClass) isStream() bool { return c.streamed.Load() }

// note records one datagram moved in direction d at now and reports
// whether it made the flow a stream.
func (c *flowClass) note(now time.Time, d flowDir) bool {
	if c.streamed.Load() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.streamed.Load() {
		return false
	}
	if c.rule == 0 {
		c.rule = activeRule()
	}
	bit := uint8(1) << (d - 1)
	if c.rule == promoteActive {
		// A gap of streamAfter or more starts a new activity period (R1-23):
		// a source reused after a pause is a new exchange, not a stream.
		// The two movers' instants may reach the lock out of order: a
		// negative gap is none, and last only moves forward.
		if d := now.Sub(c.last); c.seen == 0 || d >= streamAfter {
			c.seen, c.start, c.last = 0, now, now
		} else if d > 0 {
			c.last = now
		}
		c.seen |= bit
		if c.seen != 3 || now.Sub(c.start) < streamAfter {
			return false
		}
	} else if c.seen |= bit; c.seen != 3 {
		return false
	}
	c.streamed.Store(true)
	return true
}
