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
// them backs off up to 100 ms; they never end the flow. Other errors end it.
// ForwardPacket applies idle's classes to pc with SetIdleTimeout (Short at
// once, Stream once the flow is a stream). It sets no deadlines during the
// transfer, owns pc and local from the call on, and starts one goroutine
// that ends before it returns. Carrier changes are invisible to local.
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
}

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

// errBadDatagramCount: local's Read or Write returned a count outside
// [0, len(p)] (L42); the call is a failure of local.
var errBadDatagramCount = errors.New("l4: forwarded datagram conn returned an invalid byte count")

// forwardPacket is ForwardPacket with the passive's seed (R1-10: the class
// tracker counts the first datagram HandleUDP wrote) and an optional live
// tally. The caller's goroutine moves session → local; one pump goroutine
// moves local → session (M6 design §A7.1).
func forwardPacket(ctx context.Context, pc packetSession, local net.Conn, idle FlowIdle, seed flowSeed, tally *packetTally) PacketResult {
	mp := pc.MaxPayload()
	f := &pfwd{pc: pc, local: local, tally: tally, stop: make(chan struct{})}
	f.short, f.stream = idle.limits()
	pc.SetIdleTimeout(f.short) // net.ErrClosed only: the session already ended, which ReadFrom reports
	if seed.dir != 0 && f.class.seed(seed.at, seed.dir) {
		f.promote()
	}
	buf := make([]byte, 2*mp+1) // session → local: mp; local → session: mp + 1, so an oversize datagram shows on every OS
	pumpDone := make(chan struct{})
	go f.pump(buf[mp:], pumpDone)

	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		defer close(cancelDone)
		f.cancelled.Store(true)
		f.halt()
	})

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
		if werr == nil && (w < 0 || w > n) {
			werr = errBadDatagramCount
		}
		if werr != nil {
			if f.stopping.Load() {
				break // the teardown's deadline, not local's failure
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
	// the session's Close (a no-op once it ended), the pump's join.
	f.stopping.Store(true)
	close(f.stop)
	local.SetDeadline(time.Now())
	local.Close()
	pc.Close()
	<-pumpDone
	if !stopCancel() {
		<-cancelDone // ctx's teardown started: it touches pc and local, so it ends first
	}

	r.ToSession, r.TooLarge, r.LocalNoise = f.toSession, r.TooLarge+f.tooLarge, r.LocalNoise+f.noise
	r.Stream = f.class.isStream()
	r.LocalErr = f.localError()
	switch {
	case f.cancelled.Load() && (readErr == nil || errors.Is(readErr, net.ErrClosed)):
		// ctx's halt closed pc (or ended a local Write): ctx ended the flow.
		r.SessionErr = ctx.Err()
	case readErr == nil:
		r.SessionErr = net.ErrClosed
	default:
		r.SessionErr = readErr
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

	stop      chan struct{} // closed at the teardown: a back-off wait ends
	stopping  atomic.Bool   // the teardown (or ctx's halt) began: local's errors are not failures
	cancelled atomic.Bool   // ctx's halt ran

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

// halt is ctx's end of the forward: local's errors from now on are the
// teardown's, the session is closed (the caller's ReadFrom returns) and
// local's deadline set (a Write blocked in local returns).
func (f *pfwd) halt() {
	f.stopping.Store(true)
	f.pc.Close()
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
			switch errClass(err) {
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
