package carrier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Errors of guarded embedder calls (L51).
var (
	// ErrAbandonFull: the abandoned-call pool is full; no new carrier is
	// created until stuck embedder calls return.
	ErrAbandonFull = errors.New("rendr: abandoned-call pool full")
	// ErrNilConn: a factory returned (nil, nil).
	ErrNilConn = errors.New("rendr: factory returned no connection and no error")
	// ErrFactoryPanic: a factory panicked or called runtime.Goexit.
	ErrFactoryPanic = errors.New("rendr: factory panicked")
	// ErrWithdrawn is the cancellation cause a session uses for its dial
	// attempts when Dial's context ended after an OPEN may have been
	// admitted; Establish then sends a best-effort RST(withdrawn) (L49).
	ErrWithdrawn = errors.New("rendr: dial withdrawn")
)

// timeoutError is a net.Error whose Timeout is true (DialTimeout expiry).
type timeoutError struct{ s string }

func (e *timeoutError) Error() string   { return e.s }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// errDialTimeout reports that a factory call or a whole attempt exceeded
// Timing.DialTimeout.
var errDialTimeout error = &timeoutError{"rendr: carrier dial timed out"}

// dialGrace is how long GuardedDial still waits for a factory call after it
// gave up on it (ctx ended or DialTimeout passed), capped by AbandonWait: the
// reaction bound of a factory that honours its context. Only a call still
// running after it is stuck in embedder code and counted as abandoned (L52):
// counting a call that is merely returning would make Status.Abandoned at
// Runtime.Close's return depend on scheduling (design §3.1, §6.8 step 7). A
// cancelled attempt still ends long before the wind-downs that abandon
// attempts still running 2·AbandonWait after their cancellation (design
// §0.9 X2).
const dialGrace = 50 * time.Millisecond

// GuardedDial calls f on a fresh goroutine and returns f's result when f
// returns before ctx ends and before DialTimeout elapses. Otherwise it gives
// up, even if f ignores ctx, and returns ctx's cause or a timeout error: at
// once when f then returns within dialGrace (at most AbandonWait) — a
// factory that honours its context does — or after that grace. A panic or
// runtime.Goexit in f becomes ErrFactoryPanic; (nil, nil) becomes
// ErrNilConn; (conn, err) closes conn once and returns err; a conn that
// arrives after GuardedDial gave up is closed exactly once. A call still
// running after the grace is stuck in embedder code: it is counted in
// env.Abandon before GuardedDial returns and leaves it when f returns (L52;
// design §0.10 Y8), so a joiner that has seen the attempt end —
// Session.Done, Health.Close, Runtime.Close — already sees it in
// Status.Abandoned, while a call that honours ctx is never counted. It is
// counted once only: the attempt itself ends within AbandonWait of its
// cancellation, so no wind-down that abandons attempts still running
// 2·AbandonWait after it (design §0.9 X2) counts it again. It fails fast
// with ErrAbandonFull when env.Abandon is full. GuardedDial itself does not
// run Hooks.DialStart: Establish runs it inside f, right before the factory
// call, so callers of Establish never call it.
func GuardedDial(ctx context.Context, env *Env, f func(context.Context) (net.Conn, error)) (net.Conn, error) {
	return guardedDial(ctx, env, f)
}

// GuardedDialEarly is GuardedDial for StreamCarrier.DialEarly: first (the
// PREFACE and first frame) is passed to f, which sends it inside the
// embedder's own open request. f must not retain first after it returns.
func GuardedDialEarly(ctx context.Context, env *Env, f func(context.Context, []byte) (net.Conn, error), first []byte) (net.Conn, error) {
	return guardedDial(ctx, env, func(ctx context.Context) (net.Conn, error) { return f(ctx, first) })
}

// dialCall is one guarded factory call. The factory goroutine delivers its
// normalized result through res unless the caller gave up on it first, in
// which case the caller counted the goroutine in the abandoned-call pool and
// the goroutine, once f returned, leaves the pool and closes a late conn
// itself (exactly once).
type dialCall struct {
	env    *Env
	res    chan dialResult // cap 1
	mu     sync.Mutex
	gaveUp bool // the caller returned without the result; the goroutine is counted in env.Abandon
}

type dialResult struct {
	c   net.Conn
	err error
}

func guardedDial(ctx context.Context, env *Env, f func(context.Context) (net.Conn, error)) (net.Conn, error) {
	if env.Abandon != nil && env.Abandon.Full() {
		return nil, ErrAbandonFull
	}
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	d := &dialCall{env: env, res: make(chan dialResult, 1)}
	go d.run(ctx, f)
	tm := env.Timing.withDefaults()
	t := time.NewTimer(tm.DialTimeout)
	defer t.Stop()
	var err error
	select {
	case r := <-d.res:
		return r.c, r.err
	case <-ctx.Done():
		err = context.Cause(ctx)
	case <-t.C:
		err = errDialTimeout
	}
	// Given up: the result is err whatever f returns now. A factory that
	// honours ctx returns at once, so the call is still joined for a short
	// grace and is never counted as abandoned (L52).
	late := func(r dialResult) (net.Conn, error) {
		if r.c != nil {
			CloseConn(env, r.c) // too late for the caller: closed exactly once
		}
		return nil, err
	}
	grace := time.NewTimer(min(dialGrace, tm.AbandonWait))
	defer grace.Stop()
	select {
	case r := <-d.res:
		return late(r)
	case <-grace.C:
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case r := <-d.res: // it returned while the grace ran out
		return late(r)
	default:
	}
	// Still inside f: stuck in embedder code, and nobody waits for it any
	// more (L52). The Adopt happens under the lock the goroutine reads
	// gaveUp under, so its Leave always follows it.
	d.gaveUp = true
	if env.Abandon != nil {
		env.Abandon.Adopt()
	}
	return nil, err
}

// run calls f and normalizes its result (L51): a panic or Goexit is
// ErrFactoryPanic, (nil, nil) is ErrNilConn, and a conn returned together
// with an error is closed once.
func (d *dialCall) run(ctx context.Context, f func(context.Context) (net.Conn, error)) {
	var (
		c      net.Conn
		err    error
		normal bool
	)
	defer func() {
		if !normal {
			if r := recover(); r != nil {
				err = fmt.Errorf("%w: %v", ErrFactoryPanic, r)
			} else {
				err = fmt.Errorf("%w (runtime.Goexit)", ErrFactoryPanic)
			}
			c = nil
		}
		if c == nil && err == nil {
			err = ErrNilConn
		}
		if c != nil && err != nil {
			CloseConn(d.env, c)
			c = nil
		}
		d.mu.Lock()
		if !d.gaveUp {
			d.res <- dialResult{c, err}
			d.mu.Unlock()
			return
		}
		d.mu.Unlock()
		if d.env.Abandon != nil {
			d.env.Abandon.Leave() // f returned: the call is no longer stuck in the embedder
		}
		if c != nil {
			CloseConn(d.env, c) // a late conn: closed exactly once (its own close is watched)
		}
	}()
	c, err = f(ctx)
	normal = true
}

// CloseConn closes an embedder conn that is not (or no longer) owned by a
// Conn and returns at once: SetDeadline(now) and Close each run on a
// guarded goroutine, and the Close does not wait for the SetDeadline
// (closeOnce.async). Each conn must be passed to CloseConn at most once.
func CloseConn(env *Env, nc net.Conn) {
	if nc == nil {
		return
	}
	(&closeOnce{nc: nc}).async(env)
}

// deadlineCloser is what a closeOnce closes (M2 design Revision 1, R1-7):
// the embedder net.Conn of a stream carrier or the PacketIO of a datagram
// carrier, both of which satisfy it. The closer, its deadline part and the
// last resort of an abandonment therefore act on the real transport of
// either kind; a datagram Conn is never built with a nil conn
// (newDatagramConn).
type deadlineCloser interface {
	SetDeadline(t time.Time) error
	Close() error
}

// closeOnce closes an embedder conn exactly once (L51, L52): it calls
// SetDeadline(now) and Close at most once each, whoever comes first — the
// goroutine that owns the conn, after its last call, or the last-resort
// close of that goroutine's abandonment (design §0.8 V2). A verdict write —
// WriteAndClose, an RST(withdrawn), a PREFACE_ACK refusal — on a conn that
// ignores its write deadline but honours Close would otherwise keep the
// conn open for as long as the peer does not read: the goroutine stuck in
// it is counted in the abandoned-call pool, and only the Close it never
// reaches would unblock it.
//
// Close never waits for SetDeadline to return (design §0.14 B3).
// SetDeadline(now) is started first, on a goroutine of its own, so that a
// conn that honours deadlines unblocks its pending calls (L52), and Close
// follows at once. A conn whose deadline setters wait for a pending call —
// a websocket adapter that honours gorilla's one-reader rule serializes
// SetReadDeadline with Read — and whose Close ends that call is so closed
// at once, and its SetDeadline returns when the call has ended. A Close
// called only after SetDeadline returned would wait for a Read that, on a
// silent path, only the peer ends, with the closer and the reader counted
// in the abandoned-call pool all that time.
type closeOnce struct {
	nc      deadlineCloser // a net.Conn (stream carriers) or a PacketIO (datagram carriers)
	setting atomic.Bool    // SetDeadline(now) was started
	closing atomic.Bool    // Close was started; a Close that hangs in the embedder keeps it, so nothing closes a second time
}

// conn returns the stream conn k closes, for the stream-only paths that
// also read or write it (readHello, writeAndCloseInline). A datagram
// transport never takes those paths: conn panics for one.
func (k *closeOnce) conn() net.Conn {
	nc, ok := k.nc.(net.Conn)
	if !ok {
		panic("rendr/carrier: stream close path on a datagram transport")
	}
	return nc
}

// startDeadline reports whether the caller is to call SetDeadline(now):
// neither SetDeadline nor Close was started yet (after Close a deadline
// unblocks nothing).
func (k *closeOnce) startDeadline() bool {
	return !k.closing.Load() && k.setting.CompareAndSwap(false, true)
}

// startClose reports whether the caller is to call Close: nobody started
// it yet.
func (k *closeOnce) startClose() bool { return k.closing.CompareAndSwap(false, true) }

// async closes the conn and never blocks: SetDeadline(now) on a guarded
// goroutine, started first, and Close on another, which does not wait for
// it. A step that was started already is skipped. A goroutine still inside
// the embedder's call AbandonWait after it started is counted in
// env.Abandon until the call returns (L52).
func (k *closeOnce) async(env *Env) {
	k.goDeadline(env, env.Timing.AbandonWait)
	k.last(env)
}

// goDeadline starts SetDeadline(now) on a goroutine of its own unless a
// SetDeadline or Close was started already (startDeadline), and returns a
// channel that is closed when that call returned — at once when it was not
// started here. The goroutine is counted in env.Abandon when it is still
// inside the embedder's call d after it started, until the call returns
// (L52). d is AbandonWait plus the time the caller may still take before it
// calls Close: on a conn whose deadline setters wait for a call in
// progress, the SetDeadline returns only when that call ended, which on a
// silent path only the Close does.
func (k *closeOnce) goDeadline(env *Env, d time.Duration) <-chan struct{} {
	set := make(chan struct{})
	if !k.startDeadline() {
		close(set)
		return set
	}
	w := startWatch(env.Abandon, d)
	go func() {
		defer w.finish() // also on runtime.Goexit inside the embedder's SetDeadline
		defer close(set)
		_ = callSetDeadline(k.nc, time.Now())
	}()
	return set
}

// last calls Close on a guarded goroutine unless Close was started already;
// it never blocks. As the last resort it runs when the goroutine that owns
// the conn was adopted by the abandoned-call pool while still inside an
// embedder call that ignored its deadline (a verdict write, a drain): the
// Close unblocks that call. It is never preceded by a SetDeadline of its
// own, which could wait for that very call (design §0.14 B3).
func (k *closeOnce) last(env *Env) {
	if k.startClose() {
		goGuarded(env, func() { _ = callClose(k.nc) })
	}
}

// goGuarded runs the embedder call f on a goroutine of its own, counted in
// env.Abandon when it is still running AbandonWait after it started, until
// it returns (L52).
func goGuarded(env *Env, f func()) {
	w := startWatch(env.Abandon, env.Timing.AbandonWait)
	go func() {
		defer w.finish() // also on runtime.Goexit inside the embedder's call
		f()
	}()
}

// writeAndCloseInline is Conn.WriteAndClose for a conn that has no Conn,
// run on the calling goroutine: it writes frame bounded by deadline (zero:
// now + drainMax) and closes k's conn in the L05 order — CloseWrite on an
// OwnedTCP, a drain bounded by min(deadline, drainMax), then SetDeadline(now)
// and Close on guarded goroutines (k.async). When the calling goroutine is
// still inside the write or the drain AbandonWait after both bounds — a conn
// that ignores its deadlines and a peer that neither reads nor closes — its
// conn is closed through k as the last resort (k.last, design §0.8 V2),
// which ends the call on a conn that honours Close. That goroutine is not
// counted in the abandoned-call pool here: it belongs to the caller's
// owner, which joins it and counts it once if it stays stuck (ReadHello's
// caller is a handshake goroutine of root's handshake group, counted by
// Runtime.Close's bounded join); a count here as well would count one
// stuck goroutine twice (L52, design §0.9 X5). Every other close of the
// conn must go through k too — the caller's runtime.Goexit guard included,
// since a Goexit in a conn call skips the final close here — so that it is
// closed exactly once (L51, L52). It is the verdict form for ReadHello's
// PREFACE_ACK refusals (VERSION, FEATURE, and the gate's CAPACITY or
// GOING_AWAY): the refusal stays on the handshake goroutine and in its slot
// (L48), so Runtime.Close's handshake join covers it.
func writeAndCloseInline(env *Env, k *closeOnce, frame []byte, deadline time.Time) {
	now := time.Now()
	if deadline.IsZero() {
		deadline = now.Add(drainMax)
	}
	wait := env.Timing.withDefaults().AbandonWait + drainMax
	if d := deadline.Sub(now); d > 0 {
		wait += d
	}
	w := armWatch(nil, wait, func() { k.last(env) }) // the last resort only: the caller's owner counts this goroutine
	defer w.finish()                                 // also on runtime.Goexit in a conn call
	nc := k.conn()
	_ = callSetWriteDeadline(nc, deadline)
	if writeFull(nc, frame) == nil {
		if o, ok := nc.(*OwnedTCP); ok {
			_ = callCloseWrite(o)
		}
		until := time.Now().Add(drainMax)
		if deadline.Before(until) {
			until = deadline
		}
		drain(nc, until)
	}
	k.async(env)
}

// watch counts a goroutine that is still inside embedder code AbandonWait
// after it was armed in the abandoned-call pool (L52): exactly one of
// expire (counted: Adopt) and finish (in time) wins; a counted goroutine
// leaves the pool when it finally finishes.
type watch struct {
	state atomic.Int32 // watchRunning, watchDone or watchAbandoned
	timer *time.Timer
	pool  *AbandonPool // nil: not counted
	last  func()       // run once when the goroutine is adopted; nil: none
}

const (
	watchRunning int32 = iota
	watchDone
	watchAbandoned
)

// startWatch arms a watch that counts its goroutine in pool after d.
func startWatch(pool *AbandonPool, d time.Duration) *watch {
	return armWatch(pool, d, nil)
}

// armWatch is startWatch with a last-resort action: when the watch adopts
// its goroutine, last runs once on the timer's goroutine, after the
// adoption (design §0.8 V2: closeOnce.last). It must not block. With a nil
// pool nothing is counted (the goroutine's owner counts it) and last still
// runs when d passes before finish.
func armWatch(pool *AbandonPool, d time.Duration, last func()) *watch {
	w := &watch{pool: pool, last: last}
	if d <= 0 {
		d = time.Second
	}
	w.timer = time.AfterFunc(d, w.expire)
	return w
}

func (w *watch) expire() {
	if !w.state.CompareAndSwap(watchRunning, watchAbandoned) {
		return
	}
	if w.pool != nil {
		w.pool.Adopt()
	}
	if w.last != nil {
		w.last()
	}
}

// finish is called by the watched goroutine when its embedder call returned.
func (w *watch) finish() {
	if w.state.CompareAndSwap(watchRunning, watchDone) {
		w.timer.Stop()
		return
	}
	if w.pool != nil {
		w.pool.Leave()
	}
}

// Guarded embedder conn calls (L51). rendr never calls a method of an
// embedder net.Conn except through these wrappers: a panic becomes an
// error (*panicError); runtime.Goexit cannot be stopped and is detected by
// the calling goroutine's own deferred cleanup. Invalid counts are checked
// by the callers (checkCount).

// panicError reports a panic inside an embedder conn method.
type panicError struct {
	op string
	v  any
}

func (e *panicError) Error() string { return fmt.Sprintf("rendr: conn %s panicked: %v", e.op, e.v) }

// countError reports a Read or Write count outside [0, len] (L42).
type countError struct {
	op     string
	n, max int
}

func (e *countError) Error() string {
	return fmt.Sprintf("rendr: conn %s returned invalid count %d (buffer %d)", e.op, e.n, e.max)
}

// errZeroRead and errZeroWrite: a Read or Write that returned (0, nil) is a
// transport error (L01, L42): a reliable stream that makes no progress and
// reports no error is broken.
var (
	errZeroRead  = errors.New("rendr: conn Read returned (0, nil)")
	errZeroWrite = errors.New("rendr: conn Write returned (0, nil)")
)

func callRead(nc net.Conn, p []byte) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, err = 0, &panicError{"Read", r}
		}
	}()
	return nc.Read(p)
}

func callWrite(nc net.Conn, p []byte) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, err = 0, &panicError{"Write", r}
		}
	}()
	return nc.Write(p)
}

func callWriteBuffers(o *OwnedTCP, v *net.Buffers) (n int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, err = 0, &panicError{"Write", r}
		}
	}()
	return o.WriteBuffers(v)
}

func callSetDeadline(nc deadlineCloser, t time.Time) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &panicError{"SetDeadline", r}
		}
	}()
	return nc.SetDeadline(t)
}

func callSetReadDeadline(nc net.Conn, t time.Time) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &panicError{"SetReadDeadline", r}
		}
	}()
	return nc.SetReadDeadline(t)
}

func callSetWriteDeadline(nc net.Conn, t time.Time) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &panicError{"SetWriteDeadline", r}
		}
	}()
	return nc.SetWriteDeadline(t)
}

func callClose(nc deadlineCloser) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &panicError{"Close", r}
		}
	}()
	return nc.Close()
}

func callCloseWrite(o *OwnedTCP) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &panicError{"CloseWrite", r}
		}
	}()
	return o.CloseWrite()
}

// readFull fills p from nc with count-checked guarded Reads: a count
// outside [0, len] is a *countError, (0, nil) is errZeroRead, and an error
// before p is full is returned (bytes read so far are discarded by the
// callers, which never hand over a partial structure).
func readFull(nc net.Conn, p []byte) error {
	for got := 0; got < len(p); {
		n, err := callRead(nc, p[got:])
		if n < 0 || n > len(p)-got {
			return &countError{"Read", n, len(p) - got}
		}
		got += n
		if got == len(p) {
			return nil // complete: a trailing error is the next read's business
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return errZeroRead
		}
	}
	return nil
}

// writeFull writes p to nc with count-checked guarded Writes; a short write
// with progress and no error continues with the remainder (L42).
func writeFull(nc net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := callWrite(nc, p)
		if n < 0 || n > len(p) {
			return &countError{"Write", n, len(p)}
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return errZeroWrite
		}
		p = p[n:]
	}
	return nil
}

// isTimeout reports whether err is a deadline expiry.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
