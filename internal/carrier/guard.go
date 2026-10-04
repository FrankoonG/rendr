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

// GuardedDial calls f on a fresh goroutine and returns when f returns or when
// ctx ends or DialTimeout elapses, whichever is first, even if f ignores ctx.
// A panic or runtime.Goexit in f becomes ErrFactoryPanic; (nil, nil) becomes
// ErrNilConn; (conn, err) closes conn once and returns err; a conn that
// arrives after the call returned is closed exactly once. When GuardedDial
// returns without f's result, nobody waits for that goroutine any more: it
// is counted in env.Abandon at once and leaves it when f returns (L52;
// design §0.10 Y8), so a joiner that has seen the attempt end — Session.Done,
// Runtime.Close — already sees the stuck call in Status.Abandoned. It is
// counted once only: the attempt itself returned, so no wind-down that
// abandons attempts still running (design §0.9 X2) counts it again. It
// fails fast with ErrAbandonFull when env.Abandon is full. GuardedDial
// itself does not run Hooks.DialStart: Establish runs it inside f, right
// before the factory call, so callers of Establish never call it.
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
// normalized result through res unless the caller gave up first, in which
// case the caller counted the goroutine in the abandoned-call pool and the
// goroutine, once f returned, leaves the pool and closes a late conn itself
// (exactly once).
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
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case r := <-d.res: // the factory returned while the caller was giving up
		return r.c, r.err
	default:
	}
	// Nobody waits for the call any more: it is abandoned now (L52). The
	// Adopt happens under the lock the goroutine reads gaveUp under, so its
	// Leave always follows it.
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
// Conn: SetDeadline(now) then Close on a guarded goroutine; it returns at
// once. Each conn must be passed to CloseConn at most once.
func CloseConn(env *Env, nc net.Conn) {
	if nc == nil {
		return
	}
	w := startWatch(env.Abandon, env.Timing.AbandonWait)
	go func() {
		defer w.finish() // also on runtime.Goexit inside the embedder's Close
		closeNow(nc)
	}()
}

// closeNow unblocks and closes nc: SetDeadline(now), then Close. Panics in
// either call are contained, and Close is deferred so that it runs exactly
// once even when SetDeadline calls runtime.Goexit (L51).
func closeNow(nc net.Conn) {
	defer func() { _ = callClose(nc) }()
	_ = callSetDeadline(nc, time.Now())
}

// closeOnce closes an embedder conn exactly once (L52), whoever comes
// first: the goroutine that owns the conn, after its last call, or the
// last-resort close of that goroutine's abandonment (design §0.8 V2). A
// verdict write — WriteAndClose, an RST(withdrawn), a PREFACE_ACK refusal —
// on a conn that ignores its write deadline but honours Close would
// otherwise keep the conn open for as long as the peer does not read: the
// goroutine stuck in it is counted in the abandoned-call pool, and only the
// Close it never reaches would unblock it.
type closeOnce struct {
	nc   net.Conn
	done atomic.Bool
}

// now closes the conn on the calling goroutine (closeNow) unless it was
// closed already. A close that hangs in the embedder keeps the flag, so
// the last resort never closes a second time.
func (k *closeOnce) now() {
	if k.done.CompareAndSwap(false, true) {
		closeNow(k.nc)
	}
}

// async closes the conn on a guarded goroutine (CloseConn) unless it was
// closed already; it never blocks. As the last resort it runs when the
// goroutine that owns the conn was adopted by the abandoned-call pool while
// still inside an embedder call that ignored its deadline: the Close
// unblocks that call.
func (k *closeOnce) async(env *Env) {
	if k.done.CompareAndSwap(false, true) {
		CloseConn(env, k.nc)
	}
}

// writeAndCloseInline is Conn.WriteAndClose for a conn that has no Conn,
// run on the calling goroutine: it writes frame bounded by deadline (zero:
// now + drainMax) and closes k's conn in the L05 order — CloseWrite on an
// OwnedTCP, a drain bounded by min(deadline, drainMax), then Close on a
// guarded goroutine (k.async). The calling goroutine is watched like the
// closer of WriteAndClose: when it is still inside the write or the drain
// AbandonWait after both bounds — a conn that ignores its deadlines and a
// peer that neither reads nor closes — it is counted in the abandoned-call
// pool and its conn is closed through k as the last resort (design §0.8
// V2), which ends the call on a conn that honours Close. Every other close
// of the conn must go through k too — the caller's runtime.Goexit guard
// included, since a Goexit in a conn call skips the final close here — so
// that it is closed exactly once (L51, L52). It is the verdict form for
// ReadHello's PREFACE_ACK refusals (VERSION, FEATURE, and the gate's
// CAPACITY or GOING_AWAY): the refusal stays on the handshake goroutine and
// in its slot (L48), so Runtime.Close's handshake join covers it.
func writeAndCloseInline(env *Env, k *closeOnce, frame []byte, deadline time.Time) {
	now := time.Now()
	if deadline.IsZero() {
		deadline = now.Add(drainMax)
	}
	wait := env.Timing.withDefaults().AbandonWait + drainMax
	if d := deadline.Sub(now); d > 0 {
		wait += d
	}
	w := armWatch(env.Abandon, wait, func() { k.async(env) })
	defer w.finish() // also on runtime.Goexit in a conn call: nothing stays counted
	_ = callSetWriteDeadline(k.nc, deadline)
	if writeFull(k.nc, frame) == nil {
		if o, ok := k.nc.(*OwnedTCP); ok {
			_ = callCloseWrite(o)
		}
		until := time.Now().Add(drainMax)
		if deadline.Before(until) {
			until = deadline
		}
		drain(k.nc, until)
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
// adoption (design §0.8 V2: closeOnce.async). It must not block.
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

func callSetDeadline(nc net.Conn, t time.Time) (err error) {
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

func callClose(nc net.Conn) (err error) {
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
