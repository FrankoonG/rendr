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

// GuardedDial calls f on a fresh goroutine (counted by Hooks.DialStart via the
// caller) and returns when f returns or when ctx ends or DialTimeout elapses,
// whichever is first, even if f ignores ctx. A panic or runtime.Goexit in f
// becomes ErrFactoryPanic; (nil, nil) becomes ErrNilConn; (conn, err) closes
// conn once and returns err; a conn that arrives after the call returned is
// closed exactly once. A goroutine still inside f after AbandonWait past the
// return is counted in env.Abandon until f returns. It fails fast with
// ErrAbandonFull when env.Abandon is full.
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
// case the goroutine closes a late conn itself (exactly once) and reports
// to the abandonment watch.
type dialCall struct {
	env    *Env
	res    chan dialResult // cap 1
	mu     sync.Mutex
	gaveUp bool   // the caller returned without the result
	w      *watch // armed when the caller gave up
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
	d.gaveUp = true
	d.w = startWatch(env.Abandon, tm.AbandonWait)
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
		if c != nil {
			CloseConn(d.env, c) // a late conn: closed exactly once
		}
		d.w.finish()
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

// watch counts a goroutine that is still inside embedder code AbandonWait
// after it was armed in the abandoned-call pool (L52): exactly one of
// expire (counted: Adopt) and finish (in time) wins; a counted goroutine
// leaves the pool when it finally finishes.
type watch struct {
	state atomic.Int32 // watchRunning, watchDone or watchAbandoned
	timer *time.Timer
	pool  *AbandonPool // nil: not counted
}

const (
	watchRunning int32 = iota
	watchDone
	watchAbandoned
)

// startWatch arms a watch that counts its goroutine in pool after d.
func startWatch(pool *AbandonPool, d time.Duration) *watch {
	w := &watch{pool: pool}
	if d <= 0 {
		d = time.Second
	}
	w.timer = time.AfterFunc(d, w.expire)
	return w
}

func (w *watch) expire() {
	if w.state.CompareAndSwap(watchRunning, watchAbandoned) && w.pool != nil {
		w.pool.Adopt()
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
