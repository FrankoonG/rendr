package carrier

import (
	"context"
	"errors"
	"net"
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

// GuardedDial calls f on a fresh goroutine (counted by Hooks.DialStart via the
// caller) and returns when f returns or when ctx ends or DialTimeout elapses,
// whichever is first, even if f ignores ctx. A panic or runtime.Goexit in f
// becomes ErrFactoryPanic; (nil, nil) becomes ErrNilConn; (conn, err) closes
// conn once and returns err; a conn that arrives after the call returned is
// closed exactly once. A goroutine still inside f after AbandonWait past the
// return is counted in env.Abandon until f returns. It fails fast with
// ErrAbandonFull when env.Abandon is full.
func GuardedDial(ctx context.Context, env *Env, f func(context.Context) (net.Conn, error)) (net.Conn, error) {
	panic("unimplemented: M1b")
}

// GuardedDialEarly is GuardedDial for StreamCarrier.DialEarly: first (the
// PREFACE and first frame) is passed to f, which sends it inside the
// embedder's own open request. f must not retain first after it returns.
func GuardedDialEarly(ctx context.Context, env *Env, f func(context.Context, []byte) (net.Conn, error), first []byte) (net.Conn, error) {
	panic("unimplemented: M1b")
}

// CloseConn closes an embedder conn that is not (or no longer) owned by a
// Conn: SetDeadline(now) then Close on a guarded goroutine; it returns at
// once. Each conn must be passed to CloseConn at most once.
func CloseConn(env *Env, nc net.Conn) {
	panic("unimplemented: M1b")
}
