package rendr

import (
	"context"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
)

// Context returns a context that is done once this pending session can no
// longer be confirmed: Confirm or Reject decided it, AcceptTimeout answered
// it, the dialer withdrew it, or its Listener or Runtime closed. Its
// Deadline is the AcceptTimeout instant; its Err is context.DeadlineExceeded
// when AcceptTimeout ended it, else context.Canceled. Every call returns
// the same context; no goroutine waits on it, also when it is used with
// context.AfterFunc or as a parent (once it is done, context.AfterFunc
// runs its function on a goroutine of its own, as for every context).
// Use it to bound work done before the decision, such as a target dial;
// Confirm's error tells why the session can no longer be confirmed.
func (p *PendingConn) Context() context.Context {
	return pendingCtx{s: p.s}
}

// pendingCtx is the pending context (M4-D22, R1-8): a view of the
// session's pending phase. It is a comparable value, so every call of
// Context returns an equal context without allocating. Done is the
// session's pending-done channel, closed once when the session leaves
// StatePending; AfterFunc registers on the session's list, which the
// actor runs at that exit, so neither context.AfterFunc nor the children
// that context.WithCancel, WithDeadline and WithTimeout derive from it
// start a goroutine that waits on it (the context package uses the
// AfterFunc method of a parent that has one instead of watching its Done
// channel on a goroutine); at the exit, context.AfterFunc's function runs
// on a goroutine of its own, as always.
type pendingCtx struct{ s *session.Session }

func (c pendingCtx) Deadline() (time.Time, bool) {
	d := c.s.PendingDeadline()
	return d, !d.IsZero()
}

func (c pendingCtx) Done() <-chan struct{} { return c.s.PendingDone() }
func (c pendingCtx) Err() error            { return c.s.PendingErr() }
func (pendingCtx) Value(any) any           { return nil }

// AfterFunc arranges for f to run once the context is done (at once, on
// its own goroutine, if it is done already) and returns stop, with
// context.AfterFunc's contract. f runs on the session's actor after its
// lock was released and must not block; the context package only passes
// the cancel functions of derived contexts (and, for context.AfterFunc, a
// function that starts the caller's f on its own goroutine).
func (c pendingCtx) AfterFunc(f func()) (stop func() bool) { return c.s.PendingAfterFunc(f) }

func (pendingCtx) String() string { return "rendr.PendingConn.Context" }
