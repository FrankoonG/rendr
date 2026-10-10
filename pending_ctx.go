package rendr

import (
	"context"
	"time"
)

// Context returns a context that is done once this pending session can no
// longer be confirmed: Confirm or Reject decided it, AcceptTimeout answered
// it, the dialer withdrew it, or its Listener or Runtime closed. Its
// Deadline is the AcceptTimeout instant; its Err is context.DeadlineExceeded
// when AcceptTimeout ended it, else context.Canceled. Every call returns
// the same context; it starts no goroutine, also when used with
// context.AfterFunc or as a parent.
// Use it to bound work done before the decision, such as a target dial;
// Confirm's error tells why the session can no longer be confirmed.
//
// Not implemented yet: the context reports the deadline but is never done.
func (p *PendingConn) Context() context.Context {
	return pendingCtx{p: p} // M4 WP1: built once, done at the verdict (R1-8)
}

// pendingCtx is the skeleton's pending context, which M4's WP1 replaces:
// the AcceptTimeout deadline, never done.
type pendingCtx struct{ p *PendingConn }

func (c pendingCtx) Deadline() (time.Time, bool) {
	d := c.p.s.PendingDeadline()
	return d, !d.IsZero()
}

func (pendingCtx) Done() <-chan struct{} { return nil }
func (pendingCtx) Err() error            { return nil }
func (pendingCtx) Value(any) any         { return nil }
