package l4

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// Server defaults.
const (
	DefaultIdleTimeout = 10 * time.Minute // the L4 stream idle default (plan:660)
	DefaultDialTimeout = 5 * time.Second  // below the Listener's AcceptTimeout (10 s)
	DefaultMaxConns    = 10000
)

// maxHookCalls bounds the custom Dial hook calls a Server runs at once, in
// flight or abandoned (M4-D28, R1-9); at the cap a request is rejected
// CodeCapacity without calling the hook.
const maxHookCalls = 192

// The dial budget (M4 design §A6.3, §A6.4).
const (
	minDialTimeout = 500 * time.Millisecond
	maxDialTimeout = 30 * time.Second
	// replyReserve is kept between the dial budget's end and the pending
	// session's AcceptTimeout, so a slow target is answered CodeTimeout
	// before the core answers CAPACITY (M4-D29).
	replyReserve = 250 * time.Millisecond
	// abandonAfter is how long past its budget a handler waits for a custom
	// hook call before it answers CodeTimeout and abandons the call (M4-D30).
	abandonAfter = time.Second
)

// Errors of the hook wrapper; they reach ServerStatus.LastErr only.
var (
	errNilConn   = errors.New("l4: Dial hook returned neither a conn nor an error")
	errAbandoned = fmt.Errorf("l4: Dial hook still running %v after its budget: %w", abandonAfter, context.DeadlineExceeded)
)

// dialTCP is the target dial of a Server without a Dial hook. It is a
// variable only so that tests can observe the context the Server gives the
// default dialer (its budget and its cancellation); nothing else sets it.
var dialTCP = func(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

// hookPanic is the error of a hook call that panicked or called
// runtime.Goexit (v is nil then). It wraps nothing, so it classifies as
// CodeDialFailed whatever the panic value is.
type hookPanic struct{ v any }

func (e hookPanic) Error() string {
	if e.v == nil {
		return "l4: Dial hook called runtime.Goexit"
	}
	return fmt.Sprint("l4: Dial hook panicked: ", e.v)
}

// Server serves L4 sessions; the zero value is ready. A Server must not be
// copied after first use.
type Server struct {
	// Dial opens the target. nil: a net.Dialer's DialContext on "tcp" and
	// r.Addr. It should honour ctx; a call still running one second after
	// its budget is abandoned, and the conn it returns later is closed. The
	// abandoned call is answered CodeTimeout, unless the pending session's
	// AcceptTimeout came first, as it does whenever the budget ends less
	// than one second before it (always when the budget is AcceptTimeout
	// minus 250 ms, for example with a DialTimeout at or above
	// AcceptTimeout): the Listener has then refused the session (the dialer
	// gets ErrCapacity) and the Server sends nothing (ServerStatus.Lost).
	// Return an error wrapping ErrDenied to refuse by policy
	// (CodeNotAllowed). A panic is answered CodeDialFailed. ctx bounds the
	// dial only; it is cancelled after the dial returns, and the returned
	// conn must not depend on it. At most 192 calls run at once, abandoned
	// ones included. A conn the Server closes on the hook's behalf
	// (returned with an error, or late) is closed under recover; a conn
	// returned without an error belongs to the Server, which forwards it
	// (or resets it, when the session was decided while it dialled), and
	// must not panic.
	//
	// With UDP set, r.Cmd may be CmdUDP: return a connected datagram conn
	// (each Read one datagram from the target, each Write one datagram to
	// it; nil Dial: a net.Dialer's DialContext on "udp"). The conn must
	// report a non-nil RemoteAddr and either implement net.PacketConn (a
	// connected *net.UDPConn does) or report a LocalAddr whose Network is
	// "udp", "udp4" or "udp6" (an embedder's own datagram tunnel reports
	// "udp"); any other conn is closed and answered CodeDialFailed. A hook
	// used with UDP must check r.Cmd. Every other rule above holds for both
	// commands; at most 192 calls of each kind run at once.
	Dial func(ctx context.Context, r Request) (net.Conn, error)
	// DialTimeout bounds one target dial (0: DefaultDialTimeout; clamped to
	// 0.5–30 s) and never runs past the pending session's AcceptTimeout
	// minus 250 ms, so a slow target is answered CodeTimeout.
	DialTimeout time.Duration
	// IdleTimeout is set on every served session (0: DefaultIdleTimeout;
	// negative: none, so the Runtime's Config.IdleTimeout applies, which is
	// off by default).
	IdleTimeout time.Duration
	// MaxConns bounds the sessions this Server dials for or forwards at once
	// (0 or less: DefaultMaxConns); a session beyond it is rejected
	// CodeCapacity at once.
	MaxConns int

	// UDP enables L4 UDP flows: Serve also accepts packet sessions, and
	// HandleUDP serves them. False (the zero value): Serve never calls
	// AcceptPacket, as in v2.0.0.
	UDP bool
	// UDPIdle is the FlowIdle of every served flow (zero: the defaults).
	UDPIdle FlowIdle
	// MaxFlows bounds the UDP flows this Server dials for or forwards at once
	// (0 or less: DefaultMaxFlows); a flow beyond it is rejected CodeCapacity
	// at once. MaxConns bounds TCP connections only.
	MaxFlows int
	// UDPBuffer is the receive and send buffer size the default UDP dialer
	// requests for each target socket (0 or less: 1 MiB; the kernel caps it
	// at rmem_max and wmem_max). Bursts from the target wait there until the
	// flow's pump reads them: size it for the largest burst.
	UDPBuffer int

	conns     atomic.Int64 // handlers admitted under MaxConns: dialling or forwarding
	hooks     atomic.Int64 // custom hook calls running, abandoned ones included
	dialing   atomic.Int64
	live      atomic.Int64
	abandoned atomic.Int64

	confirmed, rejected, unconfirmed, lost, panics atomic.Uint64

	byCode  [CodeDialFailed - CodeBadRequest + 1]atomic.Uint64
	lastErr atomic.Pointer[error]
}

// Serve accepts stream sessions from ln until ctx is done or Accept fails
// and handles each on its own goroutine (see Handle). Cancelling ctx
// resets every connection it serves. Serve returns after every connection
// it started has ended, with ctx.Err() or Accept's error (net.ErrClosed
// after Listener.Close or Runtime.Close; confirmed connections keep running
// until they end or ctx is done). Packet sessions are never accepted: their
// OPENs on ln wait in its packet backlog until AcceptTimeout answers them.
// Abandoned Dial hook calls may outlive Serve; Status counts them.
func (s *Server) Serve(ctx context.Context, ln *rendr.Listener) error {
	var wg sync.WaitGroup
	for {
		p, err := ln.Accept(ctx)
		if err != nil {
			wg.Wait()
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return err
		}
		wg.Go(func() { s.Handle(ctx, p) })
	}
}

// Handle serves one pending session and returns when its connection
// ended: the OPEN's metadata names the target (malformed: rejected with the
// matching code), the target is dialled while the session is pending, the
// session is confirmed after the target connected (a dial failure is
// rejected with the matching code), and Forward runs until it ends. Use it
// to serve L4 sessions from a Listener shared with other sessions (Match
// tells them apart). Cancelling ctx stops the dial (the session is
// rejected CodeDialFailed) or resets the forwarded connection.
func (s *Server) Handle(ctx context.Context, p *rendr.PendingConn) {
	if !acquire(&s.conns, int64(s.maxConns())) {
		s.reject(p, CodeCapacity)
		return
	}
	defer s.conns.Add(-1)
	r, err := ParseMetadata(p.Metadata())
	if err != nil {
		code := CodeBadRequest
		if me, ok := errors.AsType[*MetadataError](err); ok {
			code = me.Code
		}
		s.reject(p, code)
		return
	}
	t := s.connect(ctx, p, r)
	if t == nil {
		return
	}
	c, err := p.Confirm()
	if err != nil {
		// The session was decided while the target connected (withdrawn,
		// timed out, its Listener or Runtime closed; M4-D31, R1-25).
		resetConn(t)
		s.unconfirmed.Add(1)
		return
	}
	s.confirmed.Add(1)
	if d := s.idleTimeout(); d >= 0 {
		c.SetIdleTimeout(d) // net.ErrClosed only: the session ended already, and Forward sees it
	}
	s.live.Add(1)
	defer s.live.Add(-1)
	Forward(ctx, c, t)
}

// connect dials the target of r for the pending session p within the dial
// budget (§A6.1, §A6.3). It returns the connected target, or nil after it
// answered p (or found p decided already).
func (s *Server) connect(ctx context.Context, p *rendr.PendingConn, r Request) net.Conn {
	custom := s.Dial != nil
	if custom && !acquire(&s.hooks, maxHookCalls) {
		s.reject(p, CodeCapacity) // R1-9: no hook call at the cap
		return nil
	}
	pctx := p.Context()
	now := time.Now()
	deadline := now.Add(s.dialTimeout())
	if pd, ok := pctx.Deadline(); ok {
		if lim := pd.Add(-replyReserve); lim.Before(deadline) {
			deadline = lim
		}
	}
	if pctx.Err() != nil || !now.Before(deadline) {
		if custom {
			s.hooks.Add(-1)
		}
		if pctx.Err() != nil {
			s.lost.Add(1) // decided before the dial (withdrawn, closed): no Reject
		} else {
			s.reject(p, CodeTimeout) // the budget is spent: no dial
		}
		return nil
	}
	dctx, cancel := context.WithDeadline(ctx, deadline)
	// The pending context has an AfterFunc method, so no goroutine waits on
	// it while the dial runs (R1-8); if the pending phase ends first, the
	// context package runs cancel on a goroutine of its own, as it runs
	// every AfterFunc function.
	stop := context.AfterFunc(pctx, cancel)
	s.dialing.Add(1)
	var t net.Conn
	var err error
	if custom {
		t, err = s.callHook(dctx, r, deadline)
	} else {
		t, err = dialTCP(dctx, r.Addr)
	}
	stop()
	cancel()
	s.dialing.Add(-1)
	if err == nil && ctx.Err() != nil {
		// Serve stopped while the target connected: no session is confirmed
		// that Forward would reset at once.
		resetConn(t)
		err = ctx.Err()
	}
	if err == nil {
		return t
	}
	s.lastErr.Store(&err)
	switch { // R1-6: Serve's ctx first, then the pending context, then classify
	case ctx.Err() != nil:
		s.reject(p, CodeDialFailed)
	case pctx.Err() != nil:
		s.lost.Add(1) // decided already (withdrawn, AcceptTimeout, closed): no Reject
	default:
		s.reject(p, classify(err))
	}
	return nil
}

// hookCall is one custom Dial hook call (M4-D30). The call's goroutine
// stores its result, then either hands it to the waiting handler (state
// running → returned, done closed) or, when the handler abandoned the call
// (running → abandoned), closes the late conn itself.
type hookCall struct {
	state atomic.Int32
	done  chan struct{}
	conn  net.Conn
	err   error
}

// hookCall states.
const (
	hookRunning int32 = iota
	hookReturned
	hookAbandoned
)

// callHook runs the custom hook on its own goroutine (counted in hooks by
// connect, never in Serve's WaitGroup: R1-7) and waits for its result
// until deadline + abandonAfter; a call still running then is abandoned
// and answered errAbandoned (CodeTimeout).
func (s *Server) callHook(ctx context.Context, r Request, deadline time.Time) (net.Conn, error) {
	h := &hookCall{done: make(chan struct{})}
	go s.runHook(h, ctx, r)
	t := time.NewTimer(time.Until(deadline) + abandonAfter)
	defer t.Stop()
	select {
	case <-h.done:
		return h.conn, h.err
	case <-t.C:
	}
	if h.state.CompareAndSwap(hookRunning, hookAbandoned) {
		s.abandoned.Add(1)
		return nil, errAbandoned
	}
	<-h.done // it returned at the same instant
	return h.conn, h.err
}

// runHook is the hook call's goroutine. A panic or runtime.Goexit is
// recovered into hookPanic; (nil, nil) becomes errNilConn; the conn of a
// (conn, err) result is closed once and err kept. The result is handed to
// the handler first; a conn to drop (of a (conn, err) result, or late) is
// closed after that, under recover, and the hook count is released last
// even if that Close calls runtime.Goexit.
func (s *Server) runHook(h *hookCall, ctx context.Context, r Request) {
	defer s.hooks.Add(-1)
	var conn net.Conn
	var err error
	returned := false
	defer func() {
		if !returned {
			conn, err = nil, hookPanic{v: recover()} // recover is nil under Goexit, which then goes on
			s.panics.Add(1)
		}
		var drop net.Conn
		switch {
		case err != nil && conn != nil:
			drop, conn = conn, nil
		case err == nil && conn == nil:
			err = errNilConn
		}
		h.conn, h.err = conn, err
		if h.state.CompareAndSwap(hookRunning, hookReturned) {
			close(h.done)
		} else {
			// Abandoned: the handler answered CodeTimeout already.
			if conn != nil {
				drop = conn
			}
			s.abandoned.Add(-1)
		}
		if drop != nil {
			s.closeHookConn(drop)
		}
	}()
	conn, err = s.Dial(ctx, r)
	returned = true
}

// closeHookConn closes a conn the Dial hook supplied and the Server drops.
// A panic or runtime.Goexit in its Close is counted in Panics; a panic is
// recovered (L51: nothing a hook supplies brings the process down).
func (s *Server) closeHookConn(c net.Conn) {
	closed := false
	defer func() {
		if !closed {
			recover()
			s.panics.Add(1)
		}
	}()
	c.Close()
	closed = true
}

// acquire takes one unit of the counter n below limit; it reports false at
// the limit.
func acquire(n *atomic.Int64, limit int64) bool {
	for {
		v := n.Load()
		if v >= limit {
			return false
		}
		if n.CompareAndSwap(v, v+1) {
			return true
		}
	}
}

// reject answers p with code and its fixed text (M4-D32: the raw error
// never reaches the dialer). Reject's own error is ignored: the session is
// decided either way.
func (s *Server) reject(p *rendr.PendingConn, code RejectCode) {
	p.Reject(uint32(code), code.String())
	s.rejected.Add(1)
	s.byCode[code-CodeBadRequest].Add(1)
}

func (s *Server) maxConns() int {
	if s.MaxConns <= 0 {
		return DefaultMaxConns
	}
	return s.MaxConns
}

func (s *Server) dialTimeout() time.Duration {
	if s.DialTimeout == 0 {
		return DefaultDialTimeout
	}
	return min(max(s.DialTimeout, minDialTimeout), maxDialTimeout)
}

// idleTimeout is the value Handle sets on a served session; negative: none.
func (s *Server) idleTimeout() time.Duration {
	if s.IdleTimeout == 0 {
		return DefaultIdleTimeout
	}
	return s.IdleTimeout
}

// Status returns a snapshot of the Server's counters.
func (s *Server) Status() ServerStatus {
	st := ServerStatus{
		Dialing:     int(s.dialing.Load()),
		Live:        int(s.live.Load()),
		Hooks:       int(s.hooks.Load()),
		Abandoned:   int(s.abandoned.Load()),
		Confirmed:   s.confirmed.Load(),
		Rejected:    s.rejected.Load(),
		Unconfirmed: s.unconfirmed.Load(),
		Lost:        s.lost.Load(),
		ByCode:      make(map[RejectCode]uint64),
		Panics:      s.panics.Load(),
	}
	for i := range s.byCode {
		if n := s.byCode[i].Load(); n > 0 {
			st.ByCode[CodeBadRequest+RejectCode(i)] = n
		}
	}
	if e := s.lastErr.Load(); e != nil {
		st.LastErr = *e
	}
	return st
}

// Serve is (&Server{}).Serve(ctx, ln).
func Serve(ctx context.Context, ln *rendr.Listener) error {
	return (&Server{}).Serve(ctx, ln)
}

// ServerStatus counts what a Server does.
type ServerStatus struct {
	Dialing, Live       int                   // sessions being dialled for; connections being forwarded
	Hooks               int                   // custom hook calls running, in flight or abandoned (≤ 192)
	Abandoned           int                   // hook calls still running past their bound
	Confirmed, Rejected uint64                // totals (Rejected: Reject calls, also one that found the session decided)
	Unconfirmed         uint64                // dialled, then reset because Confirm failed
	Lost                uint64                // the pending phase ended during the dial; no Reject sent
	ByCode              map[RejectCode]uint64 // Rejected by code
	Panics              uint64                // recovered hook panics and Goexits
	LastErr             error                 // the last raw dial error (never sent to the dialer)
	// UDP counts the UDP flows (Server.UDP). The fields above count TCP
	// connections, except Hooks, Abandoned, Panics and LastErr, which count
	// both kinds.
	UDP UDPServerStatus
}
