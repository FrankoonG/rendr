package l4

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// ServeTCP's accept back-off (M6 design §A8.7, R1-19): a temporary Accept
// error (EMFILE, ENFILE, ECONNABORTED, a deadline on the listener) waits
// 5 ms, doubling up to 100 ms while they continue; an accepted connection
// ends the run. The root Listener's back-off is not reachable from l4.
const (
	tcpAcceptBackoffMin = 5 * time.Millisecond
	tcpAcceptBackoffMax = 100 * time.Millisecond
)

// ServeTCP accepts connections from ln until ctx is done or Accept fails
// permanently (temporary errors back off 5–100 ms) and forwards each to
// target ("host:port", resolved by the passive; validated before the first
// Accept: ErrBadAddress). A connection beyond MaxConns, or whose Dial
// fails, is reset. ServeTCP owns ln from the call on and closes it when it
// returns, after every connection it started ended. A Unix-domain listener
// counts as loopback.
//
// Each accepted connection holds one MaxConns unit while its session is
// dialled and forwarded: Peer.Dial with Options (EarlyReturn honoured: the
// client's first bytes then ride the OPEN, and a refusal arrives as the
// session's error), the session's idle limit from IdleTimeout, then
// Forward with M4's semantics (half-close, resets both ways, never a clean
// close after a failure). A Dial error resets the client and counts
// Failed, its code in ByCode and LastErr; so does a refusal that an
// EarlyReturn session met at its open. Accepted counts every connection
// Accept returned while serving, Refused those beyond MaxConns, and
// AcceptNoise the temporary Accept errors.
//
// ServeTCP returns ctx.Err() once ctx is done, Accept's error when it fails
// permanently (net.ErrClosed after a Close by someone else), or
// net.ErrClosed when the Peer or its Runtime was closed. Before it returns
// it resets every connection still forwarded (their sessions aborted with
// AbortShutdown) and waits for each to end. Before the first Accept it
// returns at once, ln closed: an error when Peer is nil, the metadata
// error of an invalid target (ErrBadAddress), or ErrNonLoopback.
func (f *PortForward) ServeTCP(ctx context.Context, ln net.Listener, target string) error {
	s, err := f.newTCPServe(ctx, ln, target)
	if err != nil {
		ln.Close()
		return err
	}
	s.accept()
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.cause
}

// tcpServe is one ServeTCP call: its listener, the sessions' dial options
// and the connections it forwards.
type tcpServe struct {
	f    *PortForward
	ln   net.Listener
	opts rendr.DialOptions // the PortForward's, Metadata the encoded L4 metadata
	idle time.Duration     // each session's SetIdleTimeout value; negative: none

	// ctx is the caller's, also cancelled at the halt: it ends every dial
	// and resets every forwarded connection (Forward's ctx rule).
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup // one per accepted connection

	haltOnce  sync.Once
	cause     error // the halt's cause (set once, read after wg.Wait)
	closeOnce sync.Once
}

// newTCPServe runs ServeTCP's checks before the first Accept (M6-D21,
// M6-D22, §A8.1): the Peer, the target (the L4 metadata, encoded once:
// every session carries the same bytes, which the session copies), the
// listener's bind address.
func (f *PortForward) newTCPServe(ctx context.Context, ln net.Listener, target string) (*tcpServe, error) {
	if f.Peer == nil {
		return nil, errNoPeer
	}
	md, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: target, App: f.Options.Metadata})
	if err != nil {
		return nil, err
	}
	if err := f.checkIngress(ln.Addr()); err != nil {
		return nil, err
	}
	s := &tcpServe{f: f, ln: ln, opts: f.Options, idle: f.IdleTimeout}
	s.opts.Metadata = md
	if s.idle == 0 {
		s.idle = DefaultIdleTimeout
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	return s, nil
}

// halt stops the serve once (a permanent Accept error, the Peer or Runtime
// closed): the accept loop returns and every connection is reset.
func (s *tcpServe) halt(err error) {
	s.haltOnce.Do(func() {
		s.cause = err
		s.cancel()
	})
}

// closeLn closes the listener exactly once.
func (s *tcpServe) closeLn() { s.closeOnce.Do(func() { s.ln.Close() }) }

// accept is the accept loop: it runs until the serve's ctx is done or
// Accept fails permanently, then ends every connection (L52): the ctx is
// cancelled, ln closed, and every handler joined.
func (s *tcpServe) accept() {
	t := &s.f.tcp
	stop := context.AfterFunc(s.ctx, s.closeLn) // a blocked Accept returns
	defer func() {
		stop()
		s.cancel()
		s.closeLn()
		s.wg.Wait()
	}()
	var delay time.Duration
	var wait *time.Timer
	defer func() {
		if wait != nil {
			wait.Stop()
		}
	}()
	for {
		c, err := s.ln.Accept()
		if s.ctx.Err() != nil {
			if c != nil {
				resetConn(c)
			}
			return
		}
		if err == nil && c == nil {
			// A broken listener: (nil, nil) is retried as a temporary
			// error, so it cannot make the loop spin (L42).
			err = errNilAccept
		}
		if err != nil {
			if c != nil {
				resetConn(c) // a listener that returned both: the conn is not served (L42)
			}
			if !temporaryAccept(err) {
				s.halt(err)
				return
			}
			t.acceptNoise.Add(1)
			delay = min(max(2*delay, tcpAcceptBackoffMin), tcpAcceptBackoffMax)
			if wait == nil {
				wait = time.NewTimer(delay)
			} else {
				wait.Reset(delay)
			}
			select {
			case <-wait.C:
			case <-s.ctx.Done():
				return
			}
			continue
		}
		delay = 0
		t.accepted.Add(1)
		if !acquire(&t.conns, int64(s.f.maxConns())) {
			t.refused.Add(1)
			resetConn(c) // the bound: reset at once, never a clean close
			continue
		}
		s.wg.Go(func() { s.handle(c) })
	}
}

// errNilAccept is a listener's Accept that returned neither a conn nor an
// error.
var errNilAccept = errors.New("l4: listener Accept returned no conn and no error")

// temporaryAccept reports an Accept error worth retrying: a net.Error
// whose Temporary or Timeout is true (EMFILE, ENFILE, ECONNABORTED, a
// listener deadline), or a (nil, nil) Accept. Everything else — the
// listener's net.ErrClosed included — ends the serve.
func temporaryAccept(err error) bool {
	if err == errNilAccept {
		return true
	}
	var t interface{ Temporary() bool }
	if errors.As(err, &t) && t.Temporary() {
		return true
	}
	var to interface{ Timeout() bool }
	return errors.As(err, &to) && to.Timeout()
}

// handle forwards one accepted connection that holds a MaxConns unit
// (§A8.7): the session's dial, its idle limit, then Forward. A failed
// dial resets the client; a dial the stop cancelled counts no failure; a
// Peer or Runtime closed halts the serve.
func (s *tcpServe) handle(c net.Conn) {
	t := &s.f.tcp
	defer t.conns.Add(-1)
	rc, err := s.f.Peer.Dial(s.ctx, s.opts)
	if err != nil {
		resetConn(c)
		if errors.Is(err, net.ErrClosed) {
			s.halt(err)
		}
		if s.ctx.Err() == nil {
			t.dialFailed(err)
		}
		return
	}
	if s.idle >= 0 {
		rc.SetIdleTimeout(s.idle) // net.ErrClosed only: the session ended already, and Forward sees it
	}
	res := Forward(s.ctx, rc, c)
	// An EarlyReturn session's open outcome arrives as its error: the peer
	// never accepted it (its PeerInstance is still zero), so it is a dial
	// failure (Forward has reset the client).
	if s.opts.EarlyReturn && res.SessionErr != nil && rc.PeerInstance() == (rendr.InstanceID{}) && s.ctx.Err() == nil {
		t.dialFailed(res.SessionErr)
	}
}
