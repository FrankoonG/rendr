package quic

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"

	qgo "github.com/quic-go/quic-go"
)

// handoff is what Serve uses of a *rendr.Listener (tests pass a fake).
type handoff interface {
	Handle(c net.Conn) error
	HandlePacket(pc net.PacketConn, peer net.Addr) error
}

type admKey struct{}

// admToken is one admitted connection attempt; shaken: its handshake slot
// was released (accepted or ended).
type admToken struct{ shaken bool }

// waiter is an accepted connection waiting for its first event.
type waiter struct {
	qc     *qgo.Conn
	cancel context.CancelCauseFunc
}

func listen(network, address string, o Options) (*Listener, error) {
	tc, err := tlsConfig(o.TLS, true)
	if err != nil {
		return nil, err
	}
	laddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	l := &Listener{opts: o.norm(), udp: udp, done: make(chan struct{}), refs: 1}
	l.tr = &qgo.Transport{Conn: udp, StatelessResetKey: o.StatelessResetKey, ConnContext: l.connContext}
	if l.ql, err = l.tr.Listen(tc, quicConfig(o.Config, o.IdleTimeout, true, true)); err != nil {
		_ = l.tr.Close()
		_ = udp.Close()
		return nil, err
	}
	return l, nil
}

// connContext runs on quic-go's server goroutine for every new connection
// attempt, before any handshake state exists, and must not block (L48).
// Beyond MaxPending handshakes or MaxConns connections the attempt is
// refused (CONNECTION_REFUSED; the dialer's redial cadence retries). The
// token rides the connection's context; AfterFunc runs at its end.
func (l *Listener) connContext(ctx context.Context, _ *qgo.ClientInfo) (context.Context, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing || l.shaking >= l.opts.MaxPending || l.conns >= l.opts.MaxConns {
		l.stats.Refused++
		return nil, errRefused
	}
	l.shaking, l.conns = l.shaking+1, l.conns+1
	tok := &admToken{}
	context.AfterFunc(ctx, func() {
		l.mu.Lock()
		l.conns--
		l.unshakeLocked(tok)
		l.mu.Unlock()
	})
	return context.WithValue(ctx, admKey{}, tok), nil
}

func (l *Listener) unshakeLocked(tok *admToken) {
	if !tok.shaken {
		tok.shaken = true
		l.shaking--
	}
}

func (l *Listener) serve(h handoff) error {
	for {
		qc, err := l.ql.Accept(context.Background())
		if errors.Is(err, net.ErrClosed) {
			return net.ErrClosed
		} else if err != nil {
			return err
		}
		l.accept(h, qc)
	}
}

// accept classifies qc on a goroutine of its own (no blocking I/O in the
// accept loop, L48); beyond MaxPending classifications the oldest is
// evicted.
func (l *Listener) accept(h handoff, qc *qgo.Conn) {
	ctx, cancel := context.WithCancelCause(qc.Context())
	w := &waiter{qc: qc, cancel: cancel}
	l.mu.Lock()
	if tok, ok := qc.Context().Value(admKey{}).(*admToken); ok {
		l.unshakeLocked(tok)
	}
	l.refs++
	if l.closing {
		cancel(errListenerClosed)
	} else {
		if len(l.waiting) >= l.opts.MaxPending {
			l.waiting[0].cancel(errEvicted)
			l.waiting = slices.Delete(l.waiting, 0, 1)
			l.stats.Evicted++
		}
		l.waiting = append(l.waiting, w)
	}
	l.mu.Unlock()
	go l.classify(h, w, ctx)
}

// classify waits at most HandshakeTimeout for the connection's first
// client stream or DATAGRAM and hands the carrier to rendr. Both kinds,
// neither, another ALPN, a DATAGRAM limit below DatagramBudget, eviction
// and the Listener's close end the connection instead. Both kinds also
// when the stream comes after the hand-over of a datagram carrier: see
// watchLateStream.
func (l *Listener) classify(h handoff, w *waiter, ctx context.Context) {
	qc := w.qc
	ctx, stop := context.WithTimeoutCause(ctx, l.opts.HandshakeTimeout, errClassifyTimeout)
	type first struct {
		st *qgo.Stream
		dg []byte
	}
	ch := make(chan first, 2)
	go func() { st, _ := qc.AcceptStream(ctx); ch <- first{st: st} }()
	go func() { b, _ := qc.ReceiveDatagram(ctx); ch <- first{dg: b} }()
	a := <-ch
	stop()
	b := <-ch // the other waiter returns at once now (it may have succeeded too)
	cause := context.Cause(ctx)
	w.cancel(nil)
	if a.st == nil && a.dg == nil {
		a, b = b, a
	}
	alpn := qc.ConnectionState().TLS.NegotiatedProtocol == ALPN
	hand, mine, code := false, false, codeRefused
	l.mu.Lock()
	if i := slices.Index(l.waiting, w); i >= 0 {
		l.waiting, mine = slices.Delete(l.waiting, i, i+1), true
	}
	switch {
	case !mine: // evicted, or the Listener closed
		if errors.Is(cause, errListenerClosed) {
			code = codeListenerClosed
		}
	case !alpn || b.st != nil || b.dg != nil:
		l.stats.BadKind++
		code = codeBadKind
	case a.st == nil && a.dg == nil:
		if errors.Is(cause, errClassifyTimeout) {
			l.stats.ClassifyTimeouts++
		}
		code = codeHandshakeTimeout
	default:
		hand = true
	}
	l.mu.Unlock()
	rel := l.release(qc)
	switch {
	case !hand:
		rel(code)
	case a.st != nil:
		c := newStreamConn(qc, a.st, rel)
		if err := h.Handle(c); err != nil {
			_ = c.Close()
			return
		}
		l.bump(&l.stats.Streams)
	default:
		n, err := probeLimit(qc)
		if err != nil || n < DatagramBudget {
			l.bump(&l.stats.BudgetRefused)
			rel(codeBudget)
			return
		}
		d := newDgramConn(qc, a.dg, n, rel, &l.opts, &l.ctr)
		if err := h.HandlePacket(d, d.peer); err != nil {
			_ = d.Close() // pc stays ours on an error
			return
		}
		l.bump(&l.stats.Datagrams)
		go l.watchLateStream(qc, rel)
	}
}

// watchLateStream ends a handed datagram carrier whose peer opens its one
// allowed client stream after classification (W4-L2-3): nothing reads that
// stream, so quic-go would buffer up to InitialStreamReceiveWindow outside
// every rendr budget. The connection is closed with codeBadKind (BadKind
// counted); the carrier dies and rendr's session survives it (invariant 6).
// The goroutine ends with the connection.
func (l *Listener) watchLateStream(qc *qgo.Conn, rel func(qgo.ApplicationErrorCode)) {
	if _, err := qc.AcceptStream(qc.Context()); err != nil {
		return // the connection ended
	}
	l.bump(&l.stats.BadKind)
	rel(codeBadKind)
}

func (l *Listener) bump(p *uint64) {
	l.mu.Lock()
	*p++
	l.mu.Unlock()
}

// release returns the once-only close of an accepted connection, which
// drops the connection's reference on the shared Transport.
func (l *Listener) release(qc *qgo.Conn) func(qgo.ApplicationErrorCode) {
	var once sync.Once
	return func(code qgo.ApplicationErrorCode) {
		once.Do(func() {
			_ = qc.CloseWithError(code, "")
			l.unref()
		})
	}
}

// unref drops one reference; the last closes the Transport and the socket.
func (l *Listener) unref() {
	l.mu.Lock()
	l.refs--
	last := l.refs == 0
	l.mu.Unlock()
	if last {
		l.fin.Do(func() {
			_ = l.tr.Close()
			_ = l.udp.Close()
			close(l.done)
		})
	}
}
