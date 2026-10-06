package quic

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
	qgo "github.com/quic-go/quic-go"
)

// TestQUICLazyStreamBounded_L48: admission is bounded before any
// handshake state (MaxPending handshakes, MaxConns connections, refusals
// counted); connections that complete the handshake and stay silent never
// block the accept loop: beyond MaxPending the oldest is evicted, the rest
// close at HandshakeTimeout, a good carrier is handed over within 1 s, and
// every goroutine returns.
func TestQUICLazyStreamBounded_L48(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	t.Run("admission", func(t *testing.T) {
		l := &Listener{opts: Options{MaxPending: 4, MaxConns: 6}.norm()}
		admit := func() (context.CancelCauseFunc, *admToken, error) {
			ctx, cancel := context.WithCancelCause(context.Background())
			c, err := l.connContext(ctx, nil)
			if err != nil {
				cancel(err)
				return nil, nil, err
			}
			return cancel, c.Value(admKey{}).(*admToken), nil
		}
		var cancels []context.CancelCauseFunc
		var toks []*admToken
		for range 4 {
			c, tok, err := admit()
			if err != nil {
				t.Fatal(err)
			}
			cancels, toks = append(cancels, c), append(toks, tok)
		}
		if _, _, err := admit(); !errors.Is(err, errRefused) {
			t.Fatalf("a 5th handshake beyond MaxPending: %v", err)
		}
		l.mu.Lock()
		for _, tok := range toks[:3] { // three handshakes completed (Accept)
			l.unshakeLocked(tok)
		}
		l.mu.Unlock()
		for range 2 {
			c, _, err := admit()
			if err != nil {
				t.Fatal(err)
			}
			cancels = append(cancels, c)
		}
		if _, _, err := admit(); !errors.Is(err, errRefused) {
			t.Fatalf("a 7th connection beyond MaxConns: %v", err)
		}
		cancels[0](nil) // a connection ends
		eventually(t, "the ended connection's slot is free", func() bool {
			l.mu.Lock()
			defer l.mu.Unlock()
			return l.conns == 5 && l.shaking == 3
		})
		if c, _, err := admit(); err != nil {
			t.Fatal(err)
		} else {
			cancels = append(cancels, c)
		}
		if s := l.Stats(); s.Refused != 2 {
			t.Errorf("refused %d, want 2", s.Refused)
		}
		for _, c := range cancels {
			c(nil)
		}
		eventually(t, "every slot is free", func() bool {
			l.mu.Lock()
			defer l.mu.Unlock()
			return l.conns == 0 && l.shaking == 0
		})
	})
	t.Run("silent connections", func(t *testing.T) {
		l, f := serveFake(t, Options{MaxPending: 4, HandshakeTimeout: time.Second})
		tr := rawTransport(t)
		var silent []*qgo.Conn
		for range 12 {
			qc, err := tr.Dial(dialCtx(t), l.Addr(), rawClientTLS(t), quicConfig(nil, 0, false, true))
			if err != nil {
				t.Fatal(err)
			}
			defer qc.CloseWithError(0, "")
			silent = append(silent, qc)
		}
		eventually(t, "8 silent connections evicted", func() bool { return l.Stats().Evicted >= 8 })
		for i, qc := range silent[:8] {
			if code, remote := closeCode(t, qc); code != codeRefused || !remote {
				t.Errorf("silent connection %d: code %d (remote %v), want eviction", i, code, remote)
			}
		}
		sc, err := StreamCarrier("q", l.Addr().String(), clientOptions(t))
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		c, err := sc.Dial(dialCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte("PREFACE")); err != nil {
			t.Fatal(err)
		}
		handed := f.stream(t)
		defer handed.Close()
		if d := time.Since(start); d > time.Second {
			t.Errorf("the good carrier was handed over after %v", d)
		}
		for i, qc := range silent[8:] {
			if code, remote := closeCode(t, qc); code != codeHandshakeTimeout && code != codeRefused || !remote {
				t.Errorf("silent connection %d: code %d (remote %v)", 8+i, code, remote)
			}
		}
		s := l.Stats()
		if s.Evicted+s.ClassifyTimeouts != 12 || s.ClassifyTimeouts == 0 || s.Streams != 1 {
			t.Errorf("stats %+v: want 12 silent connections evicted or timed out, one stream carrier", s)
		}
	})
}

// TestQUICBothKindsRejected: a connection that opens a stream and sends a
// DATAGRAM is no rendr carrier: it is closed with codeBadKind.
func TestQUICBothKindsRejected(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	srvTLS, _ := testTLS(t)
	ft := &frameTracer{}
	l, err := Listen("udp4", "127.0.0.1:0", Options{TLS: srvTLS, Config: &qgo.Config{Tracer: ft.trace}})
	if err != nil {
		t.Fatal(err)
	}
	qc, err := rawTransport(t).Dial(dialCtx(t), l.Addr(), rawClientTLS(t), quicConfig(nil, 0, false, true))
	if err != nil {
		t.Fatal(err)
	}
	defer qc.CloseWithError(0, "")
	st, err := qc.OpenStreamSync(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("PREFACE")); err != nil {
		t.Fatal(err)
	}
	if err := qc.SendDatagram([]byte("PREFACE")); err != nil {
		t.Fatal(err)
	}
	// Classification takes the first event, then the other only if it is
	// already there: the passive handles both frames before Serve accepts
	// the connection.
	eventually(t, "the passive handled the stream and the DATAGRAM", func() bool {
		return ft.rcvStreams.Load() > 0 && ft.rcvDatagrams.Load() > 0
	})
	f := newFakeRendr()
	served := make(chan error, 1)
	go func() { served <- l.serve(f) }()
	if code, remote := closeCode(t, qc); code != codeBadKind || !remote {
		t.Errorf("closed with %d (remote %v), want codeBadKind", code, remote)
	}
	if s := l.Stats(); s.BadKind != 1 || s.Streams+s.Datagrams != 0 || len(f.streams)+len(f.packets) != 0 {
		t.Errorf("stats %+v", s)
	}
	_ = l.Close()
	if err := <-served; !errors.Is(err, net.ErrClosed) {
		t.Errorf("Serve: %v", err)
	}
	<-l.Done()
}

// TestQUICListenerCloseKeepsCarriers: closing the Listener stops
// accepting but leaves the carriers handed to rendr running on the shared
// socket; Done closes once the last of them closed. A connection still
// classifying is closed at once (codeListenerClosed), not left to its
// HandshakeTimeout.
func TestQUICListenerCloseKeepsCarriers(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	t.Run("handed carriers keep running", testListenerCloseHanded)
	t.Run("classifying connections closed", func(t *testing.T) {
		srvTLS, _ := testTLS(t)
		l, err := Listen("udp4", "127.0.0.1:0", Options{TLS: srvTLS, HandshakeTimeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan error, 1)
		go func() { served <- l.serve(newFakeRendr()) }()
		qc, err := rawTransport(t).Dial(dialCtx(t), l.Addr(), rawClientTLS(t), quicConfig(nil, 0, false, true))
		if err != nil {
			t.Fatal(err)
		}
		defer qc.CloseWithError(0, "")
		eventually(t, "the silent connection is classifying", func() bool {
			l.mu.Lock()
			defer l.mu.Unlock()
			return len(l.waiting) == 1
		})
		start := time.Now()
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		if code, remote := closeCode(t, qc); code != codeListenerClosed || !remote {
			t.Errorf("closed with %d (remote %v), want codeListenerClosed", code, remote)
		}
		select {
		case <-l.Done():
		case <-time.After(testEventuallyTime):
			t.Fatal("Done not closed")
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("the classifying connection and Done ended %v after Listener.Close", d)
		}
		if err := <-served; !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve after Close: %v", err)
		}
	})
}

func testListenerCloseHanded(t *testing.T) {
	so, _ := testTLS(t)
	l, err := Listen("udp4", "127.0.0.1:0", Options{TLS: so})
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeRendr()
	served := make(chan error, 1)
	go func() { served <- l.serve(f) }()
	sc, err := StreamCarrier("s", l.Addr().String(), clientOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	dc, err := DatagramCarrier("d", l.Addr().String(), clientOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := sc.Dial(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	pc, _, err := dc.Dial(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	cd := pc.(*dgramConn)
	defer cd.Close()
	if _, err := cs.Write([]byte("s")); err != nil {
		t.Fatal(err)
	}
	if _, err := cd.WriteTo([]byte("d"), nil); err != nil {
		t.Fatal(err)
	}
	ss, sd := f.stream(t), f.packet(t)
	buf := make([]byte, 64)
	if _, err := io.ReadFull(ss, buf[:1]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sd.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-served; !errors.Is(err, net.ErrClosed) {
		t.Errorf("Serve after Close: %v", err)
	}
	for i := range 3 {
		for _, p := range []struct{ w, r net.Conn }{{cs, ss}, {ss, cs}} {
			if _, err := p.w.Write([]byte{byte(i)}); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(p.r, buf[:1]); err != nil || buf[0] != byte(i) {
				t.Fatalf("stream carrier after Listener.Close: %v", err)
			}
		}
		for _, p := range []struct{ w, r *dgramConn }{{cd, sd}, {sd, cd}} {
			if _, err := p.w.WriteTo([]byte{byte(i)}, nil); err != nil {
				t.Fatal(err)
			}
			if n, _, err := p.r.ReadFrom(buf); err != nil || n != 1 || buf[0] != byte(i) {
				t.Fatalf("datagram carrier after Listener.Close: %v", err)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if c, err := sc.Dial(ctx); err == nil {
		c.Close()
		t.Error("a closed Listener accepted a new carrier")
	}
	select {
	case <-l.Done():
		t.Fatal("Done closed while carriers were alive")
	default:
	}
	_ = ss.Close()
	_ = sd.Close()
	select {
	case <-l.Done():
	case <-time.After(testEventuallyTime):
		t.Fatal("Done not closed after the last carrier closed")
	}
}
