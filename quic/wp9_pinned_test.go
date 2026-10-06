package quic

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
	qgo "github.com/quic-go/quic-go"
)

// TestQUICGoPinnedBehaviour pins the quic-go v0.63.0 behaviours the
// adapters are built on (M2 design A12 risk 14; quic brief §3, §5): an
// upgrade that changes one fails here, before an adapter silently breaks.
// The oversize probe is pinned by TestDatagramLimitProbe_L37.
func TestQUICGoPinnedBehaviour(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	t.Run("receive queue drops silently at 128", func(t *testing.T) { // why the pump exists (L46)
		cli, srv := rawPair(t, nil, nil)
		for i := range 200 {
			if err := cli.SendDatagram(seqDatagram(i, 100)); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(300 * time.Millisecond)
		got := 0
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			b, err := srv.ReceiveDatagram(ctx)
			cancel()
			if err != nil {
				break
			}
			if got == 0 {
				t.Logf("first queued seq %d", binary.BigEndian.Uint32(b))
			}
			got++
		}
		if got != 128 {
			t.Errorf("an unread receiver kept %d of 200 datagrams, want quic-go's 128", got)
		}
	})
	t.Run("fresh slices", func(t *testing.T) { // the pump moves ownership without copying (L46)
		cli, srv := rawPair(t, nil, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var held [][]byte
		for i := range 65 {
			if err := cli.SendDatagram(seqDatagram(i, 300)); err != nil {
				t.Fatal(err)
			}
			b, err := srv.ReceiveDatagram(ctx)
			if err != nil {
				t.Fatal(err)
			}
			held = append(held, b)
		}
		for _, b := range held {
			if !bytes.Equal(b, seqDatagram(int(binary.BigEndian.Uint32(b)), 300)) {
				t.Fatalf("a received datagram changed after later receptions")
			}
		}
	})
	t.Run("SendDatagram blocks at 32 queued", func(t *testing.T) { // why the egress queue exists (R1-9)
		str := rawTransport(t)
		srvTLS, _ := testTLS(t)
		srvTLS.NextProtos = []string{ALPN}
		ln, err := str.Listen(srvTLS, quicConfig(nil, 0, true, true))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		relay := newRateRelay(t, str.Conn.LocalAddr(), 0)
		cli, err := rawTransport(t).Dial(dialCtx(t), relay.pc.LocalAddr(), rawClientTLS(t), quicConfig(nil, 0, false, true))
		if err != nil {
			t.Fatal(err)
		}
		srv, err := ln.Accept(dialCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		defer srv.CloseWithError(0, "")
		relay.limited.Store(true) // the path drops everything from now on: no ACKs return
		var done atomic.Int64
		ended := make(chan error, 1)
		go func() {
			for range 300 {
				if err := cli.SendDatagram(make([]byte, 1000)); err != nil {
					ended <- err
					return
				}
				done.Add(1)
			}
			ended <- nil
		}()
		time.Sleep(time.Second)
		if n := done.Load(); n >= 150 {
			t.Errorf("%d of 300 SendDatagram calls returned on a path that acknowledges nothing", n)
		}
		_ = cli.CloseWithError(0, "")
		select {
		case err := <-ended:
			if err == nil {
				t.Error("every SendDatagram returned")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a blocked SendDatagram did not return at the close")
		}
	})
	t.Run("CONNECTION_CLOSE discards unread stream data", func(t *testing.T) { // why the stream linger exists
		cli, srv := rawPair(t, quicConfig(nil, 0, false, false), nil)
		st, err := cli.OpenStreamSync(dialCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Write(make([]byte, 64<<10)); err != nil {
			t.Fatal(err)
		}
		_ = cli.CloseWithError(7, "bye")
		time.Sleep(200 * time.Millisecond)
		n := 0
		var rerr error
		if ss, err := srv.AcceptStream(dialCtx(t)); err != nil {
			rerr = err
		} else {
			n, rerr = ss.Read(make([]byte, 64<<10))
		}
		if ae := (*qgo.ApplicationError)(nil); n != 0 || !errors.As(rerr, &ae) || ae.ErrorCode != 7 {
			t.Errorf("read %d bytes after the peer's CONNECTION_CLOSE: %v", n, rerr)
		}
	})
	t.Run("deadlines wake blocked stream calls", func(t *testing.T) { // what streamConn.Close relies on
		cli, srv := rawPair(t, quicConfig(nil, 0, false, false), nil)
		st, err := cli.OpenStreamSync(dialCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		ss, err := srv.AcceptStream(dialCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ss.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		read, write := make(chan error, 1), make(chan error, 1)
		go func() { _, err := ss.Read(make([]byte, 1)); read <- err }()        // the dialer sends nothing more
		go func() { _, err := ss.Write(make([]byte, 64<<20)); write <- err }() // the dialer reads nothing
		time.Sleep(100 * time.Millisecond)
		_ = ss.SetDeadline(time.Now())
		for _, c := range []chan error{read, write} {
			select {
			case err := <-c:
				var ne net.Error
				if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() {
					t.Errorf("woken with %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("a deadline did not wake a blocked call")
			}
		}
	})
	t.Run("close errors are timeouts", func(t *testing.T) { // why connErr wraps them
		for _, err := range []error{&qgo.IdleTimeoutError{}, &qgo.HandshakeTimeoutError{}} {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() || !errors.Is(err, net.ErrClosed) {
				t.Errorf("%T: Timeout %v", err, ne != nil && ne.Timeout())
			}
			if errors.As(connErr(err), &ne); ne.Timeout() || !errors.As(connErr(err), new(*qgo.IdleTimeoutError)) &&
				!errors.As(connErr(err), new(*qgo.HandshakeTimeoutError)) {
				t.Errorf("connErr(%T) is a deadline error or lost the QUIC error", err)
			}
		}
		if err := connErr(os.ErrDeadlineExceeded); err != os.ErrDeadlineExceeded {
			t.Errorf("a deadline expiry was wrapped: %v", err)
		}
	})
}
