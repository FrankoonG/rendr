package quic

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestQUICStreamConnClose_L05_L52: the stream adapter carries bytes both
// ways; Close returns at once with a blocked Read and a blocked Write
// unblocked (SetDeadline(now) first, L52), later calls fail with
// net.ErrClosed, the FIN follows what was written so the peer reads it all
// and then io.EOF, and the QUIC connection — with a dialer's own socket —
// ends after the bounded linger (L05).
func TestQUICStreamConnClose_L05_L52(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	t.Run("data, addresses", func(t *testing.T) {
		cli, srv, _ := streamPair(t, Options{}, Options{})
		data := bytes.Repeat([]byte("rendr/2 "), 32<<10)
		for _, p := range []struct{ w, r net.Conn }{{cli, srv}, {srv, cli}} {
			go p.w.Write(data)
			got := make([]byte, len(data))
			if _, err := io.ReadFull(p.r, got); err != nil || !bytes.Equal(got, data) {
				t.Fatalf("256 KiB: %v", err)
			}
		}
		if ra, ok := cli.RemoteAddr().(*net.UDPAddr); !ok || cli.RemoteAddr() != ra || ra.Port == 0 {
			t.Errorf("RemoteAddr %v", cli.RemoteAddr())
		}
		if cli.LocalAddr() == nil || srv.LocalAddr() == nil {
			t.Error("no LocalAddr")
		}
	})
	t.Run("close unblocks", func(t *testing.T) {
		cli, _, _ := streamPair(t, Options{}, Options{})
		read, write := make(chan error, 1), make(chan error, 1)
		go func() { _, err := cli.Read(make([]byte, 8)); read <- err }()
		go func() { _, err := cli.Write(make([]byte, 64<<20)); write <- err }() // beyond the peer's window: blocks
		time.Sleep(100 * time.Millisecond)                                      // the calls block; one that has not yet fails at once with net.ErrClosed
		start, closed := time.Now(), make(chan error, 1)
		go func() { closed <- cli.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close blocked behind a blocked Write")
		}
		for name, c := range map[string]chan error{"Read": read, "Write": write} {
			select {
			case err := <-c:
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("blocked %s returned %v, want net.ErrClosed", name, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("Close did not unblock %s", name)
			}
		}
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Errorf("Close took %v to unblock the calls", d)
		}
		if _, err := cli.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Write after Close: %v", err)
		}
		if _, err := cli.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Read after Close: %v", err)
		}
	})
	t.Run("fin and linger", func(t *testing.T) {
		cli, srv, _ := streamPair(t, Options{}, Options{})
		data := bytes.Repeat([]byte{7}, 100<<10)
		type result struct {
			b   []byte
			err error
		}
		got := make(chan result, 1)
		go func() { b, err := io.ReadAll(srv); got <- result{b, err} }() // reads while the bytes arrive
		if _, err := cli.Write(data); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_ = cli.Close()
		select {
		case <-cli.(*streamConn).qc.Context().Done():
		case <-time.After(2 * time.Second):
			t.Fatal("the connection outlived the linger")
		}
		if d := time.Since(start); d < 50*time.Millisecond {
			t.Errorf("CONNECTION_CLOSE %v after Close: no linger for the peer's reader", d)
		}
		if r := <-got; r.err != nil || !bytes.Equal(r.b, data) {
			t.Errorf("the peer read %d of %d bytes, then %v instead of io.EOF", len(r.b), len(data), r.err)
		}
	})
	t.Run("dialer socket released", func(t *testing.T) {
		l, _ := serveFake(t, Options{})
		tc, _ := tlsConfig(clientOptions(t).TLS, false)
		o := Options{}.norm()
		w, err := dial(dialCtx(t), l.Addr().String(), tc, &o, false)
		if err != nil {
			t.Fatal(err)
		}
		if la := w.udp.LocalAddr().(*net.UDPAddr); !la.IP.IsLoopback() {
			t.Errorf("a loopback peer's carrier bound %v", la)
		}
		w.close(codeClosed)
		if _, err := w.udp.WriteTo([]byte{1}, l.Addr()); !errors.Is(err, net.ErrClosed) {
			t.Errorf("the carrier's socket is still open: %v", err)
		}
	})
}
