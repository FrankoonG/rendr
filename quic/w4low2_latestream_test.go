package quic

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
	qgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// streamBytesTracer records the highest stream offset the passive's
// connections received (STREAM frame offset plus length): the bytes the
// passive accepted into a stream's receive buffer.
type streamBytesTracer struct{ top atomic.Int64 }

func (s *streamBytesTracer) trace(context.Context, bool, qgo.ConnectionID) qlogwriter.Trace {
	return s
}
func (s *streamBytesTracer) AddProducer() qlogwriter.Recorder { return s }
func (s *streamBytesTracer) SupportsSchemas(string) bool      { return true }
func (s *streamBytesTracer) Close() error                     { return nil }

func (s *streamBytesTracer) RecordEvent(e qlogwriter.Event) {
	p, ok := e.(qlog.PacketReceived)
	if !ok {
		return
	}
	for _, fr := range p.Frames {
		if sf, ok := fr.Frame.(*qlog.StreamFrame); ok {
			for end := sf.Offset + sf.Length; ; {
				cur := s.top.Load()
				if end <= cur || s.top.CompareAndSwap(cur, end) {
					break
				}
			}
		}
	}
}

// TestQUICLateStreamOnDatagramCarrier_L48 (W4-L2-3): a connection handed
// over as a datagram carrier that opens its one allowed client stream
// afterwards is no rendr carrier either. Nothing in rendr reads that
// stream, so quic-go would buffer up to InitialStreamReceiveWindow per
// connection outside every rendr budget; the Listener closes the
// connection with codeBadKind instead and counts BadKind. The carrier
// dies (its ReadFrom fails, never returns stream bytes as datagrams); a
// second datagram carrier on the same Listener that opens no stream keeps
// working.
func TestQUICLateStreamOnDatagramCarrier_L48(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	srvTLS, _ := testTLS(t)
	tr := &streamBytesTracer{}
	l, f := serveFake(t, Options{TLS: srvTLS, Config: &qgo.Config{Tracer: tr.trace}})
	dial := func() *qgo.Conn {
		qc, err := rawTransport(t).Dial(dialCtx(t), l.Addr(), rawClientTLS(t), quicConfig(nil, 0, false, true))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
		return qc
	}
	read := func(d *dgramConn, want string) {
		t.Helper()
		buf := make([]byte, DatagramBudget+1)
		_ = d.SetReadDeadline(time.Now().Add(handTimeout))
		n, from, err := d.ReadFrom(buf)
		if err != nil || string(buf[:n]) != want || from != d.peer {
			t.Fatalf("datagram %q from %v, %v; want %q", buf[:n], from, err, want)
		}
	}

	// A datagram carrier, handed over intact.
	qc := dial()
	if err := qc.SendDatagram([]byte("classify")); err != nil {
		t.Fatal(err)
	}
	d := f.packet(t)
	t.Cleanup(func() { _ = d.Close() })
	read(d, "classify")

	// Stimulus and load: the one allowed client stream, opened after the
	// hand-over, carrying 1 MiB (the InitialStreamReceiveWindow) under a
	// 2 s write deadline.
	st, err := qc.OpenStreamSync(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetWriteDeadline(time.Now().Add(2 * time.Second))
	type res struct {
		n   int
		err error
	}
	wrote := make(chan res, 1)
	go func() {
		n, err := st.Write(make([]byte, 1<<20))
		wrote <- res{n, err}
	}()
	if code, remote := closeCode(t, qc); code != codeBadKind || !remote {
		t.Fatalf("closed with %d (remote %v), want codeBadKind from the passive", code, remote)
	}
	w := <-wrote
	t.Logf("client wrote %d bytes (%v); the passive received stream bytes up to offset %d", w.n, w.err, tr.top.Load())

	// The handed carrier dies with the connection: ReadFrom reports the
	// end and never delivers stream bytes as a datagram.
	buf := make([]byte, DatagramBudget+1)
	_ = d.SetReadDeadline(time.Now().Add(handTimeout))
	if n, _, err := d.ReadFrom(buf); err == nil {
		t.Fatalf("handed carrier still reads (%d bytes) after the late stream", n)
	} else if isTimeout(err) {
		t.Fatalf("handed carrier still alive after the late stream: %v", err)
	}
	eventually(t, "the handed carrier's writes fail", func() bool {
		_, err := d.WriteTo([]byte("x"), nil)
		return err != nil
	})

	// A second datagram carrier that opens no stream keeps working.
	qc2 := dial()
	if err := qc2.SendDatagram([]byte("second")); err != nil {
		t.Fatal(err)
	}
	d2 := f.packet(t)
	t.Cleanup(func() { _ = d2.Close() })
	read(d2, "second")
	if err := qc2.SendDatagram([]byte("still")); err != nil {
		t.Fatal(err)
	}
	read(d2, "still")
	if err := context.Cause(qc2.Context()); err != nil {
		t.Fatalf("second carrier ended: %v", err)
	}

	if s := l.Stats(); s.BadKind != 1 || s.Datagrams != 2 || s.Streams != 0 {
		t.Errorf("stats %+v, want BadKind 1, Datagrams 2, Streams 0", s)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
