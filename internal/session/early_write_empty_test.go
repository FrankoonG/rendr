package session

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

// TestEarlyReturnEmptyWriteTriggersOpen (M4-D9, §A4.1; K21): a Write of no
// bytes that succeeds is a Write: it returns (0, nil) and opens the
// session (an OPEN without EARLY: it admitted nothing), whose next bytes
// are delivered after the verdict. A Write of no bytes that fails (its
// deadline passed) opens nothing, as a failing Write of bytes does.
func TestEarlyReturnEmptyWriteTriggersOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fl eaFlights
		w := eaNewWorld(t, fl.hooks())
		defer w.teardown()
		l := w.eaLink("a")
		s := w.eaDial(w.eaSpec(ModeSelector, 64<<10, l))
		if err := s.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if n, err := s.Write(nil); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write(nil) past its deadline = (%d, %v), want (0, os.ErrDeadlineExceeded)", n, err)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if d := l.Stats().Dials; d != 0 || s.State() != StatePending {
			t.Fatalf("a failing Write(nil) opened the session: %d factory calls, state %v", d, s.State())
		}
		if err := s.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if n, err := s.Write([]byte{}); n != 0 || err != nil {
			t.Fatalf("Write of no bytes = (%d, %v), want (0, nil)", n, err)
		}
		p := w.eaPending()
		if d := l.Stats().Dials; d != 1 {
			t.Fatalf("%d factory calls after the empty Write, want 1", d)
		}
		if e, eo := eaEarly(p); e != 0 || eo {
			t.Fatalf("passive early %d, EARLY OPEN %v: want an OPEN without EARLY", e, eo)
		}
		if ks := fl.get(); len(ks) != 0 {
			t.Fatalf("early first flights %v, want none", ks)
		}
		if err := p.Confirm(); err != nil {
			t.Fatal(err)
		}
		acWaitFor(t, 5*time.Second, "the dialer opened", func() bool { return s.State() == StateOpen })
		msg := stPattern(0, 300)
		if n, err := s.Write(msg); n != len(msg) || err != nil {
			t.Fatalf("Write after the open = (%d, %v)", n, err)
		}
		if got := stReadN(t, p, len(msg)); !bytes.Equal(got, msg) {
			t.Fatal("the passive read other bytes")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Write(nil); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write(nil) after Close: %v, want net.ErrClosed", err)
		}
	})
}
