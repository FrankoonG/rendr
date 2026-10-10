package rendr_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPassiveEndWhileViewHeldSendsRst (M4 checkpoint C-L finding; M3-D8,
// M4-D20): on a started MUX trunk a passive view is held after its OK
// until the dialer's go frame. A passive session that ends in that window —
// Conn.Abort right after Confirm, as an l4 Server does for a target that
// resets at once — still delivers its RST: the dialer's Dial succeeds and
// its Read returns the peer's *AbortError{code, Remote}. Before the fix the
// held view was retired with DETACH(ended) only and the RST dropped: the
// dialer rejoined, met UNKNOWN_SESSION and failed with ErrSessionLost (its
// Dial too, when the DETACH beat its session's start).
//
// Session 0 opens the trunk (handle 1) and stays open, so every later
// session is a view of the started trunk. Each iteration's passive
// confirms, writes 1 KiB and aborts at once; both ends close their side.
func TestPassiveEndWhileViewHeldSendsRst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const code = rendr.AbortCode(4242)
		const sessions = 200
		d, err := rendr.NewRuntime(rendr.Config{})
		if err != nil {
			t.Fatal(err)
		}
		p, err := rendr.NewRuntime(rendr.Config{})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := p.Listen(rendr.ListenConfig{})
		if err != nil {
			t.Fatal(err)
		}
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: ln.Handle})
		l.SetDelay(5*time.Millisecond, 0)
		peer, err := d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{rendr.StreamCarrier{Name: "a", Dial: l.Dial}}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			peer.Close()
			d.Close()
			p.Close()
			l.Close()
		}()
		ctx := context.Background()
		accepted := make(chan *rendr.Conn, 1)
		go func() {
			pend, err := ln.Accept(ctx)
			if err != nil {
				accepted <- nil
				return
			}
			pc, _ := pend.Confirm()
			accepted <- pc
		}()
		keep, err := peer.Dial(ctx, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("session 0: %v", err)
		}
		keepP := <-accepted
		if keepP == nil {
			t.Fatal("session 0 not accepted")
		}
		bad := 0
		for i := range sessions {
			done := make(chan error, 1)
			go func() {
				pend, err := ln.Accept(ctx)
				if err != nil {
					done <- err
					return
				}
				pc, err := pend.Confirm()
				if err != nil {
					done <- err
					return
				}
				pc.Write(make([]byte, 1<<10))
				done <- pc.Abort(code, "target reset")
			}()
			c, err := peer.Dial(ctx, rendr.DialOptions{})
			if err != nil {
				bad++
				t.Errorf("session %d: Dial: %v, want a Conn", i+1, err)
				<-done
				continue
			}
			view := false
			for _, cs := range c.Status().Carriers {
				view = view || cs.Handle > 1
			}
			if !view {
				t.Fatalf("premise: session %d is not a trunk view: %+v", i+1, c.Status().Carriers)
			}
			_, err = io.ReadAll(c)
			var ae *rendr.AbortError
			if !errors.As(err, &ae) || ae.Code != code || !ae.Remote {
				bad++
				t.Errorf("session %d: Read ended with %v, want the peer's *AbortError{%d, Remote}", i+1, err, code)
			}
			if err := <-done; err != nil {
				t.Errorf("session %d: passive: %v", i+1, err)
			}
			c.Close()
		}
		if bad > 0 {
			t.Logf("%d of %d sessions lost the peer's RST", bad, sessions)
		}
		keep.Close()
		keepP.Close()
	})
}
