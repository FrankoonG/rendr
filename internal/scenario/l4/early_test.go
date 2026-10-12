package l4

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestEarlyRejectThroughL4_L49 (plan:663, L49; M4-D11): an EarlyReturn L4
// session whose target refuses. One Link p1 of 20 ms RTT with dedicated
// carriers (CheapSubflow: the session dials a carrier of its own, so its
// first bytes ride the first flight); the Server's Dial hook is a
// ScriptedDial that refuses (ECONNREFUSED).
//
// Stimulus: l4.Dial with EarlyReturn returns before any network I/O (no
// factory call yet); the client's 32-KiB Write returns at once (below
// EarlyDataMax) and its bytes travel as early data: the passive end of the
// session's carrier read at least 32 KiB before the refusal reached the
// dialer; the hook was called once.
//
// PASS: the first Read returns the refusal, CodeRefused (a
// *rendr.RejectError, errors.Is ErrRejected), and so does the next Write;
// Done is closed; no target connection (the hook returned none, nothing
// unclosed) and the Server confirmed nothing — the passive application
// never read the early bytes; Status.BufferedBytes back to 0 on both
// Runtimes after Done; nothing left after Runtime.Close.
func TestEarlyRejectThroughL4_L49(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{}, linkSpec{name: "p1", props: rendr.Props{CheapSubflow: true}})
		peer := w.peer("p1")
		refused := w.scripted("refused", rendrtest.OutcomeRefuse())
		synctest.Wait()
		dials0 := w.dials("p1")
		c, err := l4.Dial(context.Background(), peer, "refused-1.test:80", rendr.DialOptions{EarlyReturn: true})
		if err != nil {
			t.Fatalf("Dial with EarlyReturn: %v", err)
		}
		synctest.Wait()
		if d := w.dials("p1") - dials0; d != 0 {
			t.Fatalf("stimulus: %d session factory calls before the first Write, want 0 (EarlyReturn)", d)
		}
		const early = 32 << 10
		buf := make([]byte, early)
		rendrtest.PRNG(71).Read(buf)
		start := time.Now()
		if n, err := c.Write(buf); n != early || err != nil {
			t.Fatalf("the early Write returned (%d, %v), want (%d, nil)", n, err, early)
		}
		if el := time.Since(start); el != 0 {
			t.Fatalf("the early Write took %v, want it to return at once", el)
		}
		n, rerr := c.Read(make([]byte, 1))
		if n != 0 {
			t.Fatalf("the first Read returned %d bytes", n)
		}
		if e := checkReject(rerr, l4.CodeRefused); e != nil {
			t.Fatalf("the first Read: %v", e)
		}
		if _, werr := c.Write(buf[:1]); checkReject(werr, l4.CodeRefused) != nil {
			t.Fatalf("the Write after the refusal returned %v, want the refusal", werr)
		}
		select {
		case <-c.Done():
		case <-time.After(time.Second):
			t.Fatalf("Done not closed after the refusal: %+v", c.Status())
		}
		var up int64
		for _, ci := range w.link("p1").Carriers() {
			if ci.Session {
				up += ci.Up
			}
		}
		if up < early {
			t.Fatalf("stimulus: the passive read %d bytes of the session carrier, want ≥ %d (the early data)", up, early)
		}
		if got, unclosed := refused.Calls(), refused.Unclosed(); got != 1 || unclosed != 0 {
			t.Fatalf("the refusing hook: %d calls, %d conns unclosed; want 1, 0", got, unclosed)
		}
		if st := w.srv.Status(); st.Confirmed != 0 || st.Rejected != 1 || st.ByCode[l4.CodeRefused] != 1 {
			t.Fatalf("Server %+v, want one rejection CodeRefused and nothing confirmed", plain(st))
		}
		waitFor(t, 5*time.Second, "BufferedBytes back to 0 on both Runtimes", func() bool {
			return w.d.Status().BufferedBytes == 0 && w.p.Status().BufferedBytes == 0
		})
		t.Logf("refused after %v; %d bytes up on the session carrier; dialer EarlyBytes %d", time.Since(start), up, c.Status().EarlyBytes)
		c.Close()
		w.noViolation()
		w.close()
	})
}
