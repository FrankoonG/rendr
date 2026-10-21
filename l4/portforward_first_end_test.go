package l4

import (
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2"
)

// TestPortForwardFirstRetryCounts_L37 (M6-D4, R1-4, R1-20; L37, L39): a
// first datagram the ingress let ride (its whole metadata within
// firstBudget) but whose OPEN a Handshake.MaxMetadata refused — the
// dialer's own (64: before any I/O) or the passive's (256, a 300-byte
// datagram: CodeMetadataSize) — is sent after the open by the ingress's
// flush, ahead of the queue, so its write's outcome is counted. Here the
// session has ended at that write (the flow's session closes at its first
// WriteTo): ToSession does not count the datagram, DropOpenQueue does
// (ToSession plus the drops is the client's one datagram), FirstInOpen is
// 0, the passive wrote no first datagram from an OPEN and the target
// received nothing. TestPortForwardFirstInOpenRetry_L37 is the live arm
// (ToSession 1, the target receives it exactly once).
func TestPortForwardFirstRetryCounts_L37(t *testing.T) {
	small := func(n int) (c rendr.Config) {
		c.Handshake.MaxMetadata = n
		return c
	}
	for _, tc := range []struct {
		name string
		pf   pfOpts
		size int
	}{
		{"dialer limit", pfOpts{dcfg: small(64)}, 60},
		{"passive limit", pfOpts{pcfg: small(256)}, 300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pwDialHook(t, func(_ []byte, s ingressSession) ingressSession { return &ucEndAtWrite{ingressSession: s} })
				w := newPWWorld(t, pwOpts{pf: tc.pf})
				w.serve()
				a := w.client()
				first := pwTagged(tc.size, 0xA2, 0)
				if bareLen := len(mustUDPMetadata(t, nil)); bareLen+len(first) > firstBudget {
					t.Fatalf("premise: a %d-byte first datagram does not fit firstBudget", len(first))
				}
				pfSend(t, a, first)
				ucEnded(t, w, "stopped (the session closed at the write)", func(e FlowEnds) uint64 { return e.Stopped })
				synctest.Wait()
				st := pwStatus(w.pf)
				_, _, firstSent, flows := w.pas.snapshot()
				t.Logf("passive first datagrams from an OPEN %d, flows %d; %s", firstSent, len(flows), pwDescribe(st))
				if st.Opened != 1 || st.Failed != 0 || st.FirstInOpen != 0 || firstSent != 0 {
					t.Fatalf("stimulus: Opened %d, Failed %d, FirstInOpen %d, passive FirstSent %d; want one open by the retry without the datagram (%s)",
						st.Opened, st.Failed, st.FirstInOpen, firstSent, pwDescribe(st))
				}
				if st.ToSession != 0 || st.DropOpenQueue != 1 || st.DropOpenAge != 0 || st.SessionDrops != 0 {
					t.Fatalf("ToSession %d, DropOpenQueue %d, DropOpenAge %d, SessionDrops %d; want 0, 1, 0, 0: a datagram the ended session refused is a drop (%s)",
						st.ToSession, st.DropOpenQueue, st.DropOpenAge, st.SessionDrops, pwDescribe(st))
				}
				for _, fl := range flows {
					if rx := fl.received(); len(rx) != 0 {
						t.Fatalf("the target received %d datagrams, want none", len(rx))
					}
				}
				pfNone(t, a)
			})
		})
	}
}
