//go:build unix || windows

package l4

import (
	"testing"
	"testing/synctest"
	"time"

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

// TestPortForwardFirstRetryAgeOrder_L37 (M6-D4, R1-4, R1-20; L37, L40): a
// first datagram whose OPEN a Handshake.MaxMetadata refused — the
// dialer's own (64) or the passive's (256, a 300-byte datagram) — heads
// the flush after the retry's open: it is sent ahead of the datagrams the
// client sent while the retry was opening, and it ages from its arrival
// (the 1-s rule of the opening queue). The passive holds the retry's OPEN
// for 500 ms or 1.2 s after the first datagram; two 50-byte datagrams
// arrive 300 ms before it is let through. In time, the target receives
// [0, 1, 2] (ToSession 3, DropOpenAge 0); aged, it receives [1, 2]
// (ToSession 2, DropOpenAge 1). FirstInOpen is 0 in every arm.
func TestPortForwardFirstRetryAgeOrder_L37(t *testing.T) {
	small := func(n int) (c rendr.Config) {
		c.Handshake.MaxMetadata = n
		return c
	}
	for _, lim := range []struct {
		name string
		pf   pfOpts
		size int
	}{
		{"dialer limit", pfOpts{dcfg: small(64)}, 60},
		{"passive limit", pfOpts{pcfg: small(256)}, 300},
	} {
		for _, tc := range []struct {
			name string
			hold time.Duration // the passive holds the retry's OPEN this long after the first datagram
			want []int
			aged uint64
		}{
			{"in time", 500 * time.Millisecond, []int{0, 1, 2}, 0},
			{"aged", 1200 * time.Millisecond, []int{1, 2}, 1},
		} {
			t.Run(lim.name+"/"+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					gate := make(chan struct{})
					w := newPWWorld(t, pwOpts{pf: lim.pf, target: pwSink, gate: func(int, Request) <-chan struct{} { return gate }})
					w.serve()
					c := w.client()
					first := pwTagged(lim.size, 0xA3, 0)
					if bareLen := len(mustUDPMetadata(t, nil)); bareLen+len(first) > firstBudget {
						t.Fatalf("premise: a %d-byte first datagram does not fit firstBudget", len(first))
					}
					pfSend(t, c, first)
					synctest.Wait()
					time.Sleep(tc.hold - 300*time.Millisecond)
					pfSend(t, c, pwTagged(50, 0xA3, 1))
					pfSend(t, c, pwTagged(50, 0xA3, 2))
					time.Sleep(300 * time.Millisecond)
					synctest.Wait()
					close(gate)
					time.Sleep(time.Second)
					synctest.Wait()
					_, _, firstSent, flows := w.pas.snapshot()
					st := pwStatus(w.pf)
					if len(flows) != 1 || st.Opened != 1 || st.FirstInOpen != 0 || firstSent != 0 {
						t.Fatalf("stimulus: %d flows, Opened %d, FirstInOpen %d, passive FirstSent %d; want one open by the retry without the datagram (%s)",
							len(flows), st.Opened, st.FirstInOpen, firstSent, pwDescribe(st))
					}
					var got []int
					for _, b := range flows[0].received() {
						got = append(got, pwSeq(b))
					}
					if !equalInts(got, tc.want) || st.DropOpenAge != tc.aged || st.ToSession != uint64(len(tc.want)) || st.DropOpenQueue != 0 {
						t.Fatalf("the target received %v, want %v; DropOpenAge %d, want %d; ToSession %d, DropOpenQueue %d (%s)",
							got, tc.want, st.DropOpenAge, tc.aged, st.ToSession, st.DropOpenQueue, pwDescribe(st))
					}
				})
			})
		}
	}
}
