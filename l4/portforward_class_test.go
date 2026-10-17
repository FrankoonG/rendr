package l4

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP6 (m6-design §A5.1, §A8.3, §A16.1): the ingress applies the flow
// classes to its own sessions (M6-D8, M6-D9: each end on its own). The kit
// passive's idle expiry is off in these rows, so every idle end is the
// ingress's.

// pwStreamUp makes c's flow a stream under either rule: round trips every
// 200 ms for about 3.4 s (both directions within one activity period
// longer than 2 s). It returns the instant of the last echo.
func pwStreamUp(t testing.TB, c *rendrtest.DatagramConn, tag byte) time.Time {
	t.Helper()
	for k := range 16 {
		if !pwRoundTrip(t, c, pwTagged(30, tag, k), time.Second) {
			t.Fatalf("flow %#x: round trip %d lost", tag, k)
		}
		if k < 15 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	return time.Now()
}

// pwEndTimes waits at most d for the ends of the kit passive's flows whose
// first datagrams were tagged tags and returns each one's instant
// (missing: still running at d). An ingress idle end reaches the passive
// as an abort one one-way delay later (5 ms).
func pwEndTimes(t testing.TB, w *pwWorld, d time.Duration, tags ...byte) map[byte]time.Time {
	t.Helper()
	type end struct {
		tag byte
		at  time.Time
	}
	ch := make(chan end, len(tags))
	for _, tag := range tags {
		var fl *pwFlow
		if _, ok := pwWaitFor(pfWithin, func() bool { fl = w.pas.flowOf(tag); return fl != nil }); !ok {
			t.Fatalf("kit: no passive flow tagged %#x", tag)
		}
		go func() {
			r := <-fl.res
			ch <- end{tag, time.Now()}
			fl.res <- r
		}()
	}
	out := map[byte]time.Time{}
	timeout := time.After(d)
	for len(out) < len(tags) {
		select {
		case e := <-ch:
			out[e.tag] = e.at
		case <-timeout:
			return out
		}
	}
	return out
}

// pwRuleName names a promotion rule in a row's name.
func pwRuleName(r promoteMode) string {
	return map[promoteMode]string{promoteActive: "active rule", promoteOnReply: "reply rule"}[r]
}

// TestPortForwardIngressClasses_L30_L72 (M6-D8, M6-D9, §A5.1, §A8.3,
// R1-7, R1-19; L30, L72): under both rules (promoteActive in force,
// promoteOnReply through the test hook) the ingress sets its session's
// idle limit from the flow's class — Short from the open, Stream once at
// the promotion:
//   - default classes: a stream (a 3-s two-way exchange) idle 60 s, beyond
//     Short (30 s), keeps its session: its next datagram crosses on the
//     same flow (one OPEN, no end);
//   - Idle{Short: 10 s, Stream: 40 s}: an unanswered flow ends 10 s after
//     its datagram; a stream 40 s after its last datagram; a one-shot
//     exchange 10 s after its answer under the active rule (it stays
//     short) and 40 s after it under the reply rule (its answer made it a
//     stream);
//   - Idle{Short: 10 s, Stream: −1}: a stream has no idle end at the
//     ingress (200 s idle, beyond the default Stream, then its next
//     datagram crosses on the same flow), while an unanswered flow still
//     ends at Short.
//
// Each end, seen at the passive (the ingress's abort, one one-way delay
// later), is measured from the flow's last datagram and lies within
// [limit, limit + 1.5 s] (the idle clock follows a received datagram up
// to PacketPing, 1 s, late).
func TestPortForwardIngressClasses_L30_L72(t *testing.T) {
	sinkB1 := func(fl *pwFlow) { // 0xB1's target never answers; the others echo
		if tagOf(fl.req.First) == 0xB1 {
			pwSink(fl)
			return
		}
		pwEcho(fl)
	}
	within := func(t *testing.T, what string, end, last time.Time, limit time.Duration) {
		t.Helper()
		d := end.Sub(last)
		t.Logf("%s ended %v after its last datagram (limit %v)", what, d, limit)
		if d < limit || d > limit+1500*time.Millisecond {
			t.Fatalf("%s ended %v after its last datagram, want its limit %v (+ at most 1.5 s)", what, d, limit)
		}
	}
	for _, rule := range []promoteMode{promoteActive, promoteOnReply} {
		t.Run(pwRuleName(rule)+"/stream keeps its session", func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pfRule(t, rule)
				w := newPWWorld(t, pwOpts{})
				w.serve()
				c := w.client()
				pwStreamUp(t, c, 0xB0)
				if fi := pwSnapshot(w.pf)[pwAddr(c)]; fi.State != FlowOpen || !fi.Stream {
					t.Fatalf("after the exchange: %+v, want an open stream", fi)
				}
				time.Sleep(60 * time.Second)
				if !pwRoundTrip(t, c, pwTagged(30, 0xB0, 100), time.Second) {
					t.Fatal("the stream does not carry its next datagram")
				}
				opens, _, _, _ := w.pas.snapshot()
				if st := pwStatus(w.pf); opens != 1 || st.Opened != 1 || st.Ended != (FlowEnds{}) || st.Flows != 1 || st.Replaced != 0 {
					t.Fatalf("after 60 s idle: %d OPENs, %s; want the stream's one session alive (Stream 180 s)", opens, pwDescribe(st))
				}
			})
		})
		t.Run(pwRuleName(rule)+"/limits", func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pfRule(t, rule)
				w := newPWWorld(t, pwOpts{target: sinkB1, pfwd: func(f *PortForward) { f.Idle = FlowIdle{Short: 10 * time.Second, Stream: 40 * time.Second} }})
				w.serve()
				unanswered, oneShot, stream := w.client(), w.client(), w.client()
				streamLast := pwStreamUp(t, stream, 0xB3)
				pfSend(t, unanswered, pwTagged(30, 0xB1, 0))
				unansweredLast := time.Now()
				pfSend(t, oneShot, pwTagged(30, 0xB2, 0))
				pfExpect(t, oneShot, pwTagged(30, 0xB2, 0))
				oneShotLast := time.Now()
				ends := pwEndTimes(t, w, 50*time.Second, 0xB1, 0xB2, 0xB3)
				oneShotLimit := map[promoteMode]time.Duration{promoteActive: 10 * time.Second, promoteOnReply: 40 * time.Second}[rule]
				for _, r := range []struct {
					what  string
					tag   byte
					last  time.Time
					limit time.Duration
				}{
					{"the unanswered flow", 0xB1, unansweredLast, 10 * time.Second},
					{"the one-shot exchange", 0xB2, oneShotLast, oneShotLimit},
					{"the stream", 0xB3, streamLast, 40 * time.Second},
				} {
					end, ok := ends[r.tag]
					if !ok {
						t.Fatalf("%s did not end within 50 s: %s", r.what, pwDescribe(pwStatus(w.pf)))
					}
					within(t, r.what, end, r.last, r.limit)
				}
				if st := pwStatus(w.pf); st.Ended.Idle != 3 || st.Opened != 3 {
					t.Fatalf("the ends: %s, want 3 idle ends at the ingress", pwDescribe(st))
				}
			})
		})
		t.Run(pwRuleName(rule)+"/stream limit off", func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pfRule(t, rule)
				w := newPWWorld(t, pwOpts{target: sinkB1, pfwd: func(f *PortForward) { f.Idle = FlowIdle{Short: 10 * time.Second, Stream: -1} }})
				w.serve()
				unanswered, stream := w.client(), w.client()
				pwStreamUp(t, stream, 0xB4)
				pfSend(t, unanswered, pwTagged(30, 0xB1, 0))
				unansweredLast := time.Now()
				ends := pwEndTimes(t, w, 15*time.Second, 0xB1)
				end, ok := ends[0xB1]
				if !ok {
					t.Fatalf("the unanswered flow did not end at Short: %s", pwDescribe(pwStatus(w.pf)))
				}
				within(t, "the unanswered flow", end, unansweredLast, 10*time.Second)
				time.Sleep(200 * time.Second) // beyond Short, and beyond the default Stream (180 s)
				if !pwRoundTrip(t, stream, pwTagged(30, 0xB4, 100), time.Second) {
					t.Fatal("the stream does not carry its next datagram")
				}
				if st := pwStatus(w.pf); st.Opened != 2 || st.Ended.Idle != 1 || st.Flows != 1 {
					t.Fatalf("after 200 s idle: %s; want the stream's session alive (no Stream limit)", pwDescribe(st))
				}
			})
		})
	}
}
