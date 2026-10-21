package l4

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// pwLateEnd delays the report of its session's end to the flow goroutine
// until release is closed: a goroutine that runs late after its session
// ended (scheduling latency under load).
type pwLateEnd struct {
	ingressSession
	release chan struct{}
	ended   chan struct{} // closed when ReadFrom got the end
	err     atomic.Pointer[error]
}

func (s *pwLateEnd) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := s.ingressSession.ReadFrom(b)
	if err != nil && s.err.CompareAndSwap(nil, &err) {
		close(s.ended)
		<-s.release
	}
	return n, a, err
}

// TestPortForwardEvictEndedVictim_L72 (M6-D29; L72): an eviction is
// counted only when the eviction's own close ended the victim's session.
// O-1 (a), MaxFlows 1, the ingress's classes 60 s, the passive's 10 s.
//
//   - ended first: the passive's idle limit ends flow a (AbortIdle at the
//     ingress), and a's goroutine is late (a delaying wrapper); a newcomer
//     takes a's place meanwhile. a ended by the peer's idle limit, so
//     Evicted and Ended.Evicted stay 0 and Ended.PeerIdle is 1 (the passive
//     counted its own idle end), and the newcomer's flow opens.
//   - live victim: a's session is live when the newcomer evicts it: Evicted
//     and Ended.Evicted are 1, and the passive's forward of a ends io.EOF
//     (PeerClosed there).
func TestPortForwardEvictEndedVictim_L72(t *testing.T) {
	world := func(t *testing.T) *pwWorld {
		return newPWWorld(t, pwOpts{target: pwSink,
			passiveIdle: FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second},
			pfwd: func(f *PortForward) {
				f.MaxFlows = 1
				f.Idle = FlowIdle{Short: 60 * time.Second, Stream: 60 * time.Second}
			}})
	}
	t.Run("ended first", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pfRule(t, promoteActive)
			var late *pwLateEnd
			pwDialHook(t, func(_ []byte, s ingressSession) ingressSession {
				if late == nil {
					late = &pwLateEnd{ingressSession: s, release: make(chan struct{}), ended: make(chan struct{})}
					return late
				}
				return s
			})
			w := world(t)
			w.serve()
			a := w.client()
			pfSend(t, a, pwTagged(30, 0xA1, 0))
			time.Sleep(100 * time.Millisecond)
			if st := pwStatus(w.pf); st.Flows != 1 {
				t.Fatalf("flow a not open: %s", pwDescribe(st))
			}
			select {
			case <-late.ended:
			case <-time.After(30 * time.Second):
				t.Fatal("a's session did not end")
			}
			var ae *rendr.AbortError
			if err := *late.err.Load(); !errors.As(err, &ae) || ae.Code != rendr.AbortIdle {
				t.Fatalf("a's session ended %v, want AbortIdle", err)
			}
			b := w.client()
			pfSend(t, b, pwTagged(30, 0xB1, 0))
			synctest.Wait()
			close(late.release)
			time.Sleep(100 * time.Millisecond)
			st := pwStatus(w.pf)
			pres := <-w.pas.flowOf(0xA1).res
			t.Logf("ingress %s; the passive's forward of a ended %v", pwDescribe(st), pres.SessionErr)
			if !errors.Is(pres.SessionErr, rendr.ErrIdleTimeout) {
				t.Fatalf("premise: the passive's forward of a ended %v, want its idle limit", pres.SessionErr)
			}
			if st.Evicted != 0 || st.Ended.Evicted != 0 || st.Ended.PeerIdle != 1 {
				t.Fatalf("a flow the passive's idle limit ended counted as evicted: %s", pwDescribe(st))
			}
			if fi, ok := pwSnapshot(w.pf)[pwAddr(b)]; !ok || fi.State != FlowOpen || st.Flows != 1 || st.Opened != 2 {
				t.Fatalf("the newcomer did not take a's place: %+v, %s", fi, pwDescribe(st))
			}
			pwUnits(t, w.pf)
		})
	})
	t.Run("live victim", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pfRule(t, promoteActive)
			w := world(t)
			w.serve()
			a := w.client()
			pfSend(t, a, pwTagged(30, 0xA1, 0))
			time.Sleep(1500 * time.Millisecond) // idle ≥ 1 s, the passive's limit far
			pfSend(t, w.client(), pwTagged(30, 0xB1, 0))
			synctest.Wait()
			st := pwStatus(w.pf)
			var pres PacketResult
			select {
			case pres = <-w.pas.flowOf(0xA1).res:
			case <-time.After(5 * time.Second):
				t.Fatal("the passive's forward of a did not end")
			}
			t.Logf("ingress %s; the passive's forward of a ended %v", pwDescribe(st), pres.SessionErr)
			if st.Evicted != 1 || st.Ended.Evicted != 1 || st.Ended.PeerIdle != 0 || !errors.Is(pres.SessionErr, io.EOF) {
				t.Fatalf("eviction of a live flow: %s; the passive's forward ended %v, want io.EOF", pwDescribe(st), pres.SessionErr)
			}
		})
	})
}

// TestPortForwardKeepaliveFlow_L72 (M6-D9, M6-D29, R1-23; L72): a flow
// that only exchanges keepalives — one datagram each way every 25 s, a
// quiet WireGuard tunnel's — under both rules, MaxFlows 1. It lives while
// they come within Short (100 s of life). Under O-1 (a) every gap of 2 s
// or more starts a new activity period, so it never becomes a stream and a
// newcomer to the full table evicts it (the documented behaviour: put such
// a tunnel on a PortForward of its own); under the literal rule its first
// reply made it a stream and only held entries make room, so the newcomer
// is DropFull and the flow still carries its next keepalive.
func TestPortForwardKeepaliveFlow_L72(t *testing.T) {
	for _, rule := range []promoteMode{promoteActive, promoteOnReply} {
		t.Run(pwRuleName(rule), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pfRule(t, rule)
				w := newPWWorld(t, pwOpts{passiveDefaults: true, pfwd: func(f *PortForward) { f.MaxFlows = 1 }})
				w.serve()
				a := w.client()
				for k := range 4 {
					ka := pwTagged(32, 0xA1, k)
					pfSend(t, a, ka)
					pfExpect(t, a, ka) // the echo: one datagram each way
					time.Sleep(25 * time.Second)
				}
				fi := pwSnapshot(w.pf)[pwAddr(a)]
				if st := pwStatus(w.pf); fi.State != FlowOpen || st.Opened != 1 || st.Ended != (FlowEnds{}) {
					t.Fatalf("the keepalive flow did not live 100 s: %+v, %s", fi, pwDescribe(st))
				}
				if fi.Stream != (rule == promoteOnReply) {
					t.Fatalf("Stream %v under %s", fi.Stream, pwRuleName(rule))
				}
				b := w.client()
				pfSend(t, b, pwTagged(32, 0xB1, 0))
				synctest.Wait()
				time.Sleep(100 * time.Millisecond)
				st := pwStatus(w.pf)
				t.Logf("%s: after the newcomer %s", pwRuleName(rule), pwDescribe(st))
				switch rule {
				case promoteActive:
					if st.Evicted != 1 || st.Ended.Evicted != 1 || st.DropFull != 0 || pwSnapshot(w.pf)[pwAddr(b)].State != FlowOpen {
						t.Fatalf("O-1 (a): the keepalive flow was not evicted for the newcomer: %s", pwDescribe(st))
					}
				default:
					if st.Evicted != 0 || st.DropFull != 1 || st.Ended != (FlowEnds{}) {
						t.Fatalf("literal rule: the keepalive flow made room: %s", pwDescribe(st))
					}
					pfSend(t, a, pwTagged(32, 0xA1, 4))
					pfExpect(t, a, pwTagged(32, 0xA1, 4))
				}
			})
		})
	}
}
