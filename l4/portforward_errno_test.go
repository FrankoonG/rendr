//go:build !plan9

package l4

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// TestPortForwardReadNoise_L58_L73 (M6-D25, R1-2; L58, L73): the ingress
// socket's read errors of the noise class — WSAECONNRESET (a Windows
// socket that reports an ICMP port unreachable), ECONNREFUSED, ENOBUFS,
// EACCES, bare or as the net package wraps them — are counted (ReadNoise)
// and never stop the reader: a run of 1,000 (200 in the race lane) costs
// the first 64 reads at once and then backs off (5 ms doubling to 100 ms
// per read: at most 80 reads in the run's first second), and afterwards
// the open flow carries
// its next datagram and a new client's flow opens. A fatal-set errno
// (EBADF, WSAEBADF) stops ServeUDP with that error; a Close of the socket
// by someone else stops it with net.ErrClosed; either way the socket is
// closed exactly once by ServeUDP and every flow ended.
func TestPortForwardReadNoise_L58_L73(t *testing.T) {
	noise := []pfErrno{
		{"WSAECONNRESET", syscall.Errno(10054)},
		{"ECONNREFUSED", syscall.ECONNREFUSED},
		{"ENOBUFS", syscall.ENOBUFS},
		{"EACCES", syscall.EACCES},
	}
	var rows []pfErrno
	for _, e := range noise {
		rows = append(rows, pfWrapped(e)...)
	}
	run := 1000
	if raceEnabled {
		run = 200 // racebudget: still beyond the free reads and the first second's back-off
	}
	for _, e := range rows {
		t.Run("noise "+e.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newPWWorld(t, pwOpts{wrap: func(s UDPSocket) UDPSocket { return &pwCountSock{UDPSocket: s} }})
				w.serve()
				c := w.client()
				if !pwRoundTrip(t, c, pwTagged(30, 0xF0, 0), time.Second) {
					t.Fatal("the flow did not open")
				}
				cs := w.sock.(*pwCountSock)
				reads0 := cs.reads.Load()
				w.hub.InjectRead(e.err, run)
				time.Sleep(time.Second)
				if got := cs.reads.Load() - reads0; got < noiseRunFree || got > noiseRunFree+16 {
					t.Fatalf("%d reads in the run's first second, want the %d free ones and a backed-off few", got, noiseRunFree)
				}
				time.Sleep(time.Duration(run) * noiseBackoffMax / 10 * 11)
				st := pwStatus(w.pf)
				if st.ReadNoise != uint64(run) {
					t.Fatalf("ReadNoise %d after the run, want %d: %s", st.ReadNoise, run, pwDescribe(st))
				}
				if !pwRoundTrip(t, c, pwTagged(30, 0xF0, 1), time.Second) || !pwRoundTrip(t, w.client(), pwTagged(30, 0xF1, 0), time.Second) {
					t.Fatalf("the reader stopped serving after the noise: %s", pwDescribe(pwStatus(w.pf)))
				}
				select {
				case err := <-w.served:
					t.Fatalf("ServeUDP returned %v during the noise", err)
				default:
				}
			})
		})
	}
	stopRows := []struct {
		name string
		stop func(w *pwWorld)
		want error
	}{
		{"fatal WSAEBADF", func(w *pwWorld) { w.hub.InjectRead(syscall.Errno(10009), 1) }, syscall.Errno(10009)},
		{"fatal WSAEBADF in OpError", func(w *pwWorld) {
			w.hub.InjectRead(&net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.Errno(10009))}, 1)
		}, syscall.Errno(10009)},
		{"closed by someone else", func(w *pwWorld) { w.hub.Socket().Close() }, net.ErrClosed},
	}
	for _, e := range pfSymFatal() {
		if e.name == "EBADF" {
			stopRows = append(stopRows, struct {
				name string
				stop func(w *pwWorld)
				want error
			}{"fatal EBADF", func(w *pwWorld) { w.hub.InjectRead(e.err, 1) }, e.err})
		}
	}
	for _, r := range stopRows {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newPWWorld(t, pwOpts{wrap: func(s UDPSocket) UDPSocket { return &pwCountSock{UDPSocket: s} }})
				w.serve()
				if !pwRoundTrip(t, w.client(), pwTagged(30, 0xF2, 0), time.Second) {
					t.Fatal("the flow did not open")
				}
				r.stop(w)
				var err error
				select {
				case err = <-w.served:
					w.served = nil
				case <-time.After(time.Second):
					t.Fatal("ServeUDP did not return")
				}
				cs := w.sock.(*pwCountSock)
				if !errors.Is(err, r.want) || cs.closes.Load() != 1 {
					t.Fatalf("ServeUDP = %v, %d Closes; want %v, closed once", err, cs.closes.Load(), r.want)
				}
				if st := pwStatus(w.pf); st.Flows != 0 || st.Ended.Stopped != 1 || pwFlowGoroutines() != 0 {
					t.Fatalf("after the stop: %s", pwDescribe(st))
				}
			})
		})
	}
}

// TestPortForwardReplyErrorsCounted (M6-D25, §A8.3; L73): a reply the
// ingress socket refuses to write is lost, counted in WriteNoise whatever
// the error — an Errno of the noise class (WSAECONNRESET), one of the
// fatal set (WSAEBADF), or an embedder socket's own error (a filter that
// is not an Errno) — and never ends the flow or the serve: every reply the
// targets sent is delivered or counted (ToClient + WriteNoise), and once
// the socket writes again the flow's next reply crosses.
func TestPortForwardReplyErrorsCounted(t *testing.T) {
	for _, e := range []pfErrno{
		{"noise WSAECONNRESET", syscall.Errno(10054)},
		{"fatal WSAEBADF", syscall.Errno(10009)},
		{"an embedder's own error", errors.New("filter: reply refused")},
	} {
		t.Run(e.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newPWWorld(t, pwOpts{wrap: func(s UDPSocket) UDPSocket { return &pwCountSock{UDPSocket: s} }})
				w.serve()
				c, other := w.client(), w.client()
				if !pwRoundTrip(t, c, pwTagged(30, 0xF4, 0), time.Second) {
					t.Fatal("the flow did not open")
				}
				cs := w.sock.(*pwCountSock)
				cs.failWrites(pwAddr(c), e.err)
				for k := range 10 {
					pfSend(t, c, pwTagged(30, 0xF4, 1+k))
					pfSend(t, other, pwTagged(30, 0xF5, k))
					pfExpect(t, other, pwTagged(30, 0xF5, k))
				}
				pfNone(t, c)
				st := pwStatus(w.pf)
				var replies int64
				_, _, _, flows := w.pas.snapshot()
				for _, fl := range flows {
					replies += fl.rxCount.Load() // echo targets: one reply per datagram received
				}
				if st.WriteNoise != 10 || st.ToClient+st.WriteNoise != uint64(replies) || st.Flows != 2 || st.Ended != (FlowEnds{}) {
					t.Fatalf("%d replies sent by the targets; %s; want the 10 refused ones in WriteNoise, the flows alive", replies, pwDescribe(st))
				}
				select {
				case err := <-w.served:
					t.Fatalf("ServeUDP returned %v on refused writes", err)
				default:
				}
				cs.failWrites(netip.AddrPort{}, nil)
				if !pwRoundTrip(t, c, pwTagged(30, 0xF4, 100), time.Second) {
					t.Fatal("the flow does not carry its next reply once the socket writes again")
				}
			})
		})
	}
}
