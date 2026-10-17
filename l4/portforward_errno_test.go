//go:build !plan9

package l4

import (
	"errors"
	"net"
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
// and never stop the reader: a run of 1,000 costs the first 64 reads at
// once and then backs off (5 ms doubling to 100 ms per read: at most 80
// reads in the run's first second), and afterwards the open flow carries
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
	const run = 1000
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
				time.Sleep(run * noiseBackoffMax / 10 * 11)
				st := pwStatus(w.pf)
				if st.ReadNoise != run {
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
