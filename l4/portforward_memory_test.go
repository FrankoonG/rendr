package l4

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPortForwardMemoryPerFlowStream (§A12, L48; recorded, as
// TestPortForwardMemoryPerFlow): the per-flow heap of a PortForward on a
// Peer of stream carriers only, whose flows carry Packet.MaxPayload
// (65,507 bytes; the package doc's "Bounds and memory"). 100 flows (50 in
// the race lane), one datagram each way: the ingress's own heap (its
// reply buffer is MaxPayload) and its session's open, and the passive
// forward's (its buffers are 2 × MaxPayload + 1), per flow. It fails when
// a figure exceeds the doc's by more than a third: about 84 KiB at the
// ingress (measured 65.6 KiB of its own and 16.2 KiB of the session's
// open), 128 KiB of buffers at the passive (measured 128.6 KiB).
func TestPortForwardMemoryPerFlowStream(t *testing.T) {
	const ingressBound, passiveBound = (84 << 10) * 4 / 3, (128 << 10) * 4 / 3
	n := 100
	if raceEnabled {
		n = 50
	}
	defer func(r int) { runtime.MemProfileRate = r }(runtime.MemProfileRate)
	runtime.MemProfileRate = 1
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{n: n + 1})
		pas := &pwPassive{ln: w.ln, idle: FlowIdle{Short: -1}, target: pwEcho}
		pas.wg.Add(1)
		go pas.loop()
		hub := rendrtest.NewUDPSocketHub(rendrtest.UDPSocketHubConfig{})
		pf := &PortForward{Peer: w.peer}
		ctx, cancel := context.WithCancel(context.Background())
		served := make(chan error, 1)
		go func() { served <- pf.ServeUDP(ctx, hub.Socket(), pfTarget) }()
		defer func() {
			cancel()
			<-served
			w.shutdown()
			pas.wg.Wait()
		}()
		port := 0
		client := func() *rendrtest.DatagramConn {
			port++
			return hub.Client(pwSrc(port))
		}
		if !pwRoundTrip(t, client(), pwTagged(30, 0x01, 0), time.Second) {
			t.Fatal("warm-up flow did not open")
		}
		cs := make([]*rendrtest.DatagramConn, n)
		for i := range cs {
			cs[i] = client()
		}
		sample := func() (ingress, session, passive int64) {
			synctest.Wait()
			runtime.GC()
			runtime.GC()
			ingress, session = pwIngressHeap()
			return ingress, session, pwHeapUnder("/l4.forwardPacket")
		}
		ing0, ses0, pas0 := sample()
		for i, c := range cs {
			pfSend(t, c, pwTagged(30, byte(i), 1))
			time.Sleep(time.Millisecond)
		}
		for i, c := range cs {
			pfExpect(t, c, pwTagged(30, byte(i), 1))
		}
		time.Sleep(time.Second)
		ing1, ses1, pas1 := sample()
		st := pf.Status().UDP
		if st.Flows != n+1 || st.MaxPayload != 65507 {
			t.Fatalf("load: %s", pwDescribe(st))
		}
		per := func(a, b int64) float64 { return float64(b-a) / float64(n) }
		ing, ses, ps := per(ing0, ing1), per(ses0, ses1), per(pas0, pas1)
		t.Logf("%d flows at MaxPayload %d: the ingress's own heap %.1f KiB per flow, the session's open %.1f KiB, the passive forward's %.1f KiB", n, st.MaxPayload, ing/1024, ses/1024, ps/1024)
		if ing+ses > ingressBound || ps > passiveBound {
			t.Fatalf("per flow: ingress %.0f bytes with its session (at most %d), passive forward %.0f (at most %d)", ing+ses, ingressBound, ps, passiveBound)
		}
	})
}

// pwHeapUnder sums the live heap allocated under a frame whose function
// name contains fn (the memory profile's in-use records).
func pwHeapUnder(fn string) (n int64) {
	var recs []runtime.MemProfileRecord
	k, _ := runtime.MemProfile(nil, false)
	for {
		recs = make([]runtime.MemProfileRecord, k+64)
		var ok bool
		if k, ok = runtime.MemProfile(recs, false); ok {
			recs = recs[:k]
			break
		}
	}
	for _, r := range recs {
		frames := runtime.CallersFrames(r.Stack())
		for {
			f, more := frames.Next()
			if strings.Contains(f.Function, fn) {
				n += r.InUseBytes()
				break
			}
			if !more {
				break
			}
		}
	}
	return n
}
