package rendr_test

import (
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
)

// TestIdleUDPSourceBufferedBytes (R-C3-2; plan:774, as M5's R1-4 amends
// it for a batching socket): the real-socket half of
// TestIdleSourceBufferedBytes. Two udp.Listen sockets as FromPacketConn
// sources whose readers run — each read and dropped junk datagrams, so
// each holds its read buffer — while no session or carrier exists:
//
//   - MaxBatch 1 (a plain socket on every target): Status.BufferedBytes is
//     0, the read buffer charged to nothing while the source waits;
//   - the default MaxBatch: 0 where rendr does not batch; on Linux amd64
//     and arm64 each source holds its extra receive slots and its Batch
//     (R1-4 rule 2, R1-5 rule 4; internal/udpflow's
//     TestFlowOwnedSocketCharge pins the amount), so BufferedBytes is
//     positive and does not move while more junk is read and dropped.
//
// Runtime.Close returns everything: BufferedBytes 0.
func TestIdleUDPSourceBufferedBytes(t *testing.T) {
	for _, arm := range []struct {
		name     string
		maxBatch int
	}{{"plain", 1}, {"default", 0}} {
		t.Run(arm.name, func(t *testing.T) {
			rt, err := rendr.NewRuntime(rendr.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer rt.Close()
			var srcs []rendr.Source
			var addrs []net.Addr
			for range 2 {
				pc, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{MaxBatch: arm.maxBatch})
				if err != nil {
					t.Fatalf("udp.Listen: %v", err)
				}
				srcs = append(srcs, rendr.FromPacketConn(pc))
				addrs = append(addrs, pc.LocalAddr())
			}
			if _, err := rt.Listen(rendr.ListenConfig{Sources: srcs}); err != nil {
				t.Fatalf("Listen: %v", err)
			}
			junk, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer junk.Close()
			// Stimulus: both readers run (the sources dropped want junk
			// datagrams).
			drop := func(want uint64) {
				t.Helper()
				deadline := time.Now().Add(10 * time.Second)
				for rt.Status().Datagram.Dropped < want {
					if time.Now().After(deadline) {
						t.Fatalf("the sources dropped %d junk datagrams, want %d", rt.Status().Datagram.Dropped, want)
					}
					for _, a := range addrs {
						_, _ = junk.WriteTo([]byte("junk"), a)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			drop(2)
			st := rt.Status()
			if st.Datagram.Sources != 2 || st.Datagram.Flows != 0 {
				t.Fatalf("two idle udp.Listen sources: sources %d, flows %d, want 2, 0", st.Datagram.Sources, st.Datagram.Flows)
			}
			switch {
			case arm.maxBatch == 1 || !sioBatching:
				if st.BufferedBytes != 0 {
					t.Fatalf("two idle udp.Listen sources (MaxBatch %d, no batching): BufferedBytes %d, want 0", arm.maxBatch, st.BufferedBytes)
				}
			default:
				if st.BufferedBytes <= 0 {
					t.Fatalf("two idle batching udp.Listen sources: BufferedBytes %d, want their extra slots and Batches", st.BufferedBytes)
				}
				drop(st.Datagram.Dropped + 20)
				if b := rt.Status().BufferedBytes; b != st.BufferedBytes {
					t.Fatalf("two idle batching sources: BufferedBytes %d after more junk, %d before; junk must cost nothing", b, st.BufferedBytes)
				}
			}
			rt.Close()
			if st := rt.Status(); st.Datagram.Sources != 0 || st.BufferedBytes != 0 {
				t.Fatalf("after Close: %+v", st)
			}
		})
	}
}
