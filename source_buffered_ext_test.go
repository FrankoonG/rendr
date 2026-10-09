package rendr_test

import (
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
)

// TestIdleUDPSourceBufferedBytes (R-C3-2; plan:774): the real-socket half
// of TestIdleSourceBufferedBytes. Two udp.Listen sockets as FromPacketConn
// sources whose readers run — each read and dropped a junk datagram, so
// each holds its read buffer — leave Status.BufferedBytes at 0 while no
// session or carrier exists.
func TestIdleUDPSourceBufferedBytes(t *testing.T) {
	rt, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	var srcs []rendr.Source
	var addrs []net.Addr
	for range 2 {
		pc, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{})
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
	// Stimulus: both readers run (each source dropped a junk datagram).
	deadline := time.Now().Add(10 * time.Second)
	for rt.Status().Datagram.Dropped < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("the sources dropped %d junk datagrams, want 2", rt.Status().Datagram.Dropped)
		}
		for _, a := range addrs {
			_, _ = junk.WriteTo([]byte("junk"), a)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st := rt.Status(); st.Datagram.Sources != 2 || st.Datagram.Flows != 0 || st.BufferedBytes != 0 {
		t.Fatalf("two idle udp.Listen sources: sources %d, flows %d, BufferedBytes %d, want 2, 0, 0", st.Datagram.Sources, st.Datagram.Flows, st.BufferedBytes)
	}
	rt.Close()
	if st := rt.Status(); st.Datagram.Sources != 0 || st.BufferedBytes != 0 {
		t.Fatalf("after Close: %+v", st)
	}
}
