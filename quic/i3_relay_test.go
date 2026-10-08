package quic

import (
	"net"
	"testing"
	"time"
)

// TestQERelaySurvivesServerRestart is a self-test of the end-to-end relay
// (qeRelay): the stateless-reset row of TestQUICErrorsAreDeathE2E_L01
// closes the server's socket and binds a new one at the same address, and
// the relay must keep forwarding the server → client direction to the new
// socket. A datagram relayed while the server's port was closed draws an
// ICMP port unreachable, which Linux reports on the relay's connected
// upstream socket as ECONNREFUSED at its next read; a relay that ended the
// direction on that error dropped the new listener's stateless reset, and
// the row's carrier died by ping_timeout or write_stall instead of
// transport_error (Linux race lane, 3 of 9 passes).
func TestQERelaySurvivesServerRestart(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := srv.LocalAddr().(*net.UDPAddr)
	r := newQERelay(t, addr, 0)
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	front := r.front.LocalAddr()
	buf := make([]byte, 64)

	// Stimulus: the relay's upstream socket for cli exists and reaches srv.
	if _, err := cli.WriteTo([]byte("a"), front); err != nil {
		t.Fatal(err)
	}
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, up, err := srv.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("stimulus: the server got nothing through the relay: %v", err)
	}
	srv.Close()

	// While the server's port is closed, relayed datagrams draw ICMP port
	// unreachables back to the upstream socket.
	for range 5 {
		if _, err := cli.WriteTo([]byte("b"), front); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	srv2, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("rebinding the server's address: %v", err)
	}
	defer srv2.Close()
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, err := srv2.WriteToUDPAddrPort([]byte("c"), up); err != nil {
			t.Fatal(err)
		}
		n, err := cli.Read(buf)
		if err == nil && string(buf[:n]) == "c" {
			return
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("the relay stopped forwarding server → client after the server's socket was closed and rebound")
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}
