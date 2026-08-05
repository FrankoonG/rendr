package rendr

import (
	"context"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func TestDialerAdvertisesL3IdentityCapability(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
	}()

	client, err := (&sessionDialer{
		Root:               Path("tcp", PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
		PreserveL3Identity: true,
	}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()
	stats := server.(ConnectionObserver).Stats()
	if stats.PeerCaps&proto.CapsL3Identity == 0 {
		t.Fatalf("server PeerCaps=0x%08x missing CapsL3Identity", stats.PeerCaps)
	}
	if stats.PeerCaps&proto.CapsPacketMode != 0 {
		t.Fatalf("stream PeerCaps=0x%08x unexpectedly has CapsPacketMode", stats.PeerCaps)
	}
}

func TestDialPacketAdvertisesL3IdentityAndPacketMode(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept packet: %v", err)
			return
		}
		accepted <- c
	}()

	client, err := (&sessionDialer{
		Root:               Path("udp", PathSpec{Transport: "udpflow", Address: ln.Addr().String()}),
		PreserveL3Identity: true,
	}).DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()
	stats := server.(ConnectionObserver).Stats()
	if stats.PeerCaps&proto.CapsL3Identity == 0 {
		t.Fatalf("packet PeerCaps=0x%08x missing CapsL3Identity", stats.PeerCaps)
	}
	if stats.PeerCaps&proto.CapsPacketMode == 0 {
		t.Fatalf("packet PeerCaps=0x%08x missing CapsPacketMode", stats.PeerCaps)
	}
}
