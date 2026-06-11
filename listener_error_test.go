package rendr

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/FrankoonG/rendr/internal/engine"
	uflow "github.com/FrankoonG/rendr/transport/udpflow"
)

func TestTCPListenerFailKeepsAcceptChannelOpen(t *testing.T) {
	boom := errors.New("accept failed")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &tcpListener{
		ln:      ln,
		bridges: engine.NewBridgeTable(),
		accept:  make(chan *engineBackedConn, 1),
		closed:  make(chan struct{}),
	}

	l.fail(boom)

	select {
	case _, ok := <-l.accept:
		if !ok {
			t.Fatal("fail closed accept channel")
		}
	default:
	}

	_, err = l.Accept(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("Accept error = %v, want %v", err, boom)
	}
}

func TestUDPFlowListenerFailKeepsPacketAcceptChannelOpen(t *testing.T) {
	boom := errors.New("udpflow accept failed")
	ln, err := uflow.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &udpFlowListener{
		ln:           ln,
		bridges:      engine.NewBridgeTable(),
		accept:       make(chan *engineBackedConn, 1),
		acceptPacket: make(chan *enginePacketConn, 1),
		closed:       make(chan struct{}),
	}

	l.fail(boom)

	select {
	case _, ok := <-l.acceptPacket:
		if !ok {
			t.Fatal("fail closed acceptPacket channel")
		}
	default:
	}

	_, err = l.AcceptPacket(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("AcceptPacket error = %v, want %v", err, boom)
	}
}
