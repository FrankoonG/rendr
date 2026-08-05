package l3session

import (
	"net"
	"testing"

	rendr "github.com/FrankoonG/rendr"
)

func newTestStreamSessionListener(t *testing.T, sourceName string) *rendr.SessionListener {
	t.Helper()
	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen(rendr.ListenConfig{Streams: []rendr.StreamSource{{
		Name:     sourceName,
		Carrier:  rendr.CarrierTCP,
		Listener: rawListener,
	}}})
	if err != nil {
		_ = rawListener.Close()
		t.Fatal(err)
	}
	return listener
}

func newTestPacketSessionListener(t *testing.T, sourceName string) *rendr.SessionListener {
	t.Helper()
	runtime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	rawPacketConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen(rendr.ListenConfig{Packets: []rendr.PacketSource{{
		Name:    sourceName,
		Carrier: rendr.CarrierUDP,
		Conn:    rawPacketConn,
	}}})
	if err != nil {
		_ = rawPacketConn.Close()
		t.Fatal(err)
	}
	return listener
}
