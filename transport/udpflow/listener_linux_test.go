//go:build linux

package udpflow

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestListenerRejectsLinuxMSGTRUNC(t *testing.T) {
	listener, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUDP("udp4", nil, listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	datagram := listenerDatagram(t, listenerFlowID(7101), bytes.Repeat([]byte{0x7c}, MaxDatagram+256))
	if _, err := client.Write(datagram); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = listener.Accept(ctx)
	if !errors.Is(err, ErrListenerRead) || !errors.Is(err, ErrTruncatedPacket) {
		t.Fatalf("Accept error=%v want listener/truncated error", err)
	}
	if got := listenerFlowCount(listener); got != 0 {
		t.Fatalf("truncated kernel datagram created %d flows", got)
	}
}
