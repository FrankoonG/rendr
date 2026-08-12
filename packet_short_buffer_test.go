package rendr

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestPacketConnReadFromReportsTruncation(t *testing.T) {
	listener, err := listenRuntimeUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.AcceptPacket(ctx)
		if err == nil {
			accepted <- conn
		}
	}()
	client, err := (&sessionDialer{Root: selectorRoot([]PathSpec{{
		Transport: "udpflow", Address: listener.Addr().String(),
	}})}).DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	payload := []byte("packet-must-not-be-silently-truncated")
	if _, err := client.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 7)
	n, addr, err := server.ReadFrom(buffer)
	if n != len(buffer) || addr == nil || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("ReadFrom n=%d addr=%v err=%v, want %d/non-nil/io.ErrShortBuffer",
			n, addr, err, len(buffer))
	}
	if string(buffer) != string(payload[:len(buffer)]) {
		t.Fatalf("copied prefix = %q, want %q", buffer, payload[:len(buffer)])
	}
}
