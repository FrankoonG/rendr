package rendr

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func testPeakTransferQUICDatagramPayloadBudget(t *testing.T) {
	listener, err := listenRuntimeQUICDatagram("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan PacketConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		connection, err := listener.AcceptPacket(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()

	path := func(name string) Target {
		return Path(name, PathSpec{
			Transport: "quic",
			Address:   listener.Addr().String(),
			Opts:      map[string]string{"mode": "datagram"},
		})
	}
	dialer := &sessionDialer{Root: Selector("packet-budget-root", []Target{
		path("normal"),
		path("peak"),
	}, PeakTransfer{Targets: []string{"peak"}})}
	bindOptionalFramedFactory(t, dialer, "quic")

	client, err := dialer.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server PacketConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("packet accept timed out")
	}
	defer server.Close()

	assertDelivered := func(label string, payload []byte) {
		t.Helper()
		if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("%s SetReadDeadline: %v", label, err)
		}
		if n, err := client.WriteTo(payload, nil); err != nil || n != len(payload) {
			t.Fatalf("%s WriteTo=(%d,%v), want (%d,nil)", label, n, err, len(payload))
		}
		got := make([]byte, len(payload)+1)
		n, _, err := server.ReadFrom(got)
		if err != nil {
			t.Fatalf("%s ReadFrom: %v", label, err)
		}
		if n != len(payload) || !bytes.Equal(got[:n], payload) {
			t.Fatalf("%s payload mismatch: got %d bytes, want %d", label, n, len(payload))
		}
	}

	before := client.Paths()
	assertDelivered("1184-byte boundary", bytes.Repeat([]byte{0x84}, 1184))

	for _, size := range []int{1185, 1192} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		n, err := client.WriteTo(payload, nil)
		if n != 0 || !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("%d-byte WriteTo=(%d,%v), want (0, ErrPacketTooLarge)", size, n, err)
		}
		assertDelivered("post-rejection health", []byte{byte(size), 0x5a})
	}

	after := client.Paths()
	if len(after) != len(before) {
		t.Fatalf("oversize rejection changed live path count: before=%+v after=%+v", before, after)
	}
	for index := range before {
		if after[index].ID != before[index].ID {
			t.Fatalf("oversize rejection replaced path: before=%+v after=%+v", before, after)
		}
	}
}
