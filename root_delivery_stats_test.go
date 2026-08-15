package rendr

import (
	"context"
	"io"
	"reflect"
	"testing"
	"time"
)

func waitForRootDeliveryStats(
	t *testing.T,
	observer ConnectionObserver,
	selectorName, targetName string,
	wantBytes uint64,
) RootDeliveryStats {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stats := observer.Stats().RootDelivery
		if stats.Attributable && stats.SelectorName == selectorName && stats.TargetName == targetName &&
			stats.SelectorGeneration != 0 && stats.EvidenceEpoch != 0 &&
			stats.PublishedBytes == wantBytes && stats.AckedBytes == wantBytes {
			return stats
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("root delivery did not settle: %+v", observer.Stats().RootDelivery)
	return RootDeliveryStats{}
}

func TestRootDeliveryStatsPublicProjectionForStreamAndPacket(t *testing.T) {
	statsType := reflect.TypeOf(ConnStats{})
	if last := statsType.Field(statsType.NumField() - 1); last.Name != "RootDelivery" ||
		last.Type != reflect.TypeOf(RootDeliveryStats{}) {
		t.Fatalf("ConnStats final field=%s %v, want RootDelivery RootDeliveryStats", last.Name, last.Type)
	}

	t.Run("stream", func(t *testing.T) {
		listener, err := listenRuntimeTCP("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		accepted := make(chan Conn, 1)
		acceptErr := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			connection, acceptErrValue := listener.Accept(ctx)
			if acceptErrValue != nil {
				acceptErr <- acceptErrValue
				return
			}
			accepted <- connection
		}()

		root := Selector("stream-delivery-root", []Target{
			Path("stream-delivery-path", PathSpec{Transport: "tcp", Address: listener.Addr().String()}),
		})
		client, err := (&sessionDialer{Root: root}).Dial(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		var server Conn
		select {
		case server = <-accepted:
		case err := <-acceptErr:
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			t.Fatal("stream accept timeout")
		}
		defer server.Close()

		payload := make([]byte, 32<<10)
		for index := range payload {
			payload[index] = byte(index)
		}
		if n, err := client.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("stream Write=(%d,%v)", n, err)
		}
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(server, received); err != nil {
			t.Fatal(err)
		}
		waitForRootDeliveryStats(
			t, client.(ConnectionObserver),
			"stream-delivery-root", "stream-delivery-path", uint64(len(payload)),
		)
	})

	t.Run("packet", func(t *testing.T) {
		listener, err := listenRuntimeUDP("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		accepted := make(chan PacketConn, 1)
		acceptErr := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			connection, acceptErrValue := listener.AcceptPacket(ctx)
			if acceptErrValue != nil {
				acceptErr <- acceptErrValue
				return
			}
			accepted <- connection
		}()

		root := Selector("packet-delivery-root", []Target{
			Path("packet-delivery-path", PathSpec{Transport: "udpflow", Address: listener.Addr().String()}),
		})
		client, err := (&sessionDialer{Root: root}).DialPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		var server PacketConn
		select {
		case server = <-accepted:
		case err := <-acceptErr:
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			t.Fatal("packet accept timeout")
		}
		defer server.Close()

		payload := make([]byte, 1024)
		for index := range payload {
			payload[index] = byte(index)
		}
		if n, err := client.WriteTo(payload, nil); err != nil || n != len(payload) {
			t.Fatalf("packet WriteTo=(%d,%v)", n, err)
		}
		received := make([]byte, len(payload))
		if n, _, err := server.ReadFrom(received); err != nil || n != len(payload) {
			t.Fatalf("packet ReadFrom=(%d,%v)", n, err)
		}
		waitForRootDeliveryStats(
			t, client.(ConnectionObserver),
			"packet-delivery-root", "packet-delivery-path", uint64(len(payload)),
		)
	})
}
