package rendr

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport/udpflow"
)

func TestAsymmetricPacketReceiveCapacityBeforeAndAfterMigration(t *testing.T) {
	const (
		clientInitialDatagram     = 1100
		clientReplacementDatagram = 1400
		serverDatagram            = 1250
		smallPayload              = 1000
		widePayload               = 1150
	)

	serverSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Packets: []PacketSource{{
		Name:            "asymmetric-capacity",
		Carrier:         CarrierUDP,
		Conn:            serverSocket,
		MaxDatagramSize: serverDatagram,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var (
		carriersMu sync.Mutex
		carriers   []*net.UDPConn
		dials      int
	)
	if err := clientRuntime.RegisterPacketFactory("asymmetric-capacity", PacketFactory{
		Carrier: CarrierUDP,
		Dial: func(context.Context, string) (PacketEndpoint, error) {
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
			if err != nil {
				return PacketEndpoint{}, err
			}
			carriersMu.Lock()
			dials++
			capacity := clientReplacementDatagram
			if dials == 1 {
				capacity = clientInitialDatagram
			}
			carriers = append(carriers, conn)
			carriersMu.Unlock()
			return PacketEndpoint{Conn: conn, Peer: serverSocket.LocalAddr(), MaxDatagramSize: capacity}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}

	accepted := acceptPacketContractSession(t, listener)
	clientConn, err := clientRuntime.DialPacket(context.Background(), SessionConfig{Root: Selector("root", []Target{
		Path("packet", PathSpec{Transport: "asymmetric-capacity", Address: "opaque://asymmetric"}),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	serverConn := awaitPacketContractSession(t, accepted)
	defer serverConn.Close()

	client := clientConn.(*enginePacketConn)
	server := serverConn.(*acceptedPacketConn)
	assertBidirectionalPacketSize(t, client, server, smallPayload, "before-migration")
	assertPacketSizeRejected(t, client, widePayload)
	assertPacketSizeRejected(t, server, widePayload)

	oldClientID := client.Paths()[0].ID
	oldServerID := server.Paths()[0].ID
	carriersMu.Lock()
	initialCarrier := carriers[0]
	carriersMu.Unlock()
	if err := initialCarrier.Close(); err != nil {
		t.Fatal(err)
	}
	waitForPacketReplacement(t, client, server, oldClientID, oldServerID, 5*time.Second)

	deadline := time.Now().Add(5 * time.Second)
	for {
		err = writePacketPayload(client, widePayload, "after-migration-client")
		if err == nil {
			readPacketPayload(t, server, widePayload, "after-migration-client")
			break
		}
		if !errors.Is(err, ErrPacketTooLarge) || time.Now().After(deadline) {
			t.Fatalf("client wide packet after confirmed migration: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	err = writePacketPayload(server, widePayload, "after-migration-server")
	if err != nil {
		t.Fatalf("server wide packet after confirmed migration: %v", err)
	}
	readPacketPayload(t, client, widePayload, "after-migration-server")

	if got, want := udpflow.MaxFrameSize, udpflow.MaxDatagram-udpflow.WireHeaderSize; got != want {
		t.Fatalf("udpflow carrier overhead mismatch: frame=%d datagram=%d header=%d", got, udpflow.MaxDatagram, udpflow.WireHeaderSize)
	}
}

func assertBidirectionalPacketSize(t *testing.T, client, server PacketConn, size int, label string) {
	t.Helper()
	if err := writePacketPayload(client, size, label+"-client"); err != nil {
		t.Fatal(err)
	}
	readPacketPayload(t, server, size, label+"-client")
	if err := writePacketPayload(server, size, label+"-server"); err != nil {
		t.Fatal(err)
	}
	readPacketPayload(t, client, size, label+"-server")
}

func assertPacketSizeRejected(t *testing.T, conn PacketConn, size int) {
	t.Helper()
	if err := writePacketPayload(conn, size, "must-reject"); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("packet size %d error=%v want ErrPacketTooLarge", size, err)
	}
}

func writePacketPayload(conn PacketConn, size int, label string) error {
	payload := bytes.Repeat([]byte{byte(len(label))}, size)
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err := conn.WriteTo(payload, conn.(interface{ RemoteAddr() net.Addr }).RemoteAddr())
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

func readPacketPayload(t *testing.T, conn PacketConn, size int, label string) {
	t.Helper()
	buffer := make([]byte, size+1)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFrom(buffer)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || n != size {
		t.Fatalf("%s read=(%d,%v) want %d bytes", label, n, err, size)
	}
}
