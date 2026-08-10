package udpsocket

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/platform"
	"github.com/FrankoonG/rendr/transport"
)

func TestDetectPolicyNonContextProbeErrorFallsBack(t *testing.T) {
	called := false
	selected, err := detectPolicyWith(context.Background(), func(context.Context) (platform.KernelFeatures, error) {
		called = true
		return platform.KernelFeatures{}, errors.New("synthetic probe failure")
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !called || selected.treatment != treatmentOrdinary || selected.cause != causeProbeFailed {
		t.Fatalf("called=%t policy=%+v", called, selected)
	}
}

func TestDetectPolicyContextErrorsBlockSelection(t *testing.T) {
	for _, probeErr := range []error{context.Canceled, context.DeadlineExceeded} {
		_, err := detectPolicyWith(context.Background(), func(context.Context) (platform.KernelFeatures, error) {
			return platform.KernelFeatures{}, probeErr
		}, true)
		if !errors.Is(err, probeErr) {
			t.Fatalf("probe error %v returned %v", probeErr, err)
		}
	}
}

func TestValidateBatchOwnsExactBoundaries(t *testing.T) {
	datagrams := [][]byte{bytes.Repeat([]byte{1}, 8), bytes.Repeat([]byte{2}, 8), bytes.Repeat([]byte{3}, 3)}
	segmentSize, payload, err := validateBatch(datagrams)
	if err != nil {
		t.Fatal(err)
	}
	if segmentSize != 8 || !bytes.Equal(payload, append(append(append([]byte(nil), datagrams[0]...), datagrams[1]...), datagrams[2]...)) {
		t.Fatalf("segment=%d payload=%x", segmentSize, payload)
	}
	payload[0] = 0xff
	if datagrams[0][0] == 0xff {
		t.Fatal("validated super-packet aliases caller memory")
	}
}

func TestValidateBatchRejectsInvalidShapes(t *testing.T) {
	full := bytes.Repeat([]byte{1}, 8)
	cases := [][][]byte{
		nil,
		{full},
		{full, bytes.Repeat([]byte{2}, 7), full},
		{full, nil},
		{bytes.Repeat([]byte{1}, MaxGSOSuperPacket), []byte{2}},
	}
	tooMany := make([][]byte, MaxGSOSegments+1)
	for index := range tooMany {
		tooMany[index] = []byte{byte(index)}
	}
	cases = append(cases, tooMany)
	for index, batch := range cases {
		if _, _, err := validateBatch(batch); err == nil {
			t.Fatalf("case %d accepted invalid batch", index)
		}
	}
}

func TestOrdinaryWriteBatchPreservesDatagrams(t *testing.T) {
	receiver := listenUDP4(t)
	sender := listenUDP4(t)
	socket := newSocket(sender, policy{treatment: treatmentOrdinary, cause: "test_fallback"}, 0)
	datagrams := [][]byte{[]byte("aaaaaaaa"), []byte("bbbbbbbb"), []byte("ccc")}
	completed, err := socket.WriteBatch(datagrams, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil || completed != len(datagrams) {
		t.Fatalf("WriteBatch=%d/%d err=%v", completed, len(datagrams), err)
	}
	for index, want := range datagrams {
		got := make([]byte, 32)
		n, _, err := receiver.ReadFromUDP(got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[:n], want) {
			t.Fatalf("datagram %d=%q want=%q", index, got[:n], want)
		}
	}
	status := socket.DatagramAccelerationStatus()
	if status.Mode != transport.DatagramAccelerationOrdinary || status.OrdinaryDatagrams != uint64(len(datagrams)) ||
		status.GSOAttempts != 0 || status.GSOSuperPackets != 0 {
		t.Fatalf("status=%+v", status)
	}
}

func TestWriteBatchValidatesConnectedDestination(t *testing.T) {
	receiver := listenUDP4(t)
	connected, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connected.Close() })
	socket := newSocket(connected, policy{treatment: treatmentOrdinary, cause: "test_fallback"}, 0)
	batch := [][]byte{[]byte("aaaa"), []byte("bbbb")}
	if _, err := socket.WriteBatch(batch, receiver.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatal("connected batch accepted an explicit destination")
	}
	if n, err := socket.WriteBatch(batch, nil); err != nil || n != len(batch) {
		t.Fatalf("connected WriteBatch=%d err=%v", n, err)
	}

	unconnected := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test_fallback"}, 0)
	if _, err := unconnected.WriteBatch(batch, nil); err == nil {
		t.Fatal("unconnected batch accepted a nil destination")
	}
}

func TestFallbackTransitionIsOneWayUnderConcurrency(t *testing.T) {
	socket := &Socket{}
	socket.mode.Store(uint32(treatmentGSO))
	socket.cause.Store(causeProbeConfirmed)
	var wait sync.WaitGroup
	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			socket.transitionToFallback(causePathUnsupported, false)
		}()
	}
	wait.Wait()
	status := socket.DatagramAccelerationStatus()
	if status.Mode != transport.DatagramAccelerationOrdinary || status.Cause != causePathUnsupported || status.FallbackTransitions != 1 {
		t.Fatalf("status=%+v", status)
	}
}

func TestStatusAliasesAccelerationSnapshot(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{
		treatment: treatmentOrdinary, cause: "test_fallback",
		probeGeneration: 7, probedAt: time.Unix(11, 0),
	}, 0)
	if got, want := socket.Status(), socket.DatagramAccelerationStatus(); got != want {
		t.Fatalf("Status=%+v acceleration=%+v", got, want)
	}
}

func TestDialHonorsCanceledContextBeforeOpeningSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Dial(ctx, Config{RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial error=%v want context canceled", err)
	}
}

func TestSocketDeadlineAndClose(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test_fallback"}, 0)
	if err := socket.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := socket.ReadFrom(make([]byte, 1))
	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() {
		t.Fatalf("ReadFrom error=%v want timeout", err)
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := socket.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-close ReadFrom error=%v", err)
	}
}

func listenUDP4(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
