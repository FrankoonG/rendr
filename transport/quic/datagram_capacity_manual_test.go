//go:build g3diag

package quic

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qg "github.com/FrankoonG/quic-go"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// TestDatagramAdapterCapacityDiagnostic measures the same serialized adapter
// write used by G3 without the rendr session engine. The explicit build tag
// keeps it out of ordinary package and regression runs.
func TestDatagramAdapterCapacityDiagnostic(t *testing.T) {
	duration := datagramDiagDuration(t, "RENDR_G3_DIAG_DURATION", 15*time.Second)
	targetPPS := datagramDiagInt(t, "RENDR_G3_DIAG_PPS", 100_000)
	writers := datagramDiagInt(t, "RENDR_G3_DIAG_WRITERS", 1)
	frameSize := datagramDiagInt(t, "RENDR_G3_DIAG_FRAME_SIZE", proto.HeaderSize+1032)
	fixedPacketSize := datagramDiagInt(t, "RENDR_G3_DIAG_FIXED_PACKET_SIZE", 0)
	directQUIC := os.Getenv("RENDR_G3_DIAG_DIRECT_QUIC") == "1"
	if writers < 1 || targetPPS < writers || frameSize < 0 {
		t.Fatalf("writers=%d target_pps=%d frame_size=%d", writers, targetPPS, frameSize)
	}

	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverReady := make(chan *datagramPathConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path, acceptError := listener.AcceptDatagram(ctx)
		if acceptError != nil {
			acceptErr <- acceptError
			return
		}
		serverReady <- path
	}()

	var client *datagramPathConn
	if fixedPacketSize == 0 {
		clientPath, dialErr := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{
			Address: listener.Addr().String(), Opts: map[string]string{"mode": "datagram"},
		})
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		client = clientPath.(*datagramPathConn)
	} else {
		if fixedPacketSize < 1200 || fixedPacketSize > int(^uint16(0)) {
			t.Fatalf("fixed packet size %d is outside QUIC bounds", fixedPacketSize)
		}
		remote, resolveErr := net.ResolveUDPAddr("udp", listener.Addr().String())
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		socket, socketErr := udpSocketWithBuffers(context.Background(), nil)
		if socketErr != nil {
			t.Fatal(socketErr)
		}
		quicTransport := &qg.Transport{Conn: socket.PacketConn()}
		release := sync.OnceFunc(func() {
			_ = quicTransport.Close()
			_ = socket.Close()
		})
		conn, dialErr := quicTransport.Dial(context.Background(), remote, clientTLS, &qg.Config{
			MaxIdleTimeout: 90 * time.Second, KeepAlivePeriod: 15 * time.Second,
			EnableDatagrams: true, InitialPacketSize: uint16(fixedPacketSize), DisablePathMTUDiscovery: true,
		})
		if dialErr != nil {
			release()
			t.Fatal(dialErr)
		}
		active := retainedCIDTransport(quicTransport, socket, addrAsUDP(conn.LocalAddr()))
		owner, ownerErr := newRealCIDOwner(conn, leafmobility.RoleDialer, leafmobility.SessionPacket, active, routeObservation{}, release)
		if ownerErr != nil {
			release()
			t.Fatal(ownerErr)
		}
		client = wrapDatagram(conn, false, owner)
	}
	defer client.Close()

	var server *datagramPathConn
	select {
	case server = <-serverReady:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("datagram adapter accept timed out")
	}
	defer server.Close()
	maxDatagramPayload := 0
	if err := client.conn.SendDatagram(make([]byte, 64<<10)); err != nil {
		var tooLarge *qg.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			maxDatagramPayload = int(tooLarge.MaxDatagramPayloadSize)
		}
	}
	if frameSize == 0 {
		frameSize = maxDatagramPayload
	}
	if frameSize < 8 {
		t.Fatalf("resolved frame_size=%d max_datagram_payload=%d", frameSize, maxDatagramPayload)
	}

	var received atomic.Int64
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			if _, readErr := server.ReadOwnedFrame(); readErr != nil {
				return
			}
			received.Add(1)
		}
	}()

	var sent atomic.Int64
	ready := sync.WaitGroup{}
	ready.Add(writers)
	start := make(chan struct{})
	writeErr := make(chan error, writers)
	writes := sync.WaitGroup{}
	writes.Add(writers)
	perWriterPPS := targetPPS / writers
	interval := time.Second / time.Duration(perWriterPPS)
	var started time.Time
	for writer := 0; writer < writers; writer++ {
		go func() {
			defer writes.Done()
			frame := make([]byte, frameSize)
			ready.Done()
			<-start
			endAt := started.Add(duration)
			nextTick := started
			for time.Now().Before(endAt) {
				datagramDiagPaceUntil(nextTick)
				if !time.Now().Before(endAt) {
					break
				}
				nextTick = nextTick.Add(interval)
				seq := sent.Add(1) - 1
				binary.BigEndian.PutUint64(frame, uint64(seq))
				if directQUIC {
					if err := client.conn.SendDatagram(frame); err != nil {
						writeErr <- err
						return
					}
				} else if _, err := client.Write(frame); err != nil {
					writeErr <- err
					return
				}
			}
		}()
	}
	ready.Wait()
	started = time.Now()
	close(start)
	writes.Wait()
	elapsed := time.Since(started)
	select {
	case err := <-writeErr:
		t.Fatalf("datagram capacity write: %v", err)
	default:
	}
	sentCount := sent.Load()
	drainDeadline := time.Now().Add(5 * time.Second)
	for received.Load() < sentCount && time.Now().Before(drainDeadline) {
		time.Sleep(time.Millisecond)
	}

	evidence, err := json.Marshal(map[string]any{
		"target_pps":           targetPPS,
		"writers":              writers,
		"frame_size":           frameSize,
		"fixed_packet_size":    fixedPacketSize,
		"max_datagram_payload": maxDatagramPayload,
		"direct_quic":          directQUIC,
		"sent":                 sentCount,
		"received":             received.Load(),
		"elapsed_ns":           elapsed.Nanoseconds(),
		"pps_sent":             float64(sentCount) / elapsed.Seconds(),
		"acceleration_status":  client.DatagramAccelerationStatus(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RENDR_QUIC_DATAGRAM_DIAG %s", evidence)
}

func datagramDiagPaceUntil(target time.Time) {
	for {
		now := time.Now()
		if !now.Before(target) {
			return
		}
		remaining := target.Sub(now)
		if remaining > 250*time.Microsecond {
			time.Sleep(remaining - 100*time.Microsecond)
		} else if remaining > 50*time.Microsecond {
			runtime.Gosched()
		}
	}
}

func datagramDiagInt(t *testing.T, name string, fallback int) int {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			t.Fatalf("%s=%q: %v", name, value, err)
		}
		return parsed
	}
	return fallback
}

func datagramDiagDuration(t *testing.T, name string, fallback time.Duration) time.Duration {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			t.Fatalf("%s=%q: %v", name, value, err)
		}
		return parsed
	}
	return fallback
}
