//go:build linux

package udpsocket

import (
	"net"
	"testing"

	"golang.org/x/net/ipv4"
)

var (
	benchmarkSegmentSize int
	benchmarkSegments    int
)

const (
	maxStripUDPSegmentAllocs  = 0
	maxSplitSuperPacketAllocs = 0
	maxWarmWriteAllocs        = 0
	maxWarmReadBatchAllocs    = 0
)

func BenchmarkStripUDPSegment(b *testing.B) {
	control := append(ipv4TOSControl(3), udpSegmentControl(1200)...)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		segmentSize, stripped, found, err := stripUDPSegment(control)
		if err != nil || !found {
			b.Fatal(err)
		}
		benchmarkSegmentSize = segmentSize
		benchmarkSegments = len(stripped)
	}
}

func BenchmarkSplitSuperPacket(b *testing.B) {
	payload := make([]byte, 8*1200)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		segments, err := splitSuperPacket(payload, 1200)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkSegments = segments.count
	}
}

func BenchmarkPacketConnWriteMsgUDP(b *testing.B) {
	receiver := listenUDP4(b)
	socket := newSocket(listenUDP4(b), policy{treatment: treatmentOrdinary, cause: "benchmark"}, 0)
	b.Cleanup(func() { _ = socket.Close() })
	payload := make([]byte, 1200)
	destination := receiver.LocalAddr().(*net.UDPAddr)
	view := socket.PacketConn().(*packetConnView)

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buffer := make([]byte, 2048)
		for {
			if _, _, err := receiver.ReadFromUDP(buffer); err != nil {
				return
			}
		}
	}()
	b.Cleanup(func() {
		_ = receiver.Close()
		<-drained
	})

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		if n, oobN, err := view.WriteMsgUDP(payload, nil, destination); err != nil || n != len(payload) || oobN != 0 {
			b.Fatalf("WriteMsgUDP=%d/%d err=%v", n, oobN, err)
		}
	}
}

func BenchmarkPacketConnWriteMsgUDPGSO(b *testing.B) {
	socket := newSocket(listenUDP4(b), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
	b.Cleanup(func() { _ = socket.Close() })
	socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
		return len(payload), len(oob), nil
	}
	payload := make([]byte, 8*1200)
	control := append(ipv4TOSControl(3), udpSegmentControl(1200)...)
	control = append(control, ipv4TOSControl(1)...)
	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	view := socket.PacketConn().(*packetConnView)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		if n, oobN, err := view.WriteMsgUDP(payload, control, destination); err != nil || n != len(payload) || oobN != len(control) {
			b.Fatalf("WriteMsgUDP=%d/%d err=%v", n, oobN, err)
		}
	}
}

type benchmarkBatchReader interface {
	ReadBatch([]ipv4.Message, int) (int, error)
}

func BenchmarkPacketConnReadBatch(b *testing.B) {
	receiver := newSocket(listenUDP4(b), policy{treatment: treatmentOrdinary, cause: "benchmark"}, 0)
	b.Cleanup(func() { _ = receiver.Close() })
	view := receiver.PacketConn().(*packetConnView)
	var reader benchmarkBatchReader = ipv4.NewPacketConn(view)
	if direct, ok := any(view).(benchmarkBatchReader); ok {
		reader = direct
	}

	messages := make([]ipv4.Message, 8)
	for index := range messages {
		messages[index].Buffers = [][]byte{make([]byte, 2048)}
		messages[index].OOB = make([]byte, 128)
	}
	sender := listenUDP4(b)
	b.Cleanup(func() { _ = sender.Close() })
	destination := receiver.LocalAddr().(*net.UDPAddr)
	payload := make([]byte, 1200)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			if _, err := sender.WriteToUDP(payload, destination); err != nil {
				return
			}
		}
	}()
	b.Cleanup(func() {
		_ = sender.Close()
		<-stopped
	})

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		n, err := reader.ReadBatch(messages, 0)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkSegments = n
	}
}

func TestHotPathAllocationContracts(t *testing.T) {
	t.Run("control parsing", func(t *testing.T) {
		control := append(ipv4TOSControl(3), udpSegmentControl(1200)...)
		allocations := testing.AllocsPerRun(1000, func() {
			segment, err := parseUDPSegment(control)
			if err != nil || !segment.found || segment.size != 1200 {
				t.Fatalf("segment=%+v err=%v", segment, err)
			}
		})
		if allocations > maxStripUDPSegmentAllocs {
			t.Fatalf("allocations=%v want <=%d", allocations, maxStripUDPSegmentAllocs)
		}
	})
	t.Run("segmentation", func(t *testing.T) {
		payload := make([]byte, 8*1200)
		allocations := testing.AllocsPerRun(1000, func() {
			packet, err := splitSuperPacket(payload, 1200)
			if err != nil || packet.count != 8 {
				t.Fatalf("packet=%+v err=%v", packet, err)
			}
		})
		if allocations > maxSplitSuperPacketAllocs {
			t.Fatalf("allocations=%v want <=%d", allocations, maxSplitSuperPacketAllocs)
		}
	})
	t.Run("warm send", func(t *testing.T) {
		socket := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test"}, 0)
		t.Cleanup(func() { _ = socket.Close() })
		view := socket.PacketConn().(*packetConnView)
		receiver := listenUDP4(t)
		payload := []byte{1}
		destination := receiver.LocalAddr().(*net.UDPAddr)
		if _, _, err := view.WriteMsgUDP(payload, nil, destination); err != nil {
			t.Fatal(err)
		}
		allocations := testing.AllocsPerRun(1000, func() {
			if _, _, err := view.WriteMsgUDP(payload, nil, destination); err != nil {
				t.Fatal(err)
			}
		})
		if allocations > maxWarmWriteAllocs {
			t.Fatalf("allocations=%v want <=%d", allocations, maxWarmWriteAllocs)
		}
	})
	t.Run("warm batch receive", func(t *testing.T) {
		receiver := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test"}, 0)
		t.Cleanup(func() { _ = receiver.Close() })
		sender := listenUDP4(t)
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			for {
				if _, err := sender.WriteToUDP([]byte{1}, receiver.LocalAddr().(*net.UDPAddr)); err != nil {
					return
				}
			}
		}()
		t.Cleanup(func() { _ = sender.Close(); <-stopped })
		messages := []ipv4.Message{{Buffers: [][]byte{make([]byte, 8)}, OOB: make([]byte, 8)}}
		view := receiver.PacketConn().(*packetConnView)
		if _, err := view.ReadBatch(messages, 0); err != nil {
			t.Fatal(err)
		}
		allocations := testing.AllocsPerRun(1000, func() {
			if _, err := view.ReadBatch(messages, 0); err != nil {
				t.Fatal(err)
			}
		})
		if allocations > maxWarmReadBatchAllocs {
			t.Fatalf("allocations=%v want <=%d", allocations, maxWarmReadBatchAllocs)
		}
	})
}
