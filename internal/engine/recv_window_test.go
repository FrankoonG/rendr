package engine

import (
	"errors"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func TestPacketRecvWindowCoversG3T4Duration(t *testing.T) {
	const g3T4Packets = 100_000 * 5 * 60
	if packetRecvWindowBits <= g3T4Packets {
		t.Fatalf("packetRecvWindowBits=%d, want > %d", packetRecvWindowBits, g3T4Packets)
	}
}

func TestPacketMarksDoNotTripRecvQueueOverflow(t *testing.T) {
	e := New(SideServer, [16]byte{5}, Limits{})
	defer e.Close()
	e.SetPacketMode()

	e.recvMu.Lock()
	e.recvPacketMarks = recvReorderWindowLimit
	ok := e.onFrameRecvLocked(nil, proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Seq:     1,
	}, nil, nil)
	e.recvMu.Unlock()
	if ok {
		t.Fatal("out-of-order ctrl unexpectedly woke reader")
	}

	select {
	case <-e.Closed():
		t.Fatalf("engine closed from packet marks alone: %v", e.CloseErr())
	case <-time.After(20 * time.Millisecond):
	}
}

func TestRecvQueueOverflowClosesConnection(t *testing.T) {
	e := New(SideServer, [16]byte{4}, Limits{})
	defer e.Close()

	e.recvMu.Lock()
	for i := 0; i < recvReorderWindowLimit; i++ {
		ok := e.onFrameRecvLocked(nil, proto.Header{
			Version: proto.Version,
			Type:    proto.FrameData,
			Seq:     uint64(i + 1),
		}, []byte("x"), nil)
		if ok {
			t.Fatalf("out-of-order frame %d unexpectedly woke reader", i)
		}
	}
	ok := e.onFrameRecvLocked(nil, proto.Header{
		Version: proto.Version,
		Type:    proto.FrameData,
		Seq:     recvReorderWindowLimit + 1,
	}, []byte("overflow"), nil)
	e.recvMu.Unlock()
	if ok {
		t.Fatal("overflow frame unexpectedly woke reader")
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-e.Closed():
			if !errors.Is(e.CloseErr(), ErrRecvWindowExceeded) {
				t.Fatalf("CloseErr = %v, want ErrRecvWindowExceeded", e.CloseErr())
			}
			return
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Fatal("engine did not close after receive window overflow")
}
