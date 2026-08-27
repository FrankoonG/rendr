package rendr

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
)

func TestPacketWriteDeadlinePreservesAtomicPublishedLength(t *testing.T) {
	t.Run("before publication", func(t *testing.T) {
		e := engine.New(engine.SideClient, [16]byte{0xf1}, engine.Limits{})
		configurePublicWriteDeadlineGraph(t, e)
		e.SetPacketMode()
		t.Cleanup(func() { _ = e.Close() })
		packet := newEnginePacketConn(e, nil)
		if err := packet.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if n, err := packet.WriteTo([]byte("not-published"), nil); n != 0 || !publicWriteTimeout(err) {
			t.Fatalf("WriteTo before publication=(%d,%v), want (0, timeout)", n, err)
		}
	})

	t.Run("after publication", func(t *testing.T) {
		e := engine.New(engine.SideClient, [16]byte{0xf2}, engine.Limits{})
		configurePublicWriteDeadlineGraph(t, e)
		e.SetPacketMode()
		t.Cleanup(func() { _ = e.Close() })
		packet := newEnginePacketConn(e, nil)
		if err := packet.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		payload := []byte("published-datagram")
		n, err := packet.WriteTo(payload, nil)
		if n != len(payload) || !publicWriteTimeout(err) {
			t.Fatalf("WriteTo after publication=(%d,%v), want (%d, timeout)", n, err, len(payload))
		}
		if e.CloseErr() != nil {
			t.Fatalf("write timeout became terminal: %v", e.CloseErr())
		}
	})
}

func TestStreamWriteDeadlinePreservesPublishedLength(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		deadline  func() time.Time
		wantBytes bool
	}{
		{name: "before publication", deadline: func() time.Time { return time.Now().Add(-time.Second) }},
		{name: "after publication", deadline: func() time.Time { return time.Now().Add(40 * time.Millisecond) }, wantBytes: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			e := engine.New(engine.SideClient, [16]byte{0xf3}, engine.Limits{})
			configurePublicWriteDeadlineGraph(t, e)
			t.Cleanup(func() { _ = e.Close() })
			stream := &engineBackedConn{e: e, conn: &engine.Conn{E: e}}
			if err := stream.SetWriteDeadline(testCase.deadline()); err != nil {
				t.Fatal(err)
			}
			payload := []byte("published-stream-chunk")
			n, err := stream.Write(payload)
			want := 0
			if testCase.wantBytes {
				want = len(payload)
			}
			if n != want || !publicWriteTimeout(err) {
				t.Fatalf("Write=(%d,%v), want (%d, timeout)", n, err, want)
			}
			if e.CloseErr() != nil {
				t.Fatalf("write timeout became terminal: %v", e.CloseErr())
			}
		})
	}
}

func configurePublicWriteDeadlineGraph(t testing.TB, e *engine.Engine) {
	t.Helper()
	id := proto.DeriveTargetID(proto.GraphNodeKindPath, "packet-write-deadline")
	manifest := proto.GraphManifest{RootID: id, Nodes: []proto.GraphNode{{
		ID: id, Kind: proto.GraphNodeKindPath, Name: "packet-write-deadline",
	}}}
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
}

func publicWriteTimeout(err error) bool {
	if !errors.Is(err, ErrWriteDeadlineExceeded) || !errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
