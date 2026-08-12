package engine

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type packetPipelinePath struct {
	transport.PathConn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	data    atomic.Uint64
}

func (p *packetPipelinePath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameData {
			p.data.Add(1)
			blocked := false
			p.once.Do(func() {
				blocked = true
				close(p.entered)
			})
			if blocked {
				select {
				case <-p.release:
				case <-time.After(5 * time.Second):
					return 0, net.ErrClosed
				}
			}
		}
	}
	return p.PathConn.Write(frame)
}

func TestConcurrentPacketWritesPipelineAfterOrderedCustody(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)
	clientBase, serverPath := newMemoryPathPair()
	blocked := &packetPipelinePath{
		PathConn: clientBase,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	attachRecursivePath(t, client, server, "path", blocked, serverPath)

	type result struct {
		published bool
		err       error
	}
	firstDone := make(chan result, 1)
	secondDone := make(chan result, 1)
	go func() {
		published, err := client.SendPacketResult([]byte("first"))
		firstDone <- result{published: published, err: err}
	}()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("first packet did not enter the physical writer")
	}
	go func() {
		published, err := client.SendPacketResult([]byte("second"))
		secondDone <- result{published: published, err: err}
	}()

	eventuallyEngine(t, time.Second, func() bool {
		stats := client.ReplayStats()
		if stats.PublishedNext < 2 || stats.FramesInUse < 2 {
			return false
		}
		client.pathsMu.RLock()
		slot := client.paths[client.activeID]
		queued := slot != nil && len(slot.dispatchQ) >= 1
		client.pathsMu.RUnlock()
		return queued
	})
	select {
	case result := <-secondDone:
		t.Fatalf("second packet completed before the ordered physical writer: %+v", result)
	default:
	}

	close(blocked.release)
	for name, done := range map[string]<-chan result{"first": firstDone, "second": secondDone} {
		select {
		case result := <-done:
			if !result.published || result.err != nil {
				t.Fatalf("%s packet result=%+v", name, result)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s packet did not complete", name)
		}
	}

	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 2 {
		packet, err := server.RecvPacket()
		if err != nil {
			t.Fatal(err)
		}
		seen[string(packet)] = true
	}
	if !seen["first"] || !seen["second"] || len(seen) != 2 {
		t.Fatalf("received packets=%v", seen)
	}
	if blocked.data.Load() != 2 {
		t.Fatalf("physical DATA writes=%d, want 2", blocked.data.Load())
	}
	if err := client.CloseErr(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("client close state after packet pipeline: %v", err)
	}
}
