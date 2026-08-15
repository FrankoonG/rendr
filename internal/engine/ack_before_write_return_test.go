package engine

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type ackBeforeWriteReturnPath struct {
	transport.PathConn

	delivered chan struct{}
	release   chan struct{}
	returned  chan struct{}
	blockOnce sync.Once
	closeOnce sync.Once
	dataSeq   atomic.Uint64
}

func newAckBeforeWriteReturnPath(path transport.PathConn) *ackBeforeWriteReturnPath {
	return &ackBeforeWriteReturnPath{
		PathConn:  path,
		delivered: make(chan struct{}),
		release:   make(chan struct{}),
		returned:  make(chan struct{}),
	}
}

func (p *ackBeforeWriteReturnPath) Write(frame []byte) (int, error) {
	header, isData := proto.Header{}, false
	if len(frame) >= proto.HeaderSize {
		var err error
		header, err = proto.DecodeHeader(frame[:proto.HeaderSize])
		isData = err == nil && header.Type == proto.FrameData
	}

	n, err := p.PathConn.Write(frame)
	if err != nil || !isData {
		return n, err
	}
	p.blockOnce.Do(func() {
		p.dataSeq.Store(header.Seq)
		close(p.delivered)
		<-p.release
		close(p.returned)
	})
	return n, nil
}

func (p *ackBeforeWriteReturnPath) releaseWrite() {
	p.closeOnce.Do(func() { close(p.release) })
}

func TestApplicationWriteCompletesOnAckBeforePathWriteReturns(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	clientPath, serverPath := newMemoryPathPair()
	blocked := newAckBeforeWriteReturnPath(clientPath)
	t.Cleanup(func() {
		blocked.releaseWrite()
		_ = client.Close()
		_ = server.Close()
	})

	targets := configureSymmetricLeafGroupRuntime(
		t, client, server, proto.GraphNodeKindSelector, "path",
	)
	clientPathID := attachFixturePath(
		t, client, blocked,
		transport.PathSpec{Transport: "memory", Address: "ack-before-write-return"},
		targets["path"],
	)
	attachFixturePath(
		t, server, serverPath,
		transport.PathSpec{Transport: "memory", Address: "ack-before-write-return"},
		targets["path"],
	)

	client.pathsMu.RLock()
	slot := client.paths[clientPathID]
	client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("client path slot was not attached")
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	if err := client.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	payload := []byte("peer-ack-linearizes-application-write")
	type writeResult struct {
		n   int
		err error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		n, err := (&Conn{E: client}).Write(payload)
		writeDone <- writeResult{n: n, err: err}
	}()

	select {
	case <-blocked.delivered:
	case <-time.After(time.Second):
		t.Fatal("DATA did not reach the peer-side memory path")
	}
	select {
	case <-blocked.returned:
		t.Fatal("physical PathConn.Write returned before its release")
	default:
	}

	deadlineTimer := time.NewTimer(time.Until(deadline))
	defer deadlineTimer.Stop()
	select {
	case result := <-writeDone:
		if result.n != len(payload) || result.err != nil {
			t.Fatalf("application Write=(%d,%v), want (%d,nil)", result.n, result.err, len(payload))
		}
	case <-deadlineTimer.C:
		t.Fatal("application Write did not complete before its deadline despite peer ACK")
	}

	dataSeq := blocked.dataSeq.Load()
	if ackNext := client.sendAckNext.Load(); ackNext < dataSeq+1 {
		t.Fatalf("accepted cumulative ACK next=%d does not cover DATA seq=%d", ackNext, dataSeq)
	}
	select {
	case <-blocked.returned:
		t.Fatal("application success waited for physical PathConn.Write to return")
	default:
	}

	time.Sleep(client.executionStallWindowForSlot(slot) + 25*time.Millisecond)
	if slot.dispatchStalled.Load() || slot.dispatchStallGen.Load() != 0 {
		t.Fatalf("ACK-completed dispatch was marked stalled: stalled=%t generation=%d",
			slot.dispatchStalled.Load(), slot.dispatchStallGen.Load())
	}
	select {
	case <-blocked.returned:
		t.Fatal("physical PathConn.Write unexpectedly returned while checking stalled state")
	default:
	}

	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("server SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if n, err := server.Recv(got); n != len(payload) || err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("server Recv=(%q,%d,%v), want (%q,%d,nil)", got, n, err, payload, len(payload))
	}

	blocked.releaseWrite()
	select {
	case <-blocked.returned:
	case <-time.After(time.Second):
		t.Fatal("physical PathConn.Write did not return after release")
	}

	if err := server.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("server duplicate-check SetReadDeadline: %v", err)
	}
	if n, err := server.Recv(make([]byte, len(payload))); n != 0 || !errors.Is(err, ErrReadDeadlineExceeded) {
		t.Fatalf("unexpected repeated application delivery: Recv=(%d,%v)", n, err)
	}
	if got := clientPath.DataWrites(); got != 1 {
		t.Fatalf("physical DATA writes=%d, want exactly 1", got)
	}
	if got := server.RecvDups(); got != 0 {
		t.Fatalf("receiver duplicate-frame count=%d, want 0", got)
	}
}
