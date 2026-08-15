package engine

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type terminalGapDropPath struct {
	*sequencerTestPath
	dropSeq uint64

	dataAttempts atomic.Uint32
	dropped      chan struct{}
	replayed     chan struct{}
	dropOnce     sync.Once
	replayOnce   sync.Once
}

func (p *terminalGapDropPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameData && header.Seq == p.dropSeq {
			attempt := p.dataAttempts.Add(1)
			if attempt == 1 {
				p.dropOnce.Do(func() { close(p.dropped) })
				return len(frame), nil
			}
			p.replayOnce.Do(func() { close(p.replayed) })
		}
	}
	return p.sequencerTestPath.Write(frame)
}

func attachTerminalGapTestPair(t *testing.T, client, server *Engine, dropSeq uint64, name string) (*terminalGapDropPath, *sequencerTestPath) {
	t.Helper()
	ids := configureSymmetricLeafGroupRuntime(t, client, server, proto.GraphNodeKindSelector, name)
	clientPath, serverPath := newSequencerTestPathPair()
	dropPath := &terminalGapDropPath{
		sequencerTestPath: clientPath,
		dropSeq:           dropSeq,
		dropped:           make(chan struct{}),
		replayed:          make(chan struct{}),
	}
	attachFixturePath(t, client, dropPath, transport.PathSpec{Transport: "memory", Address: name}, ids[name])
	attachFixturePath(t, server, serverPath, transport.PathSpec{Transport: "memory", Address: name}, ids[name])
	return dropPath, serverPath
}

func TestGracefulCloseReplaysGapBeforePeerEOF(t *testing.T) {
	flow := NewClientFlowID()
	limits := Limits{MigrationBudget: time.Second}
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	dropPath, serverPath := attachTerminalGapTestPair(t, client, server, 0, "terminal-gap")

	payload := []byte("payload-before-terminal-gap")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	select {
	case <-dropPath.dropped:
	default:
		t.Fatal("initial DATA was not silently dropped")
	}

	client.BeginGracefulClose()
	if !client.sendClosing.Load() {
		t.Fatal("graceful close did not publish sendClosing before replay")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.GracefulClose(proto.ByeNormal) }()

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("RecvPacket after gap replay: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("RecvPacket payload=%q want %q", got, payload)
	}
	if _, err := server.RecvPacket(); !errors.Is(err, io.EOF) {
		t.Fatalf("RecvPacket after payload error=%v want EOF", err)
	}
	select {
	case <-dropPath.replayed:
	case <-time.After(time.Second):
		t.Fatal("missing DATA was not replayed after the terminal gap ACK")
	}
	if attempts := dropPath.dataAttempts.Load(); attempts < 2 {
		t.Fatalf("DATA attempts=%d want initial publication plus replay", attempts)
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("GracefulClose: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GracefulClose did not complete after terminal gap repair")
	}
	select {
	case <-dropPath.failed:
		t.Fatal("client path died; test requires silent loss without path death")
	default:
	}
	select {
	case <-serverPath.failed:
		t.Fatal("server path died; test requires silent loss without path death")
	default:
	}
}
