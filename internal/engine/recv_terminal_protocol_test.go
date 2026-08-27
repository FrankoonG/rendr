package engine

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestRecvPacketDrainsQueuedDataBeforeTerminal(t *testing.T) {
	e := &Engine{
		recvPacketCh:   make(chan []byte, 1),
		recvPacketWake: make(chan struct{}, 1),
		closed:         make(chan struct{}),
	}
	betweenChecks := make(chan struct{})
	release := make(chan struct{})
	var hookOnce sync.Once
	e.recvPacketBeforeTerminalLock = func() {
		hookOnce.Do(func() {
			close(betweenChecks)
			<-release
		})
	}

	type recvResult struct {
		packet []byte
		err    error
	}
	result := make(chan recvResult, 1)
	go func() {
		packet, err := e.RecvPacket()
		result <- recvResult{packet: packet, err: err}
	}()

	select {
	case <-betweenChecks:
	case <-time.After(time.Second):
		t.Fatal("RecvPacket did not reach the forced interleaving")
	}
	want := []byte("queued-before-terminal")
	e.recvMu.Lock()
	e.recvPacketCh <- append([]byte(nil), want...)
	e.publishRecvTerminalLocked(io.EOF)
	e.peerNormalBye.Store(true)
	e.recvMu.Unlock()
	close(release)

	select {
	case got := <-result:
		if got.err != nil || !bytes.Equal(got.packet, want) {
			t.Fatalf("first RecvPacket = (%q, %v), want queued DATA", got.packet, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("RecvPacket did not resolve the queued DATA/terminal interleaving")
	}
	if packet, err := e.RecvPacket(); packet != nil || !errors.Is(err, io.EOF) {
		t.Fatalf("second RecvPacket = (%q, %v), want terminal EOF", packet, err)
	}
}

func TestReaderLoopFailsClosedOnTruncatedFrameHeader(t *testing.T) {
	for size := 1; size < proto.HeaderSize; size++ {
		t.Run(strconv.Itoa(size)+"-bytes", func(t *testing.T) {
			e := New(SideServer, NewClientFlowID(), Limits{})
			path := &singleFrameReaderPath{
				frame:  bytes.Repeat([]byte{0xa5}, size),
				closed: make(chan struct{}),
			}
			slot := &pathSlot{
				conn:  path,
				quit:  make(chan struct{}),
				doneR: make(chan struct{}),
			}
			t.Cleanup(func() {
				_ = path.Close()
				_ = e.Close()
			})

			go e.readerLoop(slot)
			select {
			case <-e.Closed():
			case <-time.After(time.Second):
				t.Fatal("truncated frame did not close the engine")
			}
			if err := e.CloseErr(); !errors.Is(err, ErrPeerProtocol) {
				t.Fatalf("close error = %v, want ErrPeerProtocol", err)
			}
			select {
			case <-slot.doneR:
			case <-time.After(time.Second):
				t.Fatal("reader loop did not exit after protocol failure")
			}
		})
	}
}

type singleFrameReaderPath struct {
	frame     []byte
	closed    chan struct{}
	readOnce  sync.Once
	closeOnce sync.Once
}

func (p *singleFrameReaderPath) Read(buffer []byte) (int, error) {
	read := false
	p.readOnce.Do(func() { read = true })
	if read {
		return copy(buffer, p.frame), nil
	}
	<-p.closed
	return 0, net.ErrClosed
}

func (p *singleFrameReaderPath) Write(frame []byte) (int, error) { return len(frame), nil }
func (p *singleFrameReaderPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}
func (p *singleFrameReaderPath) Quality() transport.PathQuality            { return transport.PathQuality{} }
func (p *singleFrameReaderPath) OnDeath(func(transport.DeathCause, error)) {}
func (p *singleFrameReaderPath) LocalAddr() string                         { return "single-frame-local" }
func (p *singleFrameReaderPath) RemoteAddr() string                        { return "single-frame-remote" }

var _ transport.PathConn = (*singleFrameReaderPath)(nil)
