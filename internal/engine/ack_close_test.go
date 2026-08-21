package engine

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func currentAck(e *Engine, nextSeq uint64) proto.AckPayload {
	e.sendHistMu.Lock()
	proof := e.sendAckProof
	for _, entry := range e.sendHist.entries {
		if entry.seq+1 == nextSeq {
			proof = entry.proof
			break
		}
	}
	e.sendHistMu.Unlock()
	binding := e.localGraphBinding()
	return proto.AckPayload{
		SessionEpoch:  proto.SessionEpoch(e.flowID),
		Direction:     senderDirection(e.side),
		GraphRevision: binding.revision,
		GraphDigest:   binding.digest,
		NextSeq:       nextSeq,
		Proof:         proof,
	}
}

func reserveAckTestFrame(t *testing.T, e *Engine, seq uint64, frameType proto.FrameType) {
	t.Helper()
	control := frameType == proto.FrameCtrl
	if err := e.acquireSendSlot(control, proto.HeaderSize+1); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, proto.HeaderSize+1)
	if err := (proto.Header{Version: proto.Version, Type: frameType, Seq: seq}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	frame[proto.HeaderSize] = byte(seq + 1)
	if err := e.reserveSendFrame(frame); err != nil {
		t.Fatal(err)
	}
}

func reservePublishedTestFrame(t *testing.T, e *Engine, frame []byte) {
	t.Helper()
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if err := e.acquireSendSlot(header.Type == proto.FrameCtrl, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveAndPublishOwnedSendFrame(append([]byte(nil), frame...)); err != nil {
		t.Fatal(err)
	}
}

func TestPeerAckClampedToSentSeq(t *testing.T) {
	e := New(SideClient, [16]byte{2}, Limits{})
	reserveAckTestFrame(t, e, 0, proto.FrameData)
	reserveAckTestFrame(t, e, 1, proto.FrameData)
	atomic.StoreUint64(&e.sendSeq, 2)
	e.sendPublishedNext.Store(2)

	e.notePeerAck(currentAck(e, 3))
	if got := e.sendAckNext.Load(); got != 0 {
		t.Fatalf("future ACK advanced sendAckNext to %d, want 0", got)
	}
	if progress := e.sendACKProgress.Load(); progress != nil {
		t.Fatalf("future ACK created probe progress %+v", *progress)
	}

	receivedAt := time.Unix(12_345, 678)
	e.notePeerAckAt(currentAck(e, 2), receivedAt)
	if got := e.sendAckNext.Load(); got != 2 {
		t.Fatalf("valid ACK advanced sendAckNext to %d, want 2", got)
	}
	if progress := e.sendACKProgress.Load(); progress == nil || progress.next != 2 || progress.at != receivedAt {
		t.Fatalf("valid ACK probe progress=%+v", progress)
	}
}

func TestPeerAckRefreshesZombieCounterOnlyForApplicationData(t *testing.T) {
	e := New(SideClient, [16]byte{3}, Limits{})
	atomic.StoreUint64(&e.sendSeq, 1)
	e.sendPublishedNext.Store(1)
	reserveAckTestFrame(t, e, 0, proto.FrameData)

	e.zombieMu.Lock()
	e.zombieLeft = 1
	e.zombieLastMig = nowFn()
	e.zombieMu.Unlock()

	e.notePeerAck(currentAck(e, 1))

	e.zombieMu.Lock()
	left := e.zombieLeft
	last := e.zombieLastMig
	e.zombieMu.Unlock()

	if left != e.limits.ZombieMaxMigrations {
		t.Fatalf("zombieLeft = %d, want %d", left, e.limits.ZombieMaxMigrations)
	}
	if !last.IsZero() {
		t.Fatalf("zombieLastMig = %v, want zero", last)
	}
}

func TestControlOnlyAckDoesNotRefreshZombieCounter(t *testing.T) {
	e := New(SideClient, [16]byte{4}, Limits{})
	atomic.StoreUint64(&e.sendSeq, 1)
	e.sendPublishedNext.Store(1)
	reserveAckTestFrame(t, e, 0, proto.FrameCtrl)
	e.zombieMu.Lock()
	e.zombieLeft = 1
	e.zombieMu.Unlock()

	e.notePeerAck(currentAck(e, 1))

	e.zombieMu.Lock()
	left := e.zombieLeft
	e.zombieMu.Unlock()
	if left != 1 {
		t.Fatalf("control ACK refreshed zombieLeft to %d, want 1", left)
	}
}

func TestPeerAckRejectsWrongBinding(t *testing.T) {
	e := New(SideClient, [16]byte{5}, Limits{})
	atomic.StoreUint64(&e.sendSeq, 1)
	e.sendPublishedNext.Store(1)

	tests := map[string]func(*proto.AckPayload){
		"opposite direction": func(a *proto.AckPayload) { a.Direction = proto.SenderDirectionServerToClient },
		"stale session":      func(a *proto.AckPayload) { a.SessionEpoch[0]++ },
		"stale graph":        func(a *proto.AckPayload) { a.GraphRevision++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			ack := currentAck(e, 1)
			mutate(&ack)
			if e.notePeerAck(ack) {
				t.Fatal("accepted incorrectly bound ACK")
			}
			if got := e.sendAckNext.Load(); got != 0 {
				t.Fatalf("sendAckNext = %d, want 0", got)
			}
		})
	}
}

func TestPeerAckRejectsExactFrontierWithoutFrameProof(t *testing.T) {
	e := New(SideClient, [16]byte{6}, Limits{})
	reserveAckTestFrame(t, e, 0, proto.FrameData)
	atomic.StoreUint64(&e.sendSeq, 1)
	e.sendPublishedNext.Store(1)

	ack := currentAck(e, 1)
	ack.Proof[0] ^= 0xff
	if e.notePeerAck(ack) {
		t.Fatal("accepted exact-current ACK without the published frame proof")
	}
	if got := e.sendAckNext.Load(); got != 0 {
		t.Fatalf("sendAckNext = %d, want 0", got)
	}
	e.sendHistMu.Lock()
	remaining := len(e.sendHist.entries)
	e.sendHistMu.Unlock()
	if remaining != 1 {
		t.Fatalf("replay ledger entries = %d, want 1", remaining)
	}
}
