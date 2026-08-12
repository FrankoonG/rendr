package engine

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func TestSequenceExhaustionReservesFinalSequenceForTerminalClose(t *testing.T) {
	for _, test := range []struct {
		name string
		send func(*Engine) error
	}{
		{
			name: "application-data",
			send: func(engine *Engine) error {
				_, err := engine.SendData([]byte("last-ordinary-frame"))
				return err
			},
		},
		{
			name: "sequenced-control",
			send: func(engine *Engine) error {
				return engine.sendFrame(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlPathQuality), nil)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := New(SideClient, NewClientFlowID(), Limits{MigrationBudget: 250 * time.Millisecond})
			t.Cleanup(func() { _ = engine.Close() })
			path := newCloseLinearizationPath()
			path.autoAckBye = true
			path.byeStarted = make(chan struct{})
			attachCloseLinearizationPath(t, engine, path)
			atomic.StoreUint64(&engine.sendSeq, proto.MaxSeq-1)

			if err := test.send(engine); err != nil {
				t.Fatalf("publish MaxSeq-1: %v", err)
			}
			if err := test.send(engine); !errors.Is(err, ErrSequenceExhausted) {
				t.Fatalf("exhaustion error=%v want ErrSequenceExhausted", err)
			}
			waitCloseLinearizationSignal(t, path.byeStarted, time.Second, "reserved final BYE")
			select {
			case <-engine.Closed():
			case <-time.After(time.Second):
				t.Fatal("sequence exhaustion did not close the engine")
			}
			if !errors.Is(engine.CloseErr(), ErrSequenceExhausted) {
				t.Fatalf("CloseErr=%v want ErrSequenceExhausted", engine.CloseErr())
			}

			headers := sequenceTestNonProbeHeaders(path.snapshotHeaders())
			if len(headers) != 2 {
				t.Fatalf("wire headers=%+v want one ordinary frame and one BYE", headers)
			}
			if headers[0].Seq != proto.MaxSeq-1 {
				t.Fatalf("ordinary seq=%d want %d", headers[0].Seq, proto.MaxSeq-1)
			}
			if headers[1].Seq != proto.MaxSeq || headers[1].Type != proto.FrameCtrl ||
				proto.CtrlCodeFromFlags(headers[1].Flags) != proto.CtrlBye {
				t.Fatalf("terminal header=%+v want BYE at MaxSeq", headers[1])
			}
			if got := atomic.LoadUint64(&engine.sendSeq); got != proto.MaxSeq+1 {
				t.Fatalf("next sequence=%d want MaxSeq+1", got)
			}
		})
	}
}

func TestSequenceExhaustionAndConcurrentCloseShareOneTerminalFrame(t *testing.T) {
	engine := New(SideClient, NewClientFlowID(), Limits{MigrationBudget: 250 * time.Millisecond})
	t.Cleanup(func() { _ = engine.Close() })
	byeGate := make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(byeGate) }) })
	path := newCloseLinearizationPath()
	path.autoAckBye = true
	path.byeStarted = make(chan struct{})
	path.byeGate = byeGate
	attachCloseLinearizationPath(t, engine, path)
	atomic.StoreUint64(&engine.sendSeq, proto.MaxSeq)

	if _, err := engine.SendData([]byte("exhaust")); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("SendData error=%v want ErrSequenceExhausted", err)
	}
	waitCloseLinearizationSignal(t, path.byeStarted, time.Second, "exhaustion BYE")

	const callers = 16
	results := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func() { results <- engine.GracefulClose(proto.ByeNormal) }()
	}
	time.Sleep(10 * time.Millisecond)
	release.Do(func() { close(byeGate) })
	for index := 0; index < callers; index++ {
		select {
		case err := <-results:
			if !errors.Is(err, ErrSequenceExhausted) {
				t.Errorf("close caller %d error=%v want ErrSequenceExhausted", index, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("close caller %d did not join terminal transaction", index)
		}
	}

	byeCount := 0
	for _, header := range path.snapshotHeaders() {
		if header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlBye {
			byeCount++
			if header.Seq != proto.MaxSeq {
				t.Errorf("BYE seq=%d want MaxSeq", header.Seq)
			}
		}
	}
	if byeCount != 1 {
		t.Fatalf("terminal BYE count=%d want 1", byeCount)
	}
	if _, err := engine.SendData([]byte("after-close")); !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("post-exhaustion write error=%v", err)
	}
}

func TestSequenceExhaustionRealPeerProvesMaxSequence(t *testing.T) {
	flow := NewClientFlowID()
	limits := Limits{MigrationBudget: time.Second}
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	const boundary = proto.MaxSeq - 1
	client.sendMu.Lock()
	client.sendHistMu.Lock()
	priorProof := client.sendProof
	if client.sendAckProof != priorProof {
		client.sendHistMu.Unlock()
		client.sendMu.Unlock()
		t.Fatal("new sender did not start from one proof frontier")
	}
	atomic.StoreUint64(&client.sendSeq, boundary)
	client.sendAckNext.Store(boundary)
	client.sendPublishedNext.Store(boundary)
	client.sendHistMu.Unlock()
	client.sendMu.Unlock()

	server.recvMu.Lock()
	if server.recvProof != priorProof {
		server.recvMu.Unlock()
		t.Fatal("matching receiver did not start from the sender proof frontier")
	}
	server.expectedRecvSeq = boundary
	server.recvAckSent = boundary
	server.recvMu.Unlock()

	dropPath, serverPath := attachTerminalGapTestPair(t, client, server, boundary, "sequence-boundary-peer")

	payload := []byte("max-sequence-payload")
	if _, err := client.SendData(payload); err != nil {
		t.Fatalf("publish MaxSeq-1 DATA: %v", err)
	}
	select {
	case <-dropPath.dropped:
	default:
		t.Fatal("MaxSeq-1 DATA was not silently dropped")
	}
	if _, err := client.SendData([]byte("exhaust")); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("exhaustion error=%v want ErrSequenceExhausted", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	peer := &Conn{E: server}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatalf("peer read MaxSeq-1 DATA: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("peer payload=%q want %q", got, payload)
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("peer read after MaxSeq BYE error=%v want EOF", err)
	}
	select {
	case <-dropPath.replayed:
	case <-time.After(time.Second):
		t.Fatal("automatic sequence-exhaustion close did not replay MaxSeq-1")
	}
	if attempts := dropPath.dataAttempts.Load(); attempts < 2 {
		t.Fatalf("MaxSeq-1 DATA attempts=%d want initial publication plus replay", attempts)
	}

	select {
	case <-client.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("sequence exhaustion close did not receive terminal peer proof")
	}
	if !errors.Is(client.CloseErr(), ErrSequenceExhausted) {
		t.Fatalf("CloseErr=%v want ErrSequenceExhausted", client.CloseErr())
	}
	if got := client.sendAckNext.Load(); got != proto.MaxSeq+1 {
		t.Fatalf("peer ACK frontier=%d want MaxSeq+1", got)
	}

	wantProof := advanceSequenceTestProof(t, priorProof, proto.Header{
		Version: proto.Version,
		Type:    proto.FrameData,
		Seq:     boundary,
	}, payload)
	wantProof = advanceSequenceTestProof(t, wantProof, proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlBye),
		Seq:     proto.MaxSeq,
	}, proto.ByePayload{Reason: proto.ByeNormal}.Encode())

	client.sendHistMu.Lock()
	ackProof := client.sendAckProof
	remainingHistory := len(client.sendHist.entries)
	client.sendHistMu.Unlock()
	server.recvMu.Lock()
	recvNext := server.expectedRecvSeq
	recvProof := server.recvProof
	server.recvMu.Unlock()
	if recvNext != proto.MaxSeq+1 {
		t.Fatalf("receiver frontier=%d want MaxSeq+1", recvNext)
	}
	if recvProof != wantProof {
		t.Fatalf("receiver proof=%x want %x", recvProof, wantProof)
	}
	if ackProof != wantProof {
		t.Fatalf("sender acknowledged proof=%x want %x", ackProof, wantProof)
	}
	if remainingHistory != 0 {
		t.Fatalf("acknowledged replay ledger entries=%d want 0", remainingHistory)
	}
	select {
	case <-dropPath.failed:
		t.Fatal("client path died; sequence-boundary replay requires silent loss")
	default:
	}
	select {
	case <-serverPath.failed:
		t.Fatal("server path died; sequence-boundary replay requires silent loss")
	default:
	}
}

func advanceSequenceTestProof(t *testing.T, previous proto.AckProof, header proto.Header, payload []byte) proto.AckProof {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := header.Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatalf("encode proof frame: %v", err)
	}
	copy(frame[proto.HeaderSize:], payload)
	return proto.AdvanceAckProof(previous, proto.DigestFrame(frame))
}

func sequenceTestNonProbeHeaders(headers []proto.Header) []proto.Header {
	filtered := make([]proto.Header, 0, len(headers))
	for _, header := range headers {
		if header.Type == proto.FrameCtrl {
			switch proto.CtrlCodeFromFlags(header.Flags) {
			case proto.CtrlPathProbe, proto.CtrlPathProbeReply:
				continue
			}
		}
		filtered = append(filtered, header)
	}
	return filtered
}
