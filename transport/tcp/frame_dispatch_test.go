package tcp

import (
	"bytes"
	"context"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type frameDispatchTraceConn struct {
	net.Conn

	mu          sync.Mutex
	events      []string
	authorized  []transport.FrameDispatchAuthorization
	completions []transport.FrameDispatchCompletion
	beginHook   func()
	maxWrite    int
}

type frameDispatchTraceSpan struct {
	connection *frameDispatchTraceConn
}

type panicDispatchTracer struct {
	finish bool
}

type panicDispatchSpan struct{}

func (tracer panicDispatchTracer) BeginFrameDispatch(transport.FrameDispatchAuthorization) transport.FrameDispatchSpan {
	if !tracer.finish {
		panic("begin dispatch panic")
	}
	return panicDispatchSpan{}
}

func (panicDispatchSpan) FinishFrameDispatch(transport.FrameDispatchCompletion) {
	panic("finish dispatch panic")
}

func (connection *frameDispatchTraceConn) BeginFrameDispatch(
	authorization transport.FrameDispatchAuthorization,
) transport.FrameDispatchSpan {
	connection.mu.Lock()
	connection.events = append(connection.events, "begin")
	connection.authorized = append(connection.authorized, authorization)
	hook := connection.beginHook
	connection.mu.Unlock()
	if hook != nil {
		hook()
	}
	return &frameDispatchTraceSpan{connection: connection}
}

func (span *frameDispatchTraceSpan) FinishFrameDispatch(completion transport.FrameDispatchCompletion) {
	span.connection.mu.Lock()
	span.connection.events = append(span.connection.events, "finish")
	span.connection.completions = append(span.connection.completions, completion)
	span.connection.mu.Unlock()
}

func (connection *frameDispatchTraceConn) Write(payload []byte) (int, error) {
	connection.mu.Lock()
	connection.events = append(connection.events, "write")
	maxWrite := connection.maxWrite
	connection.mu.Unlock()
	if maxWrite > 0 && len(payload) > maxWrite {
		payload = payload[:maxWrite]
	}
	return connection.Conn.Write(payload)
}

func TestPathConnContainsDispatchTracerPanicAndPreservesEndpoint(t *testing.T) {
	for _, test := range []struct {
		name   string
		finish bool
	}{
		{name: "begin"},
		{name: "finish", finish: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, peer := net.Pipe()
			path := Wrap(raw)
			path.dispatchTracer = panicDispatchTracer{finish: test.finish}
			t.Cleanup(func() {
				_ = path.Close()
				_ = peer.Close()
			})
			frames := [][]byte{
				dispatchTestFrame(t, 6, []byte("panic-contained")),
				dispatchTestFrame(t, 7, []byte("endpoint-remains-usable")),
			}
			drained := make(chan error, 1)
			go func() {
				for _, frame := range frames {
					wire := make([]byte, LengthPrefixSize+len(frame))
					if _, err := io.ReadFull(peer, wire); err != nil {
						drained <- err
						return
					}
				}
				drained <- nil
			}()
			for index, frame := range frames {
				sequence := uint64(6 + index)
				if n, err := path.WriteFrameDispatch(frame, dispatchTestAuthorization(frame, sequence)); err != nil || n != len(frame) {
					t.Fatalf("dispatch %d after tracer panic=(%d,%v), want (%d,nil)", index, n, err, len(frame))
				}
			}
			if err := <-drained; err != nil {
				t.Fatal(err)
			}
			path.endpoint.mu.Lock()
			writeActive := path.endpoint.writeActive
			path.endpoint.mu.Unlock()
			if writeActive {
				t.Fatal("dispatch tracer panic retained the endpoint write lease")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			maintenance, err := path.endpoint.beginMaintenance(ctx)
			if err != nil {
				t.Fatalf("maintenance after tracer panic: %v", err)
			}
			if err := maintenance.Resume(); err != nil {
				t.Fatalf("resume after tracer panic: %v", err)
			}
		})
	}
}

func TestPathConnForwardsFrameDispatchTraceToWrappedConn(t *testing.T) {
	raw, peer := net.Pipe()
	traced := &frameDispatchTraceConn{Conn: raw}
	path := Wrap(traced)
	t.Cleanup(func() {
		_ = path.Close()
		_ = peer.Close()
	})

	payload := []byte("trace")
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 7}).Encode(frame); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	authorization := transport.FrameDispatchAuthorization{
		Sequence: 7, PublishedNext: 8, LedgerGeneration: 1, AdmissionID: 11, AttemptID: 12,
		Kind: transport.FrameDispatchKindInitialCohort, AuthorizedAt: time.Now(),
		FrameBytes: len(frame), FrameDigest: proto.DigestFrame(frame),
	}
	received := make(chan []byte, 1)
	go func() {
		wire := make([]byte, LengthPrefixSize+len(frame))
		_, err := io.ReadFull(peer, wire)
		if err != nil {
			received <- nil
			return
		}
		received <- wire[LengthPrefixSize:]
	}()
	written, err := path.WriteFrameDispatch(frame, authorization)
	if err != nil || written != len(frame) {
		t.Fatalf("Write=%d,%v want %d,nil", written, err, len(frame))
	}
	if got := <-received; !slices.Equal(got, frame) {
		t.Fatalf("wire frame=%x want %x", got, frame)
	}

	traced.mu.Lock()
	defer traced.mu.Unlock()
	if !slices.Equal(traced.events, []string{"begin", "write", "write", "finish"}) {
		t.Fatalf("trace order=%v", traced.events)
	}
	wantAuthorization := authorization
	wantAuthorization.PhysicalOccurrence = 1
	wantAuthorization.EndpointGeneration = 1
	if len(traced.authorized) != 1 || traced.authorized[0] != wantAuthorization {
		t.Fatalf("authorization=%+v", traced.authorized)
	}
	if len(traced.completions) != 1 ||
		traced.completions[0].AttemptState != transport.FrameDispatchAttempted ||
		!traced.completions[0].WriteAttempted ||
		!traced.completions[0].WholeFrameAccepted || traced.completions[0].Err != nil {
		t.Fatalf("completion=%+v", traced.completions)
	}
}

func TestPathConnFrameDispatchAggregatesShortWritesWithinOccurrence(t *testing.T) {
	raw, peer := net.Pipe()
	traced := &frameDispatchTraceConn{Conn: raw, maxWrite: 3}
	path := Wrap(traced)
	t.Cleanup(func() {
		_ = path.Close()
		_ = peer.Close()
	})
	frame := dispatchTestFrame(t, 8, bytes.Repeat([]byte("s"), 64))
	authorization := dispatchTestAuthorization(frame, 8)
	received := make(chan []byte, 1)
	go readDispatchTestFrame(peer, len(frame), received)

	written, err := path.WriteFrameDispatch(frame, authorization)
	if err != nil || written != len(frame) {
		t.Fatalf("short-write dispatch=%d,%v want %d,nil", written, err, len(frame))
	}
	if got := <-received; !slices.Equal(got, frame) {
		t.Fatalf("short-write wire frame=%x want %x", got, frame)
	}

	traced.mu.Lock()
	defer traced.mu.Unlock()
	if len(traced.authorized) != 1 || traced.authorized[0].PhysicalOccurrence != 1 ||
		traced.authorized[0].EndpointGeneration != 1 || traced.authorized[0].FrameOffset != 0 {
		t.Fatalf("short-write authorization=%+v", traced.authorized)
	}
	if len(traced.completions) != 1 || traced.completions[0].WriteCalls <= 2 ||
		traced.completions[0].BytesWritten != len(frame) || !traced.completions[0].WholeFrameAccepted ||
		traced.completions[0].Err != nil {
		t.Fatalf("short-write completion=%+v", traced.completions)
	}
}

func TestWriteFrameDispatchWaitsForReplacementBeforeAuthorizingEndpoint(t *testing.T) {
	oldRaw, oldPeer := net.Pipe()
	oldTraced := &frameDispatchTraceConn{Conn: oldRaw}
	path := Wrap(oldTraced)
	t.Cleanup(func() {
		_ = path.Close()
		_ = oldPeer.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	maintenance, err := path.endpoint.beginMaintenance(ctx)
	if err != nil {
		t.Fatalf("begin maintenance: %v", err)
	}

	newRaw, newPeer := net.Pipe()
	newTraced := &frameDispatchTraceConn{Conn: newRaw}
	t.Cleanup(func() { _ = newPeer.Close() })
	frame := dispatchTestFrame(t, 9, []byte("replacement-bound"))
	authorization := dispatchTestAuthorization(frame, 9)
	received := make(chan []byte, 1)
	go readDispatchTestFrame(newPeer, len(frame), received)

	result := make(chan error, 1)
	go func() {
		n, writeErr := path.WriteFrameDispatch(frame, authorization)
		if writeErr == nil && n != len(frame) {
			writeErr = io.ErrShortWrite
		}
		result <- writeErr
	}()
	select {
	case err := <-result:
		t.Fatalf("dispatch escaped active maintenance: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := maintenance.Replace(newTraced); err != nil {
		t.Fatalf("replace endpoint: %v", err)
	}
	if err := maintenance.Resume(); err != nil {
		t.Fatalf("resume endpoint: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("replacement dispatch: %v", err)
	}
	if got := <-received; !slices.Equal(got, frame) {
		t.Fatalf("replacement wire frame=%x want %x", got, frame)
	}

	oldTraced.mu.Lock()
	oldEvents, oldAuthorizations := append([]string(nil), oldTraced.events...), len(oldTraced.authorized)
	oldTraced.mu.Unlock()
	newTraced.mu.Lock()
	newEvents, newAuthorizations := append([]string(nil), newTraced.events...), len(newTraced.authorized)
	newTraced.mu.Unlock()
	if len(oldEvents) != 0 || oldAuthorizations != 0 {
		t.Fatalf("predecessor events/authorizations=%v/%d, want none", oldEvents, oldAuthorizations)
	}
	if !slices.Equal(newEvents, []string{"begin", "write", "write", "finish"}) || newAuthorizations != 1 {
		t.Fatalf("replacement events/authorizations=%v/%d", newEvents, newAuthorizations)
	}
}

func TestWriteFrameDispatchReauthorizesAfterMaintenanceInterrupt(t *testing.T) {
	oldRaw, oldPeer := net.Pipe()
	entered := make(chan struct{})
	release := make(chan struct{})
	oldTraced := &frameDispatchTraceConn{Conn: oldRaw, beginHook: func() {
		close(entered)
		<-release
	}}
	path := Wrap(oldTraced)
	t.Cleanup(func() {
		_ = path.Close()
		_ = oldPeer.Close()
	})
	frame := dispatchTestFrame(t, 10, []byte("maintenance-race"))
	authorization := dispatchTestAuthorization(frame, 10)
	writeResult := make(chan error, 1)
	go func() {
		n, err := path.WriteFrameDispatch(frame, authorization)
		if err == nil && n != len(frame) {
			err = io.ErrShortWrite
		}
		writeResult <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not acquire predecessor endpoint")
	}

	maintenanceResult := make(chan *endpointMaintenance, 1)
	maintenanceErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		lease, err := path.endpoint.beginMaintenance(ctx)
		if err != nil {
			maintenanceErr <- err
			return
		}
		maintenanceResult <- lease
	}()
	// beginMaintenance publishes maintenance before interrupting the active
	// endpoint. Releasing Begin lets the exact predecessor write observe that
	// interruption and surrender its endpoint lease.
	close(release)
	var maintenance *endpointMaintenance
	select {
	case err := <-maintenanceErr:
		t.Fatalf("begin maintenance: %v", err)
	case maintenance = <-maintenanceResult:
	case <-time.After(time.Second):
		t.Fatal("maintenance did not quiesce predecessor dispatch")
	}

	newRaw, newPeer := net.Pipe()
	newTraced := &frameDispatchTraceConn{Conn: newRaw}
	t.Cleanup(func() { _ = newPeer.Close() })
	received := make(chan []byte, 1)
	go readDispatchTestFrame(newPeer, len(frame), received)
	if err := maintenance.Replace(newTraced); err != nil {
		t.Fatalf("replace endpoint: %v", err)
	}
	if err := maintenance.Resume(); err != nil {
		t.Fatalf("resume endpoint: %v", err)
	}
	if err := <-writeResult; err != nil {
		t.Fatalf("continued dispatch: %v", err)
	}
	if got := <-received; !slices.Equal(got, frame) {
		t.Fatalf("continued wire frame=%x want %x", got, frame)
	}

	for name, traced := range map[string]*frameDispatchTraceConn{"predecessor": oldTraced, "replacement": newTraced} {
		traced.mu.Lock()
		events := append([]string(nil), traced.events...)
		authorizations := len(traced.authorized)
		completions := len(traced.completions)
		traced.mu.Unlock()
		if authorizations != 1 || completions != 1 {
			t.Fatalf("%s authorization/completion=%d/%d events=%v", name, authorizations, completions, events)
		}
		begin, finish := slices.Index(events, "begin"), slices.Index(events, "finish")
		write := slices.Index(events, "write")
		if begin < 0 || write <= begin || finish <= write {
			t.Fatalf("%s unbound event order=%v", name, events)
		}
	}
	oldTraced.mu.Lock()
	oldAuthorization := oldTraced.authorized[0]
	oldTraced.mu.Unlock()
	newTraced.mu.Lock()
	newAuthorization := newTraced.authorized[0]
	newTraced.mu.Unlock()
	if oldAuthorization.AttemptID != newAuthorization.AttemptID ||
		oldAuthorization.PhysicalOccurrence != 1 || newAuthorization.PhysicalOccurrence != 2 ||
		oldAuthorization.EndpointGeneration != 1 || newAuthorization.EndpointGeneration != 2 ||
		oldAuthorization.FrameOffset != 0 || newAuthorization.FrameOffset != 0 {
		t.Fatalf("maintenance occurrence lineage old/new=%+v/%+v", oldAuthorization, newAuthorization)
	}
}

func TestWriteFrameDispatchCreditsWholeFrameAfterPrefixOnlyCutover(t *testing.T) {
	oldRaw, oldPeer := net.Pipe()
	oldTraced := &frameDispatchTraceConn{Conn: oldRaw}
	path := Wrap(oldTraced)
	t.Cleanup(func() {
		_ = path.Close()
		_ = oldPeer.Close()
	})
	frame := dispatchTestFrame(t, 11, []byte("prefix-only-cutover"))
	authorization := dispatchTestAuthorization(frame, 11)
	prefixRead := make(chan error, 1)
	go func() {
		prefix := make([]byte, LengthPrefixSize)
		_, err := io.ReadFull(oldPeer, prefix)
		prefixRead <- err
	}()
	writeResult := make(chan error, 1)
	go func() {
		n, err := path.WriteFrameDispatch(frame, authorization)
		if err == nil && n != len(frame) {
			err = io.ErrShortWrite
		}
		writeResult <- err
	}()
	if err := <-prefixRead; err != nil {
		t.Fatalf("read predecessor prefix: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	maintenance, err := path.endpoint.beginMaintenance(ctx)
	if err != nil {
		t.Fatalf("begin prefix-only maintenance: %v", err)
	}
	newRaw, newPeer := net.Pipe()
	newTraced := &frameDispatchTraceConn{Conn: newRaw}
	t.Cleanup(func() { _ = newPeer.Close() })
	received := make(chan []byte, 1)
	go func() {
		payload := make([]byte, len(frame))
		if _, err := io.ReadFull(newPeer, payload); err != nil {
			received <- nil
			return
		}
		received <- payload
	}()
	if err := maintenance.Replace(newTraced); err != nil {
		t.Fatalf("replace prefix-only endpoint: %v", err)
	}
	if err := maintenance.Resume(); err != nil {
		t.Fatalf("resume prefix-only endpoint: %v", err)
	}
	if err := <-writeResult; err != nil {
		t.Fatalf("continued prefix-only dispatch: %v", err)
	}
	if got := <-received; !slices.Equal(got, frame) {
		t.Fatalf("replacement frame=%x want %x", got, frame)
	}

	oldTraced.mu.Lock()
	oldCompletions := append([]transport.FrameDispatchCompletion(nil), oldTraced.completions...)
	oldTraced.mu.Unlock()
	newTraced.mu.Lock()
	newCompletions := append([]transport.FrameDispatchCompletion(nil), newTraced.completions...)
	newTraced.mu.Unlock()
	if len(oldCompletions) != 1 || oldCompletions[0].BytesWritten != 0 || oldCompletions[0].WholeFrameAccepted {
		t.Fatalf("predecessor completion=%+v", oldCompletions)
	}
	if len(newCompletions) != 1 || newCompletions[0].BytesWritten != len(frame) ||
		!newCompletions[0].WholeFrameAccepted || newCompletions[0].Err != nil {
		t.Fatalf("replacement completion=%+v", newCompletions)
	}
}

func dispatchTestFrame(t *testing.T, sequence uint64, payload []byte) []byte {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: sequence}).Encode(frame); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	return frame
}

func dispatchTestAuthorization(frame []byte, sequence uint64) transport.FrameDispatchAuthorization {
	return transport.FrameDispatchAuthorization{
		Sequence: sequence, PublishedNext: sequence + 1,
		AdmissionLedgerGeneration: 1, LedgerGeneration: 1,
		AdmissionID: 11, AttemptID: 12,
		Kind: transport.FrameDispatchKindInitialCohort, AuthorizedAt: time.Now(),
		FrameBytes: len(frame), FrameDigest: proto.DigestFrame(frame),
	}
}

func readDispatchTestFrame(peer net.Conn, frameBytes int, received chan<- []byte) {
	wire := make([]byte, LengthPrefixSize+frameBytes)
	if _, err := io.ReadFull(peer, wire); err != nil {
		received <- nil
		return
	}
	received <- wire[LengthPrefixSize:]
}
