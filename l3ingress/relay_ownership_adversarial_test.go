package l3ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type exactTCPFlowCloser interface {
	CloseFlowRef(FlowRef) bool
}

type exactUDPFlowCloser interface {
	CloseFlowRef(FlowRef) bool
}

func TestTCPFlowRelaySeparatesExactFlowGenerations(t *testing.T) {
	id := tcpFlowRelayIdentity()
	ref1 := FlowRef{Identity: id, Generation: 1}
	ref2 := FlowRef{Identity: id, Generation: 2}
	oldControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
	newControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
	egress := &generationTCPOverlapEgress{
		oldConn:    newOwnershipTCPConn(oldControl, nil),
		newConn:    newOwnershipTCPConn(newControl, nil),
		oldStarted: make(chan struct{}),
		newStarted: make(chan struct{}),
		releaseOld: make(chan struct{}),
	}
	registry := NewEgressRegistry()
	if err := registry.Register("direct", egress); err != nil {
		t.Fatal(err)
	}
	relay := &TCPFlowRelay{Egresses: registry}
	var releaseOnce sync.Once
	releaseOld := func() { releaseOnce.Do(func() { close(egress.releaseOld) }) }
	t.Cleanup(func() {
		releaseOld()
		_ = relay.Close()
	})

	oldEndpointControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
	newEndpointControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
	oldResult := make(chan error, 1)
	newResult := make(chan error, 1)
	go func() {
		oldResult <- relay.Serve(
			context.Background(), packetEventWithRef(tcpFlowRelayEvent(id), ref1),
			newOwnershipTCPConn(oldEndpointControl, nil),
		)
	}()
	waitClosed(t, egress.oldStarted, "old TCP generation dial")
	go func() {
		newResult <- relay.Serve(
			context.Background(), packetEventWithRef(tcpFlowRelayEvent(id), ref2),
			newOwnershipTCPConn(newEndpointControl, nil),
		)
	}()
	waitClosed(t, egress.newStarted, "new TCP generation dial")

	closer, ok := any(relay).(exactTCPFlowCloser)
	if !ok {
		t.Fatal("TCP relay does not expose generation-exact CloseFlowRef")
	}
	if !closer.CloseFlowRef(ref1) {
		t.Fatal("generation-exact close did not retire pending TCP G1")
	}
	waitForTCPRelaySessionRef(t, relay, ref2)
	if relay.CloseFlow(id) {
		t.Fatal("identity-only CloseFlow closed a generation-owned TCP session")
	}

	releaseOld()
	oldErr := waitError(t, oldResult, "retired TCP G1 Serve")
	if oldErr == nil {
		t.Fatal("retired TCP G1 was published after its exact close")
	}
	oldControl.Wait(t)
	assertCloseOwnershipCalls(t, oldControl, 1)
	if got := newControl.calls.Load(); got != 0 {
		t.Fatalf("late TCP G1 completion closed G2 %d times", got)
	}
	if !closer.CloseFlowRef(ref2) {
		t.Fatal("generation-exact close did not retire active TCP G2")
	}
	_ = waitError(t, newResult, "TCP G2 Serve")
	assertCloseOwnershipCalls(t, newControl, 1)
	assertCloseOwnershipCalls(t, oldEndpointControl, 1)
	assertCloseOwnershipCalls(t, newEndpointControl, 1)
}

func TestUDPFlowRelaySeparatesExactFlowGenerations(t *testing.T) {
	id, baseEvent := ownershipUDPEvent(t)
	ref1 := FlowRef{Identity: id, Generation: 1}
	ref2 := FlowRef{Identity: id, Generation: 2}
	oldConn := newAdmissionPacketConn()
	newConn := newAdmissionPacketConn()
	egress := &generationUDPOverlapEgress{
		oldConn:    oldConn,
		newConn:    newConn,
		remote:     netip.MustParseAddrPort("198.51.100.53:53"),
		oldStarted: make(chan struct{}),
		newStarted: make(chan struct{}),
		releaseOld: make(chan struct{}),
	}
	registry := NewEgressRegistry()
	if err := registry.Register("dns-egress", egress); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
	var releaseOnce sync.Once
	releaseOld := func() { releaseOnce.Do(func() { close(egress.releaseOld) }) }
	t.Cleanup(func() {
		releaseOld()
		_ = relay.Close()
	})

	oldCtx, cancelOld := context.WithCancel(context.Background())
	defer cancelOld()
	oldResult := make(chan error, 1)
	newResult := make(chan error, 1)
	go func() {
		oldResult <- relay.HandlePacket(oldCtx, packetEventWithRef(baseEvent, ref1))
	}()
	waitClosed(t, egress.oldStarted, "old UDP generation dial")
	go func() {
		newResult <- relay.HandlePacket(context.Background(), packetEventWithRef(baseEvent, ref2))
	}()
	waitClosed(t, egress.newStarted, "new UDP generation dial")
	if err := waitError(t, newResult, "UDP G2 packet"); err != nil {
		t.Fatalf("UDP G2 packet failed behind G1: %v", err)
	}
	if got := newConn.writes.Load(); got != 1 {
		t.Fatalf("UDP G2 writes=%d want 1 on its own generation", got)
	}

	closer, ok := any(relay).(exactUDPFlowCloser)
	if !ok {
		t.Fatal("UDP relay does not expose generation-exact CloseFlowRef")
	}
	if !closer.CloseFlowRef(ref1) {
		t.Fatal("generation-exact close did not retire pending UDP G1")
	}
	if err := waitError(t, oldResult, "retired UDP G1 packet"); err == nil {
		t.Fatal("retired UDP G1 packet unexpectedly succeeded")
	}
	releaseOld()
	waitForL3Condition(t, time.Second, func() bool { return oldConn.closes.Load() == 1 }, "stale UDP G1 cleanup")
	if got := oldConn.writes.Load(); got != 0 {
		t.Fatalf("stale UDP G1 result published %d writes", got)
	}
	if relay.CloseFlow(id) {
		t.Fatal("identity-only CloseFlow closed a generation-owned UDP session")
	}
	if !closer.CloseFlowRef(ref2) {
		t.Fatal("generation-exact close did not retire active UDP G2")
	}
	if got := newConn.closes.Load(); got != 1 {
		t.Fatalf("UDP G2 closes=%d want 1", got)
	}
}

func TestRelayAbandonedDialReportsCleanupTerminalExactlyOnce(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolTCP, ProtocolUDP} {
		for _, terminal := range []struct {
			name   string
			mode   closeOwnershipMode
			err    error
			reason CallbackFailureReason
		}{
			{name: "error", mode: closeOwnershipReturn, err: errors.New("late cleanup error")},
			{name: "panic", mode: closeOwnershipPanic, reason: CallbackFailurePanic},
			{name: "goexit", mode: closeOwnershipGoexit, reason: CallbackFailureGoexit},
		} {
			protocol := protocol
			terminal := terminal
			t.Run(protocol.String()+"/"+terminal.name, func(t *testing.T) {
				testRelayAbandonedDialDiagnostic(t, protocol, terminal.mode, terminal.err, terminal.reason)
			})
		}
	}
}

func TestRelayCloseExecutorIsProcessBoundedAcrossFreshRelays(t *testing.T) {
	const (
		relayCount       = 8
		sessionsPerRelay = l3IngressProcessCallbackLimit
	)
	total := relayCount * sessionsPerRelay
	entered := make(chan struct{}, total)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	var calls atomic.Int32
	var relays sync.WaitGroup
	relays.Add(relayCount)
	for relayIndex := range relayCount {
		sessions := make(map[int]int, sessionsPerRelay)
		for sessionIndex := range sessionsPerRelay {
			sessions[relayIndex*sessionsPerRelay+sessionIndex] = sessionIndex
		}
		go func() {
			defer relays.Done()
			closeRelaySessionsBounded(sessions, func(int) {
				calls.Add(1)
				entered <- struct{}{}
				<-release
			})
		}()
	}
	for range l3IngressProcessCallbackLimit {
		waitSignal(t, entered, "process relay close worker")
	}
	select {
	case <-entered:
		t.Fatalf("a %dth relay close worker escaped the process bound", l3IngressProcessCallbackLimit+1)
	case <-time.After(DefaultEgressCloseTimeout / 4):
	}
	unblock()
	done := make(chan struct{})
	go func() {
		relays.Wait()
		close(done)
	}()
	waitClosed(t, done, "all process relay close jobs")
	if got := calls.Load(); got != int32(total) {
		t.Fatalf("relay close jobs=%d want %d", got, total)
	}
}

type generationTCPOverlapEgress struct {
	oldConn TCPConn
	newConn TCPConn

	calls      atomic.Int32
	oldStarted chan struct{}
	newStarted chan struct{}
	releaseOld chan struct{}
}

func (e *generationTCPOverlapEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	switch e.calls.Add(1) {
	case 1:
		close(e.oldStarted)
		<-e.releaseOld
		return e.oldConn, nil
	case 2:
		close(e.newStarted)
		return e.newConn, nil
	default:
		return nil, errors.New("unexpected TCP generation dial")
	}
}

func (*generationTCPOverlapEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, errors.New("TCP-only generation egress")
}

type generationUDPOverlapEgress struct {
	oldConn net.PacketConn
	newConn net.PacketConn
	remote  netip.AddrPort

	calls      atomic.Int32
	oldStarted chan struct{}
	newStarted chan struct{}
	releaseOld chan struct{}
}

func (*generationUDPOverlapEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	return nil, errors.New("UDP-only generation egress")
}

func (e *generationUDPOverlapEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	switch e.calls.Add(1) {
	case 1:
		close(e.oldStarted)
		<-e.releaseOld
		return e.oldConn, e.remote, nil
	case 2:
		close(e.newStarted)
		return e.newConn, e.remote, nil
	default:
		return nil, netip.AddrPort{}, errors.New("unexpected UDP generation dial")
	}
}

func testRelayAbandonedDialDiagnostic(
	t *testing.T,
	protocol Protocol,
	mode closeOwnershipMode,
	terminalErr error,
	terminalReason CallbackFailureReason,
) {
	t.Helper()
	dialErr := errors.New("late dial terminal")
	control := newLateCloseOwnershipControl(mode, terminalErr)
	egress := &lateDialOwnershipEgress{
		remote:  netip.MustParseAddrPort("198.51.100.53:53"),
		err:     dialErr,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	if protocol == ProtocolTCP {
		egress.tcp = newOwnershipTCPConn(control, nil)
	} else {
		egress.udp = newOwnershipPacketConn(control, nil)
	}
	registry := NewEgressRegistry()
	name := "direct"
	if protocol == ProtocolUDP {
		name = "dns-egress"
	}
	if err := registry.Register(name, egress); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	var closeRelay func() error
	if protocol == ProtocolTCP {
		id := tcpFlowRelayIdentity()
		relay := &TCPFlowRelay{Egresses: registry}
		closeRelay = relay.Close
		result := make(chan error, 1)
		go func() {
			result <- relay.Serve(
				ctx,
				packetEventWithRef(tcpFlowRelayEvent(id), FlowRef{Identity: id, Generation: 1}),
				newOwnershipTCPConn(newCloseOwnershipControl(closeOwnershipReturn, nil), nil),
			)
		}()
		waitClosed(t, egress.started, "late TCP dial")
		assertL3CallbackReason(t, waitError(t, result, "timed-out TCP dial"), CallbackFailureTimeout)
	} else {
		id, event := ownershipUDPEvent(t)
		relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
		closeRelay = relay.Close
		result := make(chan error, 1)
		go func() {
			result <- relay.HandlePacket(
				ctx, packetEventWithRef(event, FlowRef{Identity: id, Generation: 1}),
			)
		}()
		waitClosed(t, egress.started, "late UDP dial")
		if err := waitError(t, result, "timed-out UDP dial"); !errors.Is(err, context.DeadlineExceeded) {
			assertL3CallbackReason(t, err, CallbackFailureTimeout)
		}
	}

	close(egress.release)
	waitClosed(t, control.started, "abandoned result cleanup")
	time.Sleep(DefaultEgressCloseTimeout + 25*time.Millisecond)
	control.Release()
	control.Wait(t)
	deadline := time.Now().Add(time.Second)
	for {
		err := closeRelay()
		complete := directErrorCount(err, dialErr) == 1 &&
			callbackDiagnosticCount(err, lateDialCloseCallback(protocol), CallbackFailureTimeout) == 1
		if terminalErr != nil {
			complete = complete && directErrorCount(err, terminalErr) == 1
		} else {
			complete = complete && callbackDiagnosticCount(
				err, lateDialCloseCallback(protocol), terminalReason,
			) == 1
		}
		if complete {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for abandoned dial and cleanup terminal diagnostics: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	finalErr := closeRelay()
	if got := directErrorCount(finalErr, dialErr); got != 1 {
		t.Fatalf("late Dial terminal occurrences=%d want 1: %v", got, finalErr)
	}
	if got := callbackDiagnosticCount(
		finalErr, lateDialCloseCallback(protocol), CallbackFailureTimeout,
	); got != 1 {
		t.Fatalf("late cleanup timeout occurrences=%d want 1: %v", got, finalErr)
	}
	if terminalErr != nil {
		if got := directErrorCount(finalErr, terminalErr); got != 1 {
			t.Fatalf("late cleanup terminal occurrences=%d want 1: %v", got, finalErr)
		}
	} else if got := callbackDiagnosticCount(
		finalErr, lateDialCloseCallback(protocol), terminalReason,
	); got != 1 {
		t.Fatalf("late cleanup %s occurrences=%d want 1: %v", terminalReason, got, finalErr)
	}
	assertCloseOwnershipCalls(t, control, 1)
}

func packetEventWithRef(event PacketEvent, ref FlowRef) PacketEvent {
	event.Ref = ref
	return event
}

func lateDialCloseCallback(protocol Protocol) string {
	if protocol == ProtocolTCP {
		return "late Egress.DialTCP result Close"
	}
	// UDP admission intentionally survives an individual waiter deadline so
	// another same-generation waiter can claim the singleflight result.
	return "Egress.DialUDP connection Close"
}

func callbackDiagnosticCount(err error, callback string, reason CallbackFailureReason) int {
	if err == nil {
		return 0
	}
	count := 0
	if callbackErr, ok := err.(*CallbackError); ok &&
		callbackErr.Callback == callback && callbackErr.Reason == reason {
		count++
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range wrapped.Unwrap() {
			count += callbackDiagnosticCount(child, callback, reason)
		}
	case interface{ Unwrap() error }:
		count += callbackDiagnosticCount(wrapped.Unwrap(), callback, reason)
	}
	return count
}

func waitForTCPRelaySessionRef(t *testing.T, relay *TCPFlowRelay, ref FlowRef) {
	t.Helper()
	waitForL3Condition(t, time.Second, func() bool {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		return relay.sessions[relayFlowKeyFromRef(ref)] != nil
	}, "TCP relay exact-generation session")
}
