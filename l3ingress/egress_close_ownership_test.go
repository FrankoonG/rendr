package l3ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEgressRegistryCleansNonNilErrorResultsExactlyOnce(t *testing.T) {
	callbackErr := errors.New("egress callback failed")
	closeErr := errors.New("egress close failed")
	tests := []struct {
		name string
		mode closeOwnershipMode
		want CallbackFailureReason
	}{
		{name: "returned-error", mode: closeOwnershipReturn},
		{name: "panic", mode: closeOwnershipPanic, want: CallbackFailurePanic},
		{name: "goexit", mode: closeOwnershipGoexit, want: CallbackFailureGoexit},
		{name: "blocked", mode: closeOwnershipBlock, want: CallbackFailureTimeout},
	}
	protocols := []Protocol{ProtocolTCP, ProtocolUDP}

	for _, proto := range protocols {
		proto := proto
		for _, test := range tests {
			test := test
			t.Run(proto.String()+"/"+test.name, func(t *testing.T) {
				control := newCloseOwnershipControl(test.mode, closeErr)
				egress := &staticOwnershipEgress{err: callbackErr}
				if proto == ProtocolTCP {
					egress.tcp = newOwnershipTCPConn(control, nil)
				} else {
					egress.udp = newOwnershipPacketConn(control, nil)
					egress.remote = netip.MustParseAddrPort("198.51.100.53:53")
				}
				registry := NewEgressRegistry()
				if err := registry.Register("broken", egress); err != nil {
					t.Fatal(err)
				}

				started := time.Now()
				var err error
				if proto == ProtocolTCP {
					var conn TCPConn
					conn, err = registry.DialTCP(context.Background(), "broken", L3Identity{Proto: proto})
					if conn != nil {
						t.Fatal("DialTCP returned the failed connection")
					}
				} else {
					var conn net.PacketConn
					conn, _, err = registry.DialUDP(context.Background(), "broken", L3Identity{Proto: proto})
					if conn != nil {
						t.Fatal("DialUDP returned the failed connection")
					}
				}
				if elapsed := time.Since(started); elapsed > 4*DefaultEgressCloseTimeout {
					t.Fatalf("bounded cleanup took %v", elapsed)
				}
				if !errors.Is(err, callbackErr) {
					t.Fatalf("error=%v does not retain callback failure", err)
				}
				if reason, ok := EgressErrorReasonOf(err); !ok || reason != ReasonInvalidEgressResult {
					t.Fatalf("egress reason=%q ok=%v err=%v", reason, ok, err)
				}
				if test.want != "" {
					assertL3CallbackReason(t, err, test.want)
				} else if !errors.Is(err, closeErr) {
					t.Fatalf("error=%v does not retain Close error", err)
				}
				if got := control.calls.Load(); got != 1 {
					t.Fatalf("Close calls=%d want 1", got)
				}
				control.Release()
				control.Wait(t)

				// Panic and Goexit must release callback capacity for later healthy
				// cleanup rather than poisoning the process-wide executor.
				healthy := newCloseOwnershipControl(closeOwnershipReturn, nil)
				authority, authorityErr := newEgressCloseAuthority(healthy, "healthy Close")
				if authorityErr != nil {
					t.Fatal(authorityErr)
				}
				if err := authority.Close(); err != nil {
					t.Fatalf("healthy cleanup after abnormal exit: %v", err)
				}
				if got := healthy.calls.Load(); got != 1 {
					t.Fatalf("healthy Close calls=%d want 1", got)
				}
			})
		}
	}
}

func TestEgressCloseAuthoritySaturationBoundsCallbacksAndGoroutines(t *testing.T) {
	waitForL3Condition(t, time.Second, func() bool {
		return len(l3IngressProcessCallbackSlots[l3IngressCallbackEgressCleanup]) == 0
	}, "empty egress cleanup callback executor")

	const overflow = 17
	total := l3IngressProcessCallbackLimit + overflow
	egress := &dynamicOwnershipEgress{
		mode:   closeOwnershipBlock,
		remote: netip.MustParseAddrPort("198.51.100.53:53"),
	}
	registry := NewEgressRegistry()
	if err := registry.Register("bounded", egress); err != nil {
		t.Fatal(err)
	}
	connections := make([]net.PacketConn, total)
	results := make([]error, total)
	baselineGoroutines := runtime.NumGoroutine()
	for i := range total {
		conn, _, err := registry.DialUDP(
			context.Background(),
			"bounded",
			L3Identity{Proto: ProtocolUDP},
		)
		if err != nil {
			t.Fatalf("external Dial %d: %v", i, err)
		}
		connections[i] = conn
	}
	controls := egress.Controls()
	if len(controls) != total {
		t.Fatalf("external objects=%d want %d", len(controls), total)
	}

	var callers sync.WaitGroup
	callers.Add(total)
	for i := range total {
		i := i
		go func() {
			defer callers.Done()
			results[i] = connections[i].Close()
		}()
	}
	callers.Wait()

	started := 0
	timedOut := 0
	for i, control := range controls {
		calls := control.calls.Load()
		if calls > 1 {
			t.Fatalf("connection %d Close calls=%d want at most 1", i, calls)
		}
		if calls == 1 {
			started++
		}
		var callbackErr *CallbackError
		if !errors.As(results[i], &callbackErr) {
			t.Fatalf("connection %d error=%v is not CallbackError", i, results[i])
		}
		if callbackErr.Reason == CallbackFailureTimeout {
			timedOut++
		} else {
			t.Fatalf("connection %d callback reason=%q", i, callbackErr.Reason)
		}
	}
	if got := egress.dials.Load(); got != int32(total) {
		t.Fatalf("external Dial invocations=%d want %d", got, total)
	}
	if started != l3IngressProcessCallbackLimit || timedOut != total {
		// Queued authorities also time out at the caller while preserving their
		// durable cleanup obligation.
		t.Fatalf("started=%d timed_out=%d want started=%d timed_out=%d",
			started, timedOut, l3IngressProcessCallbackLimit, total)
	}

	runtime.GC()
	waitForL3Condition(t, time.Second, func() bool {
		return runtime.NumGoroutine() <= baselineGoroutines+l3IngressProcessCallbackLimit+4
	}, "bounded Close callback goroutines")
	if got := runtime.NumGoroutine() - baselineGoroutines; got > l3IngressProcessCallbackLimit+4 {
		t.Fatalf("goroutine growth=%d exceeds callback bound", got)
	}

	for _, control := range controls[:l3IngressProcessCallbackLimit] {
		control.Release()
	}
	waitForL3Condition(t, time.Second, func() bool {
		started := 0
		for _, control := range controls {
			if control.calls.Load() == 1 {
				started++
			}
		}
		return started == total
	}, "queued Close callback dispatch")
	for _, control := range controls[l3IngressProcessCallbackLimit:] {
		control.Release()
	}
	waitForL3Condition(t, time.Second, func() bool {
		return len(l3IngressProcessCallbackSlots[l3IngressCallbackEgressCleanup]) == 0 &&
			len(l3IngressCleanupAuthoritySlots) == 0
	}, "Close callback and authority release")
	for i, control := range controls {
		if got := control.calls.Load(); got != 1 {
			t.Fatalf("connection %d final Close calls=%d want 1", i, got)
		}
	}

	healthy := newCloseOwnershipControl(closeOwnershipReturn, nil)
	healthyAuthority, err := newEgressCloseAuthority(healthy, "healthy Close after saturation")
	if err != nil {
		t.Fatal(err)
	}
	if err := healthyAuthority.Close(); err != nil {
		t.Fatalf("healthy cleanup after saturation: %v", err)
	}
	assertCloseOwnershipCalls(t, healthy, 1)
}

func TestEgressRegistryReservesCleanupBeforeExternalDial(t *testing.T) {
	reservations := make([]*egressCleanupReservation, l3IngressCleanupAuthorityLimit)
	for i := range reservations {
		reservation, err := reserveEgressCleanupAuthority("test reservation")
		if err != nil {
			t.Fatalf("reservation %d: %v", i, err)
		}
		reservations[i] = reservation
	}
	defer func() {
		for _, reservation := range reservations {
			reservation.Release()
		}
	}()

	egress := &countingOwnershipEgress{}
	registry := NewEgressRegistry()
	if err := registry.Register("capacity", egress); err != nil {
		t.Fatal(err)
	}
	if conn, err := registry.DialTCP(context.Background(), "capacity", L3Identity{Proto: ProtocolTCP}); conn != nil || err == nil {
		t.Fatalf("DialTCP conn=%v err=%v, want capacity rejection", conn, err)
	} else {
		assertL3CallbackReason(t, err, CallbackFailureSaturated)
	}
	if conn, _, err := registry.DialUDP(context.Background(), "capacity", L3Identity{Proto: ProtocolUDP}); conn != nil || err == nil {
		t.Fatalf("DialUDP conn=%v err=%v, want capacity rejection", conn, err)
	} else {
		assertL3CallbackReason(t, err, CallbackFailureSaturated)
	}
	if got := egress.dials.Load(); got != 0 {
		t.Fatalf("external Dial invocations=%d want 0", got)
	}
	if got := egress.created.Load(); got != 0 {
		t.Fatalf("external objects created=%d want 0", got)
	}
}

func TestEgressRegistryContainsAbnormalDialCallbacks(t *testing.T) {
	for _, test := range []struct {
		name string
		mode dialOwnershipMode
		want CallbackFailureReason
	}{
		{name: "panic", mode: dialOwnershipPanic, want: CallbackFailurePanic},
		{name: "goexit", mode: dialOwnershipGoexit, want: CallbackFailureGoexit},
	} {
		for _, proto := range []Protocol{ProtocolTCP, ProtocolUDP} {
			t.Run(proto.String()+"/"+test.name, func(t *testing.T) {
				beforeReservations := len(l3IngressCleanupAuthoritySlots)
				egress := &abnormalDialOwnershipEgress{mode: test.mode}
				registry := NewEgressRegistry()
				if err := registry.Register("abnormal", egress); err != nil {
					t.Fatal(err)
				}
				var err error
				if proto == ProtocolTCP {
					_, err = registry.DialTCP(context.Background(), "abnormal", L3Identity{Proto: proto})
				} else {
					_, _, err = registry.DialUDP(context.Background(), "abnormal", L3Identity{Proto: proto})
				}
				assertL3CallbackReason(t, err, test.want)
				if got := egress.calls.Load(); got != 1 {
					t.Fatalf("callback invocations=%d want 1", got)
				}
				waitForL3Condition(t, time.Second, func() bool {
					return len(l3IngressCleanupAuthoritySlots) == beforeReservations &&
						len(l3IngressProcessCallbackSlots[l3IngressCallbackEgressInvoke]) == 0
				}, "abnormal Dial capacity release")
			})
		}
	}
}

func TestEgressRegistryLateDialResultRetainsCleanupAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		proto  Protocol
		cancel bool
	}{
		{name: "TCP-canceled", proto: ProtocolTCP, cancel: true},
		{name: "UDP-timeout", proto: ProtocolUDP},
	} {
		t.Run(test.name, func(t *testing.T) {
			control := newCloseOwnershipControl(closeOwnershipReturn, nil)
			lateErr := errors.New("late egress failure")
			egress := &lateDialOwnershipEgress{
				tcp:     newOwnershipTCPConn(control, nil),
				udp:     newOwnershipPacketConn(control, nil),
				remote:  netip.MustParseAddrPort("198.51.100.53:53"),
				err:     lateErr,
				started: make(chan struct{}),
				release: make(chan struct{}),
			}
			registry := NewEgressRegistry()
			if err := registry.Register("late", egress); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			if test.cancel {
				cancel()
				ctx, cancel = context.WithCancel(context.Background())
				go func() {
					<-egress.started
					cancel()
				}()
			}
			defer cancel()
			var err error
			if test.proto == ProtocolTCP {
				_, err = registry.DialTCP(ctx, "late", L3Identity{Proto: test.proto})
			} else {
				_, _, err = registry.DialUDP(ctx, "late", L3Identity{Proto: test.proto})
			}
			if test.cancel {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Dial error=%v want context cancellation", err)
				}
			} else {
				assertL3CallbackReason(t, err, CallbackFailureTimeout)
			}
			if got := control.calls.Load(); got != 0 {
				t.Fatalf("late connection closed before callback return: %d", got)
			}
			close(egress.release)
			control.Wait(t)
			assertCloseOwnershipCalls(t, control, 1)
			waitForL3Condition(t, time.Second, func() bool {
				return len(l3IngressProcessCallbackSlots[l3IngressCallbackEgressInvoke]) == 0 &&
					len(l3IngressProcessCallbackSlots[l3IngressCallbackEgressCleanup]) == 0
			}, "late Dial and cleanup callback release")
		})
	}
}

func TestEgressDialSaturationPrecedesCallbackAndDoesNotBlockCleanup(t *testing.T) {
	baselineGoroutines := runtime.NumGoroutine()
	cleanupControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
	healthy := &staticOwnershipEgress{
		udp:    newOwnershipPacketConn(cleanupControl, nil),
		remote: netip.MustParseAddrPort("198.51.100.53:53"),
	}
	healthyRegistry := NewEgressRegistry()
	if err := healthyRegistry.Register("healthy", healthy); err != nil {
		t.Fatal(err)
	}
	accepted, _, err := healthyRegistry.DialUDP(
		context.Background(), "healthy", L3Identity{Proto: ProtocolUDP},
	)
	if err != nil {
		t.Fatal(err)
	}

	blocked := &blockingDialOwnershipEgress{
		started: make(chan struct{}, l3IngressProcessCallbackLimit+1),
		release: make(chan struct{}),
	}
	registry := NewEgressRegistry()
	if err := registry.Register("blocked", blocked); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, l3IngressProcessCallbackLimit)
	for range l3IngressProcessCallbackLimit {
		go func() {
			_, err := registry.DialTCP(context.Background(), "blocked", L3Identity{Proto: ProtocolTCP})
			results <- err
		}()
	}
	for range l3IngressProcessCallbackLimit {
		waitSignal(t, blocked.started, "blocked Egress.DialTCP invocation")
	}
	if got := len(l3IngressProcessCallbackSlots[l3IngressCallbackEgressInvoke]); got != l3IngressProcessCallbackLimit {
		t.Fatalf("blocked Dial callbacks=%d want %d", got, l3IngressProcessCallbackLimit)
	}

	const overflow = 17
	overflowResults := make(chan error, overflow)
	for range overflow {
		go func() {
			_, overflowErr := registry.DialTCP(
				context.Background(), "blocked", L3Identity{Proto: ProtocolTCP},
			)
			overflowResults <- overflowErr
		}()
	}
	for range overflow {
		assertL3CallbackReason(t, waitError(t, overflowResults, "saturated Dial"), CallbackFailureSaturated)
	}
	if got := blocked.calls.Load(); got != l3IngressProcessCallbackLimit {
		t.Fatalf("external callback invocations=%d want %d", got, l3IngressProcessCallbackLimit)
	}
	if got := blocked.created.Load(); got != 0 {
		t.Fatalf("external objects created=%d want 0", got)
	}
	runtime.GC()
	if got := runtime.NumGoroutine() - baselineGoroutines; got > 2*l3IngressProcessCallbackLimit+8 {
		t.Fatalf("blocked Dial goroutine growth=%d exceeds bounded callers+callbacks", got)
	}

	if err := accepted.Close(); err != nil {
		t.Fatalf("cleanup while Dial executor saturated: %v", err)
	}
	assertCloseOwnershipCalls(t, cleanupControl, 1)

	close(blocked.release)
	for range l3IngressProcessCallbackLimit {
		if err := waitError(t, results, "blocked Dial completion"); reasonOrEmpty(err) != ReasonInvalidEgressConn {
			t.Fatalf("blocked Dial completion error=%v", err)
		}
	}
	waitForL3Condition(t, time.Second, func() bool {
		return len(l3IngressProcessCallbackSlots[l3IngressCallbackEgressInvoke]) == 0
	}, "egress Dial callback release")
}

func TestTCPFlowRelayCloseOwnershipAcrossConcurrentTriggers(t *testing.T) {
	id := tcpFlowRelayIdentity()
	endpointControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
	egressControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
	endpoint := newOwnershipTCPConn(endpointControl, nil)
	egressConn := newOwnershipTCPConn(egressControl, nil)
	egress := &staticOwnershipEgress{tcp: egressConn, dialed: make(chan struct{})}
	registry := NewEgressRegistry()
	if err := registry.Register("direct", egress); err != nil {
		t.Fatal(err)
	}
	relay := &TCPFlowRelay{Egresses: registry}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- relay.Serve(ctx, tcpFlowRelayEvent(id), endpoint) }()
	waitClosed(t, egress.dialed, "TCP egress dial")
	waitForTCPRelaySession(t, relay, id)

	closeErr := make(chan error, 1)
	closeFlowDone := make(chan struct{})
	go func() { closeErr <- relay.Close() }()
	go func() {
		relay.CloseFlow(id)
		close(closeFlowDone)
	}()
	cancel()

	if err := waitError(t, closeErr, "TCP relay Close"); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, closeFlowDone, "TCP CloseFlow")
	if err := waitError(t, serveErr, "TCP relay Serve"); err != nil {
		t.Fatal(err)
	}
	assertCloseOwnershipCalls(t, endpointControl, 1)
	assertCloseOwnershipCalls(t, egressControl, 1)

	lateControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
	lateRegistry := NewEgressRegistry()
	if err := lateRegistry.Register("direct", &staticOwnershipEgress{
		tcp: newOwnershipTCPConn(lateControl, nil),
	}); err != nil {
		t.Fatal(err)
	}
	relay.Egresses = lateRegistry
	lateEndpoint := newOwnershipTCPConn(newCloseOwnershipControl(closeOwnershipReturn, nil), nil)
	if err := relay.Serve(context.Background(), tcpFlowRelayEvent(id), lateEndpoint); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve after Close error=%v want %v", err, net.ErrClosed)
	}
	if got := lateControl.calls.Load(); got != 0 {
		t.Fatalf("Serve after Close dialed/closed egress %d times", got)
	}

	t.Run("close-uses-bounded-fanout", testTCPRelayBoundedCloseFanout)
	t.Run("immediate-error-is-not-duplicated", testTCPRelayImmediateCloseError)
	for _, test := range []struct {
		name   string
		mode   closeOwnershipMode
		err    error
		reason CallbackFailureReason
	}{
		{name: "returned-error", mode: closeOwnershipReturn, err: errors.New("late TCP close error")},
		{name: "panic", mode: closeOwnershipPanic, reason: CallbackFailurePanic},
		{name: "goexit", mode: closeOwnershipGoexit, reason: CallbackFailureGoexit},
	} {
		test := test
		t.Run("late-terminal/"+test.name, func(t *testing.T) {
			testTCPRelayLateTerminal(t, test.mode, test.err, test.reason)
		})
	}
	t.Run("late-terminal-generation-isolation", testTCPRelayLateTerminalGenerationIsolation)
}

func TestRelayGlobalCloseDuringEgressDialOwnsLateResults(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		id := tcpFlowRelayIdentity()
		endpointControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
		egressControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
		releaseDial := make(chan struct{})
		egress := &staticOwnershipEgress{
			tcp:         newOwnershipTCPConn(egressControl, nil),
			dialed:      make(chan struct{}),
			dialRelease: releaseDial,
		}
		registry := NewEgressRegistry()
		if err := registry.Register("direct", egress); err != nil {
			t.Fatal(err)
		}
		relay := &TCPFlowRelay{Egresses: registry}
		serveErr := make(chan error, 1)
		go func() {
			serveErr <- relay.Serve(
				context.Background(),
				tcpFlowRelayEvent(id),
				newOwnershipTCPConn(endpointControl, nil),
			)
		}()
		waitClosed(t, egress.dialed, "blocked TCP egress dial")
		if err := relay.Close(); err != nil {
			t.Fatal(err)
		}
		close(releaseDial)
		if err := waitError(t, serveErr, "late TCP egress admission"); err == nil {
			t.Fatal("late TCP egress result was admitted after Close")
		}
		assertCloseOwnershipCalls(t, endpointControl, 1)
		waitForL3Condition(t, time.Second, func() bool {
			return egressControl.calls.Load() == 1
		}, "late TCP egress cleanup")
		assertCloseOwnershipCalls(t, egressControl, 1)
	})

	t.Run("UDP", func(t *testing.T) {
		_, ev := ownershipUDPEvent(t)
		control := newCloseOwnershipControl(closeOwnershipReturn, nil)
		releaseDial := make(chan struct{})
		egress := &staticOwnershipEgress{
			udp:         newOwnershipPacketConn(control, nil),
			remote:      netip.MustParseAddrPort("198.51.100.53:53"),
			dialed:      make(chan struct{}),
			dialRelease: releaseDial,
		}
		registry := NewEgressRegistry()
		if err := registry.Register("dns-egress", egress); err != nil {
			t.Fatal(err)
		}
		relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
		handleErr := make(chan error, 1)
		go func() { handleErr <- relay.HandlePacket(context.Background(), ev) }()
		waitClosed(t, egress.dialed, "blocked UDP egress dial")
		if err := relay.Close(); err != nil {
			t.Fatal(err)
		}
		close(releaseDial)
		if err := waitError(t, handleErr, "late UDP egress admission"); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("HandlePacket error=%v want %v", err, net.ErrClosed)
		}
		control.Wait(t)
		assertCloseOwnershipCalls(t, control, 1)
	})
}

func TestRelayGlobalCloseJoinsCloseFlowInProgress(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		id := tcpFlowRelayIdentity()
		endpointControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
		egressControl := newCloseOwnershipControl(closeOwnershipBlock, nil)
		egress := &staticOwnershipEgress{
			tcp:    newOwnershipTCPConn(egressControl, nil),
			dialed: make(chan struct{}),
		}
		registry := NewEgressRegistry()
		if err := registry.Register("direct", egress); err != nil {
			t.Fatal(err)
		}
		relay := &TCPFlowRelay{Egresses: registry}
		serveErr := make(chan error, 1)
		go func() {
			serveErr <- relay.Serve(
				context.Background(),
				tcpFlowRelayEvent(id),
				newOwnershipTCPConn(endpointControl, nil),
			)
		}()
		waitClosed(t, egress.dialed, "TCP egress dial")
		waitForTCPRelaySession(t, relay, id)
		closeFlowDone := make(chan struct{})
		go func() {
			relay.CloseFlow(id)
			close(closeFlowDone)
		}()
		waitClosed(t, egressControl.started, "TCP CloseFlow cleanup")
		assertL3CallbackReason(t, relay.Close(), CallbackFailureTimeout)
		waitClosed(t, closeFlowDone, "TCP CloseFlow completion")
		egressControl.Release()
		egressControl.Wait(t)
		_ = waitError(t, serveErr, "TCP relay Serve")
		assertCloseOwnershipCalls(t, endpointControl, 1)
		assertCloseOwnershipCalls(t, egressControl, 1)
	})

	t.Run("UDP", func(t *testing.T) {
		id, ev := ownershipUDPEvent(t)
		control := newCloseOwnershipControl(closeOwnershipBlock, nil)
		registry := NewEgressRegistry()
		if err := registry.Register("dns-egress", &staticOwnershipEgress{
			udp:    newOwnershipPacketConn(control, nil),
			remote: netip.MustParseAddrPort("198.51.100.53:53"),
		}); err != nil {
			t.Fatal(err)
		}
		relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
		if err := relay.HandlePacket(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
		waitForUDPRelaySession(t, relay, id)
		closeFlowDone := make(chan struct{})
		go func() {
			relay.CloseFlow(id)
			close(closeFlowDone)
		}()
		waitClosed(t, control.started, "UDP CloseFlow cleanup")
		assertL3CallbackReason(t, relay.Close(), CallbackFailureTimeout)
		waitClosed(t, closeFlowDone, "UDP CloseFlow completion")
		control.Release()
		control.Wait(t)
		assertCloseOwnershipCalls(t, control, 1)
	})
}

func TestTCPFlowRelayErrorAndHostileCloseRemainBounded(t *testing.T) {
	t.Run("stream-error", func(t *testing.T) {
		streamErr := errors.New("TCP source failed")
		endpointControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
		egressControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
		endpoint := newOwnershipTCPConn(endpointControl, streamErr)
		egressConn := newOwnershipTCPConn(egressControl, nil)
		registry := NewEgressRegistry()
		if err := registry.Register("direct", &staticOwnershipEgress{tcp: egressConn}); err != nil {
			t.Fatal(err)
		}
		relay := &TCPFlowRelay{Egresses: registry}
		err := relay.Serve(context.Background(), tcpFlowRelayEvent(tcpFlowRelayIdentity()), endpoint)
		if !errors.Is(err, streamErr) {
			t.Fatalf("Serve error=%v want %v", err, streamErr)
		}
		assertCloseOwnershipCalls(t, endpointControl, 1)
		assertCloseOwnershipCalls(t, egressControl, 1)
	})

	for _, test := range []struct {
		name string
		mode closeOwnershipMode
		want CallbackFailureReason
	}{
		{name: "panic", mode: closeOwnershipPanic, want: CallbackFailurePanic},
		{name: "blocked", mode: closeOwnershipBlock, want: CallbackFailureTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := tcpFlowRelayIdentity()
			endpointControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
			egressControl := newCloseOwnershipControl(test.mode, nil)
			endpoint := newOwnershipTCPConn(endpointControl, nil)
			egress := &staticOwnershipEgress{
				tcp:    newOwnershipTCPConn(egressControl, nil),
				dialed: make(chan struct{}),
			}
			registry := NewEgressRegistry()
			if err := registry.Register("direct", egress); err != nil {
				t.Fatal(err)
			}
			relay := &TCPFlowRelay{Egresses: registry}
			serveErr := make(chan error, 1)
			go func() { serveErr <- relay.Serve(context.Background(), tcpFlowRelayEvent(id), endpoint) }()
			waitClosed(t, egress.dialed, "TCP egress dial")
			waitForTCPRelaySession(t, relay, id)

			started := time.Now()
			err := relay.Close()
			if elapsed := time.Since(started); elapsed > 4*DefaultEgressCloseTimeout {
				t.Fatalf("Close took %v", elapsed)
			}
			assertL3CallbackReason(t, err, test.want)
			assertL3CallbackReason(t, relay.Close(), test.want)
			egressControl.Release()
			egressControl.Wait(t)
			_ = waitError(t, serveErr, "TCP hostile Serve")
			assertCloseOwnershipCalls(t, endpointControl, 1)
			assertCloseOwnershipCalls(t, egressControl, 1)
		})
	}
}

func TestUDPFlowRelayCloseOwnershipAcrossConcurrentTriggers(t *testing.T) {
	id, ev := ownershipUDPEvent(t)
	control := newCloseOwnershipControl(closeOwnershipReturn, nil)
	pc := newOwnershipPacketConn(control, nil)
	egress := &staticOwnershipEgress{
		udp:    pc,
		remote: netip.MustParseAddrPort("198.51.100.53:53"),
		dialed: make(chan struct{}),
	}
	registry := NewEgressRegistry()
	if err := registry.Register("dns-egress", egress); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
	ctx, cancel := context.WithCancel(context.Background())
	if err := relay.HandlePacket(ctx, ev); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, egress.dialed, "UDP egress dial")
	waitForUDPRelaySession(t, relay, id)

	closeErr := make(chan error, 1)
	closeFlowDone := make(chan struct{})
	go func() { closeErr <- relay.Close() }()
	go func() {
		relay.CloseFlow(id)
		close(closeFlowDone)
	}()
	cancel()
	if err := waitError(t, closeErr, "UDP relay Close"); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, closeFlowDone, "UDP CloseFlow")
	control.Wait(t)
	assertCloseOwnershipCalls(t, control, 1)

	t.Run("same-identity-single-flight", func(t *testing.T) {
		const callers = 64
		id, event := ownershipUDPEvent(t)
		candidate := newAdmissionPacketConn()
		started := make(chan struct{})
		release := make(chan struct{})
		var startOnce sync.Once
		var dials atomic.Int32
		egress := udpAdmissionEgress{dialUDP: func(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
			dials.Add(1)
			startOnce.Do(func() { close(started) })
			<-release
			return candidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
		}}
		registry := NewEgressRegistry()
		if err := registry.Register("dns-egress", egress); err != nil {
			t.Fatal(err)
		}
		relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
		results := make(chan error, callers)
		launch := make(chan struct{})
		for range callers {
			go func() {
				<-launch
				results <- relay.HandlePacket(context.Background(), event)
			}()
		}
		close(launch)
		waitClosed(t, started, "first UDP admission")
		waitForUDPRelayPendingWaiters(t, relay, id, callers)
		if got := dials.Load(); got != 1 {
			t.Fatalf("DialUDP calls=%d want 1", got)
		}
		close(release)
		for range callers {
			if err := waitError(t, results, "single-flight packet"); err != nil {
				t.Fatal(err)
			}
		}
		if got := candidate.writes.Load(); got != callers {
			t.Fatalf("WriteTo calls=%d want %d", got, callers)
		}
		if err := relay.Close(); err != nil {
			t.Fatal(err)
		}
		if got := candidate.closes.Load(); got != 1 {
			t.Fatalf("candidate Close calls=%d want 1", got)
		}
	})

	t.Run("different-identities-dial-concurrently", func(t *testing.T) {
		idA, eventA := ownershipUDPEvent(t)
		idB := idA
		idB.SrcPort++
		eventB := ownershipUDPEventForIdentity(t, idB, []byte("second"))
		started := make(chan struct{}, 2)
		release := make(chan struct{})
		var dials atomic.Int32
		var active atomic.Int32
		var maxActive atomic.Int32
		var candidates sync.Map
		egress := udpAdmissionEgress{dialUDP: func(_ context.Context, id L3Identity) (net.PacketConn, netip.AddrPort, error) {
			dials.Add(1)
			current := active.Add(1)
			updateAtomicMax(&maxActive, current)
			candidate := newAdmissionPacketConn()
			candidates.Store(id, candidate)
			started <- struct{}{}
			<-release
			active.Add(-1)
			return candidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
		}}
		registry := NewEgressRegistry()
		if err := registry.Register("dns-egress", egress); err != nil {
			t.Fatal(err)
		}
		relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
		results := make(chan error, 2)
		go func() { results <- relay.HandlePacket(context.Background(), eventA) }()
		go func() { results <- relay.HandlePacket(context.Background(), eventB) }()
		waitSignal(t, started, "first identity admission")
		waitSignal(t, started, "second identity admission")
		if got := dials.Load(); got != 2 {
			t.Fatalf("DialUDP calls=%d want 2", got)
		}
		if got := maxActive.Load(); got != 2 {
			t.Fatalf("maximum concurrent DialUDP calls=%d want 2", got)
		}
		close(release)
		for range 2 {
			if err := waitError(t, results, "independent identity packet"); err != nil {
				t.Fatal(err)
			}
		}
		for _, id := range []L3Identity{idA, idB} {
			value, ok := candidates.Load(id)
			if !ok {
				t.Fatalf("missing candidate for %v", id)
			}
			if got := value.(*admissionPacketConn).writes.Load(); got != 1 {
				t.Fatalf("identity %v WriteTo calls=%d want 1", id, got)
			}
		}
		if err := relay.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("failure-and-leader-cancellation-allow-retry", func(t *testing.T) {
		t.Run("definitive-failure", func(t *testing.T) {
			const followers = 31
			id, event := ownershipUDPEvent(t)
			failure := errors.New("first UDP admission failed")
			started := make(chan struct{})
			release := make(chan struct{})
			retryCandidate := newAdmissionPacketConn()
			var dials atomic.Int32
			egress := udpAdmissionEgress{dialUDP: func(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
				if dials.Add(1) == 1 {
					close(started)
					<-release
					return nil, netip.AddrPort{}, failure
				}
				return retryCandidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
			}}
			registry := NewEgressRegistry()
			if err := registry.Register("dns-egress", egress); err != nil {
				t.Fatal(err)
			}
			relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
			results := make(chan error, followers+1)
			go func() { results <- relay.HandlePacket(context.Background(), event) }()
			waitClosed(t, started, "failed UDP admission")
			for range followers {
				go func() { results <- relay.HandlePacket(context.Background(), event) }()
			}
			waitForUDPRelayPendingWaiters(t, relay, id, followers+1)
			close(release)
			for range followers + 1 {
				if err := waitError(t, results, "shared failed UDP admission"); !errors.Is(err, failure) {
					t.Fatalf("HandlePacket error=%v want %v", err, failure)
				}
			}
			if got := dials.Load(); got != 1 {
				t.Fatalf("DialUDP calls after shared failure=%d want 1", got)
			}
			if err := relay.HandlePacket(context.Background(), event); err != nil {
				t.Fatalf("retry HandlePacket: %v", err)
			}
			if got := dials.Load(); got != 2 {
				t.Fatalf("DialUDP calls after retry=%d want 2", got)
			}
			if got := retryCandidate.writes.Load(); got != 1 {
				t.Fatalf("retry WriteTo calls=%d want 1", got)
			}
			if err := relay.Close(); err != nil {
				t.Fatal(err)
			}
		})

		t.Run("leader-cancellation-does-not-cancel-followers", func(t *testing.T) {
			const followers = 31
			id, event := ownershipUDPEvent(t)
			started := make(chan struct{})
			release := make(chan struct{})
			candidate := newAdmissionPacketConn()
			var dials atomic.Int32
			egress := udpAdmissionEgress{dialUDP: func(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
				dials.Add(1)
				close(started)
				<-release
				return candidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
			}}
			registry := NewEgressRegistry()
			if err := registry.Register("dns-egress", egress); err != nil {
				t.Fatal(err)
			}
			relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
			leaderCtx, cancelLeader := context.WithCancel(context.Background())
			leaderResult := make(chan error, 1)
			followerResults := make(chan error, followers)
			go func() { leaderResult <- relay.HandlePacket(leaderCtx, event) }()
			waitClosed(t, started, "cancelable UDP admission")
			for range followers {
				go func() { followerResults <- relay.HandlePacket(context.Background(), event) }()
			}
			waitForUDPRelayPendingWaiters(t, relay, id, followers+1)
			cancelLeader()
			if err := waitError(t, leaderResult, "canceled UDP leader"); !errors.Is(err, context.Canceled) {
				t.Fatalf("leader HandlePacket error=%v want context cancellation", err)
			}
			waitForUDPRelayPendingWaiters(t, relay, id, followers)
			close(release)
			for range followers {
				if err := waitError(t, followerResults, "UDP admission follower"); err != nil {
					t.Fatal(err)
				}
			}
			if got := dials.Load(); got != 1 {
				t.Fatalf("DialUDP calls after leader cancellation=%d want 1", got)
			}
			if got := candidate.writes.Load(); got != followers {
				t.Fatalf("follower WriteTo calls=%d want %d", got, followers)
			}
			if err := relay.Close(); err != nil {
				t.Fatal(err)
			}
		})

		t.Run("canceled-sole-waiter-cleans-candidate-and-retries", func(t *testing.T) {
			id, event := ownershipUDPEvent(t)
			started := make(chan struct{})
			release := make(chan struct{})
			abandoned := newAdmissionPacketConn()
			retryCandidate := newAdmissionPacketConn()
			var dials atomic.Int32
			egress := udpAdmissionEgress{dialUDP: func(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
				if dials.Add(1) == 1 {
					close(started)
					<-release
					return abandoned, netip.MustParseAddrPort("198.51.100.53:53"), nil
				}
				return retryCandidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
			}}
			registry := NewEgressRegistry()
			if err := registry.Register("dns-egress", egress); err != nil {
				t.Fatal(err)
			}
			relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
			leaderCtx, cancelLeader := context.WithCancel(context.Background())
			leaderResult := make(chan error, 1)
			go func() { leaderResult <- relay.HandlePacket(leaderCtx, event) }()
			waitClosed(t, started, "sole UDP admission")
			waitForUDPRelayPendingWaiters(t, relay, id, 1)
			cancelLeader()
			if err := waitError(t, leaderResult, "canceled sole UDP leader"); !errors.Is(err, context.Canceled) {
				t.Fatalf("leader HandlePacket error=%v want context cancellation", err)
			}
			close(release)
			waitClosed(t, abandoned.closed, "abandoned UDP candidate cleanup")
			if got := abandoned.writes.Load(); got != 0 {
				t.Fatalf("abandoned candidate WriteTo calls=%d want 0", got)
			}
			if err := relay.HandlePacket(context.Background(), event); err != nil {
				t.Fatalf("retry HandlePacket: %v", err)
			}
			if got := dials.Load(); got != 2 {
				t.Fatalf("DialUDP calls after cancellation retry=%d want 2", got)
			}
			if got := retryCandidate.writes.Load(); got != 1 {
				t.Fatalf("retry WriteTo calls=%d want 1", got)
			}
			if err := relay.Close(); err != nil {
				t.Fatal(err)
			}
		})

		t.Run("typed-nil-result-clears-pending", func(t *testing.T) {
			_, event := ownershipUDPEvent(t)
			var typedNil *admissionPacketConn
			retryCandidate := newAdmissionPacketConn()
			var dials atomic.Int32
			egress := udpAdmissionEgress{dialUDP: func(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
				if dials.Add(1) == 1 {
					return typedNil, netip.MustParseAddrPort("198.51.100.53:53"), nil
				}
				return retryCandidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
			}}
			registry := NewEgressRegistry()
			if err := registry.Register("dns-egress", egress); err != nil {
				t.Fatal(err)
			}
			relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
			if err := relay.HandlePacket(context.Background(), event); err == nil {
				t.Fatal("typed-nil PacketConn was accepted")
			} else if reason, ok := EgressErrorReasonOf(err); !ok || reason != ReasonInvalidEgressConn {
				t.Fatalf("typed-nil error=%v reason=%q", err, reason)
			}
			if err := relay.HandlePacket(context.Background(), event); err != nil {
				t.Fatalf("retry after typed-nil result: %v", err)
			}
			if got := dials.Load(); got != 2 {
				t.Fatalf("DialUDP calls=%d want 2", got)
			}
			if err := relay.Close(); err != nil {
				t.Fatal(err)
			}
		})
	})

	t.Run("timeout-retries-only-after-late-settlement", func(t *testing.T) {
		id, event := ownershipUDPEvent(t)
		lateControl := newCloseOwnershipControl(closeOwnershipBlock, nil)
		lateCandidate := newOwnershipPacketConn(lateControl, nil)
		retryCandidate := newAdmissionPacketConn()
		started := make(chan struct{})
		release := make(chan struct{})
		var dials atomic.Int32
		var active atomic.Int32
		var overlap atomic.Bool
		egress := udpAdmissionEgress{dialUDP: func(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
			if active.Add(1) != 1 {
				overlap.Store(true)
			}
			defer active.Add(-1)
			if dials.Add(1) == 1 {
				close(started)
				<-release
				return lateCandidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
			}
			return retryCandidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
		}}
		registry := NewEgressRegistry()
		if err := registry.Register("dns-egress", egress); err != nil {
			t.Fatal(err)
		}
		relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
		dialCtx, cancelDial := context.WithTimeout(context.Background(), 20*time.Millisecond)
		key := legacyRelayFlowKey(id)
		pending := &udpSessionPending{key: key, done: make(chan struct{}), cancel: cancelDial, waiters: 1}
		relay.pending = map[relayFlowKey]*udpSessionPending{key: pending}
		go relay.admitUDPSession(dialCtx, pending, event)
		waitClosed(t, started, "timed-out UDP callback")
		_, err := relay.waitUDPSession(context.Background(), pending)
		assertL3CallbackReason(t, err, CallbackFailureTimeout)
		if retryErr := relay.HandlePacket(context.Background(), event); retryErr == nil {
			t.Fatal("same identity retried before callback settlement")
		} else {
			assertL3CallbackReason(t, retryErr, CallbackFailureTimeout)
		}
		if got := dials.Load(); got != 1 {
			t.Fatalf("DialUDP calls before settlement=%d want 1", got)
		}
		if overlap.Load() {
			t.Fatal("same-identity DialUDP callbacks overlapped before settlement")
		}
		close(release)
		waitClosed(t, lateControl.started, "late timed-out candidate cleanup")
		if retryErr := relay.HandlePacket(context.Background(), event); retryErr == nil {
			t.Fatal("same identity retried while late cleanup remained in flight")
		} else {
			assertL3CallbackReason(t, retryErr, CallbackFailureTimeout)
		}
		if got := dials.Load(); got != 1 {
			t.Fatalf("DialUDP calls during late cleanup=%d want 1", got)
		}
		lateControl.Release()
		lateControl.Wait(t)
		waitForL3Condition(t, time.Second, func() bool {
			relay.mu.Lock()
			defer relay.mu.Unlock()
			return relay.pending[key] == nil
		}, "timed-out UDP admission settlement")
		assertCloseOwnershipCalls(t, lateControl, 1)
		if err := relay.HandlePacket(context.Background(), event); err != nil {
			t.Fatalf("retry after settlement: %v", err)
		}
		if got := dials.Load(); got != 2 {
			t.Fatalf("DialUDP calls after settlement=%d want 2", got)
		}
		if overlap.Load() {
			t.Fatal("same-identity DialUDP callbacks overlapped")
		}
		if got := retryCandidate.writes.Load(); got != 1 {
			t.Fatalf("retry candidate WriteTo calls=%d want 1", got)
		}
		if err := relay.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unclaimed-publication-is-reclaimed", func(t *testing.T) {
		t.Run("last-canceled-waiter", func(t *testing.T) {
			const iterations = 100
			for iteration := range iterations {
				id, _ := ownershipUDPEvent(t)
				id.SrcPort += uint16(iteration)
				candidate := newAdmissionPacketConn()
				authority, err := newEgressCloseAuthority(candidate, "unclaimed UDP candidate Close")
				if err != nil {
					t.Fatal(err)
				}
				sessionCtx, cancelSession := context.WithCancel(context.Background())
				key := legacyRelayFlowKey(id)
				session := &udpFlowSession{
					key: key, id: id, pc: candidate, ctx: sessionCtx, cancel: cancelSession,
					cleanup: newEgressSessionCleanup(authority),
				}
				pending := &udpSessionPending{
					key: key, done: make(chan struct{}), session: session, waiters: 1, closed: true,
				}
				close(pending.done)
				relay := &UDPFlowRelay{
					sessions: map[relayFlowKey]*udpFlowSession{key: session},
					pending:  map[relayFlowKey]*udpSessionPending{key: pending},
				}
				waitCtx, cancelWait := context.WithCancel(context.Background())
				cancelWait()
				if _, err := relay.waitUDPSession(waitCtx, pending); !errors.Is(err, context.Canceled) {
					t.Fatalf("iteration %d wait error=%v", iteration, err)
				}
				waitClosed(t, candidate.closed, "unclaimed candidate cleanup")
				if got := candidate.closes.Load(); got != 1 {
					t.Fatalf("iteration %d Close calls=%d want 1", iteration, got)
				}
				relay.mu.Lock()
				_, sessionPresent := relay.sessions[key]
				_, pendingPresent := relay.pending[key]
				relay.mu.Unlock()
				if sessionPresent || pendingPresent {
					t.Fatalf("iteration %d retained session=%v pending=%v", iteration, sessionPresent, pendingPresent)
				}
			}
		})

		t.Run("simultaneous-result-and-cancellation", func(t *testing.T) {
			const iterations = 200
			for iteration := range iterations {
				id, event := ownershipUDPEvent(t)
				id.SrcPort += uint16(iteration)
				event = ownershipUDPEventForIdentity(t, id, []byte("claim-race"))
				candidate := newAdmissionPacketConn()
				started := make(chan struct{})
				release := make(chan struct{})
				egress := udpAdmissionEgress{dialUDP: func(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
					close(started)
					<-release
					return candidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
				}}
				registry := NewEgressRegistry()
				if err := registry.Register("dns-egress", egress); err != nil {
					t.Fatal(err)
				}
				relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
				ctx, cancel := context.WithCancel(context.Background())
				result := make(chan error, 1)
				go func() { result <- relay.HandlePacket(ctx, event) }()
				waitClosed(t, started, "claim-race UDP callback")
				fire := make(chan struct{})
				var actions sync.WaitGroup
				actions.Add(2)
				go func() { defer actions.Done(); <-fire; close(release) }()
				go func() { defer actions.Done(); <-fire; cancel() }()
				close(fire)
				actions.Wait()
				_ = waitError(t, result, "claim-race HandlePacket")
				waitClosed(t, candidate.closed, "claim-race candidate cleanup")
				if got := candidate.closes.Load(); got != 1 {
					t.Fatalf("iteration %d Close calls=%d want 1", iteration, got)
				}
				waitForL3Condition(t, time.Second, func() bool {
					relay.mu.Lock()
					defer relay.mu.Unlock()
					key := legacyRelayFlowKey(id)
					return relay.sessions[key] == nil && relay.pending[key] == nil
				}, "claim-race session retirement")
				if err := relay.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	})

	t.Run("close-wakes-pending-and-cleans-late-candidate", func(t *testing.T) {
		const followers = 31
		id, event := ownershipUDPEvent(t)
		candidate := newAdmissionPacketConn()
		started := make(chan struct{})
		release := make(chan struct{})
		var dials atomic.Int32
		egress := udpAdmissionEgress{dialUDP: func(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
			dials.Add(1)
			close(started)
			<-release
			return candidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
		}}
		registry := NewEgressRegistry()
		if err := registry.Register("dns-egress", egress); err != nil {
			t.Fatal(err)
		}
		relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
		results := make(chan error, followers+1)
		go func() { results <- relay.HandlePacket(context.Background(), event) }()
		waitClosed(t, started, "late UDP admission")
		for range followers {
			go func() { results <- relay.HandlePacket(context.Background(), event) }()
		}
		waitForUDPRelayPendingWaiters(t, relay, id, followers+1)
		startedAt := time.Now()
		if err := relay.Close(); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(startedAt); elapsed > DefaultEgressCloseTimeout {
			t.Fatalf("Close took %v with pending admission", elapsed)
		}
		for range followers + 1 {
			if err := waitError(t, results, "closed pending UDP admission"); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("HandlePacket error=%v want %v", err, net.ErrClosed)
			}
		}
		if got := dials.Load(); got != 1 {
			t.Fatalf("DialUDP calls=%d want 1", got)
		}
		if got := candidate.writes.Load(); got != 0 {
			t.Fatalf("late candidate WriteTo calls=%d want 0", got)
		}
		close(release)
		waitClosed(t, candidate.closed, "late UDP candidate cleanup")
		if got := candidate.closes.Load(); got != 1 {
			t.Fatalf("late candidate Close calls=%d want 1", got)
		}
	})

	t.Run("close-uses-bounded-fanout", func(t *testing.T) {
		const sessionCount = 4 * l3IngressRelayCloseFanoutLimit
		tracker := newCloseFanoutTracker(sessionCount)
		var candidateMu sync.Mutex
		candidates := make([]*fanoutAdmissionPacketConn, 0, sessionCount)
		egress := udpAdmissionEgress{dialUDP: func(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
			candidate := newFanoutAdmissionPacketConn(tracker)
			candidateMu.Lock()
			candidates = append(candidates, candidate)
			candidateMu.Unlock()
			return candidate, netip.MustParseAddrPort("198.51.100.53:53"), nil
		}}
		registry := NewEgressRegistry()
		if err := registry.Register("dns-egress", egress); err != nil {
			t.Fatal(err)
		}
		relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
		baseID, _ := ownershipUDPEvent(t)
		for index := range sessionCount {
			id := baseID
			id.SrcPort += uint16(index)
			event := ownershipUDPEventForIdentity(t, id, []byte("close-fanout"))
			if err := relay.HandlePacket(context.Background(), event); err != nil {
				t.Fatalf("session %d admission: %v", index, err)
			}
		}
		runtime.GC()
		baselineGoroutines := runtime.NumGoroutine()
		closeResult := make(chan error, 1)
		go func() { closeResult <- relay.Close() }()
		for range l3IngressRelayCloseFanoutLimit {
			waitSignal(t, tracker.started, "bounded UDP session Close")
		}
		select {
		case <-tracker.started:
			t.Fatal("UDP relay started more Close callbacks than its fixed fanout")
		case <-time.After(DefaultEgressCloseTimeout / 4):
		}
		if growth := runtime.NumGoroutine() - baselineGoroutines; growth > 4*l3IngressRelayCloseFanoutLimit+16 {
			t.Fatalf("Close goroutine growth=%d exceeds fixed fanout bound", growth)
		}
		tracker.Release()
		if err := waitError(t, closeResult, "bounded UDP relay Close"); err != nil {
			t.Fatal(err)
		}
		candidateMu.Lock()
		gotCandidates := append([]*fanoutAdmissionPacketConn(nil), candidates...)
		candidateMu.Unlock()
		if len(gotCandidates) != sessionCount {
			t.Fatalf("candidates=%d want %d", len(gotCandidates), sessionCount)
		}
		for index, candidate := range gotCandidates {
			if got := candidate.closes.Load(); got != 1 {
				t.Fatalf("candidate %d Close calls=%d want 1", index, got)
			}
		}
		if got := tracker.maximum.Load(); got > l3IngressRelayCloseFanoutLimit {
			t.Fatalf("maximum concurrent Close callbacks=%d limit=%d", got, l3IngressRelayCloseFanoutLimit)
		}
		waitForL3Condition(t, time.Second, func() bool {
			return runtime.NumGoroutine() <= baselineGoroutines+8
		}, "bounded UDP Close goroutine retirement")
	})

	t.Run("immediate-error-is-not-duplicated", testUDPRelayImmediateCloseError)
	for _, test := range []struct {
		name   string
		mode   closeOwnershipMode
		err    error
		reason CallbackFailureReason
	}{
		{name: "returned-error", mode: closeOwnershipReturn, err: errors.New("late UDP close error")},
		{name: "panic", mode: closeOwnershipPanic, reason: CallbackFailurePanic},
		{name: "goexit", mode: closeOwnershipGoexit, reason: CallbackFailureGoexit},
	} {
		test := test
		t.Run("late-terminal/"+test.name, func(t *testing.T) {
			testUDPRelayLateTerminal(t, test.mode, test.err, test.reason)
		})
	}
	t.Run("late-terminal-generation-isolation", testUDPRelayLateTerminalGenerationIsolation)
}

func TestUDPFlowRelayErrorHostileCloseAndReuse(t *testing.T) {
	t.Run("write-error", func(t *testing.T) {
		_, ev := ownershipUDPEvent(t)
		writeErr := errors.New("UDP write failed")
		control := newCloseOwnershipControl(closeOwnershipReturn, nil)
		registry := NewEgressRegistry()
		if err := registry.Register("dns-egress", &staticOwnershipEgress{
			udp:    newOwnershipPacketConn(control, writeErr),
			remote: netip.MustParseAddrPort("198.51.100.53:53"),
		}); err != nil {
			t.Fatal(err)
		}
		relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
		if err := relay.HandlePacket(context.Background(), ev); !errors.Is(err, writeErr) {
			t.Fatalf("HandlePacket error=%v want %v", err, writeErr)
		}
		if err := relay.Close(); err != nil {
			t.Fatal(err)
		}
		assertCloseOwnershipCalls(t, control, 1)
	})

	for _, test := range []struct {
		name string
		mode closeOwnershipMode
		want CallbackFailureReason
	}{
		{name: "goexit", mode: closeOwnershipGoexit, want: CallbackFailureGoexit},
		{name: "blocked", mode: closeOwnershipBlock, want: CallbackFailureTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, ev := ownershipUDPEvent(t)
			control := newCloseOwnershipControl(test.mode, nil)
			registry := NewEgressRegistry()
			if err := registry.Register("dns-egress", &staticOwnershipEgress{
				udp:    newOwnershipPacketConn(control, nil),
				remote: netip.MustParseAddrPort("198.51.100.53:53"),
			}); err != nil {
				t.Fatal(err)
			}
			relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
			if err := relay.HandlePacket(context.Background(), ev); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			err := relay.Close()
			if elapsed := time.Since(started); elapsed > 4*DefaultEgressCloseTimeout {
				t.Fatalf("Close took %v", elapsed)
			}
			assertL3CallbackReason(t, err, test.want)
			assertL3CallbackReason(t, relay.Close(), test.want)
			control.Release()
			control.Wait(t)
			assertCloseOwnershipCalls(t, control, 1)
		})
	}

	t.Run("healthy-reuse", func(t *testing.T) {
		id, ev := ownershipUDPEvent(t)
		first := newCloseOwnershipControl(closeOwnershipReturn, nil)
		second := newCloseOwnershipControl(closeOwnershipReturn, nil)
		egress := &sequenceOwnershipEgress{
			conns: []net.PacketConn{
				newOwnershipPacketConn(first, nil),
				newOwnershipPacketConn(second, nil),
			},
			remote: netip.MustParseAddrPort("198.51.100.53:53"),
		}
		registry := NewEgressRegistry()
		if err := registry.Register("dns-egress", egress); err != nil {
			t.Fatal(err)
		}
		relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
		if err := relay.HandlePacket(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
		if !relay.CloseFlow(id) {
			t.Fatal("first CloseFlow returned false")
		}
		if err := relay.HandlePacket(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
		if !relay.CloseFlow(id) {
			t.Fatal("second CloseFlow returned false")
		}
		assertCloseOwnershipCalls(t, first, 1)
		assertCloseOwnershipCalls(t, second, 1)
		if err := relay.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTCPFlowRelayContainsAcceptedDataPlaneCallbacks(t *testing.T) {
	operations := []string{"Read", "Write", "CloseWrite"}
	modes := []struct {
		name   string
		action dataPlaneAction
		want   CallbackFailureReason
	}{
		{name: "panic", action: dataPlanePanic, want: CallbackFailurePanic},
		{name: "goexit", action: dataPlaneGoexit, want: CallbackFailureGoexit},
		{name: "block", action: dataPlaneBlock},
	}
	for _, operation := range operations {
		operation := operation
		for _, mode := range modes {
			mode := mode
			t.Run(operation+"/"+mode.name, func(t *testing.T) {
				endpointControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
				egressControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
				endpoint := newDataPlaneTCPConn(endpointControl)
				egressConn := newDataPlaneTCPConn(egressControl)
				var started <-chan struct{}
				switch operation {
				case "Read":
					endpoint.readAction = mode.action
					started = endpoint.readStarted
				case "Write":
					endpoint.readAction = dataPlanePayload
					egressConn.writeAction = mode.action
					started = egressConn.writeStarted
				case "CloseWrite":
					endpoint.readAction = dataPlaneEOF
					egressConn.closeWriteAction = mode.action
					started = egressConn.closeWriteStarted
				}

				registry := NewEgressRegistry()
				if err := registry.Register("direct", &staticOwnershipEgress{tcp: egressConn}); err != nil {
					t.Fatal(err)
				}
				relay := &TCPFlowRelay{Egresses: registry}
				serveErr := make(chan error, 1)
				go func() {
					serveErr <- relay.Serve(
						context.Background(),
						tcpFlowRelayEvent(tcpFlowRelayIdentity()),
						endpoint,
					)
				}()
				waitClosed(t, started, "TCP "+operation+" callback")

				if mode.action == dataPlaneBlock {
					if err := relay.Close(); err != nil {
						t.Fatalf("Close during blocked %s: %v", operation, err)
					}
					_ = waitError(t, serveErr, "blocked TCP "+operation+" relay")
				} else {
					err := waitError(t, serveErr, "abnormal TCP "+operation+" relay")
					assertDataPlaneCallback(t, err, mode.want, "TCPFlowRelay TCPConn."+operation)
					if err := relay.Close(); err != nil {
						t.Fatalf("Close after abnormal %s: %v", operation, err)
					}
				}
				endpointControl.Wait(t)
				egressControl.Wait(t)
				assertCloseOwnershipCalls(t, endpointControl, 1)
				assertCloseOwnershipCalls(t, egressControl, 1)
			})
		}
	}
	t.Run("local-close-read-does-not-half-close", func(t *testing.T) {
		sourceControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
		destinationControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
		source := newDataPlaneTCPConn(sourceControl)
		destination := newDataPlaneTCPConn(destinationControl)
		result := make(chan error, 1)
		go runTCPRelayWorker(context.Background(), result, destination, source, 0)
		waitClosed(t, source.readStarted, "TCP local-close Read callback")
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		if err := waitError(t, result, "TCP local-close Read worker"); err != nil {
			t.Fatalf("local teardown worker error=%v", err)
		}
		if got := destination.closeWriteCalls.Load(); got != 0 {
			t.Fatalf("local teardown propagated %d false half-closes", got)
		}
		if err := destination.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("canceled-eof-does-not-half-close", func(t *testing.T) {
		sourceControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
		destinationControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
		source := newDataPlaneTCPConn(sourceControl)
		source.readAction = dataPlaneEOF
		destination := newDataPlaneTCPConn(destinationControl)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result := make(chan error, 1)
		go runTCPRelayWorker(ctx, result, destination, source, 0)
		if err := waitError(t, result, "TCP canceled EOF worker"); err != nil {
			t.Fatalf("canceled EOF worker error=%v", err)
		}
		if got := destination.closeWriteCalls.Load(); got != 0 {
			t.Fatalf("canceled EOF propagated %d false half-closes", got)
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		if err := destination.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestUDPFlowRelayContainsAcceptedDataPlaneCallbacks(t *testing.T) {
	modes := []struct {
		name   string
		action dataPlaneAction
		want   CallbackFailureReason
	}{
		{name: "panic", action: dataPlanePanic, want: CallbackFailurePanic},
		{name: "goexit", action: dataPlaneGoexit, want: CallbackFailureGoexit},
		{name: "block", action: dataPlaneBlock},
	}
	for _, operation := range []string{"ReadFrom", "WriteTo"} {
		operation := operation
		for _, mode := range modes {
			mode := mode
			t.Run(operation+"/"+mode.name, func(t *testing.T) {
				_, ev := ownershipUDPEvent(t)
				control := newCloseOwnershipControl(closeOwnershipReturn, nil)
				pc := newDataPlanePacketConn(control)
				var started <-chan struct{}
				if operation == "ReadFrom" {
					pc.readAction = mode.action
					started = pc.readStarted
				} else {
					pc.writeAction = mode.action
					started = pc.writeStarted
				}
				registry := NewEgressRegistry()
				if err := registry.Register("dns-egress", &staticOwnershipEgress{
					udp: pc, remote: netip.MustParseAddrPort("198.51.100.53:53"),
				}); err != nil {
					t.Fatal(err)
				}
				relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}

				if operation == "WriteTo" {
					handleErr := make(chan error, 1)
					go func() { handleErr <- relay.HandlePacket(context.Background(), ev) }()
					waitClosed(t, started, "UDP WriteTo callback")
					if mode.action == dataPlaneBlock {
						if err := relay.Close(); err != nil {
							t.Fatalf("Close during blocked WriteTo: %v", err)
						}
						_ = waitError(t, handleErr, "blocked UDP WriteTo")
					} else {
						err := waitError(t, handleErr, "abnormal UDP WriteTo")
						assertDataPlaneCallback(t, err, mode.want, "UDPFlowRelay PacketConn.WriteTo")
						assertDataPlaneCallback(t, relay.Close(), mode.want, "UDPFlowRelay PacketConn.WriteTo")
					}
				} else {
					if err := relay.HandlePacket(context.Background(), ev); err != nil {
						t.Fatal(err)
					}
					waitClosed(t, started, "UDP ReadFrom callback")
					if mode.action == dataPlaneBlock {
						if err := relay.Close(); err != nil {
							t.Fatalf("Close during blocked ReadFrom: %v", err)
						}
					} else {
						waitClosed(t, pc.readDone, "abnormal UDP ReadFrom completion")
						assertDataPlaneCallback(t, relay.Close(), mode.want, "UDPFlowRelay PacketConn.ReadFrom")
					}
				}
				control.Wait(t)
				assertCloseOwnershipCalls(t, control, 1)
			})
		}
	}
}

func TestUDPFlowRelayBlockedWritesUseOnePerFlowWorker(t *testing.T) {
	const requests = 32
	_, ev := ownershipUDPEvent(t)
	control := newCloseOwnershipControl(closeOwnershipReturn, nil)
	pc := newDataPlanePacketConn(control)
	pc.writeAction = dataPlaneBlock
	registry := NewEgressRegistry()
	if err := registry.Register("dns-egress", &staticOwnershipEgress{
		udp: pc, remote: netip.MustParseAddrPort("198.51.100.53:53"),
	}); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
	results := make(chan error, requests)
	go func() { results <- relay.HandlePacket(context.Background(), ev) }()
	waitClosed(t, pc.writeStarted, "first blocked UDP WriteTo")
	var launched sync.WaitGroup
	launched.Add(requests - 1)
	for range requests - 1 {
		go func() {
			launched.Done()
			results <- relay.HandlePacket(context.Background(), ev)
		}()
	}
	launched.Wait()
	if got := pc.writeCalls.Load(); got != 1 {
		t.Fatalf("concurrent PacketConn.WriteTo calls=%d want 1", got)
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("Close during queued writes: %v", err)
	}
	for range requests {
		_ = waitError(t, results, "queued UDP write")
	}
	if got := pc.writeCalls.Load(); got != 1 {
		t.Fatalf("PacketConn.WriteTo calls after Close=%d want 1", got)
	}
	control.Wait(t)
	assertCloseOwnershipCalls(t, control, 1)
}

func testTCPRelayBoundedCloseFanout(t *testing.T) {
	const sessionCount = 4 * l3IngressRelayCloseFanoutLimit
	runtime.GC()
	idleGoroutines := runtime.NumGoroutine()
	tracker := newCloseFanoutTracker(sessionCount)
	egress := &dynamicOwnershipEgress{mode: closeOwnershipReturn}
	registry := NewEgressRegistry()
	if err := registry.Register("direct", egress); err != nil {
		t.Fatal(err)
	}
	relay := &TCPFlowRelay{Egresses: registry}
	baseID := tcpFlowRelayIdentity()
	endpointControls := make([]*closeOwnershipControl, 0, sessionCount)
	serveResults := make(chan error, sessionCount)
	for index := range sessionCount {
		id := baseID
		id.SrcPort += uint16(index)
		control := newCloseOwnershipControl(closeOwnershipReturn, nil)
		control.fanout = tracker
		endpointControls = append(endpointControls, control)
		endpoint := newOwnershipTCPConn(control, nil)
		go func() { serveResults <- relay.Serve(context.Background(), tcpFlowRelayEvent(id), endpoint) }()
		waitForTCPRelaySession(t, relay, id)
	}
	runtime.GC()
	activeGoroutines := runtime.NumGoroutine()
	closeResult := make(chan error, 1)
	go func() { closeResult <- relay.Close() }()
	for range l3IngressRelayCloseFanoutLimit {
		waitSignal(t, tracker.started, "bounded TCP session Close")
	}
	select {
	case <-tracker.started:
		t.Fatal("TCP relay started more Close callbacks than its fixed fanout")
	case <-time.After(DefaultEgressCloseTimeout / 4):
	}
	if growth := runtime.NumGoroutine() - activeGoroutines; growth > 4*l3IngressRelayCloseFanoutLimit+16 {
		t.Fatalf("TCP Close goroutine growth=%d exceeds fixed fanout bound", growth)
	}
	tracker.Release()
	if err := waitError(t, closeResult, "bounded TCP relay Close"); err != nil {
		t.Fatal(err)
	}
	for range sessionCount {
		_ = waitError(t, serveResults, "bounded TCP relay Serve")
	}
	for index, control := range endpointControls {
		control.Wait(t)
		if got := control.calls.Load(); got != 1 {
			t.Fatalf("endpoint %d Close calls=%d want 1", index, got)
		}
	}
	egressControls := egress.Controls()
	if len(egressControls) != sessionCount {
		t.Fatalf("egress connections=%d want %d", len(egressControls), sessionCount)
	}
	for index, control := range egressControls {
		control.Wait(t)
		if got := control.calls.Load(); got != 1 {
			t.Fatalf("egress %d Close calls=%d want 1", index, got)
		}
	}
	if got := tracker.maximum.Load(); got != l3IngressRelayCloseFanoutLimit {
		t.Fatalf("maximum concurrent TCP Close callbacks=%d want %d", got, l3IngressRelayCloseFanoutLimit)
	}
	waitForL3Condition(t, time.Second, func() bool {
		return runtime.NumGoroutine() <= idleGoroutines+8
	}, "bounded TCP Close goroutine retirement")
}

func testTCPRelayImmediateCloseError(t *testing.T) {
	closeErr := errors.New("immediate TCP close error")
	endpointControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
	egressControl := newCloseOwnershipControl(closeOwnershipReturn, closeErr)
	registry := NewEgressRegistry()
	if err := registry.Register("direct", &staticOwnershipEgress{
		tcp: newOwnershipTCPConn(egressControl, nil),
	}); err != nil {
		t.Fatal(err)
	}
	relay := &TCPFlowRelay{Egresses: registry}
	serveResult := make(chan error, 1)
	id := tcpFlowRelayIdentity()
	go func() {
		serveResult <- relay.Serve(
			context.Background(),
			tcpFlowRelayEvent(id),
			newOwnershipTCPConn(endpointControl, nil),
		)
	}()
	waitForTCPRelaySession(t, relay, id)
	err := relay.Close()
	if got := directErrorCount(err, closeErr); got != 1 {
		t.Fatalf("immediate TCP Close error occurrences=%d want 1: %v", got, err)
	}
	if got := directErrorCount(relay.Close(), closeErr); got != 1 {
		t.Fatalf("repeated TCP Close error occurrences=%d want 1", got)
	}
	_ = waitError(t, serveResult, "immediate-error TCP Serve")
	assertCloseOwnershipCalls(t, endpointControl, 1)
	assertCloseOwnershipCalls(t, egressControl, 1)
}

func testTCPRelayLateTerminal(
	t *testing.T,
	mode closeOwnershipMode,
	terminalErr error,
	terminalReason CallbackFailureReason,
) {
	endpointControl := newCloseOwnershipControl(closeOwnershipReturn, nil)
	terminal := newLateCloseOwnershipControl(mode, terminalErr)
	registry := NewEgressRegistry()
	if err := registry.Register("direct", &staticOwnershipEgress{
		tcp: newOwnershipTCPConn(terminal, nil),
	}); err != nil {
		t.Fatal(err)
	}
	relay := &TCPFlowRelay{Egresses: registry}
	serveResult := make(chan error, 1)
	id := tcpFlowRelayIdentity()
	go func() {
		serveResult <- relay.Serve(
			context.Background(),
			tcpFlowRelayEvent(id),
			newOwnershipTCPConn(endpointControl, nil),
		)
	}()
	waitForTCPRelaySession(t, relay, id)
	started := time.Now()
	firstErr := relay.Close()
	if elapsed := time.Since(started); elapsed > 4*DefaultEgressCloseTimeout {
		t.Fatalf("first TCP Close took %v", elapsed)
	}
	if got := callbackReasonCount(firstErr, CallbackFailureTimeout); got != 1 {
		t.Fatalf("first TCP Close timeout occurrences=%d want 1: %v", got, firstErr)
	}
	waitClosed(t, terminal.started, "late TCP Close callback")
	assertCloseOwnershipCalls(t, terminal, 1)
	terminal.Release()
	terminal.Wait(t)
	waitForL3Condition(t, time.Second, func() bool {
		return hasLateTerminalResult(relay.Close(), terminalErr, terminalReason)
	}, "late TCP terminal diagnostic")
	finalErr := relay.Close()
	assertLateTerminalResult(t, finalErr, terminalErr, terminalReason)
	assertConcurrentLateTerminalClose(t, relay.Close, terminalErr, terminalReason)
	_ = waitError(t, serveResult, "late-terminal TCP Serve")
	assertCloseOwnershipCalls(t, endpointControl, 1)
	assertCloseOwnershipCalls(t, terminal, 1)
}

func testTCPRelayLateTerminalGenerationIsolation(t *testing.T) {
	id := tcpFlowRelayIdentity()
	lateErr := errors.New("old TCP generation late close error")
	oldEndpoint := newCloseOwnershipControl(closeOwnershipReturn, nil)
	oldEgress := newLateCloseOwnershipControl(closeOwnershipReturn, lateErr)
	registry := NewEgressRegistry()
	if err := registry.Register("direct", &staticOwnershipEgress{
		tcp: newOwnershipTCPConn(oldEgress, nil),
	}); err != nil {
		t.Fatal(err)
	}
	relay := &TCPFlowRelay{Egresses: registry}
	oldServe := make(chan error, 1)
	go func() {
		oldServe <- relay.Serve(
			context.Background(), tcpFlowRelayEvent(id), newOwnershipTCPConn(oldEndpoint, nil),
		)
	}()
	waitForTCPRelaySession(t, relay, id)
	if !relay.CloseFlow(id) {
		t.Fatal("old TCP generation was not closed")
	}
	waitClosed(t, oldEgress.started, "old TCP generation Close")

	newEndpoint := newCloseOwnershipControl(closeOwnershipReturn, nil)
	newEgress := newCloseOwnershipControl(closeOwnershipReturn, nil)
	if err := registry.Register("direct", &staticOwnershipEgress{
		tcp: newOwnershipTCPConn(newEgress, nil),
	}); err != nil {
		t.Fatal(err)
	}
	newServe := make(chan error, 1)
	go func() {
		newServe <- relay.Serve(
			context.Background(), tcpFlowRelayEvent(id), newOwnershipTCPConn(newEndpoint, nil),
		)
	}()
	waitForTCPRelaySession(t, relay, id)
	oldEgress.Release()
	oldEgress.Wait(t)
	waitForL3Condition(t, time.Second, func() bool {
		return directErrorCount(tcpRelayTeardownError(relay), lateErr) == 1
	}, "old TCP generation late diagnostic")
	if got := newEgress.calls.Load(); got != 0 {
		t.Fatalf("old TCP completion closed new generation %d times", got)
	}
	if !relay.CloseFlow(id) {
		t.Fatal("new TCP generation was not closed")
	}
	_ = waitError(t, oldServe, "old TCP generation Serve")
	_ = waitError(t, newServe, "new TCP generation Serve")
	finalErr := relay.Close()
	assertLateTerminalResult(t, finalErr, lateErr, "")
	assertCloseOwnershipCalls(t, oldEndpoint, 1)
	assertCloseOwnershipCalls(t, oldEgress, 1)
	assertCloseOwnershipCalls(t, newEndpoint, 1)
	assertCloseOwnershipCalls(t, newEgress, 1)
}

func testUDPRelayImmediateCloseError(t *testing.T) {
	closeErr := errors.New("immediate UDP close error")
	control := newCloseOwnershipControl(closeOwnershipReturn, closeErr)
	registry := NewEgressRegistry()
	if err := registry.Register("dns-egress", &staticOwnershipEgress{
		udp: newOwnershipPacketConn(control, nil), remote: netip.MustParseAddrPort("198.51.100.53:53"),
	}); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
	_, event := ownershipUDPEvent(t)
	if err := relay.HandlePacket(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	err := relay.Close()
	if got := directErrorCount(err, closeErr); got != 1 {
		t.Fatalf("immediate UDP Close error occurrences=%d want 1: %v", got, err)
	}
	if got := directErrorCount(relay.Close(), closeErr); got != 1 {
		t.Fatalf("repeated UDP Close error occurrences=%d want 1", got)
	}
	assertCloseOwnershipCalls(t, control, 1)
}

func testUDPRelayLateTerminal(
	t *testing.T,
	mode closeOwnershipMode,
	terminalErr error,
	terminalReason CallbackFailureReason,
) {
	terminal := newLateCloseOwnershipControl(mode, terminalErr)
	registry := NewEgressRegistry()
	if err := registry.Register("dns-egress", &staticOwnershipEgress{
		udp: newOwnershipPacketConn(terminal, nil), remote: netip.MustParseAddrPort("198.51.100.53:53"),
	}); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
	_, event := ownershipUDPEvent(t)
	if err := relay.HandlePacket(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	firstErr := relay.Close()
	if elapsed := time.Since(started); elapsed > 4*DefaultEgressCloseTimeout {
		t.Fatalf("first UDP Close took %v", elapsed)
	}
	if got := callbackReasonCount(firstErr, CallbackFailureTimeout); got != 1 {
		t.Fatalf("first UDP Close timeout occurrences=%d want 1: %v", got, firstErr)
	}
	waitClosed(t, terminal.started, "late UDP Close callback")
	assertCloseOwnershipCalls(t, terminal, 1)
	terminal.Release()
	terminal.Wait(t)
	waitForL3Condition(t, time.Second, func() bool {
		return hasLateTerminalResult(relay.Close(), terminalErr, terminalReason)
	}, "late UDP terminal diagnostic")
	finalErr := relay.Close()
	assertLateTerminalResult(t, finalErr, terminalErr, terminalReason)
	assertConcurrentLateTerminalClose(t, relay.Close, terminalErr, terminalReason)
	assertCloseOwnershipCalls(t, terminal, 1)
}

func testUDPRelayLateTerminalGenerationIsolation(t *testing.T) {
	id, event := ownershipUDPEvent(t)
	lateErr := errors.New("old UDP generation late close error")
	oldEgress := newLateCloseOwnershipControl(closeOwnershipReturn, lateErr)
	registry := NewEgressRegistry()
	if err := registry.Register("dns-egress", &staticOwnershipEgress{
		udp: newOwnershipPacketConn(oldEgress, nil), remote: netip.MustParseAddrPort("198.51.100.53:53"),
	}); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
	if err := relay.HandlePacket(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if !relay.CloseFlow(id) {
		t.Fatal("old UDP generation was not closed")
	}
	waitClosed(t, oldEgress.started, "old UDP generation Close")

	newEgress := newCloseOwnershipControl(closeOwnershipReturn, nil)
	if err := registry.Register("dns-egress", &staticOwnershipEgress{
		udp: newOwnershipPacketConn(newEgress, nil), remote: netip.MustParseAddrPort("198.51.100.53:53"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := relay.HandlePacket(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	waitForUDPRelaySession(t, relay, id)
	oldEgress.Release()
	oldEgress.Wait(t)
	waitForL3Condition(t, time.Second, func() bool {
		return directErrorCount(udpRelayTeardownError(relay), lateErr) == 1
	}, "old UDP generation late diagnostic")
	if got := newEgress.calls.Load(); got != 0 {
		t.Fatalf("old UDP completion closed new generation %d times", got)
	}
	if !relay.CloseFlow(id) {
		t.Fatal("new UDP generation was not closed")
	}
	finalErr := relay.Close()
	assertLateTerminalResult(t, finalErr, lateErr, "")
	assertCloseOwnershipCalls(t, oldEgress, 1)
	assertCloseOwnershipCalls(t, newEgress, 1)
}

func assertConcurrentLateTerminalClose(
	t *testing.T,
	closeRelay func() error,
	terminalErr error,
	terminalReason CallbackFailureReason,
) {
	t.Helper()
	const callers = 32
	results := make(chan error, callers)
	for range callers {
		go func() { results <- closeRelay() }()
	}
	for range callers {
		assertLateTerminalResult(t, waitError(t, results, "concurrent repeated relay Close"), terminalErr, terminalReason)
	}
}

func hasLateTerminalResult(err, terminalErr error, terminalReason CallbackFailureReason) bool {
	if callbackReasonCount(err, CallbackFailureTimeout) != 1 {
		return false
	}
	if terminalErr != nil {
		return directErrorCount(err, terminalErr) == 1
	}
	return callbackReasonCount(err, terminalReason) == 1
}

func assertLateTerminalResult(
	t *testing.T,
	err error,
	terminalErr error,
	terminalReason CallbackFailureReason,
) {
	t.Helper()
	if got := callbackReasonCount(err, CallbackFailureTimeout); got != 1 {
		t.Fatalf("timeout occurrences=%d want 1: %v", got, err)
	}
	if terminalErr != nil {
		if got := directErrorCount(err, terminalErr); got != 1 {
			t.Fatalf("terminal error occurrences=%d want 1: %v", got, err)
		}
		return
	}
	if got := callbackReasonCount(err, terminalReason); got != 1 {
		t.Fatalf("terminal %s occurrences=%d want 1: %v", terminalReason, got, err)
	}
}

func callbackReasonCount(err error, reason CallbackFailureReason) int {
	if err == nil {
		return 0
	}
	count := 0
	if callbackErr, ok := err.(*CallbackError); ok && callbackErr.Reason == reason {
		count++
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range wrapped.Unwrap() {
			count += callbackReasonCount(child, reason)
		}
	case interface{ Unwrap() error }:
		count += callbackReasonCount(wrapped.Unwrap(), reason)
	}
	return count
}

func directErrorCount(err, target error) int {
	if err == nil || target == nil {
		return 0
	}
	count := 0
	if err == target {
		count++
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range wrapped.Unwrap() {
			count += directErrorCount(child, target)
		}
	case interface{ Unwrap() error }:
		count += directErrorCount(wrapped.Unwrap(), target)
	}
	return count
}

func tcpRelayTeardownError(relay *TCPFlowRelay) error {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.teardownErr
}

func udpRelayTeardownError(relay *UDPFlowRelay) error {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.teardownErr
}

type closeOwnershipMode uint8

const (
	closeOwnershipReturn closeOwnershipMode = iota
	closeOwnershipPanic
	closeOwnershipGoexit
	closeOwnershipBlock
)

type closeOwnershipControl struct {
	mode   closeOwnershipMode
	err    error
	late   bool
	fanout *closeFanoutTracker

	calls atomic.Int32
	start sync.Once
	end   sync.Once
	open  sync.Once

	started chan struct{}
	done    chan struct{}
	release chan struct{}
}

func newCloseOwnershipControl(mode closeOwnershipMode, err error) *closeOwnershipControl {
	return &closeOwnershipControl{
		mode:    mode,
		err:     err,
		started: make(chan struct{}),
		done:    make(chan struct{}),
		release: make(chan struct{}),
	}
}

func newLateCloseOwnershipControl(mode closeOwnershipMode, err error) *closeOwnershipControl {
	control := newCloseOwnershipControl(mode, err)
	control.late = true
	return control
}

func (c *closeOwnershipControl) Close() error {
	c.calls.Add(1)
	c.start.Do(func() { close(c.started) })
	defer c.end.Do(func() { close(c.done) })
	if c.fanout != nil {
		c.fanout.Enter()
	}
	if c.late {
		<-c.release
	}
	switch c.mode {
	case closeOwnershipPanic:
		panic(closeOwnershipPanicValue{})
	case closeOwnershipGoexit:
		runtime.Goexit()
	case closeOwnershipBlock:
		if !c.late {
			<-c.release
		}
	}
	return c.err
}

func (c *closeOwnershipControl) Release() {
	c.open.Do(func() { close(c.release) })
}

func (c *closeOwnershipControl) Wait(t *testing.T) {
	t.Helper()
	waitClosed(t, c.done, "external Close completion")
}

type closeOwnershipPanicValue struct{}

type dialOwnershipMode uint8

const (
	dialOwnershipPanic dialOwnershipMode = iota + 1
	dialOwnershipGoexit
)

type abnormalDialOwnershipEgress struct {
	mode  dialOwnershipMode
	calls atomic.Int32
}

func (e *abnormalDialOwnershipEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	e.fail()
	return nil, nil
}

func (e *abnormalDialOwnershipEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.fail()
	return nil, netip.AddrPort{}, nil
}

func (e *abnormalDialOwnershipEgress) fail() {
	e.calls.Add(1)
	switch e.mode {
	case dialOwnershipPanic:
		panic(closeOwnershipPanicValue{})
	case dialOwnershipGoexit:
		runtime.Goexit()
	}
}

type lateDialOwnershipEgress struct {
	tcp    TCPConn
	udp    net.PacketConn
	remote netip.AddrPort
	err    error

	startOnce sync.Once
	started   chan struct{}
	release   chan struct{}
}

func (e *lateDialOwnershipEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	e.wait()
	return e.tcp, e.err
}

func (e *lateDialOwnershipEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.wait()
	return e.udp, e.remote, e.err
}

func (e *lateDialOwnershipEgress) wait() {
	e.startOnce.Do(func() { close(e.started) })
	<-e.release
}

type blockingDialOwnershipEgress struct {
	calls   atomic.Int32
	created atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (e *blockingDialOwnershipEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	e.block()
	return nil, nil
}

func (e *blockingDialOwnershipEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.block()
	return nil, netip.AddrPort{}, nil
}

func (e *blockingDialOwnershipEgress) block() {
	e.calls.Add(1)
	e.started <- struct{}{}
	<-e.release
}

type ownershipTCPConn struct {
	control *closeOwnershipControl
	readErr error

	readOnce  atomic.Bool
	closeOnce sync.Once
	closed    chan struct{}
}

func newOwnershipTCPConn(control *closeOwnershipControl, readErr error) *ownershipTCPConn {
	return &ownershipTCPConn{control: control, readErr: readErr, closed: make(chan struct{})}
}

func (c *ownershipTCPConn) Read([]byte) (int, error) {
	if c.readErr != nil && c.readOnce.CompareAndSwap(false, true) {
		return 0, c.readErr
	}
	<-c.closed
	return 0, net.ErrClosed
}

func (c *ownershipTCPConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
}

func (c *ownershipTCPConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.control.Close()
}

func (*ownershipTCPConn) CloseWrite() error                { return nil }
func (*ownershipTCPConn) LocalAddr() net.Addr              { return fakeAddr("ownership-local") }
func (*ownershipTCPConn) RemoteAddr() net.Addr             { return fakeAddr("ownership-remote") }
func (*ownershipTCPConn) SetDeadline(time.Time) error      { return nil }
func (*ownershipTCPConn) SetReadDeadline(time.Time) error  { return nil }
func (*ownershipTCPConn) SetWriteDeadline(time.Time) error { return nil }

type ownershipPacketConn struct {
	control  *closeOwnershipControl
	writeErr error

	closeOnce sync.Once
	closed    chan struct{}
}

func newOwnershipPacketConn(control *closeOwnershipControl, writeErr error) *ownershipPacketConn {
	return &ownershipPacketConn{control: control, writeErr: writeErr, closed: make(chan struct{})}
}

func (c *ownershipPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, io.EOF
}

func (c *ownershipPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *ownershipPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.control.Close()
}

func (*ownershipPacketConn) LocalAddr() net.Addr              { return fakeAddr("ownership-packet") }
func (*ownershipPacketConn) SetDeadline(time.Time) error      { return nil }
func (*ownershipPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*ownershipPacketConn) SetWriteDeadline(time.Time) error { return nil }

type dataPlaneAction uint8

const (
	dataPlaneBlock dataPlaneAction = iota
	dataPlanePanic
	dataPlaneGoexit
	dataPlanePayload
	dataPlaneEOF
	dataPlaneSuccess
)

type dataPlaneTCPConn struct {
	control *closeOwnershipControl

	readAction          dataPlaneAction
	writeAction         dataPlaneAction
	closeWriteAction    dataPlaneAction
	readOnce            atomic.Bool
	readCalls           atomic.Int32
	writeCalls          atomic.Int32
	closeWriteCalls     atomic.Int32
	closeOnce           sync.Once
	closed              chan struct{}
	readStarted         chan struct{}
	writeStarted        chan struct{}
	closeWriteStarted   chan struct{}
	readStartOnce       sync.Once
	writeStartOnce      sync.Once
	closeWriteStartOnce sync.Once
}

func newDataPlaneTCPConn(control *closeOwnershipControl) *dataPlaneTCPConn {
	return &dataPlaneTCPConn{
		control:           control,
		readAction:        dataPlaneBlock,
		writeAction:       dataPlaneSuccess,
		closeWriteAction:  dataPlaneSuccess,
		closed:            make(chan struct{}),
		readStarted:       make(chan struct{}),
		writeStarted:      make(chan struct{}),
		closeWriteStarted: make(chan struct{}),
	}
}

func (c *dataPlaneTCPConn) Read(p []byte) (int, error) {
	c.readCalls.Add(1)
	c.readStartOnce.Do(func() { close(c.readStarted) })
	switch c.readAction {
	case dataPlanePanic:
		panic(closeOwnershipPanicValue{})
	case dataPlaneGoexit:
		runtime.Goexit()
	case dataPlanePayload:
		if c.readOnce.CompareAndSwap(false, true) {
			return copy(p, []byte("payload")), io.EOF
		}
		return 0, io.EOF
	case dataPlaneEOF:
		return 0, io.EOF
	default:
		<-c.closed
		return 0, net.ErrClosed
	}
	return 0, nil
}

func (c *dataPlaneTCPConn) Write(p []byte) (int, error) {
	c.writeCalls.Add(1)
	c.writeStartOnce.Do(func() { close(c.writeStarted) })
	switch c.writeAction {
	case dataPlanePanic:
		panic(closeOwnershipPanicValue{})
	case dataPlaneGoexit:
		runtime.Goexit()
	case dataPlaneBlock:
		<-c.closed
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
	return 0, nil
}

func (c *dataPlaneTCPConn) CloseWrite() error {
	c.closeWriteCalls.Add(1)
	c.closeWriteStartOnce.Do(func() { close(c.closeWriteStarted) })
	switch c.closeWriteAction {
	case dataPlanePanic:
		panic(closeOwnershipPanicValue{})
	case dataPlaneGoexit:
		runtime.Goexit()
	case dataPlaneBlock:
		<-c.closed
		return net.ErrClosed
	default:
		return nil
	}
	return nil
}

func (c *dataPlaneTCPConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.control.Close()
}

func (*dataPlaneTCPConn) LocalAddr() net.Addr              { return fakeAddr("data-plane-local") }
func (*dataPlaneTCPConn) RemoteAddr() net.Addr             { return fakeAddr("data-plane-remote") }
func (*dataPlaneTCPConn) SetDeadline(time.Time) error      { return nil }
func (*dataPlaneTCPConn) SetReadDeadline(time.Time) error  { return nil }
func (*dataPlaneTCPConn) SetWriteDeadline(time.Time) error { return nil }

type dataPlanePacketConn struct {
	control *closeOwnershipControl

	readAction     dataPlaneAction
	writeAction    dataPlaneAction
	readCalls      atomic.Int32
	writeCalls     atomic.Int32
	closeOnce      sync.Once
	closed         chan struct{}
	readStarted    chan struct{}
	writeStarted   chan struct{}
	readDone       chan struct{}
	readStartOnce  sync.Once
	writeStartOnce sync.Once
	readDoneOnce   sync.Once
}

func newDataPlanePacketConn(control *closeOwnershipControl) *dataPlanePacketConn {
	return &dataPlanePacketConn{
		control:      control,
		readAction:   dataPlaneBlock,
		writeAction:  dataPlaneSuccess,
		closed:       make(chan struct{}),
		readStarted:  make(chan struct{}),
		writeStarted: make(chan struct{}),
		readDone:     make(chan struct{}),
	}
}

func (c *dataPlanePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.readCalls.Add(1)
	c.readStartOnce.Do(func() { close(c.readStarted) })
	defer c.readDoneOnce.Do(func() { close(c.readDone) })
	switch c.readAction {
	case dataPlanePanic:
		panic(closeOwnershipPanicValue{})
	case dataPlaneGoexit:
		runtime.Goexit()
	default:
		<-c.closed
		return 0, nil, net.ErrClosed
	}
	return 0, nil, nil
}

func (c *dataPlanePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.writeCalls.Add(1)
	c.writeStartOnce.Do(func() { close(c.writeStarted) })
	switch c.writeAction {
	case dataPlanePanic:
		panic(closeOwnershipPanicValue{})
	case dataPlaneGoexit:
		runtime.Goexit()
	case dataPlaneBlock:
		<-c.closed
		return 0, net.ErrClosed
	default:
		return len(p), nil
	}
	return 0, nil
}

func (c *dataPlanePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.control.Close()
}

func (*dataPlanePacketConn) LocalAddr() net.Addr              { return fakeAddr("data-plane-packet") }
func (*dataPlanePacketConn) SetDeadline(time.Time) error      { return nil }
func (*dataPlanePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*dataPlanePacketConn) SetWriteDeadline(time.Time) error { return nil }

type staticOwnershipEgress struct {
	tcp    TCPConn
	udp    net.PacketConn
	remote netip.AddrPort
	err    error

	dialOnce    sync.Once
	dialed      chan struct{}
	dialRelease <-chan struct{}
}

type udpAdmissionEgress struct {
	dialUDP func(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error)
}

func (udpAdmissionEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	return nil, errors.New("UDP admission test egress does not support TCP")
}

func (e udpAdmissionEgress) DialUDP(
	ctx context.Context,
	id L3Identity,
) (net.PacketConn, netip.AddrPort, error) {
	return e.dialUDP(ctx, id)
}

type admissionPacketConn struct {
	writes  atomic.Int32
	closes  atomic.Int32
	closed  chan struct{}
	closeMu sync.Once
}

func newAdmissionPacketConn() *admissionPacketConn {
	return &admissionPacketConn{closed: make(chan struct{})}
}

func (c *admissionPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *admissionPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.writes.Add(1)
	return len(p), nil
}

func (c *admissionPacketConn) Close() error {
	c.closes.Add(1)
	c.closeMu.Do(func() { close(c.closed) })
	return nil
}

func (*admissionPacketConn) LocalAddr() net.Addr              { return fakeAddr("admission-packet") }
func (*admissionPacketConn) SetDeadline(time.Time) error      { return nil }
func (*admissionPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*admissionPacketConn) SetWriteDeadline(time.Time) error { return nil }

type closeFanoutTracker struct {
	started chan struct{}
	release chan struct{}
	active  atomic.Int32
	maximum atomic.Int32
	once    sync.Once
}

func newCloseFanoutTracker(capacity int) *closeFanoutTracker {
	return &closeFanoutTracker{
		started: make(chan struct{}, capacity),
		release: make(chan struct{}),
	}
}

func (t *closeFanoutTracker) Enter() {
	active := t.active.Add(1)
	updateAtomicMax(&t.maximum, active)
	t.started <- struct{}{}
	<-t.release
	t.active.Add(-1)
}

func (t *closeFanoutTracker) Release() {
	t.once.Do(func() { close(t.release) })
}

type fanoutAdmissionPacketConn struct {
	*admissionPacketConn
	tracker *closeFanoutTracker
}

func newFanoutAdmissionPacketConn(tracker *closeFanoutTracker) *fanoutAdmissionPacketConn {
	return &fanoutAdmissionPacketConn{
		admissionPacketConn: newAdmissionPacketConn(),
		tracker:             tracker,
	}
}

func (c *fanoutAdmissionPacketConn) Close() error {
	c.closes.Add(1)
	c.tracker.Enter()
	c.closeMu.Do(func() { close(c.closed) })
	return nil
}

func (e *staticOwnershipEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	e.signalDialed()
	e.waitDialRelease()
	return e.tcp, e.err
}

func (e *staticOwnershipEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.signalDialed()
	e.waitDialRelease()
	return e.udp, e.remote, e.err
}

func (e *staticOwnershipEgress) signalDialed() {
	if e.dialed != nil {
		e.dialOnce.Do(func() { close(e.dialed) })
	}
}

func (e *staticOwnershipEgress) waitDialRelease() {
	if e.dialRelease != nil {
		<-e.dialRelease
	}
}

type sequenceOwnershipEgress struct {
	mu     sync.Mutex
	conns  []net.PacketConn
	remote netip.AddrPort
}

type countingOwnershipEgress struct {
	dials   atomic.Int32
	created atomic.Int32
}

type dynamicOwnershipEgress struct {
	mode   closeOwnershipMode
	remote netip.AddrPort
	dials  atomic.Int32

	mu       sync.Mutex
	controls []*closeOwnershipControl
}

func (e *dynamicOwnershipEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	control := e.addControl()
	return newOwnershipTCPConn(control, nil), nil
}

func (e *dynamicOwnershipEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	control := e.addControl()
	return newOwnershipPacketConn(control, nil), e.remote, nil
}

func (e *dynamicOwnershipEgress) addControl() *closeOwnershipControl {
	e.dials.Add(1)
	control := newCloseOwnershipControl(e.mode, nil)
	e.mu.Lock()
	e.controls = append(e.controls, control)
	e.mu.Unlock()
	return control
}

func (e *dynamicOwnershipEgress) Controls() []*closeOwnershipControl {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*closeOwnershipControl(nil), e.controls...)
}

func (e *countingOwnershipEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	e.dials.Add(1)
	e.created.Add(1)
	return newOwnershipTCPConn(newCloseOwnershipControl(closeOwnershipReturn, nil), nil), nil
}

func (e *countingOwnershipEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.dials.Add(1)
	e.created.Add(1)
	return newOwnershipPacketConn(newCloseOwnershipControl(closeOwnershipReturn, nil), nil),
		netip.MustParseAddrPort("198.51.100.53:53"), nil
}

func (*sequenceOwnershipEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
	return nil, errors.New("UDP-only ownership egress")
}

func (e *sequenceOwnershipEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.conns) == 0 {
		return nil, netip.AddrPort{}, errors.New("ownership egress exhausted")
	}
	conn := e.conns[0]
	e.conns = e.conns[1:]
	return conn, e.remote, nil
}

func ownershipUDPEvent(t *testing.T) (L3Identity, PacketEvent) {
	t.Helper()
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.53"),
		DstPort: 53,
	}
	packet := mustBuildUDPPacket(t, id, []byte("query"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	return id, PacketEvent{
		Packet:   packet,
		Meta:     meta,
		Flow:     FlowMeta{L3Identity: id, Direction: DirectionIngress},
		Decision: FlowDecision{Egress: "dns-egress"},
		Decided:  true,
	}
}

func ownershipUDPEventForIdentity(t *testing.T, id L3Identity, payload []byte) PacketEvent {
	t.Helper()
	packet := mustBuildUDPPacket(t, id, payload)
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	return PacketEvent{
		Packet:   packet,
		Meta:     meta,
		Flow:     FlowMeta{L3Identity: id, Direction: DirectionIngress},
		Decision: FlowDecision{Egress: "dns-egress"},
		Decided:  true,
	}
}

func waitForTCPRelaySession(t *testing.T, relay *TCPFlowRelay, id L3Identity) {
	t.Helper()
	waitForL3Condition(t, time.Second, func() bool {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		return relay.sessions[legacyRelayFlowKey(id)] != nil
	}, "TCP relay session")
}

func waitForUDPRelaySession(t *testing.T, relay *UDPFlowRelay, id L3Identity) {
	t.Helper()
	waitForL3Condition(t, time.Second, func() bool {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		return relay.sessions[legacyRelayFlowKey(id)] != nil
	}, "UDP relay session")
}

func waitForUDPRelayPendingWaiters(t *testing.T, relay *UDPFlowRelay, id L3Identity, want int) {
	t.Helper()
	waitForL3Condition(t, time.Second, func() bool {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		pending := relay.pending[legacyRelayFlowKey(id)]
		return pending != nil && pending.waiters == want
	}, "UDP relay pending followers")
}

func updateAtomicMax(maximum *atomic.Int32, candidate int32) {
	for {
		current := maximum.Load()
		if current >= candidate || maximum.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func assertCloseOwnershipCalls(t *testing.T, control *closeOwnershipControl, want int32) {
	t.Helper()
	if got := control.calls.Load(); got != want {
		t.Fatalf("Close calls=%d want %d", got, want)
	}
}

func assertDataPlaneCallback(
	t *testing.T,
	err error,
	wantReason CallbackFailureReason,
	wantCallback string,
) {
	t.Helper()
	var callbackErr *CallbackError
	if !errors.As(err, &callbackErr) {
		t.Fatalf("error=%v does not contain CallbackError", err)
	}
	if callbackErr.Reason != wantReason || callbackErr.Callback != wantCallback {
		t.Fatalf(
			"callback error=(%q, %q) want (%q, %q): %v",
			callbackErr.Callback,
			callbackErr.Reason,
			wantCallback,
			wantReason,
			err,
		)
	}
}

func waitClosed(t *testing.T, done <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitError(t *testing.T, result <-chan error, description string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
		return nil
	}
}

func waitSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func reasonOrEmpty(err error) EgressErrorReason {
	reason, _ := EgressErrorReasonOf(err)
	return reason
}
