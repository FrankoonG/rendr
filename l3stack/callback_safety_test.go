package l3stack

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/l3ingress"
)

type hostileGatewayPanicPayload struct{}

func (hostileGatewayPanicPayload) String() string { panic("panic payload was formatted") }

func TestGatewayFlowErrorObserverAbnormalAndBlockedCallbacksAreContained(t *testing.T) {
	const timeout = 15 * time.Millisecond
	release := make(chan struct{})
	var calls atomic.Int32
	gateway := &Gateway{
		observerTimeout: timeout,
		onFlowError: func(l3ingress.L3Identity, error) {
			switch calls.Add(1) {
			case 1:
				<-release
			case 2:
				runtime.Goexit()
			case 3:
				panic(hostileGatewayPanicPayload{})
			}
		},
	}
	wantErr := errors.New("flow failed")
	started := time.Now()
	gateway.reportFlowError(l3ingress.L3Identity{}, wantErr)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("blocked observer delayed report for %v", elapsed)
	}
	for i := 0; i < 256; i++ {
		gateway.reportFlowError(l3ingress.L3Identity{}, wantErr)
	}
	status := gateway.CallbackStatus()
	if calls.Load() != 1 || status.Timeouts != 1 || status.Drops != 256 {
		t.Fatalf("blocked observer calls=%d status=%+v", calls.Load(), status)
	}

	close(release)
	waitForGatewayCondition(t, time.Second, func() bool { return !gateway.flowErrorBusy.Load() }, "flow observer release")
	gateway.reportFlowError(l3ingress.L3Identity{}, wantErr)
	status = gateway.CallbackStatus()
	if status.Goexits != 1 || gateway.flowErrorBusy.Load() {
		t.Fatalf("Goexit observer status=%+v busy=%v", status, gateway.flowErrorBusy.Load())
	}
	gateway.reportFlowError(l3ingress.L3Identity{}, wantErr)
	status = gateway.CallbackStatus()
	if status.Panics != 1 || status.LastFailure.PanicType != "l3stack.hostileGatewayPanicPayload" {
		t.Fatalf("panic observer status=%+v", status)
	}
	_ = status.LastFailure.Error()
	gateway.reportFlowError(l3ingress.L3Identity{}, wantErr)
	if calls.Load() != 4 || gateway.flowErrorBusy.Load() {
		t.Fatalf("observer slot was not reusable calls=%d busy=%v", calls.Load(), gateway.flowErrorBusy.Load())
	}
}

func TestGatewayFlowErrorConcurrencyIsProcessBoundedAcrossObjects(t *testing.T) {
	const processLimit = l3StackProcessOptionalCallbackLimit
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseCallbacks := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCallbacks()

	var started atomic.Int32
	var returned sync.WaitGroup
	returned.Add(processLimit)
	reports := make(chan struct{}, processLimit)
	for i := 0; i < processLimit; i++ {
		gateway := &Gateway{
			observerTimeout: 100 * time.Millisecond,
			onFlowError: func(l3ingress.L3Identity, error) {
				started.Add(1)
				defer returned.Done()
				<-release
			},
		}
		go func(gateway *Gateway) {
			gateway.reportFlowError(l3ingress.L3Identity{}, errors.New("blocked"))
			reports <- struct{}{}
		}(gateway)
	}
	waitForGatewayCondition(t, 2*time.Second, func() bool {
		return started.Load() == processLimit
	}, "process-wide flow error callback saturation")
	for i := 0; i < processLimit; i++ {
		<-reports
	}

	var extraCalls atomic.Int32
	extraGateway := &Gateway{
		observerTimeout: time.Second,
		onFlowError: func(l3ingress.L3Identity, error) {
			extraCalls.Add(1)
		},
	}
	extraGateway.reportFlowError(l3ingress.L3Identity{}, errors.New("beyond limit"))
	status := extraGateway.CallbackStatus()
	if extraCalls.Load() != 0 || status.Drops != 1 ||
		status.LastFailure.Reason != l3ingress.CallbackFailureSaturated {
		t.Fatalf("process bound calls=%d status=%+v", extraCalls.Load(), status)
	}

	releaseCallbacks()
	returned.Wait()
	waitForGatewayCondition(t, time.Second, func() bool {
		extraGateway.reportFlowError(l3ingress.L3Identity{}, errors.New("reused"))
		return extraCalls.Load() == 1
	}, "flow error process permit release")
}

func waitForGatewayCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}
