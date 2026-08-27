package gvisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func newCandidateSnapshotTestOwner(
	t *testing.T,
) (*linkOwner, *linkMaintenance, linkAttemptOwnerSnapshot) {
	t.Helper()
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newLinkOwner(
		linkID{0xc1}, linkSecret{0xc2}, leafmobility.RoleDialer,
		[4]byte{10, 64, 0, 193}, newPacketWire(packetConn, false),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41931}, nil, func([]byte) {},
	)
	if err != nil {
		_ = packetConn.Close()
		t.Fatal(err)
	}
	owner.mu.Lock()
	source := snapshotLinkAttemptOwnerLocked(owner)
	owner.mu.Unlock()
	maintenance, err := owner.beginMaintenance(context.Background(), source.incarnation)
	if err != nil {
		owner.close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		maintenance.release()
		owner.close()
	})
	return owner, maintenance, source
}

func TestLinkOwnerCandidateOpenerConcurrentSnapshot(t *testing.T) {
	owner, maintenance, source := newCandidateSnapshotTestOwner(t)
	errFirst := errors.New("first candidate opener")
	errSecond := errors.New("second candidate opener")
	var firstCalls atomic.Uint64
	var secondCalls atomic.Uint64
	first := func(context.Context, net.Addr) (*packetWire, routeObservation, error) {
		firstCalls.Add(1)
		return nil, routeObservation{}, errFirst
	}
	second := func(context.Context, net.Addr) (*packetWire, routeObservation, error) {
		secondCalls.Add(1)
		return nil, routeObservation{}, errSecond
	}
	owner.mu.Lock()
	owner.openCandidate = first
	owner.mu.Unlock()

	const (
		workers    = 8
		iterations = 500
	)
	start := make(chan struct{})
	stopReplacement := make(chan struct{})
	replacementDone := make(chan struct{})
	go func() {
		defer close(replacementDone)
		<-start
		for useFirst := false; ; useFirst = !useFirst {
			owner.mu.Lock()
			if useFirst {
				owner.openCandidate = first
			} else {
				owner.openCandidate = second
			}
			owner.mu.Unlock()
			select {
			case <-stopReplacement:
				return
			default:
			}
		}
	}()

	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for iteration := range iterations {
				_, _, _, err := owner.stageCandidate(
					context.Background(), maintenance, outerControl{}, source,
				)
				if !errors.Is(err, errFirst) && !errors.Is(err, errSecond) {
					errCh <- fmt.Errorf("worker %d iteration %d: unexpected error %v", worker, iteration, err)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(stopReplacement)
	select {
	case <-replacementDone:
	case <-time.After(time.Second):
		t.Fatal("candidate opener replacement did not stop")
	}
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if got, want := firstCalls.Load()+secondCalls.Load(), uint64(workers*iterations); got != want {
		t.Fatalf("candidate opener calls=%d, want %d", got, want)
	}
}

func TestLinkOwnerCandidateOpenerNilFailsClosed(t *testing.T) {
	owner, maintenance, source := newCandidateSnapshotTestOwner(t)
	owner.mu.Lock()
	owner.openCandidate = nil
	owner.mu.Unlock()

	_, _, _, err := owner.stageCandidate(context.Background(), maintenance, outerControl{}, source)
	if err == nil || err.Error() != "gvisor: packet-link candidate opener unavailable" {
		t.Fatalf("stage with nil candidate opener error=%v", err)
	}
}

func TestLinkOwnerCandidateOpenerDoesNotBypassSourceValidation(t *testing.T) {
	owner, maintenance, source := newCandidateSnapshotTestOwner(t)
	var calls atomic.Uint64
	owner.mu.Lock()
	owner.openCandidate = func(context.Context, net.Addr) (*packetWire, routeObservation, error) {
		calls.Add(1)
		return nil, routeObservation{}, errors.New("must not be called")
	}
	owner.peerGeneration++
	owner.signalChangedLocked()
	owner.mu.Unlock()

	_, _, _, err := owner.stageCandidate(context.Background(), maintenance, outerControl{}, source)
	if err == nil || err.Error() != "gvisor: stale packet-link source before staging" {
		t.Fatalf("stage with stale source error=%v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("stale source invoked candidate opener %d times", got)
	}
}
