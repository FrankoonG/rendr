package engine

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

func detachLastPathForMigrationBudgetTest(
	t *testing.T,
	e *Engine,
	id uint32,
) migrationBudgetEpisode {
	t.Helper()
	e.pathsMu.Lock()
	slot := e.paths[id]
	if slot == nil {
		e.pathsMu.Unlock()
		t.Fatalf("path %d is not active", id)
	}
	departure := e.detachPathLocked(
		slot,
		e.localExecutionRuntime(),
		transport.CauseTransportError,
		errors.New("injected zero-path episode"),
		false,
	)
	e.pathsMu.Unlock()
	e.retirePathAsync(slot)
	if departure.hasPaths {
		t.Fatal("last-path departure retained an active path")
	}
	if !departure.migrationBudget.valid() {
		t.Fatal("last-path departure did not start a migration-budget episode")
	}
	return departure.migrationBudget
}

func TestMigrationBudgetExpiryRevalidatesConcurrentRecovery(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	installEngineNowForTest(t, func() time.Time { return time.Unix(0, clock.Load()) })

	e := New(SideClient, [16]byte{0xb1}, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "leaf")
	binding := PathBinding{LocalTXTargetID: targets["leaf"], PeerTXTargetID: targets["leaf"]}
	initialID, err := e.AttachPathBound(
		newLifecycleHealthyPath(),
		transport.PathSpec{Transport: "migration-budget-initial"},
		binding,
	)
	if err != nil {
		t.Fatal(err)
	}
	episode := detachLastPathForMigrationBudgetTest(t, e, initialID)
	clock.Store(episode.deadline.UnixNano())

	reachedFinalCheck := make(chan struct{})
	releaseFinalCheck := make(chan struct{})
	var releaseOnce sync.Once
	releaseExpiry := func() { releaseOnce.Do(func() { close(releaseFinalCheck) }) }
	defer releaseExpiry()
	e.migrationBudgetBeforeExpiryCommit = func(got migrationBudgetEpisode) {
		if got != episode {
			t.Errorf("expiry episode=%+v want %+v", got, episode)
		}
		close(reachedFinalCheck)
		<-releaseFinalCheck
	}
	expired := make(chan bool, 1)
	go func() { expired <- e.expireMigrationBudget(episode) }()
	select {
	case <-reachedFinalCheck:
	case <-time.After(time.Second):
		t.Fatal("expiry did not reach final revalidation hook")
	}

	recoveredID, err := e.AttachPathBound(
		newLifecycleHealthyPath(),
		transport.PathSpec{Transport: "migration-budget-recovery"},
		binding,
	)
	if err != nil {
		t.Fatalf("concurrent recovery attach: %v", err)
	}
	if active := e.ActivePath(); active != recoveredID {
		t.Fatalf("active path after recovery=%d want %d", active, recoveredID)
	}
	releaseExpiry()
	select {
	case committed := <-expired:
		if committed {
			t.Fatal("stale migration-budget episode closed the recovered session")
		}
	case <-time.After(time.Second):
		t.Fatal("expiry did not finish after recovery publication")
	}
	if e.IsClosed() || e.CloseErr() != nil {
		t.Fatalf("recovered session closed: closed=%t err=%v", e.IsClosed(), e.CloseErr())
	}
	if state := e.State(); state != BridgeActive {
		t.Fatalf("state after recovery=%s want %s", state, BridgeActive)
	}
}

func TestMigrationBudgetBriefRecoveryStartsFreshFullEpisode(t *testing.T) {
	base := time.Unix(1_800_100_000, 0)
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	installEngineNowForTest(t, func() time.Time { return time.Unix(0, clock.Load()) })

	e := New(SideClient, [16]byte{0xb2}, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "leaf")
	binding := PathBinding{LocalTXTargetID: targets["leaf"], PeerTXTargetID: targets["leaf"]}
	initialID, err := e.AttachPathBound(
		newLifecycleHealthyPath(),
		transport.PathSpec{Transport: "migration-budget-episode-one"},
		binding,
	)
	if err != nil {
		t.Fatal(err)
	}
	first := detachLastPathForMigrationBudgetTest(t, e, initialID)

	recoveryAt := first.deadline.Add(-time.Second)
	clock.Store(recoveryAt.UnixNano())
	recoveredID, err := e.AttachPathBound(
		newLifecycleHealthyPath(),
		transport.PathSpec{Transport: "migration-budget-brief-recovery"},
		binding,
	)
	if err != nil {
		t.Fatalf("brief recovery attach: %v", err)
	}
	second := detachLastPathForMigrationBudgetTest(t, e, recoveredID)
	if second.generation == first.generation {
		t.Fatalf("second episode reused generation %d", second.generation)
	}
	wantSecondDeadline := recoveryAt.Add(e.limits.MigrationBudget)
	if !second.deadline.Equal(wantSecondDeadline) {
		t.Fatalf("second deadline=%v want fresh full budget through %v", second.deadline, wantSecondDeadline)
	}

	clock.Store(first.deadline.UnixNano())
	if e.expireMigrationBudget(first) {
		t.Fatal("first episode remained authoritative after brief recovery")
	}
	if e.expireMigrationBudget(second) {
		t.Fatal("second episode expired at the first episode deadline")
	}
	if e.IsClosed() {
		t.Fatal("session closed before the fresh second budget elapsed")
	}

	clock.Store(second.deadline.Add(-time.Nanosecond).UnixNano())
	if e.expireMigrationBudget(second) {
		t.Fatal("second episode expired before its full budget elapsed")
	}
	clock.Store(second.deadline.UnixNano())
	if !e.expireMigrationBudget(second) {
		t.Fatal("second episode did not expire at its own deadline")
	}
	if !errors.Is(e.CloseErr(), ErrMigrationBudgetExceeded) {
		t.Fatalf("close error=%v want %v", e.CloseErr(), ErrMigrationBudgetExceeded)
	}
}
