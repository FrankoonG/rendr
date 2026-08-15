package engine

import (
	"errors"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

func setZombieLeftForTrip(t *testing.T, e *Engine) {
	t.Helper()
	e.zombieMu.Lock()
	e.zombieLeft = 1
	e.zombieLastMig = time.Time{}
	e.zombieMu.Unlock()
}

func requireZombieClose(t *testing.T, e *Engine) {
	t.Helper()
	select {
	case <-e.closed:
	case <-time.After(time.Second):
		t.Fatal("zombie decision did not close the engine")
	}
	if err := e.CloseErr(); !errors.Is(err, ErrZombie) {
		t.Fatalf("close error=%v want=%v", err, ErrZombie)
	}
}

func TestZombieDeathTripRevalidatesPayloadFromDeathHook(t *testing.T) {
	for _, test := range []struct {
		name          string
		creditPayload bool
	}{
		{name: "payload-invalidates-ticket", creditPayload: true},
		{name: "no-payload-trips", creditPayload: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			targets := configureLeafSelectorRuntime(t, e, "failed", "survivor")

			failed := newLifecycleHealthyPath()
			failedID := attachFixturePath(t, e, failed, transport.PathSpec{Transport: "test", Address: "failed"}, targets["failed"])
			survivor := newLifecycleHealthyPath()
			survivorID := attachFixturePath(t, e, survivor, transport.PathSpec{Transport: "test", Address: "survivor"}, targets["survivor"])
			setZombieLeftForTrip(t, e)

			hookCalls := 0
			var activeAtDeathHook uint32
			cancel := e.OnPathDeathSerial(func(event PathDeathEvent) {
				if event.ID != failedID {
					return
				}
				hookCalls++
				activeAtDeathHook = e.ActivePath()
				if test.creditPayload {
					e.markPayload()
				}
			})
			defer cancel()

			failed.die(transport.CauseTransportError, errors.New("injected death"))
			if hookCalls != 1 {
				t.Fatalf("death hook calls=%d want=1", hookCalls)
			}
			if activeAtDeathHook != survivorID {
				t.Fatalf("active path at death hook=%d want survivor %d", activeAtDeathHook, survivorID)
			}

			if !test.creditPayload {
				requireZombieClose(t, e)
				return
			}
			select {
			case <-e.closed:
				t.Fatalf("payload credited by death hook lost to stale ticket: %v", e.CloseErr())
			case <-time.After(25 * time.Millisecond):
			}
			if got := policyTxZombieLeft(e); got != e.limits.ZombieMaxMigrations {
				t.Fatalf("zombie counter=%d want reset %d", got, e.limits.ZombieMaxMigrations)
			}
		})
	}
}

func TestPathDeathPublishesFallbackBeforeAsyncPolicyAlignment(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "failed", "survivor")

	failed := newLifecycleHealthyPath()
	failedID := attachFixturePath(t, e, failed, transport.PathSpec{Transport: "test", Address: "failed"}, targets["failed"])
	survivor := newLifecycleHealthyPath()
	survivorID := attachFixturePath(t, e, survivor, transport.PathSpec{Transport: "test", Address: "survivor"}, targets["survivor"])
	if got := e.ActivePath(); got != failedID {
		t.Fatalf("initial active path=%d want failed %d", got, failedID)
	}

	// Block the asynchronous policy transaction. The physical-death commit
	// itself must still publish its immediate fallback before OnDeath returns.
	e.sendMu.Lock()
	failed.die(transport.CauseTransportError, errors.New("injected death"))
	if got := e.ActivePath(); got != survivorID {
		e.sendMu.Unlock()
		t.Fatalf("active path before policy alignment=%d want survivor %d", got, survivorID)
	}
	e.sendMu.Unlock()
}

func TestZombieRecoveryTripRevalidatesPayloadAfterPublication(t *testing.T) {
	for _, test := range []struct {
		name          string
		creditPayload bool
	}{
		{name: "payload-invalidates-ticket", creditPayload: true},
		{name: "no-payload-trips", creditPayload: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			targets := configureLeafSelectorRuntime(t, e, "path")

			initial := newLifecycleHealthyPath()
			attachFixturePath(t, e, initial, transport.PathSpec{Transport: "test", Address: "initial"}, targets["path"])
			initial.die(transport.CauseTransportError, errors.New("initial path failed"))
			if got := e.ActivePath(); got != 0 {
				t.Fatalf("active path after death=%d want=0", got)
			}
			setZombieLeftForTrip(t, e)

			var publishedID uint32
			hookCalls := 0
			publishedAtTrip := uint32(0)
			e.zombieBeforeTrip = func() {
				hookCalls++
				publishedAtTrip = e.ActivePath()
				if publishedAtTrip == 0 || publishedAtTrip != publishedID {
					t.Fatalf("recovery was not published at pre-trip hook: active=%d published=%d", publishedAtTrip, publishedID)
				}
				if test.creditPayload {
					e.markPayload()
				}
			}

			recovery := newLifecycleHealthyPath()
			pendingID, err := e.PreparePathBound(
				recovery,
				transport.PathSpec{Transport: "test", Address: "recovery"},
				PathBinding{LocalTXTargetID: targets["path"], PeerTXTargetID: targets["path"]},
			)
			if err != nil {
				t.Fatal(err)
			}
			publishedID = pendingID
			if err := e.CommitPathAttach(pendingID); err != nil {
				t.Fatal(err)
			}
			if hookCalls != 1 || publishedAtTrip != publishedID {
				t.Fatalf("pre-trip publication calls/active=%d/%d want=1/%d", hookCalls, publishedAtTrip, publishedID)
			}

			if !test.creditPayload {
				requireZombieClose(t, e)
				return
			}
			if got := e.ActivePath(); got != publishedID {
				t.Fatalf("active recovery=%d want=%d", got, publishedID)
			}
			select {
			case <-e.closed:
				t.Fatalf("payload credited after recovery publication lost to stale ticket: %v", e.CloseErr())
			case <-time.After(25 * time.Millisecond):
			}
			if got := policyTxZombieLeft(e); got != e.limits.ZombieMaxMigrations {
				t.Fatalf("zombie counter=%d want reset %d", got, e.limits.ZombieMaxMigrations)
			}
		})
	}
}

func TestZombieTripTicketIsOneShot(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	setZombieLeftForTrip(t, e)

	ticket := e.accountMigration()
	if !e.tripZombie(ticket) {
		t.Fatal("current threshold ticket did not commit")
	}
	if e.tripZombie(ticket) {
		t.Fatal("duplicate threshold ticket committed twice")
	}
	requireZombieClose(t, e)
}
