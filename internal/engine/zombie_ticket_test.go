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

			failed := newLifecycleHealthyPath()
			failedID, err := e.AttachPath(failed, transport.PathSpec{Transport: "test", Address: "failed"})
			if err != nil {
				t.Fatal(err)
			}
			survivor := newLifecycleHealthyPath()
			survivorID, err := e.AttachPath(survivor, transport.PathSpec{Transport: "test", Address: "survivor"})
			if err != nil {
				t.Fatal(err)
			}
			setZombieLeftForTrip(t, e)

			hookCalls := 0
			cancel := e.OnPathDeathSerial(func(event PathDeathEvent) {
				if event.ID != failedID {
					return
				}
				hookCalls++
				if test.creditPayload {
					e.markPayload()
				}
			})
			defer cancel()

			failed.die(transport.CauseTransportError, errors.New("injected death"))
			if hookCalls != 1 {
				t.Fatalf("death hook calls=%d want=1", hookCalls)
			}
			if got := e.ActivePath(); got != survivorID {
				t.Fatalf("active path=%d want survivor %d", got, survivorID)
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

			initial := newLifecycleHealthyPath()
			if _, err := e.AttachPath(initial, transport.PathSpec{Transport: "test", Address: "initial"}); err != nil {
				t.Fatal(err)
			}
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
			pendingID, err := e.PreparePathBound(recovery, transport.PathSpec{Transport: "test", Address: "recovery"}, PathBinding{})
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
