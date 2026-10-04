package session

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// Selector quality policy (design §7.2; L22, L28, L29): a fresh challenger
// that beats the active factory by Band and Floor for Dwell gets a JOIN;
// only its JOIN_ACK changes routing; the old lane retires once its spans
// are acknowledged; both ends count one quality migration.

// TestActorQualitySwitch: a mid-transfer planned switch to the better
// factory: nothing changes until the JOIN attached, then one quality
// migration on both ends, the predecessor retires (not a death), the
// cooldown holds the next switch, and every byte arrives.
func TestActorQualitySwitch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		h := acNewHealth(2, w.a.p.Selector.Fresh)
		h.set(30*time.Millisecond, 0)
		l1, l2 := w.slowLink("p1"), w.slowLink("p2")
		l1.SetRate(8 << 20) // the transfer outlasts Dwell
		l2.SetRate(8 << 20)
		a, b := w.open(ModeSelector, h, l1, l2)
		first := acActive(a)
		if first == 0 || a.Status().Carriers[0].Name != "p1" {
			t.Fatalf("opened on %+v, want p1 (the only measured factory)", a.Status().Carriers)
		}

		const n = 16 << 20
		done := make(chan [2]error, 1)
		go func() {
			we, re := acTransfer(a, b, n, 41, true)
			done <- [2]error{we, re}
		}()
		defer acFreshen(h)()
		h.set(30*time.Millisecond, 10*time.Millisecond)
		start := time.Now()
		acWaitFor(t, 3*time.Second, "the quality switch", func() bool { return a.Status().MigQuality == 1 })
		if d := time.Since(start); d < a.p.Selector.Dwell {
			t.Fatalf("switched %v after the evidence changed, before Dwell %v", d, a.p.Selector.Dwell)
		}
		if got := acActive(a); got == first || got == 0 {
			t.Fatalf("active %d after the switch (was %d)", got, first)
		}
		if d := b.Status().DeliveredBytes; d >= n {
			t.Fatal("the transfer finished before the switch: no load across it")
		}
		// A reverse improvement inside the cooldown does not switch back.
		h.set(4*time.Millisecond, 10*time.Millisecond)
		time.Sleep(a.p.Selector.Dwell + 100*time.Millisecond)
		if q := a.Status().MigQuality; q != 1 {
			t.Fatalf("%d quality switches inside the cooldown, want 1", q)
		}
		h.set(30*time.Millisecond, 10*time.Millisecond)
		r := <-done
		if r[0] != nil || r[1] != nil {
			t.Fatalf("transfer: write %v, read %v", r[0], r[1])
		}
		as, bs := a.Status(), b.Status()
		if as.MigQuality != 1 || bs.MigQuality != 1 || as.MigDeath+bs.MigDeath+as.MigExplicit+bs.MigExplicit != 0 {
			t.Fatalf("migrations: dialer %d/%d/%d passive %d/%d/%d, want one quality each",
				as.MigDeath, as.MigQuality, as.MigExplicit, bs.MigDeath, bs.MigQuality, bs.MigExplicit)
		}
		if l2.Stats().Session.Bytes == 0 || l1.Stats().Session.Bytes == 0 {
			t.Fatal("both paths must have carried the transfer")
		}
		var old *CarrierStatus
		for i := range as.Carriers {
			if as.Carriers[i].ID == first {
				old = &as.Carriers[i]
			}
		}
		if old == nil || old.State != LaneDead || old.DeathCause != carrier.CauseRetired {
			t.Fatalf("predecessor %+v, want dead by retirement", old)
		}
	})
}
