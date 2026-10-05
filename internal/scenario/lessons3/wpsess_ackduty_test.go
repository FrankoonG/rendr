package lessons3

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// After a death that only the dialer detects, the passive's ACKs follow
// the dialer's SCHED (design §0.13 A7 (c), M1c). Path a fails in the
// passive-to-dialer direction only and the dialer's close of it never
// reaches the passive (an L7 relay that keeps its far side open, or a path
// that also loses the FIN): the dialer detects the death (its PINGs go
// unanswered) and fails over to b, while the passive, whose death deadline
// is longer, still holds a. The passive moves its sending to b when it
// applies the dialer's SCHED; its ACKs must move with it, or the dialer's
// acknowledged front and send window stall until the passive detects the
// death itself. Helpers of this file start with "wpsess".

// wpsessLossyConn is the passive's end of a carrier of path a: once lossy
// is set, every Write reports success and forwards nothing (whole writes).
type wpsessLossyConn struct {
	net.Conn
	lossy     *atomic.Bool
	swallowed *atomic.Int64
}

func (c *wpsessLossyConn) Write(p []byte) (int, error) {
	if c.lossy.Load() {
		c.swallowed.Add(int64(len(p)))
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// wpsessMuteCloseConn is the dialer's end of a carrier of path a: once
// mute is set, Close only cuts this end off with a past deadline, so the
// passive never reads the end of the carrier. The Link closes the far ends
// when the world closes.
type wpsessMuteCloseConn struct {
	net.Conn
	mute *atomic.Bool
}

func (c *wpsessMuteCloseConn) Close() error {
	if c.mute.Load() {
		return c.Conn.SetDeadline(time.Unix(1, 0))
	}
	return c.Conn.Close()
}

// TestWpsessOneWayLossAckFollowsSched_L27: a selector session streams
// dialer → passive over a (1 ms one-way) with b (5 ms) idle, both 2 MiB/s,
// 1 MiB window, quality switching disabled. Then path a fails one way, as
// above; the dialer's death deadline is the default (3–4 s), the passive's
// 20 s. The dialer fails over to b at once (ping_timeout); after the
// passive applies its SCHED, the dialer sees the SCHED echoed on b within
// about one RTT of b and its acknowledged front moving within an RTT plus
// the ACK delay, and the stream continues at about the path rate — without
// the passive's ACKs following the SCHED it stalled with an exhausted
// window until the passive's own detection about 20 s after the fault.
// Integrity: the stream ends intact, then both ends finish cleanly.
func TestWpsessOneWayLossAckFollowsSched_L27(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			rate     = 2 * mib
			bDelay   = 5 * time.Millisecond
			passDead = 20 * time.Second
		)
		dov := testhooks.Overrides{SelectorDwell: time.Hour, SelectorCooldown: time.Hour, Window: mib}
		pov := dov
		pov.DeadMin, pov.DeadMax = passDead, passDead
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "b", delay: bDelay, rate: rate}},
			dov:   &dov, pov: &pov,
		})
		var lossy, mute atomic.Bool
		var swallowed atomic.Int64
		la := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: func(c net.Conn) error {
			return w.ln.Handle(&wpsessLossyConn{Conn: c, lossy: &lossy, swallowed: &swallowed})
		}})
		la.SetDelay(time.Millisecond, 0)
		la.SetRate(rate)
		w.links = append(w.links, la)
		ca := rendr.StreamCarrier{Name: "a", Dial: func(ctx context.Context) (net.Conn, error) {
			c, err := la.Dial(ctx)
			if err != nil {
				return nil, err
			}
			return &wpsessMuteCloseConn{Conn: c, mute: &mute}, nil
		}}
		dc, pc := w.open(w.peerOf(ca, carrierOf(w.link("b"))), rendr.ModeSelector)
		first := mustActive(t, dc, "dialer")
		if first.Name != "a" {
			t.Fatalf("initial active %+v, want a carrier of a", first)
		}
		up := w.startFlow("up", dc, pc, 251, flowOpts{chunk: 32 * kib})
		waitFor(t, 10*time.Second, "1 MiB delivered over a", func() bool { return up.recvd.Load() >= mib })

		mark, pmark := w.dev.mark(), w.pev.mark()
		faultAt := time.Now()
		lossy.Store(true)
		mute.Store(true)
		dmig := w.dev.wait(t, mark, 10*time.Second, "the dialer's death migration", isKind(rendr.EventMigration, dc.ID()))
		pmig := w.pev.wait(t, pmark, 5*time.Second, "the passive applying the dialer's SCHED", isKind(rendr.EventMigration, pc.ID()))
		applied := pmig.Time

		// Stimulus: the death is the dialer's alone; the passive applied
		// the SCHED while it still held a, whose writes were being lost.
		dead, _ := carrierByID(dc, first.ID)
		now := mustActive(t, dc, "dialer")
		if dmig.From != first.ID || dmig.Cause != rendr.CausePingTimeout || dead.DeathCause != rendr.CausePingTimeout || now.Name != "b" {
			t.Fatalf("dialer migration %+v, a %+v, active %+v: want a's ping_timeout and b active", dmig, dead, now)
		}
		ps := pc.Status()
		var paLive bool
		for _, c := range ps.Carriers {
			paLive = paLive || (c.State != rendr.CarrierDead && c.ID == first.ID)
		}
		if !paLive || ps.SchedEpoch != dc.Status().SchedEpoch || swallowed.Load() == 0 {
			t.Fatalf("passive holds a %v, epoch %d (dialer %d), %d bytes lost: want the SCHED applied while a lived (stimulus)",
				paLive, ps.SchedEpoch, dc.Status().SchedEpoch, swallowed.Load())
		}

		// The passive's ACKs travel on b at once: the echo of the SCHED
		// reaches the dialer within about one RTT of b, and the first ACK
		// that moves its acknowledged front follows the data the dialer
		// sends on b (its JOIN_ACK already acknowledged everything the
		// passive had read before), within an RTT plus the ACK delay.
		acked := dc.Status().AckedBytes
		var echoAt, ackAt time.Time
		for deadline := applied.Add(passDead); echoAt.IsZero() || ackAt.IsZero(); time.Sleep(time.Millisecond) {
			st := dc.Status()
			if echoAt.IsZero() && st.SchedEchoed == st.SchedEpoch {
				echoAt = time.Now()
			}
			if ackAt.IsZero() && st.AckedBytes > acked {
				ackAt = time.Now()
			}
			if !time.Now().Before(deadline) {
				t.Fatalf("within %v of the passive's SCHED: echo at %v, acknowledged front moved at %v", passDead, echoAt, ackAt)
			}
		}
		t.Logf("fault +%v: dialer failover; passive applied the SCHED +%v; echo %v and the next ACK %v later",
			dmig.Time.Sub(faultAt), applied.Sub(faultAt), echoAt.Sub(applied), ackAt.Sub(applied))
		if rtt := 2 * bDelay; echoAt.Sub(applied) > 2*rtt {
			t.Fatalf("the dialer saw its SCHED echoed %v after the passive applied it, want within about one RTT (%v)", echoAt.Sub(applied), rtt)
		}
		if d := ackAt.Sub(applied); d > 100*time.Millisecond {
			t.Fatalf("the dialer's acknowledged front moved %v after the passive applied the SCHED, want within an RTT and the ACK delay", d)
		}

		// Load: the stream goes on at about the path rate.
		before := up.recvd.Load()
		time.Sleep(time.Second)
		if got := up.recvd.Load() - before; got < rate/2 {
			t.Fatalf("%d bytes delivered in the second after the failover, want at least %d (the window stalled)", got, int64(rate/2))
		}
		up.stop()
		up.wait(t, 30*time.Second)
		wantMigrations(t, "dialer", dc, rendr.MigrationCounts{Death: 1})
		wantMigrations(t, "passive", pc, rendr.MigrationCounts{Death: 1})
		finishSession(t, dc, pc)
		w.finish()
	})
}
