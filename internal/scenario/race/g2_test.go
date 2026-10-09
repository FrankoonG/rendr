package race

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestG2RaceMiniature: gold/G2-race (M3 design B1.3, plan:732–738) at
// reduced scale: the zero Config on both ends, two Links p1 and p2 of 20 ms
// RTT shaped to 50 Mbit/s each, one race session (both members listed on
// both ends first). The dialer A sends a 1-KiB echo request (an 8-byte seq
// and PRNG bytes) every 100 ms and the passive B echoes it; the baseline is
// the first 100 s (1,000 samples) without stimulus, the treatment the next
// 300 s (3,000 samples) with a member hard-killed every 25 s, p1 and p2 in
// turn (12 kills; the gold kills every 50 s for 30 min). Each kill is timed
// into a request's unacknowledged window (E14's effective kill): it lands
// 2 ms after the request's Write returned, well inside the 10-ms one-way
// delay, and the member of the victim's factory is killed with Link.Kill.
// Before each kill both ends list two members (the previous victim
// rejoined).
//
// PASS (plan:736, B1.3): every response arrives, byte-identical to its
// request and in order (zero loss, duplicate and reorder), on one Conn
// without an application error; treatment P99 ≤ max(2 × baseline P99,
// baseline P99 + 20 ms) and P99.9 < 1 s; at least one death migration on
// the dialer per kill (every kill is effective: the dialer's request was
// in flight on the killed member, M3-D34) and Rejoins + 1 per kill; each
// killed carrier recorded dead with transport_error on both ends within
// 2 s (E42); no migration in the baseline; a clean end with io.EOF on both
// ends and nothing left after Runtime.Close. No quality event: race has no
// quality switching (plan:741).
func TestG2RaceMiniature(t *testing.T) {
	synctest.Test(t, g2)
}

// G2 miniature timing.
const (
	g2Every    = 100 * time.Millisecond
	g2Msg      = 1024
	g2Baseline = 100 * time.Second
	g2Treat    = 300 * time.Second
	g2KillGap  = 25 * time.Second
	g2KillLag  = 2 * time.Millisecond // after the request's Write: inside its unacknowledged window
)

func g2(t *testing.T) {
	const rate = 50e6 / 8 // 50 Mbit/s
	w := newWorld(t, worldOpts{}, linkSpec{name: "p1", oneWay: 10 * time.Millisecond, rate: rate},
		linkSpec{name: "p2", oneWay: 10 * time.Millisecond, rate: rate})
	dc, pc := w.open(w.peer("p1", "p2"), rendr.DialOptions{Mode: rendr.ModeRace})
	waitFor(t, 10*time.Second, "two race members on both ends", func() bool { return twoMembers(dc, pc) })

	// The echo server.
	served := make(chan error, 1)
	go func() {
		_, err := io.Copy(struct{ io.Writer }{pc}, struct{ io.Reader }{pc})
		if err == nil {
			err = pc.CloseWrite()
		}
		served <- err
	}()

	// The client: one request every g2Every; sent reports each request's
	// Write (coalescing, so the client never waits for the test).
	n := int((g2Baseline + g2Treat) / g2Every)
	start := time.Now()
	sent := make(chan time.Time, 1)
	lat := make([]time.Duration, n)
	cerr := make(chan error, 1)
	stop := make(chan struct{}) // closed by the world's shutdown
	w.stops = append(w.stops, stop)
	go func() {
		req, resp := make([]byte, g2Msg), make([]byte, g2Msg)
		for i := range n {
			select {
			case <-stop:
				cerr <- fmt.Errorf("stopped before request %d", i)
				return
			case <-time.After(time.Until(start.Add(time.Duration(i) * g2Every))):
			}
			binary.BigEndian.PutUint64(req, uint64(i))
			rendrtest.PRNG(uint64(i) + 1).Read(req[8:])
			at := time.Now()
			if _, err := dc.Write(req); err != nil {
				cerr <- fmt.Errorf("request %d: Write: %w", i, err)
				return
			}
			select {
			case sent <- at:
			default:
			}
			if _, err := io.ReadFull(dc, resp); err != nil {
				cerr <- fmt.Errorf("request %d: Read: %w", i, err)
				return
			}
			lat[i] = time.Since(at)
			if !bytes.Equal(req, resp) {
				cerr <- fmt.Errorf("response %d differs from its request (seq %d): loss, duplicate, reorder or corruption",
					i, binary.BigEndian.Uint64(resp))
				return
			}
		}
		if err := dc.CloseWrite(); err != nil {
			cerr <- err
			return
		}
		if m, err := dc.Read(resp); m != 0 || err != io.EOF {
			cerr <- fmt.Errorf("after the last response: Read %d, %v; want io.EOF", m, err)
			return
		}
		cerr <- nil
	}()

	// The baseline must not migrate; then a kill every g2KillGap.
	sleepUntil(start.Add(g2Baseline))
	ds0, ps0 := dc.Status(), pc.Status()
	if ds0.Migrations != (rendr.MigrationCounts{}) || ps0.Migrations != (rendr.MigrationCounts{}) {
		t.Fatalf("the baseline migrated: dialer %+v, passive %+v", ds0.Migrations, ps0.Migrations)
	}
	type kill struct {
		at time.Time
		id rendr.CarrierID
	}
	var ks []kill
	for k := 0; ; k++ {
		slotAt := start.Add(g2Baseline + g2KillGap/2 + time.Duration(k)*g2KillGap)
		if !slotAt.Before(start.Add(g2Baseline + g2Treat)) {
			break
		}
		sleepUntil(slotAt)
		name := [2]string{"p1", "p2"}[k%2]
		ds, ps := dc.Status(), pc.Status()
		if len(liveOf(ds)) != 2 || len(liveOf(ps)) != 2 {
			t.Fatalf("kill %d: not two members on both ends (the previous victim did not rejoin): dialer %+v, passive %+v", k, liveOf(ds), liveOf(ps))
		}
		select { // arm on the next request
		case <-sent:
		default:
		}
		var at time.Time
		select {
		case at = <-sent:
		case <-time.After(time.Second):
			t.Fatalf("kill %d: no request within 1 s", k)
		}
		sleepUntil(at.Add(g2KillLag))
		m, _ := liveNamed(dc.Status(), name)
		l := w.link(name)
		before := l.Stats().Session.Killed
		kt := time.Now()
		l.Kill()
		if l.Stats().Session.Killed == before {
			t.Fatalf("stimulus: kill %d of %s ended no session carrier", k, name)
		}
		ks = append(ks, kill{kt, m.ID})
	}
	select {
	case err := <-cerr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the client did not finish")
	}
	if err := <-served; err != nil {
		t.Fatalf("echo server: %v", err)
	}

	// Latency.
	base := slices.Clone(lat[:int(g2Baseline/g2Every)])
	treat := slices.Clone(lat[int(g2Baseline/g2Every):])
	slices.Sort(base)
	slices.Sort(treat)
	bp99, tp99, tp999 := pct(base, 0.99), pct(treat, 0.99), pct(treat, 0.999)
	if limit := max(2*bp99, bp99+20*time.Millisecond); tp99 > limit {
		t.Fatalf("treatment P99 %v > max(2 × baseline P99, baseline P99 + 20 ms) = %v", tp99, limit)
	}
	if tp999 >= time.Second {
		t.Fatalf("treatment P99.9 %v, want < 1 s", tp999)
	}
	t.Logf("%d baseline and %d treatment samples: baseline P99 %v; treatment P99 %v, P99.9 %v, max %v",
		len(base), len(treat), bp99, tp99, tp999, treat[len(treat)-1])

	// Migrations, rejoins, death records.
	ds, ps := dc.Status(), pc.Status()
	if d := ds.Migrations.Death - ds0.Migrations.Death; d < uint64(len(ks)) {
		t.Fatalf("the dialer counted %d death migrations for %d effective kills (M3-D34)", d, len(ks))
	}
	if r := ds.Rejoins - ds0.Rejoins; r < uint64(len(ks)) {
		t.Fatalf("Rejoins rose by %d for %d kills", r, len(ks))
	}
	for i, k := range ks {
		for j, l := range []*eventLog{w.dev, w.pev} {
			ev, ok := l.downOf(k.id)
			if !ok || ev.Cause != rendr.CauseTransportError || ev.Time.Sub(k.at) > 2*time.Second {
				t.Fatalf("kill %d: the %s's death record of %d: %+v (found %v), want transport_error within 2 s", i, side(j), k.id, ev, ok)
			}
		}
	}
	t.Logf("%d kills; migrations: dialer %+v, passive %+v; Rejoins +%d", len(ks), ds.Migrations, ps.Migrations, ds.Rejoins-ds0.Rejoins)
	finish(t, dc, pc)
	w.noViolation()
	w.close()
}

// pct returns the q-quantile of sorted ds (nearest rank).
func pct(ds []time.Duration, q float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	i := int(q*float64(len(ds))+0.999999) - 1
	return ds[min(max(i, 0), len(ds)-1)]
}
