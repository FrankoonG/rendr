package l4

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The L4 gold miniatures (M4 design §A12.2; B1.1–B1.3 at reduced scale):
// one L4 connection through an ingress Forward and the l4.Server, a
// selector session on a Peer of two factories p1, p2 (default Props: rendr
// mux), the zero Config on both ends, Links of 20 ms RTT.

// TestL4G1Miniature: gold/G1-l4 (B1.1; plan:725–730, plan:806) at reduced
// scale: the client half-closes at once and reads 256 MiB (64 MiB under
// -race, on the same 10.24-s timeline, R1-11) that the target generates;
// the Links are shaped so the transfer takes 10.24 s on one path.
//
// Stimulus: when the client has read 30 %, 50 % and 70 % of the bytes,
// the Link carrying the session's data (its active carrier) is killed —
// Link.Kill closes both ends, the RST of the gold. Each kill must end a
// session carrier while the client is mid-transfer.
//
// PASS: every byte verified and io.EOF exactly at the end (the SHA-256 of
// the gold); no client error and a clean ingress Forward; no
// zero-delivery gap above 500 ms at the client; Death ≥ 3 on the
// dialer; the target accepted exactly one connection, saw no reset either
// way, wrote all its bytes and its FIN; nothing left after Runtime.Close.
func TestL4G1Miniature(t *testing.T) {
	size := int64(256 << 20)
	if raceEnabled {
		size = 64 << 20 // R1-11: the same 10.24-s timeline at a quarter of the rate
	}
	synctest.Test(t, func(t *testing.T) { g1(t, size) })
}

// g1Span is the transfer time of the G1 miniature at the link rate.
const g1Span = 10240 * time.Millisecond

func g1(t *testing.T, size int64) {
	const seed = 11
	rate := float64(size) / g1Span.Seconds()
	w := newWorld(t, worldOpts{}, linkSpec{name: "p1", rate: rate}, linkSpec{name: "p2", rate: rate})
	gen := w.target("gen", rendrtest.TargetGen(size, seed))
	in := w.mustIngress(w.peer("p1", "p2"), "gen-1.test:80", rendr.DialOptions{}, 0)
	if err := in.cli.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	start := time.Now()
	rx := startReceiver(in.cli, seed, size)
	deaths0 := in.c.Status().Migrations.Death
	for i, frac := range []float64{0.3, 0.5, 0.7} {
		waitFor(t, 2*time.Minute, fmt.Sprintf("%.0f %% of the bytes", 100*frac), func() bool {
			return rx.got.Load() >= int64(frac*float64(size))
		})
		l, cs := w.activeLink(in.c, 10*time.Second)
		before := l.Stats().Session.Killed
		if got := rx.got.Load(); got >= size {
			t.Fatalf("stimulus: kill %d: the client already read everything", i)
		}
		l.Kill()
		if l.Stats().Session.Killed == before {
			t.Fatalf("stimulus: kill %d of %s ended no session carrier", i, l.Name())
		}
		t.Logf("kill %d: %s (carrier %d) at +%v, %d of %d bytes read", i, l.Name(), cs.ID, time.Since(start), rx.got.Load(), size)
	}
	rx.wait(t, 2*time.Minute)
	res, err := in.result(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean || res.ToLocal != size || res.ToSession != 0 {
		t.Fatalf("ingress Forward %+v, want a clean end with %d bytes to the client", res, size)
	}
	if gap, at := rx.maxGap(start, rx.end()); gap > 500*time.Millisecond {
		t.Fatalf("a zero-delivery gap of %v at +%v, want ≤ 500 ms", gap, at.Sub(start))
	}
	if d := in.c.Status().Migrations.Death - deaths0; d < 3 {
		t.Fatalf("the dialer counted %d death migrations for 3 kills, want ≥ 3: %+v", d, in.c.Status().Migrations)
	}
	waitFor(t, 10*time.Second, "the target connection closed", func() bool { return gen.Counts().Open == 0 })
	c := gen.Counts()
	if c.Accepted != 1 || c.RSTIn != 0 || c.RSTOut != 0 || c.BytesOut != size || c.FINOut != 1 || c.FINIn != 1 {
		t.Fatalf("target %+v; want one connection, no reset, %d bytes and a FIN out, the client's FIN in", totals(c), size)
	}
	t.Logf("%d MiB in %v; migrations %+v", size>>20, rx.end().Sub(start), in.c.Status().Migrations)
	in.cli.Close()
	w.noViolation()
	w.close()
}

// TestL4G2Miniature: gold/G2-l4 (B1.2; plan:732–738, plan:806; L65)
// at reduced scale: Links of 50 Mbit/s; one L4 connection to an echo
// target; the client sends a 1-KiB message every 100 ms (250 ms under
// -race; an absolute schedule) for 11 virtual minutes, each message the next 1 KiB of
// PRNG(seed), and reads the echo; then it half-closes. The run is longer
// than the session's 10-min L4 idle default on both ends (l4.Dial and the
// Server set it), so an idle clock that traffic did not move would fire
// inside it.
//
// Stimulus: every 50 s the Link carrying the session's data is killed
// (13 kills); each must end a session carrier.
//
// PASS: zero loss, duplicates and reordering by content (every echoed
// message is the next one sent, then io.EOF); P99.9 of the echo latency
// < 1 s (the gold's); one target connection; Death ≥ 13 on the dialer;
// the idle timeout never fired on either end (the session ends exactly
// once on each end, with io.EOF); a clean ingress Forward; nothing left
// after Runtime.Close.
func TestL4G2Miniature(t *testing.T) {
	synctest.Test(t, g2)
}

const (
	g2Span = 11 * time.Minute // longer than the 10-min L4 idle default
	g2Msg  = 1 << 10
	g2Kill = 50 * time.Second
	g2Seed = 21
	g2Rate = 50e6 / 8 // 50 Mbit/s
)

// g2Every is the message interval: 100 ms, and 250 ms under the race
// detector (m3 R1-23's first lever, I3 of M4: the same 11 minutes, kills
// and criteria on fewer messages); g2Echoes the messages of the run.
var (
	g2Every  = map[bool]time.Duration{false: 100 * time.Millisecond, true: 250 * time.Millisecond}[raceEnabled]
	g2Echoes = int64(g2Span / g2Every)
)

func g2(t *testing.T) {
	w := newWorld(t, worldOpts{}, linkSpec{name: "p1", rate: g2Rate}, linkSpec{name: "p2", rate: g2Rate})
	echo := w.target("echo", rendrtest.TargetEcho())
	in := w.mustIngress(w.peer("p1", "p2"), "echo-1.test:80", rendr.DialOptions{}, 0)
	start := time.Now()
	sent := make([]time.Time, g2Echoes)
	var werr error
	wdone := make(chan struct{})
	go func() {
		defer close(wdone)
		src := rendrtest.PRNG(g2Seed)
		msg := make([]byte, g2Msg)
		for k := range g2Echoes {
			if !pace(in.quit, start.Add(time.Duration(k)*g2Every)) {
				werr = fmt.Errorf("message %d: stopped by the world's shutdown", k)
				return
			}
			src.Read(msg)
			sent[k] = time.Now()
			if _, err := in.cli.Write(msg); err != nil {
				werr = fmt.Errorf("message %d: %w", k, err)
				return
			}
		}
		werr = in.cli.CloseWrite()
	}()
	lat := make([]time.Duration, 0, g2Echoes)
	var rerr error
	rdone := make(chan struct{})
	go func() {
		defer close(rdone)
		want := rendrtest.PRNG(g2Seed)
		exp, got := make([]byte, g2Msg), make([]byte, g2Msg)
		for k := range g2Echoes {
			if _, err := io.ReadFull(in.cli, got); err != nil {
				rerr = fmt.Errorf("echo %d: %w (loss)", k, err)
				return
			}
			want.Read(exp)
			if !bytes.Equal(got, exp) {
				rerr = fmt.Errorf("echo %d is not message %d (a lost, duplicated or reordered message)", k, k)
				return
			}
			lat = append(lat, time.Since(sent[k]))
		}
		if n, err := in.cli.Read(got); n != 0 || err != io.EOF {
			rerr = fmt.Errorf("after the last echo: %d bytes, %v; want io.EOF (a duplicate or a stray byte)", n, err)
		}
	}()

	deaths0 := in.c.Status().Migrations.Death
	kills := 0
	for at := g2Kill; at < g2Span; at += g2Kill {
		sleepUntil(start.Add(at))
		l, _ := w.activeLink(in.c, 10*time.Second)
		before := l.Stats().Session.Killed
		l.Kill()
		if l.Stats().Session.Killed == before {
			t.Fatalf("stimulus: the kill at +%v of %s ended no session carrier", at, l.Name())
		}
		kills++
	}
	select {
	case <-rdone:
	case <-time.After(time.Minute):
		t.Fatalf("the echoes did not end a minute after the last message: %d of %d", len(lat), g2Echoes)
	}
	<-wdone
	if werr != nil || rerr != nil {
		t.Fatalf("client: write %v, read %v", werr, rerr)
	}
	if int64(len(lat)) != g2Echoes {
		t.Fatalf("load: %d echoes, want %d", len(lat), g2Echoes)
	}
	res, err := in.result(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean || res.ToSession != g2Echoes*g2Msg || res.ToLocal != g2Echoes*g2Msg {
		t.Fatalf("ingress Forward %+v, want a clean end with every message both ways", res)
	}
	slices.Sort(lat)
	p99, p999 := lat[len(lat)*99/100], lat[len(lat)*999/1000]
	if p999 >= time.Second {
		t.Fatalf("echo latency P99.9 %v (P99 %v, max %v), want < 1 s", p999, p99, lat[len(lat)-1])
	}
	if d := in.c.Status().Migrations.Death - deaths0; d < uint64(kills) {
		t.Fatalf("the dialer counted %d death migrations for %d kills of the active carrier", d, kills)
	}
	waitFor(t, 10*time.Second, "both ends' EventSessionEnd", func() bool { return len(w.dev.ends()) > 0 && len(w.pev.ends()) > 0 })
	for i, l := range []*eventLog{w.dev, w.pev} {
		var n int
		for _, ev := range l.ends() {
			if ev.Session != in.c.ID() {
				t.Fatalf("the %s ended a session %v that is not the run's %v", side(i), ev.Session, in.c.ID())
			}
			if ev.Err != io.EOF {
				t.Fatalf("the %s's session ended with %v, want io.EOF (no idle expiry)", side(i), ev.Err)
			}
			n++
		}
		if n != 1 {
			t.Fatalf("the %s recorded %d EventSessionEnd for the session, want 1", side(i), n)
		}
	}
	waitFor(t, 10*time.Second, "the target connection closed", func() bool { return echo.Counts().Open == 0 })
	if c := echo.Counts(); c.Accepted != 1 || c.RSTIn+c.RSTOut != 0 || c.BytesIn != g2Echoes*g2Msg || c.Conns[0].SHAIn != c.Conns[0].SHAOut {
		t.Fatalf("target %+v; want one connection, no reset, every message echoed", totals(c))
	}
	t.Logf("%d echoes through %d kills: P50 %v, P99 %v, P99.9 %v, max %v; migrations %+v", len(lat), kills,
		lat[len(lat)/2], p99, p999, lat[len(lat)-1], in.c.Status().Migrations)
	in.cli.Close()
	w.noViolation()
	w.close()
}

// TestL4G4Miniature: gold/G4-l4 (B1.3; plan:746–751, plan:806; L27) at
// reduced scale: Links of 8 MiB/s; the client half-closes at once and
// reads 64 MiB (32 MiB under -race, R1-11) that the target generates.
//
// Stimulus: when the client has read 30 %, the Link carrying the
// session's data is blackholed in both directions until the end in
// BlackholeCloses mode (the gold's nft DROP: no RST crosses, so each end
// must reach its own verdict). The session's carrier there must have
// carried data, the Link must drop session bytes, and the carrier's close
// must be held by the blackhole.
//
// PASS: no client error and no early EOF; no zero-delivery interval at the
// client above 5 s from the DROP to the last byte; every byte verified,
// then io.EOF; the dropped carrier's death cause ping_timeout or
// write_stall on both ends (after the DROP); one target connection that
// saw no reset; a clean ingress Forward; nothing left after Runtime.Close.
func TestL4G4Miniature(t *testing.T) {
	size := int64(64 << 20)
	if raceEnabled {
		size = 32 << 20 // R1-11: the full rate on a shorter transfer
	}
	synctest.Test(t, func(t *testing.T) { g4(t, size, 8<<20) })
}

func g4(t *testing.T, size int64, rate float64) {
	const seed = 41
	w := newWorld(t, worldOpts{}, linkSpec{name: "p1", rate: rate}, linkSpec{name: "p2", rate: rate})
	gen := w.target("gen", rendrtest.TargetGen(size, seed))
	in := w.mustIngress(w.peer("p1", "p2"), "gen-1.test:80", rendr.DialOptions{}, 0)
	if err := in.cli.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	start := time.Now()
	rx := startReceiver(in.cli, seed, size)
	waitFor(t, time.Minute, "30 % of the bytes", func() bool { return rx.got.Load() >= size*3/10 })
	l, victim := w.activeLink(in.c, 10*time.Second)
	if victim.RxBytes == 0 {
		t.Fatalf("stimulus: the active carrier %d carried no data before the DROP: %+v", victim.ID, victim)
	}
	seq := dropTarget(t, l)
	dropped0 := l.Stats().Session.Dropped
	drop := time.Now()
	l.SetBlackholeMode(rendrtest.BlackholeCloses)
	l.SetBlackhole(true)

	rx.wait(t, 2*time.Minute)
	if l.Stats().Session.Dropped == dropped0 {
		t.Fatal("stimulus: the DROP dropped no session byte")
	}
	if gap, at := rx.maxGap(drop, rx.end()); gap > 5*time.Second {
		t.Fatalf("delivery stalled after the DROP: a zero-delivery gap of %v at DROP +%v, want ≤ 5 s", gap, at.Sub(drop))
	}
	droppedCause(t, w, victim.ID, drop)
	closeHeld(t, l, seq)
	res, err := in.result(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean || res.ToLocal != size {
		t.Fatalf("ingress Forward %+v, want a clean end with %d bytes to the client", res, size)
	}
	waitFor(t, 10*time.Second, "the target connection closed", func() bool { return gen.Counts().Open == 0 })
	if c := gen.Counts(); c.Accepted != 1 || c.RSTIn+c.RSTOut != 0 || c.BytesOut != size || c.FINOut != 1 {
		t.Fatalf("target %+v; want one connection, no reset, %d bytes and a FIN out", totals(c), size)
	}
	gap, _ := rx.maxGap(drop, rx.end())
	t.Logf("DROP of %s at +%v; longest gap after it %v; transfer %v", l.Name(), drop.Sub(start), gap, rx.end().Sub(start))
	in.cli.Close()
	w.noViolation()
	w.close()
}

// dropTarget returns the Seq of the link's one open session carrier just
// before the DROP: the trunk under the session's active carrier.
func dropTarget(t testing.TB, l *rendrtest.Link) int {
	t.Helper()
	seq := -1
	for _, ci := range l.Carriers() {
		if !ci.Session || ci.Closed {
			continue
		}
		if seq >= 0 {
			t.Fatalf("premise: open session carriers %d and %d on the link at the DROP, want one", seq, ci.Seq)
		}
		seq = ci.Seq
	}
	if seq < 0 {
		t.Fatalf("premise: no open session carrier on the link at the DROP: %+v", l.Carriers())
	}
	return seq
}

// closeHeld is the stimulus proof of BlackholeCloses: the close of the
// end that decided first did not cross the blackhole — the dropped
// carrier seq is held open (CloseHeld) while the link is still
// blackholed, so the other end's verdict is its own.
func closeHeld(t testing.TB, l *rendrtest.Link, seq int) {
	t.Helper()
	ci := l.Carriers()[seq]
	if !ci.CloseHeld || ci.Closed || l.Stats().Session.ClosesHeld < 1 {
		t.Fatalf("stimulus: the dropped carrier %+v (ClosesHeld %d), want its close held by the blackhole and the carrier still open",
			ci, l.Stats().Session.ClosesHeld)
	}
}

// droppedCause requires each end's death record of the blackholed carrier
// id with ping_timeout or write_stall, after the DROP — or, on the end
// whose peer reached its verdict first, peer_down after that verdict
// (PA-86: the first end's DOWN crosses on another trunk of the pair).
func droppedCause(t testing.TB, w *world, id rendr.CarrierID, drop time.Time) {
	t.Helper()
	var ends [2][]rendr.Event
	for i, l := range []*eventLog{w.dev, w.pev} {
		waitFor(t, 10*time.Second, side(i)+"'s death record of the dropped carrier", func() bool {
			ends[i] = l.downOf(id)
			return len(ends[i]) > 0
		})
	}
	silent := func(ev rendr.Event) bool {
		return (ev.Cause == rendr.CausePingTimeout || ev.Cause == rendr.CauseWriteStall) && !ev.Time.Before(drop)
	}
	for i, evs := range ends {
		other := ends[1-i][0]
		for _, ev := range evs {
			if !silent(ev) && !(ev.Cause == rendr.CausePeerDown && silent(other) && !ev.Time.Before(other.Time)) {
				t.Fatalf("the %s's death record of the dropped carrier %d: %+v at DROP %+v, want ping_timeout or write_stall after the DROP (or peer_down after the other end's)",
					side(i), id, ev, ev.Time.Sub(drop))
			}
		}
		t.Logf("%s: the dropped carrier %d dead with %v at DROP +%v", side(i), id, evs[0].Cause, evs[0].Time.Sub(drop))
	}
}
