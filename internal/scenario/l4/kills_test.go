package l4

import (
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The L4 connection through kills, rendr mux and race (M4 design §A12.2;
// M4-D42): Forward never sees a migration.

// echoConn is one forwarded echo exchange: a paced sender and a verified
// receiver on the client end of an ingress.
type echoConn struct {
	in   *ingress
	mode rendr.Mode
	seed uint64
	tx   *sender
	rx   *receiver
}

// startEcho starts sending size bytes of PRNG(seed) on in's client in
// 16-KiB Writes paced over span, half-closing at the end, and verifying
// the echo.
func startEcho(in *ingress, mode rendr.Mode, seed uint64, size int64, span time.Duration) *echoConn {
	const chunk = 16 << 10
	interval := time.Duration(int64(span) * chunk / size)
	return &echoConn{in: in, mode: mode, seed: seed,
		rx: startReceiver(in.cli, seed, size),
		tx: startSender(in.cli, in.quit, seed, size, chunk, interval, in.cli.CloseWrite)}
}

// finish waits for both directions and the ingress Forward's clean end.
func (e *echoConn) finish(t testing.TB, size int64) {
	t.Helper()
	if err := e.tx.check(2 * time.Minute); err != nil {
		t.Fatalf("%s (%v): client send: %v", e.in.addr, e.mode, err)
	}
	if err := e.rx.check(2 * time.Minute); err != nil {
		t.Fatalf("%s (%v): echo: %v", e.in.addr, e.mode, err)
	}
	res, err := e.in.result(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean || res.ToSession != size || res.ToLocal != size {
		t.Fatalf("%s (%v): ingress Forward %+v, want a clean end with %d bytes each way", e.in.addr, e.mode, res, size)
	}
}

// checkEchoTarget requires the echo target's connections to have read
// and echoed exactly the PRNG streams of seeds (in any order) with no
// reset, and to be closed.
func checkEchoTarget(t testing.TB, tg *rendrtest.Target, size int64, seeds ...uint64) {
	t.Helper()
	waitFor(t, 10*time.Second, "every target connection closed", func() bool { return tg.Counts().Open == 0 })
	c := tg.Counts()
	if c.Accepted != len(seeds) || c.RSTIn+c.RSTOut != 0 || c.FINIn != len(seeds) || c.FINOut != len(seeds) {
		t.Fatalf("target %+v; want %d connections, no reset, a FIN each way on each", totals(c), len(seeds))
	}
	want := map[[32]byte]int{}
	for _, s := range seeds {
		want[prngSum(s, size)]++
	}
	for i, cc := range c.Conns {
		if cc.BytesIn != size || cc.BytesOut != size || cc.SHAIn != cc.SHAOut || want[cc.SHAIn] == 0 {
			t.Fatalf("target connection %d (%s): %d bytes in, %d out, echo intact %v, a stream sent %v",
				i, cc.Addr, cc.BytesIn, cc.BytesOut, cc.SHAIn == cc.SHAOut, want[cc.SHAIn] > 0)
		}
		want[cc.SHAIn]--
	}
}

// TestL4EchoThroughKills_L10 (L10): a selector, a bond and a race L4
// session, each on a Peer of its own over two Links of its own (default
// Props), each echoing 16 MiB each way (4 MiB under -race, R1-11) through
// an ingress Forward and one echo target, paced over 10 s (Links of
// 8 MiB/s, 2 MiB/s under -race: above the offered load, also on one path).
//
// Stimulus: every 2 virtual s from +1 s, each session's data carrier is
// killed (Link.Kill of the Link under it): the selector's active carrier,
// the bond member whose dialer TxBytes grew in the last 100 ms (bond
// places demand-limited bytes on one member, L54), the race members in
// turn. Each kill must end a session carrier of that Link.
//
// PASS: every byte echoed intact both ways (the client's verifier and the
// target's per-connection SHA-256), then io.EOF; clean ingress Forwards;
// ≥ 3 death migrations on each session's dialer; Target.Accepted == 3
// and no reset; nothing left after Runtime.Close.
func TestL4EchoThroughKills_L10(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		size, rate := int64(16<<20), float64(8<<20)
		if raceEnabled {
			size, rate = 4<<20, 2<<20 // R1-11: the same 10-s timeline
		}
		const span = 10 * time.Second
		modes := []rendr.Mode{rendr.ModeSelector, rendr.ModeBond, rendr.ModeRace}
		var specs []linkSpec
		for _, m := range modes {
			for _, k := range []string{"1", "2"} {
				specs = append(specs, linkSpec{name: fmt.Sprintf("%v%s", m, k), rate: rate})
			}
		}
		w := newWorld(t, worldOpts{}, specs...)
		echo := w.target("echo", rendrtest.TargetEcho())
		var ins []*ingress
		for _, m := range modes {
			peer := w.peer(fmt.Sprintf("%v1", m), fmt.Sprintf("%v2", m))
			in := w.mustIngress(peer, fmt.Sprintf("echo-%v.test:80", m), rendr.DialOptions{Mode: m}, 0)
			if m != rendr.ModeSelector {
				waitFor(t, 10*time.Second, fmt.Sprintf("two %v members", m), func() bool { return len(liveOf(in.c.Status())) == 2 })
			}
			ins = append(ins, in)
		}
		deaths0 := make([]uint64, len(ins))
		for i, in := range ins {
			deaths0[i] = in.c.Status().Migrations.Death
		}
		start := time.Now()
		var es []*echoConn
		for i, in := range ins {
			es = append(es, startEcho(in, modes[i], uint64(100+i), size, span))
		}
		kills := 0
		for at := time.Second; at < span; at += 2 * time.Second {
			sleepUntil(start.Add(at - 100*time.Millisecond))
			before := make([]rendr.SessionStatus, len(ins))
			for i, in := range ins {
				before[i] = in.c.Status()
			}
			sleepUntil(start.Add(at))
			for i, in := range ins {
				cs, ok := dataCarrier(in.c.Status(), before[i], modes[i], kills)
				if !ok {
					t.Fatalf("kill %d: the %v session has no data carrier: %+v", kills, modes[i], in.c.Status().Carriers)
				}
				l := w.link(cs.Name)
				killed := l.Stats().Session.Killed
				l.Kill()
				if l.Stats().Session.Killed == killed {
					t.Fatalf("stimulus: kill %d of %s (the %v session's carrier %d) ended no session carrier", kills, cs.Name, modes[i], cs.ID)
				}
			}
			kills++
		}
		for _, e := range es {
			e.finish(t, size)
		}
		for i, in := range ins {
			st := in.c.Status()
			if d := st.Migrations.Death - deaths0[i]; d < 3 {
				t.Errorf("%v session: %d death migrations through %d kills, want ≥ 3: %+v", modes[i], d, kills, st.Migrations)
			}
			t.Logf("%v session: migrations %+v, rejoins %d, retransmitted %d B", modes[i], st.Migrations, st.Rejoins, st.RetransmittedBytes)
		}
		if t.Failed() {
			t.FailNow()
		}
		checkEchoTarget(t, echo, size, 100, 101, 102)
		for _, in := range ins {
			in.cli.Close()
		}
		w.noViolation()
		w.close()
	})
}

// dataCarrier picks the carrier under a session's data on the dialer:
// the selector's active carrier; the bond member whose TxBytes grew most
// since before (bond places demand-limited bytes on one member, L54); the
// race member of factory 1 on even kills, of factory 2 on odd ones (every
// race member carries every byte).
func dataCarrier(st, before rendr.SessionStatus, mode rendr.Mode, kill int) (rendr.CarrierStatus, bool) {
	switch mode {
	case rendr.ModeSelector:
		return active(st)
	case rendr.ModeRace:
		suffix := [2]string{"1", "2"}[kill%2]
		for _, cs := range liveOf(st) {
			if strings.HasSuffix(cs.Name, suffix) {
				return cs, true
			}
		}
		return rendr.CarrierStatus{}, false
	}
	var best rendr.CarrierStatus
	var grew uint64
	for _, cs := range liveOf(st) {
		var tx0 uint64
		if prev, ok := carrierOf(before, cs.ID); ok {
			tx0 = prev.TxBytes
		}
		if d := cs.TxBytes - tx0; d > grew {
			best, grew = cs, d
		}
	}
	return best, grew > 0
}

// TestL4MuxSharedTrunk (M3-D2; m3:R1-19): 8 selector L4 sessions on one
// Peer of two factories p1, p2 with default Props share one trunk — the
// carrier of p1 their data runs on (Shared 8 on all of them) — each
// echoing 4 MiB each way (1 MiB under -race) paced over 4 s.
//
// Stimulus: 2 s into the exchanges p1 is killed (the trunk and, with it,
// every session's active carrier); the kill must end a session carrier
// and every session must count a death migration.
//
// PASS: every echo intact both ways, then io.EOF, through clean ingress
// Forwards; 8 target connections, none reset; at most one session
// factory call per factory from the kill to the end of the exchanges (the
// sessions' redials coalesce, m3:R1-19); nothing left after
// Runtime.Close.
func TestL4MuxSharedTrunk(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		size := int64(4 << 20)
		if raceEnabled {
			size = 1 << 20
		}
		const n, span = 8, 4 * time.Second
		w := newWorld(t, worldOpts{}, linkSpec{name: "p1", rate: 16 << 20}, linkSpec{name: "p2", rate: 16 << 20})
		peer := w.peer("p1", "p2")
		echo := w.target("echo", rendrtest.TargetEcho())
		var ins []*ingress
		for i := range n {
			ins = append(ins, w.mustIngress(peer, fmt.Sprintf("echo-%d.test:80", i), rendr.DialOptions{}, 0))
		}
		var trunk rendr.CarrierID
		waitFor(t, 10*time.Second, "every session active on one trunk of p1 (Shared 8)", func() bool {
			trunk = 0
			for _, in := range ins {
				cs, ok := active(in.c.Status())
				if !ok || cs.Name != "p1" || cs.Shared != n || (trunk != 0 && cs.ID != trunk) {
					return false
				}
				trunk = cs.ID
			}
			return true
		})
		deaths0 := make([]uint64, n)
		for i, in := range ins {
			deaths0[i] = in.c.Status().Migrations.Death
		}
		start := time.Now()
		var es []*echoConn
		for i, in := range ins {
			es = append(es, startEcho(in, rendr.ModeSelector, uint64(200+i), size, span))
		}
		sleepUntil(start.Add(span / 2))
		for i, e := range es {
			if got := e.rx.got.Load(); got == 0 || got >= size {
				t.Fatalf("stimulus: session %d read %d of %d echo bytes at the kill, want mid-transfer", i, got, size)
			}
		}
		l := w.link("p1")
		before := l.Stats().Session.Killed
		kill := time.Now()
		l.Kill()
		if l.Stats().Session.Killed == before {
			t.Fatal("stimulus: the kill of p1 ended no session carrier")
		}
		for _, e := range es {
			e.finish(t, size)
		}
		end := time.Now()
		for i, in := range ins {
			if d := in.c.Status().Migrations.Death - deaths0[i]; d < 1 {
				t.Fatalf("stimulus: session %d counted no death migration for the kill of its trunk %d: %+v", i, trunk, in.c.Status())
			}
		}
		for _, f := range []string{"p1", "p2"} {
			if k := w.dialsIn(f, kill, end); k > 1 {
				t.Fatalf("%d session factory calls on %s from the kill to the end, want ≤ 1 (the redials coalesce, m3:R1-19)", k, f)
			}
		}
		seeds := make([]uint64, n)
		for i := range seeds {
			seeds[i] = uint64(200 + i)
		}
		checkEchoTarget(t, echo, size, seeds...)
		t.Logf("trunk %d killed at +%v; dials after it: p1 %d, p2 %d", trunk, kill.Sub(start), w.dialsIn("p1", kill, end), w.dialsIn("p2", kill, end))
		for _, in := range ins {
			in.cli.Close()
		}
		w.noViolation()
		w.close()
	})
}

// TestL4RaceMode (M3 interplay, T-1): one race L4 session on a Peer of two
// factories p1, p2 (Links of 8 MiB/s); the client half-closes at once and
// reads 32 MiB (8 MiB under -race) that the target generates over both
// members.
//
// Stimulus/load: both members are attached on the dialer before the
// target starts sending, and both carry the data (the dialer counts
// duplicate bytes: the race copies).
//
// PASS: every byte verified, then io.EOF; DupBytes > 0 on the receiving
// dialer; one target connection, no reset; a clean ingress Forward;
// nothing left after Runtime.Close.
func TestL4RaceMode(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		size := int64(32 << 20)
		if raceEnabled {
			size = 8 << 20
		}
		const seed = 61
		w := newWorld(t, worldOpts{}, linkSpec{name: "p1", rate: 8 << 20}, linkSpec{name: "p2", rate: 8 << 20})
		gen := w.target("gen", rendrtest.TargetHalf(size)) // sends after the client's FIN
		in := w.mustIngress(w.peer("p1", "p2"), "gen-1.test:80", rendr.DialOptions{Mode: rendr.ModeRace}, 0)
		waitFor(t, 10*time.Second, "two race members", func() bool { return len(liveOf(in.c.Status())) == 2 })
		rx := startReceiver(in.cli, 0, size) // TargetHalf sends PRNG(0)'s stream
		if err := in.cli.CloseWrite(); err != nil {
			t.Fatalf("client CloseWrite: %v", err)
		}
		rx.wait(t, 2*time.Minute)
		res, err := in.result(time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Clean || res.ToLocal != size {
			t.Fatalf("ingress Forward %+v, want a clean end with %d bytes to the client", res, size)
		}
		st := in.c.Status()
		if st.DupBytes == 0 || st.DeliveredBytes != uint64(size) {
			t.Fatalf("race: the dialer delivered %d bytes with %d duplicate bytes, want %d and duplicates > 0", st.DeliveredBytes, st.DupBytes, size)
		}
		for _, cs := range liveOf(st) {
			if cs.RxBytes == 0 {
				t.Fatalf("load: race member %d (%s) carried no byte: %+v", cs.ID, cs.Name, st.Carriers)
			}
		}
		waitFor(t, 10*time.Second, "the target connection closed", func() bool { return gen.Counts().Open == 0 })
		if c := gen.Counts(); c.Accepted != 1 || c.RSTIn+c.RSTOut != 0 || c.BytesOut != size || c.FINOut != 1 {
			t.Fatalf("target %+v; want one connection, no reset, %d bytes and a FIN out", totals(c), size)
		}
		t.Logf("%d MiB over race: %d duplicate bytes", size>>20, st.DupBytes)
		in.cli.Close()
		w.noViolation()
		w.close()
	})
}
