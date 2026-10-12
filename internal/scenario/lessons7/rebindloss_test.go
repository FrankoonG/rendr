package lessons7

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// G6's lost request at the NAT flush (run 20261011-234731, session
// ps18004): a peer-close packet echo on the raw-UDP NAT route got 15 of its
// 16 replies. The dialer sent 16 requests, the passive received and echoed
// 15, and every drop counter of both ends stayed 0; the session ran on a
// MUX trunk that existed before the conntrack flush, and the passive
// source's committed rebinds went from 0 to 2 in the sample interval
// holding the flush. A request that leaves after a flush is NATed anew,
// possibly on another port, so the passive reads it from a new address: a
// rebind candidate (M2-D27, R3-14). The question was whether rendr lets
// such a candidate's frames be consumed by the rebind decision without
// delivering or counting them.
//
// TestPacketRebindDeliversCandidate_L59 replays the echo in virtual time
// on G6's path (one-way 5 ms each way, natu's 10-ms RTT) over a
// DatagramHub — the passive on FromPacketConn, so the real udpflow Flow
// reads the candidates — with the move (Rebind: the client's later
// datagrams come from a new address, datagrams to the old one are lost)
// placed against the echo in every position G6's schedule allows:
//
//   - gap/beforeN: 16 requests at a 1-ms gap (PktChurn.EchoGap) with the
//     move half a millisecond before request N is written (N = 0: after
//     the open, before the first request; N = 16: after the last);
//   - burst/afterN: the 16 requests written in one instant, the move after
//     request N, so requests from both addresses wait in the flow's inbox
//     together (a foreign conn moves one datagram per call; the batched
//     read that meets a candidate among them is pinned by
//     TestFlowReadDatagramsOrder, TestFlowReadDatagramsEndsAtCandidate_L55
//     and TestDgramBatchRebindSame_L55/flow, which deliver its DGRAM);
//   - double: two moves a millisecond apart, the second while the
//     challenge to the first is in flight;
//   - open: the move on the idle trunk right before the echo session's
//     Dial, so its OPEN rides a candidate (the passive's OPEN_ACK to the
//     old address is lost and repeated after the commit: the dialer's view
//     comes up about 200 ms late, as G6's views on this trunk did);
//   - flush: G6's order — the move on a trunk whose older session carries
//     passive→dialer traffic (the passive writes to the old address first,
//     as B did after the flush), the echo session opened 250 ms later on
//     the rebound trunk (ps18004 opened 248 ms after the flush).
//
// What each case proves:
//
//   - Stimulus: the hub moved the client, the passive committed the
//     rebind on the same carrier (Rebinds on the carrier and the Runtime),
//     and — wherever a request follows the move — the passive read a
//     datagram holding a DGRAM from the new address before the commit:
//     a request rode a candidate.
//   - Requests (the claim): every request is delivered exactly once —
//     the passive read all 16 intact, its Received is 16 and the dialer's
//     PeerReceived equals its Sent, with every drop counter 0 and no
//     duplicate. A candidate's frames pass the same frame checks as any
//     other datagram's and are dispatched; the rebind decision consumes
//     nothing.
//   - Replies (the accounting, m2 B1.0): the move costs only what the
//     passive wrote to the old address — every lost reply was written no
//     earlier than one one-way delay before the move and no later than the
//     commit (the passive's read of the challenge answer from the new
//     address, after which it writes nothing to the old one); on the final
//     counters after Done the loss is counted exactly in the passive's
//     Sent − PeerReceived, the dialer's Sent equals its PeerReceived and
//     its Received the passive's PeerReceived.
//   - No carrier changed: no carrier went down, no migration, no protocol
//     violation; both ends finish cleanly and leave nothing.
//
// A move during an echo costs the replies written before the commit (10
// to 16 of 16 here); ps18004 lost none of the 15 replies
// the passive wrote (passive Sent 15 = PeerReceived 15), so its reply
// address was valid for every reply and no move was pending while it
// echoed — and the request that a move would make a candidate is
// delivered. The request was lost before it reached the passive's
// process: in the network between the dialer's socket and B's.
//
// Mutants: a candidate's DGRAM frames skipped (dgFrames); a candidate
// datagram handed to the rebind decision only; a candidate dropped by the
// flow's one-datagram ReadDatagrams. Each fails gap/before0 … before15 and
// burst (TestPacketNatRebind_L59 also catches them). A candidate dropped
// from a batched ReadDatagrams after other results is TestFlowReadDatagramsOrder's.
func TestPacketRebindDeliversCandidate_L59(t *testing.T) {
	var cases []rlCase
	for n := 0; n <= rlRequests; n++ {
		cases = append(cases, rlCase{name: fmt.Sprintf("gap/before%d", n), gap: rlGap, moves: []int{n}})
	}
	for _, n := range []int{0, 7, 14} {
		cases = append(cases, rlCase{name: fmt.Sprintf("burst/after%d", n), moves: []int{n + 1}})
	}
	cases = append(cases,
		rlCase{name: "double", gap: rlGap, moves: []int{4, 5}},
		rlCase{name: "open", gap: rlGap, open: true},
		rlCase{name: "flush", gap: rlGap, flush: 250 * time.Millisecond})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { rebindEcho(t, c) })
		})
	}
}

// Schedule of the rows: G6's natu path and pkt-echo churn session.
const (
	rlOneWay   = 5 * time.Millisecond // natu: RTT 10 ms
	rlGap      = time.Millisecond     // PktChurn.EchoGap
	rlRequests = 16                   // PktChurn.EchoCount
	rlSize     = 1024                 // PktChurn.EchoSize
	rlSeed     = 0x5eb1
	rlSettle   = 3 * time.Second // the trunk is quiet again
)

// rlCase places the NAT move against the echo.
type rlCase struct {
	name string
	gap  time.Duration // between requests (0: a burst in one instant)
	// moves: a Rebind before request n is written (half a gap before it
	// with a gap; between WriteTo calls in a burst); n = rlRequests: after
	// the last request.
	moves []int
	open  bool          // the move right before the echo session's Dial
	flush time.Duration // > 0: the move on a trunk with passive→dialer traffic, the echo opened this long after it
}

func rebindEcho(t *testing.T, c rlCase) {
	w := newWorld(t, worldOpts{hubUp: rlOneWay, hubDown: rlOneWay})
	p := w.peer(w.hubCarrier("u1", 0))
	// The trunk exists before the move, as G6's did: an older session
	// keeps it (idle, or with passive→dialer traffic in the flush order).
	hd, hp := w.open(p, rendr.DialOptions{})
	time.Sleep(time.Second)
	var hold *flow
	if c.flush > 0 {
		hold = startFlow(hp, hd, 0x401d, 10*time.Millisecond)
		time.Sleep(time.Second)
	}
	reads, _ := w.tap.snapshot()
	if len(reads) == 0 {
		t.Fatal("the passive read nothing before the move")
	}
	oldAddr := reads[len(reads)-1].addr
	var moved []time.Time
	move := func() {
		moved = append(moved, time.Now())
		w.hub.Rebind(0)
	}
	if c.open || c.flush > 0 {
		move()
		time.Sleep(c.flush)
	}
	dc, pc := w.open(p, rendr.DialOptions{})
	opened := time.Now()
	dcar := oneLive(t, "dialer", dc)
	pcar := oneLive(t, "passive", pc)
	if c.flush > 0 {
		// G6's order: the trunk's rebind committed before the echo opened.
		if r := w.p.Status().Datagram.Rebinds; r != 1 {
			t.Fatalf("stimulus: %d rebinds committed %v after the move, want 1 before the echo opens", r, c.flush)
		}
	}

	// The passive's echo: every request read, verified and written back,
	// with the time each reply was handed to WriteTo.
	reqs := rendrtest.NewPacketVerifier(rlSeed)
	var mu sync.Mutex
	replied := map[uint64]time.Time{}
	edone := make(chan error, 1)
	go func() {
		buf := make([]byte, pc.MaxPayload()+1)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				edone <- err
				return
			}
			if verr := reqs.Add(buf[:n], time.Now()); verr != nil {
				edone <- verr
				return
			}
			if _, err := pc.WriteTo(buf[:n], nil); err != nil {
				edone <- fmt.Errorf("WriteTo of reply %d: %w", seqOf(buf), err)
				return
			}
			mu.Lock()
			replied[seqOf(buf)] = time.Now()
			mu.Unlock()
		}
	}()
	// The dialer's reader: replies verified, recorded by seq.
	reps := rendrtest.NewPacketVerifier(rlSeed)
	got := map[uint64]bool{}
	rdone := make(chan error, 1)
	go func() {
		buf := make([]byte, dc.MaxPayload()+1)
		for {
			n, _, err := dc.ReadFrom(buf)
			if err != nil {
				rdone <- err
				return
			}
			if verr := reps.Add(buf[:n], time.Now()); verr != nil {
				rdone <- verr
				return
			}
			mu.Lock()
			got[seqOf(buf)] = true
			mu.Unlock()
		}
	}()

	// The requests, with the moves placed among them.
	buf := make([]byte, rlSize)
	at := func(n int) time.Time { return opened.Add(time.Duration(n) * c.gap) }
	mi := 0
	for seq := range rlRequests + 1 {
		for mi < len(c.moves) && c.moves[mi] == seq {
			if c.gap > 0 {
				sleepTo(at(seq).Add(-c.gap / 2))
			}
			move()
			mi++
		}
		if seq == rlRequests {
			break
		}
		sleepTo(at(seq))
		if _, err := dc.WriteTo(rendrtest.PacketPayload(buf, rlSeed, uint64(seq), rlSize, time.Now()), nil); err != nil {
			t.Fatalf("WriteTo of request %d: %v", seq, err)
		}
	}
	time.Sleep(rlSettle)

	// Stimulus: every move happened, the passive committed the rebind on
	// the same carrier, and a request rode a candidate wherever one
	// followed the move.
	if s := w.hub.Stats(); s.Rebinds != uint64(len(moved)) {
		t.Fatalf("stimulus: the hub moved the client %d times, want %d", s.Rebinds, len(moved))
	}
	reads, writes := w.tap.snapshot()
	final := reads[len(reads)-1].addr
	if final == oldAddr {
		t.Fatalf("stimulus: the passive still reads the trunk from its old address %v", oldAddr)
	}
	// The commit: the passive's read of the challenge answer (a PONG with
	// id 0) from the new address; from then on it writes nothing to the
	// old one.
	commitAt := time.Time{}
	for _, d := range reads {
		if !d.at.Before(moved[len(moved)-1]) && d.addr == final && len(d.frames) > 0 && d.frames[0].typ == wire.TypePong && d.frames[0].id == 0 {
			commitAt = d.at
			break
		}
	}
	if commitAt.IsZero() {
		t.Fatalf("stimulus: the passive read no challenge answer from the new address %v after the move", final)
	}
	if late := writesWith(writes, commitAt.Add(time.Nanosecond), func(d tapDgram) bool { return d.addr != final }); len(late) != 0 {
		t.Fatalf("after the commit at %v the passive wrote %v to %v", commitAt.Sub(opened), late[0].types(), late[0].addr)
	}
	if r := w.p.Status().Datagram.Rebinds; r < 1 || r > uint64(len(moved)) {
		t.Fatalf("stimulus: %d rebinds committed for %d moves", r, len(moved))
	}
	if pc2, ok := carrierOf(pc.Status(), pcar.ID); !ok || pc2.Rebinds < 1 {
		t.Fatalf("stimulus: the session's carrier committed no rebind: %+v", pc.Status().Carriers)
	}
	if c.open && !openOnCandidate(reads, moved[0], commitAt, oldAddr) {
		t.Fatal("stimulus: the passive read no OPEN from the new address between the move and the commit")
	}
	if c.moves != nil && c.moves[0] < rlRequests {
		if !requestOnCandidate(reads, moved[0], commitAt, oldAddr) {
			t.Fatalf("stimulus: no datagram holding a DGRAM was read from a new address between the move (%v) and the commit (%v)",
				moved[0].Sub(opened), commitAt.Sub(opened))
		}
	}

	// Requests: all 16 delivered once, nothing dropped.
	ds, ps := dc.Status().Packet, pc.Status().Packet
	rq := reqs.Result()
	if rq.Unique != rlRequests || rq.Duplicates+rq.Corrupt+rq.BadSize != 0 || ps.Received != rlRequests || ds.Sent != rlRequests {
		t.Fatalf("requests: the passive read %+v, Received %d; the dialer Sent %d; want all %d once",
			rq, ps.Received, ds.Sent, rlRequests)
	}
	if drops(ds)+drops(ps)+ds.DropRecvQueue+ds.DropLate+ps.DropRecvQueue+ps.DropLate+ds.Duplicates+ps.Duplicates != 0 {
		t.Fatalf("drop or duplicate counters moved: dialer %+v, passive %+v", ds, ps)
	}

	// Replies: lost only when written to the old address before the commit.
	mu.Lock()
	lost := 0
	for seq, wrote := range replied {
		if got[seq] {
			continue
		}
		lost++
		if wrote.Before(moved[0].Add(-rlOneWay)) || wrote.After(commitAt) {
			mu.Unlock()
			t.Fatalf("reply %d written %v after the open was lost; the move was at %v, the commit at %v",
				seq, wrote.Sub(opened), moved[0].Sub(opened), commitAt.Sub(opened))
		}
	}
	nrep := len(replied)
	mu.Unlock()
	rp := reps.Result()
	if nrep != rlRequests || ps.Sent != rlRequests || rp.Duplicates+rp.Corrupt+rp.BadSize != 0 || ds.Received != uint64(nrep-lost) {
		t.Fatalf("replies: %d written, %d lost, dialer %+v, verifier %+v", nrep, lost, ds, rp)
	}
	if c.flush > 0 && lost != 0 {
		t.Fatalf("flush order: %d replies lost although the rebind committed before the echo opened", lost)
	}

	// The same carrier on both ends throughout.
	if l := liveOf(dc.Status()); len(l) != 1 || l[0].ID != dcar.ID {
		t.Fatalf("the dialer's carriers changed: %+v", dc.Status().Carriers)
	}
	if l := liveOf(pc.Status()); len(l) != 1 || l[0].ID != pcar.ID {
		t.Fatalf("the passive's carriers changed: %+v", pc.Status().Carriers)
	}
	if m := dc.Status().Migrations; m != (rendr.MigrationCounts{}) || len(w.dev.of(rendr.EventCarrierDown))+len(w.pev.of(rendr.EventCarrierDown)) != 0 {
		t.Fatalf("the session changed carriers: migrations %+v, carrier-down events %d/%d",
			m, len(w.dev.of(rendr.EventCarrierDown)), len(w.pev.of(rendr.EventCarrierDown)))
	}
	w.noViolation()

	// The older session's traffic lost only what the passive wrote to the
	// old address.
	if hold != nil {
		hold.halt(t, "holder")
		time.Sleep(time.Second)
		if in, out := hold.lostIn([2]time.Time{moved[0].Add(-rlOneWay), commitAt}); len(out) != 0 || len(in) == 0 {
			t.Fatalf("holder: lost %v at the move and %v elsewhere; want a loss at the move only", in, out)
		}
	}

	// Clean ends.
	dc.Close()
	if err := <-edone; !errors.Is(err, io.EOF) {
		t.Fatalf("the passive's echo ended with %v, want io.EOF", err)
	}
	pc.Close()
	if err := <-rdone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("the dialer's reader ended with %v, want net.ErrClosed", err)
	}
	hd.Close()
	if hold != nil {
		hold.waitReader(t, 10*time.Second, net.ErrClosed, "holder passive → dialer")
	}
	hp.Close()
	waitDone(t, 10*time.Second, dc, pc, hd, hp)

	// The final accounting (m2 B1.0; G6 reads these counters after Done):
	// the dialer's Sent − PeerReceived is 0 — no request in flight was
	// lost — and the replies lost to the old address are exactly the
	// passive's Sent − PeerReceived. Mid-session a bare PACK the passive
	// wrote to the old address is not repeated (latest wins, M2-D39); the
	// reliable end PACKs carry the final values.
	ds, ps = dc.Status().Packet, pc.Status().Packet
	if ds.Sent != rlRequests || ds.PeerReceived != ds.Sent || ps.Received != rlRequests ||
		ps.Sent-ps.PeerReceived != uint64(lost) || ds.Received != ps.PeerReceived {
		t.Fatalf("final accounting: dialer %+v, passive %+v, %d replies lost; want the dialer's Sent = PeerReceived and the loss exactly in the passive's Sent − PeerReceived",
			ds, ps, lost)
	}
	if drops(ds)+drops(ps)+ds.DropRecvQueue+ds.DropLate+ps.DropRecvQueue+ps.DropLate+ds.Duplicates+ps.Duplicates != 0 {
		t.Fatalf("final: drop or duplicate counters moved: dialer %+v, passive %+v", ds, ps)
	}
	t.Logf("%s: moves at %v, commit at %v after the open; requests %d of %d; replies lost %d (passive Sent − PeerReceived %d)",
		c.name, sinceAll(moved, opened), commitAt.Sub(opened), ps.Received, ds.Sent, lost, ps.Sent-ps.PeerReceived)
	w.close()
}

// requestOnCandidate reports whether reads hold a datagram with a DGRAM
// frame from an address other than old, read in [from, to].
func requestOnCandidate(reads []tapDgram, from, to time.Time, old netip.AddrPort) bool {
	for _, d := range reads {
		if d.at.Before(from) || d.at.After(to) || d.addr == old {
			continue
		}
		for _, f := range d.frames {
			if f.typ == wire.TypeDgram {
				return true
			}
		}
	}
	return false
}

// openOnCandidate reports whether reads hold a REL(OPEN) from an address
// other than old, read in [from, to].
func openOnCandidate(reads []tapDgram, from, to time.Time, old netip.AddrPort) bool {
	for _, d := range reads {
		if d.at.Before(from) || d.at.After(to) || d.addr == old {
			continue
		}
		for _, f := range d.frames {
			if f.typ == wire.TypeRel && f.inner == wire.TypeOpen {
				return true
			}
		}
	}
	return false
}

// sinceAll returns each time's offset from base.
func sinceAll(ts []time.Time, base time.Time) []time.Duration {
	out := make([]time.Duration, len(ts))
	for i, t := range ts {
		out[i] = t.Sub(base)
	}
	return out
}

// sleepTo sleeps until at (no-op when it passed).
func sleepTo(at time.Time) {
	if d := time.Until(at); d > 0 {
		time.Sleep(d)
	}
}

// seqOf returns a test datagram's seq (its first 8 bytes, big-endian).
func seqOf(b []byte) uint64 {
	var s uint64
	for _, c := range b[:8] {
		s = s<<8 | uint64(c)
	}
	return s
}
