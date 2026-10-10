package session

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// WP3 (M3 design §A6.2–§A6.7, §A11.1): the stream race data plane — the
// per-lane cursors over the one send ring, the receiver's duplicate rules,
// the ACK duty on the fastest lane (a copy on every member) and the unique
// accounting. Sessions and lanes are the stream harness's (fake ports, Fill
// and delivery by hand);
// membership is set up as bond's (every lane a data member, M3-D29), which
// WP4 wires into the actor. Helpers start with "rc".

// rcRaceLanes makes every lane of s a race data member (state member, no
// selector active lane), as bond membership does, with its cursors started
// as at its attach. Tests call it right after adding the lanes.
func rcRaceLanes(s *Session) {
	for _, l := range s.lanes {
		rcRaceLane(s, l)
	}
}

// rcRaceLane makes l a race data member and starts its cursors.
func rcRaceLane(s *Session, l *lane) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctl.active == l {
		s.ctl.active = nil
	}
	l.data = true
	l.state = LaneMember
	s.raceAttachLocked(l)
}

// rcSender is a race dialer whose peer advertised a 1 GiB window.
func rcSender(o stOpt) *Session {
	o.mode = ModeRace
	s := stSession(o)
	s.mu.Lock()
	s.peerWindowLocked(1 << 30)
	s.mu.Unlock()
	return s
}

// rcPair is a race dialer and a race passive joined by links lanes, every
// lane a data member on both sides.
func rcPair(links int, ao, bo stOpt) *stPair {
	ao.mode, bo.mode = ModeRace, ModeRace
	p := stNewPair(ao, bo, links)
	rcRaceLanes(p.a)
	rcRaceLanes(p.b)
	return p
}

// rcWrite writes data on s (the test goroutine; the window must hold it).
func rcWrite(t *testing.T, s *Session, data []byte) {
	t.Helper()
	if n, err := s.Write(data); n != len(data) || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
}

// rcDataSpan returns the first offset and the bytes of the DATA frames in
// fs (first = ^0 when none).
func rcDataSpan(fs []stFrame) (first uint64, n int) {
	first = ^uint64(0)
	for _, f := range fs {
		if f.typ == wire.TypeData {
			first = min(first, f.off)
			n += f.n
		}
	}
	return first, n
}

// rcStream returns (sBase, sNext, copyBytes, retxBytes) of s.
func rcStream(s *Session) [4]uint64 {
	return stLocked(s, func(st *stream) [4]uint64 { return [4]uint64{st.sBase, st.sNext, st.copyBytes, st.retxBytes} })
}

// TestRaceStreamCursor_L10: every data lane sends from its own cursor; an
// ACK moves the acknowledged front and a lane behind it resumes there; sNext
// is the furthest cursor; a lane attached later starts at sBase (L10's
// replay from the ACK point), not at sNext.
func TestRaceStreamCursor_L10(t *testing.T) {
	s := rcSender(stOpt{window: 4 << 20})
	a, _ := stAddLane(s, 1, true)
	b, _ := stAddLane(s, 2, true)
	rcRaceLanes(s)
	rcWrite(t, s, stPattern(0, 256<<10))

	fa, ba := stFill(a, time.Now())
	ba.ReleaseRefs()
	if first, n := rcDataSpan(fa); first != 0 || n != 256<<10 {
		t.Fatalf("lane a sent %d bytes from %d, want 256 KiB from 0", n, first)
	}
	if v := rcStream(s); v[1] != 256<<10 || v[2] != 0 {
		t.Fatalf("after a: sNext %d copies %d, want 256 KiB and 0", v[1], v[2])
	}
	// b still sends from its own cursor (0): copies of what a placed.
	fb, bb := stFill(b, time.Now())
	bb.ReleaseRefs()
	if first, n := rcDataSpan(fb); first != 0 || n != 256<<10 {
		t.Fatalf("lane b sent %d bytes from %d, want its own copy of 256 KiB from 0", n, first)
	}
	if v := rcStream(s); v[1] != 256<<10 || v[2] != 256<<10 {
		t.Fatalf("after b: sNext %d copies %d, want 256 KiB both", v[1], v[2])
	}

	// More data; a sends it, then the peer acknowledges 300 KiB on a: b's
	// cursor (256 KiB) jumps to the ACK edge.
	rcWrite(t, s, stPattern(256<<10, 256<<10))
	fa, ba = stFill(a, time.Now())
	ba.ReleaseRefs()
	if first, n := rcDataSpan(fa); first != 256<<10 || n != 256<<10 {
		t.Fatalf("lane a resumed at %d with %d bytes, want 256 KiB at 256 KiB", first, n)
	}
	if err := stSendAck(a, 0, 300<<10, 4<<20); err != nil {
		t.Fatal(err)
	}
	fb, bb = stFill(b, time.Now())
	bb.ReleaseRefs()
	if first, n := rcDataSpan(fb); first != 300<<10 || n != 212<<10 {
		t.Fatalf("lane b sent %d bytes from %d after the ACK, want 212 KiB from 300 KiB", n, first)
	}
	if v := rcStream(s); v[0] != 300<<10 || v[1] != 512<<10 {
		t.Fatalf("sBase %d sNext %d, want 300 KiB and 512 KiB (the furthest cursor)", v[0], v[1])
	}

	// A lane attached now starts at the ACK point and carries everything
	// unacknowledged.
	c, _ := stAddLane(s, 3, true)
	rcRaceLane(s, c)
	if got := stLocked(s, func(*stream) uint64 { return c.rnext }); got != 300<<10 {
		t.Fatalf("new lane's cursor %d, want sBase 300 KiB", got)
	}
	fc, bc := stFill(c, time.Now())
	bc.ReleaseRefs()
	if first, n := rcDataSpan(fc); first != 300<<10 || n != 212<<10 {
		t.Fatalf("new lane sent %d bytes from %d, want 212 KiB from sBase", n, first)
	}
	stEnd(s, errClosed)
}

// TestRaceSlowLaneSkipsDelivered_L08: a slow member (small capacity) never
// drags the fast one and never resends what the peer already delivered: once
// the fast member's ACK moved sBase past the slow member's cursor, the slow
// member's next DATA starts at sBase (M3-D30's clamp).
func TestRaceSlowLaneSkipsDelivered_L08(t *testing.T) {
	p := rcPair(2, stOpt{window: 4 << 20}, stOpt{window: 4 << 20})
	p.ap[1].set(func(f *stPort) { f.capacity = 16 << 10 })
	data := stPattern(0, 512<<10)
	rcWrite(t, p.a, data)

	// The slow lane (1) places one segment within its 16 KiB capacity (a
	// segment is never cut for the cap); the fast lane (0) everything.
	if n, _ := p.step(1, true, time.Now()); n == 0 {
		t.Fatal("the slow lane placed nothing")
	}
	slowAt := stLocked(p.a, func(*stream) uint64 { return p.al[1].rnext })
	if slowAt == 0 || slowAt >= 128<<10 {
		t.Fatalf("slow cursor %d, want one segment", slowAt)
	}
	for range 4 {
		p.step(0, true, time.Now())
	}
	// The receiver reads everything and acknowledges on the fast lane.
	got := stReadN(t, p.b, len(data))
	if !bytes.Equal(got, data) {
		t.Fatal("integrity: the bytes read differ")
	}
	p.step(0, false, time.Now())
	if v := rcStream(p.a); v[0] != 512<<10 {
		t.Fatalf("sBase %d after the ACK, want 512 KiB", v[0])
	}
	// The slow lane's capacity frees; it has nothing left to send.
	p.ap[1].set(func(f *stPort) { f.capacity = 1 << 30 })
	fs, b := stFill(p.al[1], time.Now())
	b.ReleaseRefs()
	if first, n := rcDataSpan(fs); n != 0 {
		t.Fatalf("the slow lane resent %d delivered bytes from %d", n, first)
	}
	// New bytes: it starts at sBase, not at its old cursor.
	rcWrite(t, p.a, stPattern(512<<10, 64<<10))
	fs, b = stFill(p.al[1], time.Now())
	b.ReleaseRefs()
	if first, n := rcDataSpan(fs); first != 512<<10 || n != 64<<10 {
		t.Fatalf("the slow lane sent %d bytes from %d, want 64 KiB from 512 KiB", n, first)
	}
	p.close(t)
}

// rcRecv is a race (or bond) receiver with two confirmed lanes.
func rcRecv(mode Mode) (*Session, *lane, *lane) {
	s := stSession(stOpt{role: RolePassive, mode: mode, window: 1 << 20})
	l1, _ := stAddLane(s, 1, true)
	l2, _ := stAddLane(s, 2, true)
	if mode == ModeRace {
		rcRaceLanes(s)
	}
	return s, l1, l2
}

// TestRaceDupNoImmediateAck: a race receiver gets every byte once per
// member; the second copy is counted (DupBytes) and dropped without an
// immediate ACK — the delivery cadence covers the first copy (M3-D31). A
// bond receiver still answers a whole duplicate at once (its sender may
// have missed an ACK).
func TestRaceDupNoImmediateAck(t *testing.T) {
	for _, mode := range []Mode{ModeRace, ModeBond} {
		s, l1, l2 := rcRecv(mode)
		d := stPattern(0, 32<<10)
		if err := stDeliverData(l1, 0, d); err != nil {
			t.Fatal(err)
		}
		gen := stLocked(s, func(st *stream) uint64 { return st.ackGen })
		if err := stDeliverData(l2, 0, d); err != nil {
			t.Fatal(err)
		}
		gen2, dup := stLocked(s, func(st *stream) uint64 { return st.ackGen }), stLocked(s, func(st *stream) uint64 { return st.dupBytes })
		if dup != 32<<10 {
			t.Fatalf("%v: DupBytes %d, want 32 KiB", mode, dup)
		}
		if mode == ModeRace && gen2 != gen {
			t.Fatalf("race: the duplicate bumped an ACK (ackGen %d → %d)", gen, gen2)
		}
		if mode == ModeBond && gen2 == gen {
			t.Fatal("bond: a whole duplicate must still bump an immediate ACK")
		}
		if got := s.Status().DupBytes; got != 32<<10 {
			t.Fatalf("%v: Status.DupBytes %d", mode, got)
		}
		stEnd(s, errClosed)
	}
}

// TestRaceConflictKillsSecond_L13: a copy that differs in one byte from
// bytes this side still holds — unread in order, or held out of order — is
// a violation of the delivering carrier (race copy mismatch); the stream
// keeps the first copy and reads it intact.
func TestRaceConflictKillsSecond_L13(t *testing.T) {
	s, l1, l2 := rcRecv(ModeRace)
	d := stPattern(0, 48<<10)
	if err := stDeliverData(l1, 0, d[:16<<10]); err != nil {
		t.Fatal(err)
	}
	if err := stDeliverData(l1, 32<<10, d[32<<10:]); err != nil { // held out of order
		t.Fatal(err)
	}
	for _, at := range []int{100, 40 << 10} { // in order (unread), out of order
		bad := bytes.Clone(d)
		bad[at] ^= 0x10
		err := stDeliverData(l2, 0, bad)
		if !errors.Is(err, errRaceMismatch) {
			t.Fatalf("flip at %d: Data = %v, want the race copy mismatch", at, err)
		}
	}
	// The missing middle arrives intact; the stream reads the first copy.
	if err := stDeliverData(l1, 16<<10, d[16<<10:32<<10]); err != nil {
		t.Fatal(err)
	}
	if got := stReadN(t, s, len(d)); !bytes.Equal(got, d) {
		t.Fatal("integrity: the stream did not keep the first copy")
	}
	stEnd(s, errClosed)
}

// TestRaceCopyAfterDeliveryDropped_L13: a copy of bytes the application
// already read is dropped uncompared and counted (no history is kept,
// PA-35): even a flipped one is no violation, and nothing changes.
func TestRaceCopyAfterDeliveryDropped_L13(t *testing.T) {
	s, l1, l2 := rcRecv(ModeRace)
	d := stPattern(0, 32<<10)
	if err := stDeliverData(l1, 0, d); err != nil {
		t.Fatal(err)
	}
	if got := stReadN(t, s, len(d)); !bytes.Equal(got, d) {
		t.Fatal("integrity")
	}
	bad := bytes.Clone(d)
	bad[7] ^= 1
	if err := stDeliverData(l2, 0, bad); err != nil {
		t.Fatalf("a copy of read bytes: %v, want dropped", err)
	}
	st := s.Status()
	if st.DupBytes != 32<<10 || st.DeliveredBytes != 32<<10 || st.RxBytes != 32<<10 {
		t.Fatalf("Dup %d Delivered %d Rx %d, want 32 KiB each", st.DupBytes, st.DeliveredBytes, st.RxBytes)
	}
	stEnd(s, errClosed)
}

// rcPumpCount pumps p link by link until nothing moves and returns the
// DATA bytes each of a's lanes placed.
func rcPumpCount(p *stPair) []int {
	out := make([]int, len(p.al))
	for {
		moved := 0
		for i := range p.al {
			for _, aToB := range []bool{true, false} {
				before := len(p.traceAB)
				n, _ := p.step(i, aToB, time.Now())
				moved += n
				if aToB {
					_, k := rcDataSpan(p.traceAB[before:])
					out[i] += k
				}
			}
		}
		if moved == 0 {
			return out
		}
	}
}

// TestRaceUniqueAccounting_L35: 32 KiB over two members, both copies
// delivered: the session counters count unique bytes (TxBytes, AckedBytes,
// RxBytes, DeliveredBytes = 32 KiB), the extra is the sender's
// Race.CopyBytes and the receiver's DupBytes (32 KiB each), every carrier
// carried its own 32 KiB, RetransmittedBytes stays 0, and the same
// delivered value acknowledged on both lanes changes nothing.
func TestRaceUniqueAccounting_L35(t *testing.T) {
	p := rcPair(2, stOpt{}, stOpt{})
	data := stPattern(0, 32<<10)
	rcWrite(t, p.a, data)
	per := rcPumpCount(p)
	if got := stReadN(t, p.b, len(data)); !bytes.Equal(got, data) {
		t.Fatal("integrity")
	}
	p.pump(true)
	if per[0] != 32<<10 || per[1] != 32<<10 {
		t.Fatalf("carrier DATA bytes %v, want 32 KiB on each (physical copies)", per)
	}
	sa, sb := p.a.Status(), p.b.Status()
	if sa.TxBytes != 32<<10 || sa.AckedBytes != 32<<10 || sa.RetransmittedBytes != 0 || sa.Race.CopyBytes != 32<<10 {
		t.Fatalf("sender: Tx %d Acked %d Retx %d CopyBytes %d", sa.TxBytes, sa.AckedBytes, sa.RetransmittedBytes, sa.Race.CopyBytes)
	}
	if sb.RxBytes != 32<<10 || sb.DeliveredBytes != 32<<10 || sb.DupBytes != 32<<10 {
		t.Fatalf("receiver: Rx %d Delivered %d Dup %d", sb.RxBytes, sb.DeliveredBytes, sb.DupBytes)
	}
	// Each lane carries the ACK of the same delivered value: nothing moves.
	for _, l := range p.al {
		if err := stSendAck(l, 0, 32<<10, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	if sa2 := p.a.Status(); sa2.AckedBytes != sa.AckedBytes || sa2.TxBytes != sa.TxBytes || sa2.Race != sa.Race {
		t.Fatalf("a repeated ACK changed the counters: %+v → %+v", sa, sa2)
	}
	p.close(t)
}

// TestRaceBondAccountingProperty_L35: over random member counts, write
// patterns, capacity limits and payload quotas (copies cut at other
// boundaries than the first copy's), the receiver's unique delivered bytes are
// exactly the first deliveries — the sum over members of the bytes each
// delivered first — for race and bond alike; the payload beyond the unique
// bytes is the receiver's DupBytes, which equals the race sender's
// CopyBytes when every copy arrives, and is 0 in bond; no member and no
// counter ever exceeds the application's written bytes.
func TestRaceBondAccountingProperty_L35(t *testing.T) {
	// midFront counts, per mode, the acknowledgements between two members'
	// Fills that moved the sender's acknowledged front (stimulus).
	midFront := map[Mode]int{}
	for seed := range uint64(40) {
		rng := rand.New(rand.NewPCG(seed, 7))
		mode := ModeRace
		if seed%2 == 1 {
			mode = ModeBond
		}
		links := 2 + rng.IntN(3)
		p := stNewPair(stOpt{mode: mode, window: 1 << 20}, stOpt{mode: mode, window: 1 << 20}, links)
		if mode == ModeRace {
			rcRaceLanes(p.a)
			rcRaceLanes(p.b)
		}
		for i := range p.ap {
			c := int64(8<<10 + rng.IntN(256<<10))
			p.ap[i].set(func(f *stPort) { f.capacity = c })
		}
		first := make([]uint64, links)   // bytes each member delivered first
		payload := make([]uint64, links) // DATA payload each member delivered
		var written uint64
		for range 6 {
			n := 1 + rng.IntN(96<<10)
			rcWrite(t, p.a, stPattern(written, n))
			written += uint64(n)
			// ack is the receiver's acknowledgement: it reads what it can
			// and acknowledges on every link (a race ACK leaves on every
			// member, PA-33 as amended), in random order; the sender frees
			// capacity as the ACKs arrive.
			ack := func() (moved int) {
				if k := stLocked(p.b, func(st *stream) uint64 { return st.rTail - st.rRead }); k > 0 {
					stReadN(t, p.b, int(k))
				}
				for _, i := range rng.Perm(links) {
					moved += p.stepAck(i)
					p.ap[i].set(func(f *stPort) { f.inflight = 0 })
				}
				return moved
			}
			for round := 0; round < 64; round++ {
				moved := 0
				// The acknowledgement comes once inside the round, after a
				// member chosen at random — between two members' Fills, as
				// a duty lane's ACK can: it frees capacity and moves the
				// acknowledged front (bond's sBase, race's cursor clamp)
				// between them — and once after the round, so that race
				// still copies when no ACK comes between the Fills.
				ackAfter := rng.IntN(links)
				for j, i := range rng.Perm(links) {
					b := p.batch
					b.Reset(time.Now())
					if rng.IntN(2) == 0 {
						// A payload quota (as a MUX writer's) cuts this
						// member's segments elsewhere than the others'.
						b.SetQuota(1 + rng.IntN(40<<10))
					}
					p.al[i].Fill(nil, b)
					for k := range b.Len() {
						f := b.Frame(k)
						if f.Header.Type != wire.TypeData {
							if err := p.bl[i].Control(nil, f.Header, f.Payload); err != nil {
								t.Fatal(err)
							}
							continue
						}
						before := stLocked(p.b, func(st *stream) uint64 { return st.rxBytes })
						if err := stDeliverData(p.bl[i], f.Off, f.Body); err != nil {
							t.Fatalf("seed %d: %v", seed, err)
						}
						first[i] += stLocked(p.b, func(st *stream) uint64 { return st.rxBytes }) - before
						payload[i] += uint64(len(f.Body))
					}
					moved += b.Len()
					b.ReleaseRefs()
					if j == ackAfter {
						acked := p.a.Status().AckedBytes
						moved += ack()
						if j < links-1 && p.a.Status().AckedBytes > acked {
							midFront[mode]++
						}
					}
				}
				moved += ack()
				if moved == 0 {
					break
				}
			}
			sb := p.b.Status()
			if sb.DeliveredBytes > written || sb.RxBytes > written || p.a.Status().AckedBytes > written {
				t.Fatalf("seed %d: a counter exceeds the %d written bytes: %+v", seed, written, sb)
			}
		}
		sa, sb := p.a.Status(), p.b.Status()
		var sumFirst, sumPayload uint64
		for i := range first {
			sumFirst += first[i]
			sumPayload += payload[i]
			if payload[i] > written {
				t.Fatalf("seed %d %v: member %d carried %d of %d bytes", seed, mode, i, payload[i], written)
			}
		}
		if sb.DeliveredBytes != written || sumFirst != written || sa.AckedBytes != written {
			t.Fatalf("seed %d %v: written %d delivered %d Σfirst %d acked %d", seed, mode, written, sb.DeliveredBytes, sumFirst, sa.AckedBytes)
		}
		if sumPayload != written+sb.DupBytes {
			t.Fatalf("seed %d %v: Σpayload %d ≠ written %d + DupBytes %d", seed, mode, sumPayload, written, sb.DupBytes)
		}
		if mode == ModeBond && (sb.DupBytes != 0 || sa.Race.CopyBytes != 0) {
			t.Fatalf("seed %d bond: DupBytes %d CopyBytes %d, want 0", seed, sb.DupBytes, sa.Race.CopyBytes)
		}
		if mode == ModeRace && (sa.Race.CopyBytes != sb.DupBytes || sb.DupBytes == 0) {
			t.Fatalf("seed %d race: the sender's CopyBytes %d ≠ the receiver's DupBytes %d (every copy arrived)", seed, sa.Race.CopyBytes, sb.DupBytes)
		}
		p.close(t)
	}
	if midFront[ModeRace] == 0 || midFront[ModeBond] == 0 {
		t.Fatalf("acknowledgements between two members' Fills that moved the front: %v, want some in both modes (stimulus)", midFront)
	}
}

// stepAck runs link i's b → a Fill and delivers it, late enough that a
// delayed ACK is due; it returns the frames moved.
func (p *stPair) stepAck(i int) int {
	n, _ := p.step(i, false, time.Now().Add(time.Hour))
	return n
}

// TestRaceAggregateUnknown_L35: the session status publishes no figure
// derived from a race's members — no aggregate rate, RTT, latency or
// goodput (L35: race's are Unknown, PA-36); each carrier reports its own.
func TestRaceAggregateUnknown_L35(t *testing.T) {
	ty := reflect.TypeFor[Status]()
	for i := range ty.NumField() {
		name := strings.ToLower(ty.Field(i).Name)
		for _, bad := range []string{"rtt", "rate", "latency", "goodput", "throughput", "bandwidth", "delay"} {
			if strings.Contains(name, bad) {
				t.Errorf("Status.%s looks like an aggregate %s", ty.Field(i).Name, bad)
			}
		}
	}
	for _, f := range []string{"CopyBytes", "Copies"} {
		if _, ok := reflect.TypeFor[RaceCounters]().FieldByName(f); !ok {
			t.Errorf("RaceCounters.%s missing", f)
		}
	}
	if n := reflect.TypeFor[RaceCounters]().NumField(); n != 2 {
		t.Errorf("RaceCounters has %d fields, want CopyBytes and Copies only", n)
	}
}

// TestRaceRetransmittedExcludesCopies: race copies are never
// retransmissions (RetransmittedBytes stays 0 while both members carry
// every byte); bytes the death of the last data lane requeued are, and the
// next lane's cursor sends them once, as retransmissions, not as copies.
func TestRaceRetransmittedExcludesCopies(t *testing.T) {
	p := rcPair(2, stOpt{}, stOpt{})
	data := stPattern(0, 200<<10)
	rcWrite(t, p.a, data)
	p.pump(false)
	if got := stReadN(t, p.b, len(data)); !bytes.Equal(got, data) {
		t.Fatal("integrity")
	}
	p.pump(true)
	if st := p.a.Status(); st.RetransmittedBytes != 0 || st.Race.CopyBytes != 200<<10 {
		t.Fatalf("copies: Retransmitted %d CopyBytes %d, want 0 and 200 KiB", st.RetransmittedBytes, st.Race.CopyBytes)
	}
	p.close(t)

	// One member sends 64 KiB and dies unacknowledged as the last data
	// lane (M1's requeue from the ACK edge); a new member carries them.
	s := rcSender(stOpt{})
	a, _ := stAddLane(s, 1, true)
	rcRaceLanes(s)
	rcWrite(t, s, stPattern(0, 64<<10))
	_, b := stFill(a, time.Now())
	b.ReleaseRefs()
	stKillLane(s, a)
	c, _ := stAddLane(s, 2, true)
	rcRaceLane(s, c)
	fs, b := stFill(c, time.Now())
	b.ReleaseRefs()
	retx := 0
	for _, f := range fs {
		if f.typ == wire.TypeData && f.retx {
			retx += f.n
		}
	}
	if st := s.Status(); retx != 64<<10 || st.RetransmittedBytes != 64<<10 || st.Race.CopyBytes != 0 {
		t.Fatalf("after the last lane's death: retx frames %d, Retransmitted %d, CopyBytes %d; want 64 KiB, 64 KiB, 0",
			retx, st.RetransmittedBytes, st.Race.CopyBytes)
	}
	stEnd(s, errClosed)
}

// TestRaceAckOnFastest: a race receiver's ACK duty sits on the live lane
// with the lowest SRTT (M3-D33), re-chosen at every ACK decision, and every
// other live data lane carries a copy of each ACK (PA-33 as amended by
// RACEACK): with a 5-ms and an 80-ms member the duty first lands on lane 0
// (SRTTs unknown at attach) and moves to the 5-ms lane once the SRTTs are
// known; after warm-up both lanes carry the same ACK stream — every
// delivered value the receiver acknowledged leaves on each lane, none
// skipped on either, the last one the bytes read. When the fast lane dies,
// the slow lane's copies already carried the latest value: the sender's
// acknowledged front equals the bytes read with no further step (no step
// in the ACK stream), and the death's urgent ACK leaves on the slow lane at
// its next Fill.
func TestRaceAckOnFastest(t *testing.T) {
	p := rcPair(2, stOpt{ackEvery: 16 << 10}, stOpt{ackEvery: 16 << 10})
	p.pump(true) // SRTTs unknown: the duty is on lane 0 (attach order)
	if l := stLocked(p.b, func(st *stream) *lane { return st.ackLane }); l != p.bl[0] {
		t.Fatalf("initial duty on %v", l)
	}
	p.bp[0].set(func(f *stPort) { f.srtt = 80 * time.Millisecond })
	p.bp[1].set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
	var acks [2][]uint64 // the Delivered values of the ACKs on each lane
	off := 0
	for round := range 40 {
		rcWrite(t, p.a, stPattern(uint64(off), 32<<10))
		off += 32 << 10
		for i := range 2 {
			p.step(i, true, time.Now())
		}
		stReadN(t, p.b, 32<<10)
		for i := range 2 {
			before := len(p.traceBA)
			p.step(i, false, time.Now())
			if round < 4 {
				continue
			}
			for _, f := range p.traceBA[before:] {
				if f.typ == wire.TypeAck {
					acks[i] = append(acks[i], f.ack.Delivered)
				}
			}
		}
	}
	if l := stLocked(p.b, func(st *stream) *lane { return st.ackLane }); l != p.bl[1] {
		t.Fatalf("after warm-up the duty is on lane %d, want the 5-ms lane", l.id)
	}
	if n := len(acks[1]); n < 36 || !slices.Equal(acks[0], acks[1]) || acks[1][n-1] != uint64(off) {
		t.Fatalf("ACK streams: %v on the 80-ms lane, %v on the 5-ms lane; want the same stream on both, ending at %d", acks[0], acks[1], off)
	}
	// The fast lane dies: the slow lane already carried the latest ACK.
	p.cut[1] = true
	stKillLane(p.b, p.bl[1])
	if base := rcStream(p.a)[0]; base != uint64(off) {
		t.Fatalf("the sender's acknowledged front %d at the fast lane's death, want %d", base, off)
	}
	fs, b := stFill(p.bl[0], time.Now())
	b.ReleaseRefs()
	if stCount(fs, wire.TypeAck) == 0 {
		t.Fatalf("after the fast lane's death the slow lane's next Fill placed %v, want an ACK", fs)
	}
	p.close(t)
}

// TestRaceFinPerMember: each data member places our FIN once its own cursor
// reached it (M3-D30), so when the member that carried it first dies before
// it arrives, the other member's FIN completes the stream — before any
// death step ran.
func TestRaceFinPerMember(t *testing.T) {
	p := rcPair(2, stOpt{}, stOpt{})
	data := stPattern(0, 40<<10)
	rcWrite(t, p.a, data)
	if err := p.a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		fs, b := stFill(p.al[i], time.Now())
		if n := stCount(fs, wire.TypeFin); n != 1 {
			t.Fatalf("member %d placed %d FINs, want 1: %v", i, n, fs)
		}
		if i == 1 { // member 0's batch is lost with it; member 1's arrives
			if err := stDeliver(b, p.bl[1]); err != nil {
				t.Fatal(err)
			}
		}
		b.ReleaseRefs()
	}
	got := stReadN(t, p.b, len(data))
	if !bytes.Equal(got, data) {
		t.Fatal("integrity")
	}
	if n, err := p.b.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read after the FIN = %d, %v; want io.EOF", n, err)
	}
	// A member never places the FIN twice.
	fs, b := stFill(p.al[1], time.Now())
	b.ReleaseRefs()
	if stCount(fs, wire.TypeFin) != 0 {
		t.Fatalf("member 1 placed the FIN again: %v", fs)
	}
	p.close(t)

	// A member places the FIN only once its own cursor reached it: the
	// slow member (16 KiB of capacity) places none while its DATA is short
	// of the end, though the fast member's cursor (sNext) is past it.
	p = rcPair(2, stOpt{segment: 16 << 10}, stOpt{})
	rcWrite(t, p.a, data)
	if err := p.a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	fs, b = stFill(p.al[0], time.Now())
	b.ReleaseRefs()
	if stCount(fs, wire.TypeFin) != 1 {
		t.Fatalf("premise: the fast member placed %v", fs)
	}
	p.ap[1].set(func(f *stPort) { f.capacity = 16 << 10 })
	fs, b = stFill(p.al[1], time.Now())
	b.ReleaseRefs()
	if _, n := rcDataSpan(fs); n != 16<<10 || stCount(fs, wire.TypeFin) != 0 {
		t.Fatalf("the slow member at 16 KiB of 40 KiB placed %d DATA bytes and %d FINs, want 16 KiB and none", n, stCount(fs, wire.TypeFin))
	}
	p.ap[1].set(func(f *stPort) { f.capacity = 1 << 30 })
	fs, b = stFill(p.al[1], time.Now())
	b.ReleaseRefs()
	if _, n := rcDataSpan(fs); n != 24<<10 || stCount(fs, wire.TypeFin) != 1 {
		t.Fatalf("the slow member's rest: %d DATA bytes and %d FINs, want 24 KiB and one", n, stCount(fs, wire.TypeFin))
	}
	p.close(t)
}

// TestRaceDupPartialOverlap_L35: copies cut differently from the first
// copy count exactly their already-held bytes in DupBytes (M3-D35) — the
// part the application read (dropped uncompared), the unread in-order
// part and the part over an out-of-order segment still held — and only
// their new bytes as unique, so the payload delivered is the unique bytes
// plus DupBytes; the stream reads every byte once.
func TestRaceDupPartialOverlap_L35(t *testing.T) {
	s, l1, l2 := rcRecv(ModeRace)
	d := stPattern(0, 96<<10)
	payload := 0
	deliver := func(l *lane, from, to int) {
		t.Helper()
		if err := stDeliverData(l, uint64(from), d[from:to]); err != nil {
			t.Fatalf("[%d, %d): %v", from, to, err)
		}
		payload += to - from
	}
	// RxBytes counts in-order bytes: held out-of-order bytes join it
	// when the gap before them fills.
	check := func(what string, dup, rx, held uint64) {
		t.Helper()
		st := s.Status()
		if st.DupBytes != dup || st.RxBytes != rx || uint64(payload) != st.RxBytes+held+st.DupBytes {
			t.Fatalf("%s: DupBytes %d RxBytes %d (payload %d); want %d and %d", what, st.DupBytes, st.RxBytes, payload, dup, rx)
		}
	}
	deliver(l1, 0, 48<<10)
	deliver(l1, 64<<10, 80<<10) // held out of order
	if got := stReadN(t, s, 16<<10); !bytes.Equal(got, d[:16<<10]) {
		t.Fatal("integrity")
	}
	check("first copies", 0, 48<<10, 16<<10)
	// [8 KiB, 72 KiB): 8 KiB read, 32 KiB unread in order, 16 KiB new and
	// 8 KiB over the held segment.
	deliver(l2, 8<<10, 72<<10)
	check("a copy over read, unread, missing and held bytes", 48<<10, 80<<10, 0)
	// [76 KiB, 96 KiB): 4 KiB in order (the held segment merged), 16 KiB new.
	deliver(l2, 76<<10, 96<<10)
	check("a copy past the in-order end", 52<<10, 96<<10, 0)
	if got := stReadN(t, s, 80<<10); !bytes.Equal(got, d[16<<10:]) {
		t.Fatal("integrity: the stream did not read every byte once")
	}
	if st := s.Status(); st.DeliveredBytes != 96<<10 {
		t.Fatalf("DeliveredBytes %d, want 96 KiB", st.DeliveredBytes)
	}
	stEnd(s, errClosed)
}

// TestRaceAckDutyQualifies (M3-D33): the race ACK duty skips a lane that
// is write-blocked or leaving (Retire called) even when it is the fastest,
// falls back to M1's choice (a lane keeps the duty) when every lane is
// leaving, and between equal SRTTs takes the lower factory index over the
// attach order.
func TestRaceAckDutyQualifies(t *testing.T) {
	s, slow, fast := rcRecv(ModeRace)
	ps, pf := slow.port.(*stPort), fast.port.(*stPort)
	ps.set(func(f *stPort) { f.srtt = 80 * time.Millisecond })
	pf.set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
	duty := func() *lane {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.ackBumpForTest()
		return s.st.ackLane
	}
	name := func(l *lane) string {
		switch l {
		case slow:
			return "the 80-ms lane"
		case fast:
			return "the 5-ms lane"
		}
		return "no lane"
	}
	want := func(what string, l *lane) {
		t.Helper()
		if got := duty(); got != l {
			t.Fatalf("%s: the duty is on %s, want %s", what, name(got), name(l))
		}
	}
	retire := func(l *lane, on bool) {
		s.mu.Lock()
		l.retireCalled = on
		s.mu.Unlock()
	}
	want("known SRTTs", fast)
	pf.set(func(f *stPort) { f.blocked = true })
	want("the fast lane write-blocked", slow)
	pf.set(func(f *stPort) { f.blocked = false })
	want("unblocked", fast)
	retire(fast, true)
	want("the fast lane retiring", slow)
	retire(slow, true)
	if duty() == nil {
		t.Fatal("every lane retiring: M1's fallback must keep a lane on the duty")
	}
	retire(fast, false)
	retire(slow, false)
	ps.set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
	s.mu.Lock()
	slow.factory, fast.factory = 1, 0
	s.mu.Unlock()
	want("equal SRTTs, factory 0 attached second", fast)
	stEnd(s, errClosed)
}

// TestRaceRequeueBelowLiveCursor (M3-D30): spans a dead member's requeue
// put back below a live member's cursor are bytes that member already sent;
// its next Fill sends new bytes from its cursor, neither stalling at the
// requeued span nor flagging new bytes as retransmissions. The rows: the
// dead member was behind the live one's cursor, or exactly at it. (Until
// WP4's death rule M2's requeue runs on any member's death; afterwards
// nothing is requeued while a data lane lives, and the rows still hold.)
func TestRaceRequeueBelowLiveCursor(t *testing.T) {
	for _, bSent := range []int{64 << 10, 128 << 10} {
		s := rcSender(stOpt{window: 4 << 20, segment: 16 << 10})
		a, _ := stAddLane(s, 1, true)
		b, bp := stAddLane(s, 2, true)
		rcRaceLanes(s)
		rcWrite(t, s, stPattern(0, 128<<10))
		fa, ba := stFill(a, time.Now())
		ba.ReleaseRefs()
		if _, n := rcDataSpan(fa); n != 128<<10 {
			t.Fatalf("premise: a sent %d bytes", n)
		}
		bp.set(func(f *stPort) { f.capacity = int64(bSent) })
		fb, bb := stFill(b, time.Now())
		bb.ReleaseRefs()
		if _, n := rcDataSpan(fb); n != bSent {
			t.Fatalf("premise: b sent %d bytes, want %d", n, bSent)
		}
		stKillLane(s, b)
		rcWrite(t, s, stPattern(128<<10, 64<<10))
		fs, bf := stFill(a, time.Now())
		bf.ReleaseRefs()
		retx := 0
		for _, f := range fs {
			if f.typ == wire.TypeData && f.retx {
				retx += f.n
			}
		}
		if first, n := rcDataSpan(fs); first != 128<<10 || n != 64<<10 || retx != 0 {
			t.Fatalf("b sent %d: a's next Fill sent %d bytes from %d (%d flagged retransmission), want 64 KiB of new bytes from 128 KiB",
				bSent, n, first, retx)
		}
		if st := s.Status(); st.RetransmittedBytes != 0 {
			t.Fatalf("b sent %d: RetransmittedBytes %d, want 0", bSent, st.RetransmittedBytes)
		}
		stEnd(s, errClosed)
	}
}

// TestRaceStreamWakeEveryMember (M3-D30; the stream variant of
// TestRaceWakeEveryMember, wired by WP4's wakeDataLocked dispatch): every
// race member places every byte, so one Write wakes every idle member that
// is not write-blocked, not only the first data lane; pullableLocked counts
// the bytes of the least advanced live member (racePullableLocked), so a
// member that placed everything is passed by a wake while a slower one
// still owes its copy; once the peer acknowledged everything nothing is
// pullable, and a member is woken again only for its FIN.
func TestRaceStreamWakeEveryMember(t *testing.T) {
	s := rcSender(stOpt{window: 4 << 20})
	var ls []*lane
	var ps []*stPort
	for id := uint32(1); id <= 3; id++ {
		l, p := stAddLane(s, id, true)
		ls, ps = append(ls, l), append(ps, p)
	}
	rcRaceLanes(s)
	ps[1].set(func(f *stPort) { f.blocked = true })
	s.mu.Lock()
	for _, l := range ls {
		l.idle = true
	}
	s.mu.Unlock()
	wakes := func() (w [3]int) {
		for i, p := range ps {
			w[i] = p.wakeCount()
		}
		return w
	}
	pullable := func() uint64 {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.pullableLocked()
	}
	w0 := wakes()
	rcWrite(t, s, stPattern(0, 64<<10))
	if w := wakes(); w[0]-w0[0] != 1 || w[1] != w0[1] || w[2]-w0[2] != 1 {
		t.Fatalf("one Write woke the members %v times, want once each but the write-blocked member 1",
			[3]int{w[0] - w0[0], w[1] - w0[1], w[2] - w0[2]})
	}
	if n := pullable(); n != 64<<10 {
		t.Fatalf("pullable %d before any Fill, want 64 KiB", n)
	}
	// Member 0 places everything and goes idle; members 1 and 2 still owe
	// their copies: pullable stays 64 KiB, and a wake passes member 0 but
	// wakes the idle member 2 again.
	f0, b0 := stFill(ls[0], time.Now())
	b0.ReleaseRefs()
	if _, n := rcDataSpan(f0); n != 64<<10 {
		t.Fatalf("member 0 placed %d bytes, want 64 KiB", n)
	}
	if n := pullable(); n != 64<<10 {
		t.Fatalf("pullable %d after the fastest member's Fill, want 64 KiB (the slowest member's)", n)
	}
	s.mu.Lock()
	for _, l := range ls {
		l.idle = true
	}
	s.mu.Unlock()
	w0 = wakes()
	s.mu.Lock()
	s.wakeDataLocked(time.Now())
	s.mu.Unlock()
	if w := wakes(); w[0] != w0[0] || w[1] != w0[1] || w[2]-w0[2] != 1 {
		t.Fatalf("a wake woke the members %v times, want member 2 only",
			[3]int{w[0] - w0[0], w[1] - w0[1], w[2] - w0[2]})
	}
	// The peer acknowledges everything on member 0: nothing is pullable,
	// and no member is woken for bytes.
	if err := stSendAck(ls[0], 0, 64<<10, 4<<20); err != nil {
		t.Fatal(err)
	}
	if n := pullable(); n != 0 {
		t.Fatalf("pullable %d after the full ACK, want 0", n)
	}
	s.mu.Lock()
	for _, l := range ls {
		l.idle = true
	}
	s.mu.Unlock()
	w0 = wakes()
	s.mu.Lock()
	s.wakeDataLocked(time.Now())
	s.mu.Unlock()
	if w := wakes(); w != w0 {
		t.Fatalf("a wake with nothing to place woke the members %v times", [3]int{w[0] - w0[0], w[1] - w0[1], w[2] - w0[2]})
	}
	stEnd(s, errClosed)
}
