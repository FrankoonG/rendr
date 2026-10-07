package session

import (
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// dpSent writes n datagrams on s and places them on l; it returns s's
// next seq.
func dpSent(t testing.TB, s *Session, l *lane, n int) uint64 {
	t.Helper()
	for i := range n {
		dpWrite(t, s, uint64(i), 20)
	}
	dpIdle(l)
	return dpLocked(s, func(_ *stream, pk *packet) uint64 { return pk.nextSeq })
}

// TestPackValidation_L13: a PACK is checked against what this side sent
// (§A3.2, M2-D39): more datagrams than seqs assigned, a highest seq not yet
// assigned or below FirstSeq, and FIN_DELIVERED before our FIN was placed
// are violations of the delivering carrier; otherwise it merges by
// maximum, acknowledges our FIN, records the peer's DONE and (dialer) the
// SCHED echo. ACK and DATA on a packet session are violations.
func TestPackValidation_L13(t *testing.T) {
	s := dpSession(dpOpt{})
	l, _ := dpAddLane(s, 1, true, true)
	if next := dpSent(t, s, l, 10); next != 10 {
		t.Fatalf("next seq %d after 10 placed", next)
	}
	for _, tc := range []struct {
		name  string
		flags uint8
		pa    wire.Pack
		want  error
	}{
		{"received beyond sent", 0, wire.Pack{HighestSeq: 9, Received: 11}, errPackBeyondSent},
		{"highest beyond sent", 0, wire.Pack{HighestSeq: 10, Received: 5}, errPackBeyondSent},
		{"FIN_DELIVERED before our FIN", wire.FlagPackFinDelivered, wire.Pack{HighestSeq: 9, Received: 10}, errFinDeliveredEarly},
		{"everything", 0, wire.Pack{HighestSeq: 9, Received: 10}, nil},
		{"nothing", 0, wire.Pack{}, nil},
	} {
		if err := dpSendPack(l, tc.flags, tc.pa); err != tc.want {
			t.Fatalf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if c := dpCtr(s); c.PeerReceived != 10 {
		t.Fatalf("PeerReceived %d, want 10", c.PeerReceived)
	}
	var ack [wire.AckLen]byte
	if err := (*plane)(l).Control(nil, wire.Header{Type: wire.TypeAck, Len: wire.AckLen, Handle: wire.SessionHandle}, ack[:]); err != errAckOnPacket {
		t.Fatalf("ACK on a packet session: %v", err)
	}
	pool := s.env.Carrier.Bufs
	buf := pool.Get(carrier.BigData, nil)
	if err := (*plane)(l).Data(nil, 0, buf.B[:100], buf); err != errDataOnPacket {
		t.Fatalf("DATA on a packet session: %v", err)
	}

	// The dialer's epoch echo, as an ACK's.
	s.mu.Lock()
	s.ctl.epoch = 3
	s.mu.Unlock()
	_ = dpSendPack(l, 0, wire.Pack{EpochEcho: 4}) // never published: ignored
	_ = dpSendPack(l, 0, wire.Pack{EpochEcho: 3})
	if echo := dpLocked(s, func(st *stream, _ *packet) uint32 { return st.echoIn }); echo != 3 {
		t.Fatalf("echoIn %d, want 3", echo)
	}

	// After our FIN was placed: FIN_DELIVERED acknowledges it, DONE is recorded.
	dpClose(s)
	dpIdle(l)
	if err := dpSendPack(l, wire.FlagPackFinDelivered|wire.FlagPackDone, wire.Pack{HighestSeq: 9, Received: 10}); err != nil {
		t.Fatal(err)
	}
	type endState struct {
		acked, done bool
		facts       uint32
	}
	es := dpLocked(s, func(st *stream, _ *packet) endState { return endState{st.fin.acked, st.peerDone, st.facts} })
	if !es.acked || !es.done || es.facts&factFinAcked == 0 || es.facts&factPeerDone == 0 {
		t.Fatalf("after PACK(FIN_DELIVERED|DONE): %+v", es)
	}
	dpEnd(s, io.EOF)

	// FirstSeq preset: a highest seq below it was never sent.
	f := dpSession(dpOpt{firstSeq: 100})
	fl, _ := dpAddLane(f, 1, true, true)
	dpSent(t, f, fl, 1)
	if err := dpSendPack(fl, 0, wire.Pack{HighestSeq: 99, Received: 1}); err != errPackBeyondSent {
		t.Fatalf("highest below FirstSeq: %v", err)
	}
	if err := dpSendPack(fl, 0, wire.Pack{HighestSeq: 100, Received: 1}); err != nil {
		t.Fatal(err)
	}
	dpEnd(f, io.EOF)
}

// TestPackReorderNotViolation_L43: datagram carriers reorder, so a PACK
// lower than an earlier one — on the same lane or another — is never a
// violation: PACKs merge by maximum (M2-D39).
func TestPackReorderNotViolation_L43(t *testing.T) {
	s := dpSession(dpOpt{mode: ModeBond})
	l1, _ := dpAddLane(s, 1, true, true)
	l2, _ := dpAddLane(s, 2, true, true)
	dpSent(t, s, l1, 10)
	for i, step := range []struct {
		l  *lane
		pa wire.Pack
	}{
		{l1, wire.Pack{HighestSeq: 9, Received: 10}},
		{l1, wire.Pack{HighestSeq: 4, Received: 5}}, // reordered on the same lane
		{l2, wire.Pack{HighestSeq: 2, Received: 3}},
		{l1, wire.Pack{}},
	} {
		if err := dpSendPack(step.l, 0, step.pa); err != nil {
			t.Fatalf("PACK %d (%+v): %v; a lower PACK is never a violation", i, step.pa, err)
		}
	}
	hi, c := dpLocked(s, func(_ *stream, pk *packet) uint64 { return pk.peerHi }), dpCtr(s)
	if hi != 9 || c.PeerReceived != 10 {
		t.Fatalf("merged highest %d, PeerReceived %d; want the maxima 9 and 10", hi, c.PeerReceived)
	}
	dpEnd(s, io.EOF)
}

// TestPackDutyMovesOnRelFull: a reliable PACK that the duty lane's
// datagram batch refuses for lack of REL room moves the PACK duty to a lane
// that can carry it now — a datagram lane with REL room, or a stream lane
// — and wakes it; with none, the duty stays (R1-17). A full stream batch,
// or a full datagram batch that still has REL room, never moves it (D8).
func TestPackDutyMovesOnRelFull(t *testing.T) {
	setup := func(third bool) (*Session, []*lane, []*dpPort) {
		s := dpSession(dpOpt{role: RolePassive, mode: ModeBond})
		var ls []*lane
		var ps []*dpPort
		for i := range 3 {
			if i == 2 && !third {
				break
			}
			l, p := dpAddLane(s, uint32(i+1), true, i < 2)
			p.set(func(f *dpPort) { f.srtt = time.Duration(i+1) * time.Millisecond })
			ls, ps = append(ls, l), append(ps, p)
		}
		for _, l := range ls {
			dpIdle(l)
		}
		s.mu.Lock()
		s.refreshOrderLocked(time.Now(), true)
		s.st.ackLane = ls[0]
		s.mu.Unlock()
		if err := dpSendFin(ls[0], 0); err != nil { // delivered at once: a PACK with FIN_DELIVERED is due
			t.Fatal(err)
		}
		return s, ls, ps
	}
	duty := func(s *Session) *lane { return dpLocked(s, func(st *stream, _ *packet) *lane { return st.ackLane }) }

	s, ls, ps := setup(true)
	ps[0].set(func(f *dpPort) { f.relRoom = 0 })
	w := ps[1].wakeCount()
	if fs := dpFrames(dpFill(ls[0], time.Now())); dpCount(fs, wire.TypePack) != 0 {
		t.Fatalf("a reliable PACK placed without REL room: %v", fs)
	}
	if duty(s) != ls[1] || ps[1].wakeCount() != w+1 {
		t.Fatal("the duty did not move to the datagram lane with REL room, or it was not woken")
	}
	fs := dpFrames(dpFill(ls[1], time.Now()))
	if dpCount(fs, wire.TypePack) != 1 || !fs[0].rel || fs[0].flags&wire.FlagPackFinDelivered == 0 {
		t.Fatalf("the new duty lane placed %v; want a REL-wrapped PACK with FIN_DELIVERED", fs)
	}
	dpEnd(s, io.EOF)

	s, ls, ps = setup(true)
	ps[0].set(func(f *dpPort) { f.relRoom = 0 })
	ps[1].set(func(f *dpPort) { f.relRoom = 0 })
	dpFill(ls[0], time.Now())
	if duty(s) != ls[2] {
		t.Fatal("with no REL room on datagram lanes the duty must go to the stream lane")
	}
	if fs := dpFrames(dpFill(ls[2], time.Now())); dpCount(fs, wire.TypePack) != 1 || fs[0].rel {
		t.Fatalf("the stream lane placed %v; want a plain PACK", fs)
	}
	dpEnd(s, io.EOF)

	s, ls, ps = setup(false)
	ps[0].set(func(f *dpPort) { f.relRoom = 0 })
	ps[1].set(func(f *dpPort) { f.relRoom = 0 })
	dpFill(ls[0], time.Now())
	if duty(s) != ls[0] {
		t.Fatal("with no lane able to carry it the duty must stay")
	}
	dpEnd(s, io.EOF)

	// Full batches: the PACK stays due on its lane.
	s, ls, _ = setup(true)
	s.mu.Lock()
	s.st.ackLane = ls[2]
	s.mu.Unlock()
	b := carrier.NewBatch(0)
	b.Reset(time.Now())
	for !b.Full() {
		b.AddFin(wire.SessionHandle, 0)
	}
	(*plane)(ls[2]).Fill(nil, b)
	if duty(s) != ls[2] {
		t.Fatal("a full stream batch moved the duty (D8)")
	}
	s.mu.Lock()
	s.st.ackLane = ls[0]
	s.mu.Unlock()
	b.Reset(time.Now())
	b.SetDatagram(1400, wire.RelWindow)
	for !b.Full() {
		b.AddDgram(wire.SessionHandle, 0, nil, nil)
	}
	(*plane)(ls[0]).Fill(nil, b)
	if duty(s) != ls[0] {
		t.Fatal("a full datagram batch with REL room moved the duty")
	}
	dpEnd(s, io.EOF)
}

// TestPacketPackPlacement: the PACK cadence (M2-D39, §A5.5): the first
// unreported datagram arms a PacketPing delay that the duty lane's writer
// timer fires; PackEvery datagrams bump at once; an idle session places
// none (M2-D65). A PACK is REL-wrapped exactly when it carries a flag or
// an epoch echo not yet carried reliably on its lane. The idle clock moves
// with the accepted datagrams it reports.
func TestPacketPackPlacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const pp = time.Second
		s := dpSession(dpOpt{role: RolePassive, packetPing: pp, packEvery: 256})
		l, fp := dpAddLane(s, 1, true, true)
		dpIdle(l)
		t0 := time.Now()
		time.Sleep(time.Second)
		w := fp.wakeCount()
		_ = dpDatagram(l, 0, []byte("a"))
		if fp.wakeCount() != w+1 {
			t.Fatal("the first unreported datagram must wake the duty lane once")
		}
		if ld := dpLocked(s, func(st *stream, _ *packet) time.Time { return st.lastData }); !ld.Equal(t0.Add(time.Second)) {
			t.Fatalf("idle clock %v after an accepted datagram", ld.Sub(t0))
		}
		_ = dpDatagram(l, 1, []byte("b"))
		if fp.wakeCount() != w+1 {
			t.Fatal("a second unreported datagram woke the lane again")
		}
		b := dpFill(l, time.Now())
		if dpCount(dpFrames(b), wire.TypePack) != 0 || !b.WakeTime().Equal(t0.Add(time.Second+pp)) {
			t.Fatalf("before the delay: %v, wake %v", dpFrames(b), b.WakeTime().Sub(t0))
		}
		time.Sleep(pp)
		fs := dpFrames(dpFill(l, time.Now()))
		if len(fs) != 1 || fs[0].typ != wire.TypePack || fs[0].rel || fs[0].pack != (wire.Pack{HighestSeq: 1, Received: 2}) {
			t.Fatalf("after the delay: %v; want one plain PACK{1, 2}", fs)
		}
		if ld := dpLocked(s, func(st *stream, _ *packet) time.Time { return st.lastData }); !ld.Equal(t0.Add(time.Second + pp)) {
			t.Fatalf("idle clock %v after the PACK that reports the datagrams", ld.Sub(t0))
		}
		for seq := uint64(2); seq < 2+255; seq++ {
			_ = dpDatagram(l, seq, nil)
		}
		if fs := dpFrames(dpFill(l, time.Now())); dpCount(fs, wire.TypePack) != 0 {
			t.Fatalf("255 datagrams placed a PACK early: %v", fs)
		}
		_ = dpDatagram(l, 257, nil)
		if fs := dpFrames(dpFill(l, time.Now())); len(fs) != 1 || fs[0].pack.Received != 258 {
			t.Fatalf("the 256th datagram: %v; want an immediate PACK reporting 258", fs)
		}
		dpReadAll(t, s)
		for range 60 {
			time.Sleep(time.Second)
			if fs := dpFrames(dpFill(l, time.Now())); len(fs) != 0 {
				t.Fatalf("an idle session placed %v", fs)
			}
		}

		// A new epoch echo is REL-wrapped once.
		s.mu.Lock()
		s.ctl.epoch = 2
		s.bumpNowLocked()
		s.mu.Unlock()
		if fs := dpFrames(dpFill(l, time.Now())); len(fs) != 1 || !fs[0].rel || fs[0].pack.EpochEcho != 2 {
			t.Fatalf("a new echo: %v; want a REL-wrapped PACK", fs)
		}
		s.mu.Lock()
		s.bumpNowLocked()
		s.mu.Unlock()
		if fs := dpFrames(dpFill(l, time.Now())); len(fs) != 1 || fs[0].rel {
			t.Fatalf("an echo already carried reliably: %v; want a plain PACK", fs)
		}
		dpEnd(s, io.EOF)
	})
}
