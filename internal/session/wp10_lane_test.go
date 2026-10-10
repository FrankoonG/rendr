package session

import (
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestLaneGoFrame (M3-D8, R1-12; session half): a dialer lane on a view
// opened on a started MUX trunk owes a go frame, which its first Fill
// places before anything else — an ACK of what it delivered with the right
// edge it already advertised for a stream session, a PACK of what it
// received for a packet session: REL-wrapped on a datagram trunk, plain on
// a stream trunk. It carries no flags, changes no ACK duty, is placed once
// (the next Fill places none), and a Fill whose batch is full places
// nothing else. A datagram batch without REL room for it (m3 DGMUX, L40)
// lets the lane's datagrams out at once and keeps the go frame owed: the
// next Fill with REL room places it first; a lane with nothing to send
// places the go PACK's unreliable stand-in instead, once. A stream batch
// that refuses it (its control arena short) places nothing else. The
// carrier half (the passive's
// hold until it, both trunk kinds) is TestMuxResponseHold; end to end
// TestLaneGoFrameE2E and TestMuxDatagramGoFrameUnderLoss_L40.
func TestLaneGoFrame(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		s := stSession(stOpt{})
		l, _ := stAddLane(s, 7, true)
		s.mu.Lock()
		l.goOwed = true
		s.st.rRead, s.st.rTail = 1000, 1000
		s.st.peerLimit = 1 << 20 // the peer's window (its OPEN_ACK)
		edge := s.st.rightEdge
		s.mu.Unlock()
		if _, err := s.Write(make([]byte, 100)); err != nil {
			t.Fatal(err)
		}
		fs, b := stFill(l, time.Now())
		b.ReleaseRefs()
		if len(fs) < 2 || fs[0].typ != wire.TypeAck || fs[0].flags != 0 || fs[0].ack.Delivered != 1000 ||
			uint64(fs[0].ack.Window) != edge-1000 || !wp10Has(fs, wire.TypeData) {
			t.Fatalf("first Fill %v, want the go frame ACK(1000, w=%d, f=0) first, then the DATA", fs, edge-1000)
		}
		s.mu.Lock()
		owed := l.goOwed
		s.mu.Unlock()
		if owed {
			t.Fatal("the go frame stayed owed after it was placed")
		}
		if _, err := s.Write(make([]byte, 100)); err != nil {
			t.Fatal(err)
		}
		fs, b = stFill(l, time.Now())
		b.ReleaseRefs()
		if len(fs) == 0 || fs[0].typ != wire.TypeData {
			t.Fatalf("second Fill %v: want the DATA first (no second go frame)", fs)
		}
		stEnd(s, nil)
	})
	for _, dgram := range []bool{true, false} {
		name := "packet on a stream trunk"
		if dgram {
			name = "packet on a datagram trunk"
		}
		t.Run(name, func(t *testing.T) {
			s := dpSession(dpOpt{})
			l, _ := dpAddLane(s, 7, true, dgram)
			s.mu.Lock()
			l.goOwed = true
			s.pk.rxCount, s.pk.rxHigh = 3, 9
			s.mu.Unlock()
			fs := dpFrames(dpFill(l, time.Now()))
			if len(fs) == 0 || fs[0].typ != wire.TypePack || fs[0].flags != 0 || fs[0].rel != dgram ||
				fs[0].pack.Received != 3 || fs[0].pack.HighestSeq != 9 {
				t.Fatalf("first Fill %v, want the go frame PACK(hi=9 rcv=3, rel=%v)", fs, dgram)
			}
			for _, f := range dpFrames(dpFill(l, time.Now())) {
				if f.typ == wire.TypePack && f.pack.Received == 3 && f.flags == 0 && f.rel == dgram {
					s.mu.Lock()
					owed := l.goOwed
					s.mu.Unlock()
					if owed {
						t.Fatal("the go frame stayed owed after it was placed")
					}
				}
			}
			dpEnd(s, nil)
		})
	}
	t.Run("no REL room: the datagrams leave, the go frame stays owed", func(t *testing.T) {
		s := dpSession(dpOpt{})
		l, fp := dpAddLane(s, 7, true, true)
		s.mu.Lock()
		l.goOwed = true
		s.mu.Unlock()
		fp.set(func(f *dpPort) { f.relRoom = 0 })
		if _, err := s.WriteTo(make([]byte, 100)); err != nil {
			t.Fatal(err)
		}
		fs := dpFrames(dpFill(l, time.Now()))
		if len(fs) == 0 || fs[len(fs)-1].typ != wire.TypeDgram {
			t.Fatalf("a Fill without REL room placed %v, want the queued DGRAM", fs)
		}
		for _, f := range fs {
			if f.rel {
				t.Fatalf("a Fill without REL room placed %v: a REL frame", fs)
			}
		}
		s.mu.Lock()
		owed, sent, standIn := l.goOwed, s.pk.ctr.Sent, l.goStandIn
		s.mu.Unlock()
		if !owed || sent != 1 || standIn {
			t.Fatalf("go frame owed %v, sent %d, stand-in %v: want it still owed, the datagram sent and no stand-in", owed, sent, standIn)
		}
		if _, err := s.WriteTo(make([]byte, 100)); err != nil {
			t.Fatal(err)
		}
		fp.set(func(f *dpPort) { f.relRoom = wire.RelWindow })
		fs = dpFrames(dpFill(l, time.Now()))
		if len(fs) < 2 || fs[0].typ != wire.TypePack || !fs[0].rel || fs[0].flags != 0 || fs[len(fs)-1].typ != wire.TypeDgram {
			t.Fatalf("with REL room: %v, want the go frame first, then the queued DGRAM", fs)
		}
		s.mu.Lock()
		owed = l.goOwed
		s.mu.Unlock()
		if owed {
			t.Fatal("the go frame stayed owed after it was placed")
		}
		dpEnd(s, nil)
	})
	t.Run("no REL room, nothing to send: the stand-in, once", func(t *testing.T) {
		s := dpSession(dpOpt{})
		l, fp := dpAddLane(s, 7, true, true)
		s.mu.Lock()
		l.goOwed = true
		s.pk.rxCount, s.pk.rxHigh = 3, 9
		s.mu.Unlock()
		fp.set(func(f *dpPort) { f.relRoom = 0 })
		// The PACK the attach made due (laneAddedLocked) goes first: it
		// ends the passive's hold as well, so no stand-in yet.
		fs := dpFrames(dpFill(l, time.Now()))
		if len(fs) != 1 || fs[0].typ != wire.TypePack || fs[0].rel {
			t.Fatalf("first Fill without REL room: %v, want the attach's plain PACK", fs)
		}
		fs = dpFrames(dpFill(l, time.Now()))
		if len(fs) != 1 || fs[0].typ != wire.TypePack || fs[0].rel || fs[0].flags != 0 ||
			fs[0].pack.Received != 3 || fs[0].pack.HighestSeq != 9 {
			t.Fatalf("a Fill with nothing to send and no REL room: %v, want the go PACK's stand-in PACK(hi=9 rcv=3, plain)", fs)
		}
		if fs := dpFrames(dpFill(l, time.Now())); len(fs) != 0 {
			t.Fatalf("the next Fill placed %v, want nothing (one stand-in per lane)", fs)
		}
		s.mu.Lock()
		owed := l.goOwed
		s.mu.Unlock()
		if !owed {
			t.Fatal("the stand-in cleared the go frame's debt")
		}
		fp.set(func(f *dpPort) { f.relRoom = wire.RelWindow })
		fs = dpFrames(dpFill(l, time.Now()))
		if len(fs) != 1 || fs[0].typ != wire.TypePack || !fs[0].rel || fs[0].flags != 0 {
			t.Fatalf("with REL room: %v, want the go frame REL{PACK}", fs)
		}
		dpEnd(s, nil)
	})
	t.Run("stream batch without control room: nothing else", func(t *testing.T) {
		s := dpSession(dpOpt{})
		l, _ := dpAddLane(s, 7, true, false)
		s.mu.Lock()
		l.goOwed = true
		s.mu.Unlock()
		if _, err := s.WriteTo(make([]byte, 100)); err != nil {
			t.Fatal(err)
		}
		// A stream batch whose control arena has less room than a PACK
		// but is not full (RelRoom is 0 on a stream batch).
		b := carrier.NewBatch(0)
		b.Reset(time.Now())
		msg := make([]byte, wire.MaxMsg)
		short := carrier.ControlArena - wire.PackLen/2
		for left := short; left > 0; {
			n := min(left, wire.RstFixedLen+wire.MaxMsg)
			if !b.AddRst(99, &wire.Rst{Msg: msg[:n-wire.RstFixedLen]}) {
				t.Fatal("AddRst refused before the arena was short")
			}
			left -= n
		}
		if b.Full() || b.Datagram() || b.RelRoom() != 0 {
			t.Fatalf("batch full %v, datagram %v, REL room %d: want a stream batch, not full", b.Full(), b.Datagram(), b.RelRoom())
		}
		n := b.Len()
		(*plane)(l).Fill(nil, b)
		if b.Len() != n {
			t.Fatalf("a Fill whose stream batch refused the go PACK appended %d frames", b.Len()-n)
		}
		s.mu.Lock()
		owed := l.goOwed
		s.mu.Unlock()
		if !owed {
			t.Fatal("the go frame is no longer owed")
		}
		b.ReleaseRefs()
		fs := dpFrames(dpFill(l, time.Now()))
		if len(fs) < 2 || fs[0].typ != wire.TypePack || fs[0].rel || fs[len(fs)-1].typ != wire.TypeDgram {
			t.Fatalf("next Fill: %v, want the go frame first, then the queued DGRAM", fs)
		}
		dpEnd(s, nil)
	})
	t.Run("full batch: nothing else", func(t *testing.T) {
		s := dpSession(dpOpt{})
		l, _ := dpAddLane(s, 7, true, true)
		s.mu.Lock()
		l.goOwed = true
		s.mu.Unlock()
		if _, err := s.WriteTo(make([]byte, 100)); err != nil {
			t.Fatal(err)
		}
		b := carrier.NewBatch(0)
		b.Reset(time.Now())
		b.SetDatagram(1400, wire.RelWindow)
		for seq := uint64(0); !b.Full(); seq++ {
			if !b.AddDgram(99, seq, nil, nil) {
				t.Fatal("AddDgram refused before the batch was full")
			}
		}
		n := b.Len()
		(*plane)(l).Fill(nil, b)
		if b.Len() != n {
			t.Fatalf("a Fill on a full batch appended %d frames", b.Len()-n)
		}
		s.mu.Lock()
		owed := l.goOwed
		s.mu.Unlock()
		if !owed {
			t.Fatal("the go frame is no longer owed after a Fill on a full batch")
		}
		b.ReleaseRefs()
		fs := dpFrames(dpFill(l, time.Now()))
		if len(fs) < 2 || fs[0].typ != wire.TypePack || !fs[0].rel || fs[len(fs)-1].typ != wire.TypeDgram {
			t.Fatalf("next Fill: %v, want the go frame first, then the queued DGRAM", fs)
		}
		dpEnd(s, nil)
	})
}

// TestLaneHandleFromView (M3-D4): every session frame a lane places
// carries its view's handle — DATA, ACK, FIN, SCHED, RST, DGRAM, PACK — and
// a lane without a carrier view (a fake port) keeps wire.SessionHandle.
// End to end (several sessions on one trunk, each frame's handle on the
// wire) TestLaneHandleFromViewE2E.
func TestLaneHandleFromView(t *testing.T) {
	s := stSession(stOpt{})
	l, _ := stAddLane(s, 7, true)
	if h := l.Handle(); h != wire.SessionHandle {
		t.Fatalf("a lane without a view: handle %d, want %d", h, wire.SessionHandle)
	}
	stEnd(s, nil)

	s = stSession(stOpt{})
	l, fp := stAddLane(s, 7, true)
	l.port = &wp10StPort{stPort: fp, h: 9} // a view of handle 9
	if _, err := s.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.st.peerLimit = 1 << 20
	s.st.ackGen++ // an ACK owed on the duty lane
	s.st.fin.requested, s.st.fin.off = true, s.st.resEnd
	s.mu.Unlock()
	_, b := stFill(l, time.Now())
	seen := map[wire.Type]bool{}
	for i := range b.Len() {
		f := b.Frame(i)
		seen[f.Header.Type] = true
		if f.Header.Handle != 9 {
			t.Fatalf("frame %v carries handle %d, want the view's 9", f.Header.Type, f.Header.Handle)
		}
	}
	b.ReleaseRefs()
	if !seen[wire.TypeData] || !seen[wire.TypeAck] || !seen[wire.TypeFin] {
		t.Fatalf("frames %v: want DATA, ACK and FIN", seen)
	}
	stEnd(s, nil)

	p := dpSession(dpOpt{})
	pl, dfp := dpAddLane(p, 7, true, true)
	pl.port = &wp10DpPort{dpPort: dfp, h: 11}
	if _, err := p.WriteTo(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.st.ackGen++
	p.mu.Unlock()
	pb := carrier.NewBatch(0)
	pb.Reset(time.Now())
	pb.SetDatagram(1400, wire.RelWindow)
	(*plane)(pl).Fill(nil, pb)
	n := 0
	for i := range pb.Len() {
		f := pb.Frame(i)
		if f.Header.Handle != 11 {
			t.Fatalf("packet frame %v carries handle %d, want 11", f.Header.Type, f.Header.Handle)
		}
		n++
	}
	if n < 2 {
		t.Fatalf("packet Fill placed %d frames, want a PACK and a DGRAM", n)
	}
	dpEnd(p, nil)
}

// wp10StPort and wp10DpPort are the stream and packet test ports of a view
// of handle h (the carrier's Conn.Handle).
type wp10StPort struct {
	*stPort
	h uint32
}

func (p *wp10StPort) Handle() uint32 { return p.h }

type wp10DpPort struct {
	*dpPort
	h uint32
}

func (p *wp10DpPort) Handle() uint32 { return p.h }

// wp10Has reports whether fs holds a frame of type typ.
func wp10Has(fs []stFrame, typ wire.Type) bool {
	for _, f := range fs {
		if f.typ == typ {
			return true
		}
	}
	return false
}
