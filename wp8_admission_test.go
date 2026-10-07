package rendr

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPassiveBudgetNegotiated_L37: the passive accepts a datagram carrier's
// frame budget as cmtu_acc = min(the dialer's offer, its own transport's
// limit) and fixes it before the carrier starts (M2-D50, §A5.4; the root
// half of Revision 1's R1-34 move): the transport's receive limit follows
// it (SetBudget → SetLimit, R1-6). A QUIC-like transport (limit 1152) takes
// an offer of 1000 as 1000 — not its own 1152, which a 1000-byte path would
// black-hole — and an offer of 1400 as 1152; a transport of unknown limit
// (HandlePacket's 65,507) takes any offer. The accepted MaxPayload follows
// M2-D49's passive rule (packetAccept; the L37 worked example included).
// The end-to-end half (PendingPacket.MaxPayload, the dialer's SetBudget)
// passes at integration 2.
func TestPassiveBudgetNegotiated_L37(t *testing.T) {
	for _, tc := range []struct {
		name         string
		limit        int
		offer        uint32
		pmtu         uint16
		wantCmtu     int
		wantMaxPayld int
	}{
		{"QUIC-like transport, smaller offer", 1152, 1000, 975, 1000, 975},
		{"QUIC-like transport, larger offer", 1152, 1400, 1375, 1152, 1127},
		{"unknown limit", wire.MaxDatagram, 1400, 1375, 1400, 1375},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, nil)
				ln := wpListen(t, rt, ListenConfig{})
				w := newWDLink(t, rt, ln, tc.limit)
				d := w.dial(wpInst(0xb1), 7)
				d.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(1), 1, tc.offer, tc.pmtu))
				d.expectH2(rt)
				synctest.Wait()
				if got := w.io(0).lastLimit(); got != tc.wantCmtu {
					t.Fatalf("receive limit %d after the admission, want cmtu_acc %d", got, tc.wantCmtu)
				}
				if st := rt.Status(); st.AcceptBacklog != [2]int{0, 1} || st.Sessions.Pending != 1 {
					t.Fatalf("the packet OPEN was not admitted: %+v", st)
				}
				o := wire.Open{Kind: wire.KindDatagram, Window: tc.offer, PMTU: tc.pmtu}
				if cm, mp := packetAccept(&o, tc.limit, rt.eff.cfg.Packet.MaxPayload); cm != tc.wantCmtu || mp != tc.wantMaxPayld {
					t.Fatalf("packetAccept = %d, %d; want %d, %d", cm, mp, tc.wantCmtu, tc.wantMaxPayld)
				}
				d.close()
				rt.Close()
			})
		})
	}
	// M2-D49's passive table.
	for _, tc := range []struct {
		name                  string
		window, limit, ownMax int
		pmtu                  uint16
		cmtu, maxPayload      int
	}{
		{"stream carrier", 0, 0, 65507, 1250, 0, 1250},
		{"stream carrier, own limit", 0, 0, 1000, 1250, 0, 1000},
		{"L37: selector offer 1100 on MTU 1125, own 1250", 1125, wire.MaxDatagram, 1250, 1100, 1125, 1100},
		{"L37: bond with a stream factory offers 65,507, own 1250", 1425, wire.MaxDatagram, 1250, 65507, 1425, 1250},
		{"datagram offer fits, transport smaller", 1400, 1152, 65507, 1375, 1152, 1127},
		{"offer beyond the datagram budget is kept", 1400, 1152, 65507, 65507, 1152, 65507},
		{"own limit below the budget", 1400, 65507, 600, 1375, 1400, 600},
	} {
		o := wire.Open{Kind: wire.KindDatagram, Window: uint32(tc.window), PMTU: tc.pmtu}
		if cm, mp := packetAccept(&o, tc.limit, tc.ownMax); cm != tc.cmtu || mp != tc.maxPayload {
			t.Errorf("%s: packetAccept = %d, %d; want %d, %d", tc.name, cm, mp, tc.cmtu, tc.maxPayload)
		}
	}
	// The JOIN half (§A5.4: cmtu_acc = min(rxNext, io.Limit())): admitJoin
	// bounds a datagram carrier's offer by its transport's limit before the
	// session fixes the budget; a stream carrier's rxNext (an offset) and
	// an offer out of range (refused by the session) pass unchanged. The
	// end-to-end row (a JOIN offering 1400 on a 1152 transport is answered
	// JOIN_ACK cmtu_acc 1152) passes at integration 2.
	for _, tc := range []struct {
		name   string
		rxNext uint64
		kind   wire.CarrierKind
		limit  int
		want   uint64
	}{
		{"QUIC-like transport, larger offer", 1400, wire.KindDatagram, 1152, 1152},
		{"QUIC-like transport, smaller offer", 1000, wire.KindDatagram, 1152, 1000},
		{"unknown limit", 1400, wire.KindDatagram, wire.MaxDatagram, 1400},
		{"stream carrier: rxNext is an offset", 1 << 40, wire.KindStream, 0, 1 << 40},
		{"stream carrier of a packet session", 0, wire.KindStream, 0, 0},
		{"offer below the floor stays refused", wire.MinFrameBudget - 1, wire.KindDatagram, 1152, wire.MinFrameBudget - 1},
		{"offer above MaxDatagram stays refused", wire.MaxDatagram + 1, wire.KindDatagram, 1152, wire.MaxDatagram + 1},
	} {
		if got := joinOffer(tc.rxNext, tc.kind, tc.limit); got != tc.want {
			t.Errorf("%s: joinOffer(%d, %v, %d) = %d, want %d", tc.name, tc.rxNext, tc.kind, tc.limit, got, tc.want)
		}
	}
}

// TestOpenKindMismatchRefused: an OPEN routed to an existing session of
// the other kind (the same dialer instance and SID) is refused BAD_REQUEST
// CodeBadKind on its own carrier and never attached (M2 design §A3.5;
// invariant 6: the carrier that violates the protocol is refused, the
// session survives). A packet OPEN — over a datagram flow or over a stream
// carrier — meets a pending stream session, and a stream OPEN meets a
// pending packet session; each existing session keeps its backlog slot and
// its first carrier, which then receives its verdict. Attaching a datagram
// carrier to a stream session would make the stream session's writer put
// an ACK into a datagram batch, a panic on a carrier goroutine.
func TestOpenKindMismatchRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		hub := rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "kind"})
		defer hub.Close()
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromPacketConn(hub.PacketConn())}})
		inst := wpInst(0xb6)

		// A pending stream session; a packet OPEN of its key on a datagram
		// flow and on a stream carrier.
		ss := wpConnect(t, ln, inst, 1)
		ss.hello(rt)
		ss.send(wire.TypeOpen, 0, wpOpen(wpSID(20), wire.KindStream, 1, nil))
		synctest.Wait()
		g := wdHubDial(t, hub, inst, 2)
		g.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(20), 1, 1223, 1198))
		g.expectH2(rt)
		if a := g.expectOpenAck(wire.StatusBadRequest, wire.CodeBadKind); a.Window != 0 {
			t.Fatalf("refusal of a packet OPEN on a stream session: %+v", a)
		}
		sp := wpConnect(t, ln, inst, 3)
		sp.hello(rt)
		sp.send(wire.TypeOpen, 0, wdPacketOpen(wpSID(20), 1, 0, 1127))
		sp.expectOpenAck(wire.StatusBadRequest, wire.CodeBadKind)

		// A pending packet session; a stream OPEN of its key.
		pg := wdHubDial(t, hub, inst, 4)
		pg.sendH1(wire.TypeOpen, wdPacketOpen(wpSID(21), 1, 1223, 1198))
		pg.expectH2(rt)
		synctest.Wait()
		ps := wpConnect(t, ln, inst, 5)
		ps.hello(rt)
		ps.send(wire.TypeOpen, 0, wpOpen(wpSID(21), wire.KindStream, 1, nil))
		ps.expectOpenAck(wire.StatusBadRequest, wire.CodeBadKind)

		synctest.Wait()
		if st := rt.Status(); st.AcceptBacklog != [2]int{1, 1} || st.Sessions.Pending != 2 {
			t.Fatalf("the existing sessions after the refusals: %+v", st)
		}
		pc, err := ln.Accept(context.Background())
		if err != nil || pc.ID() != SessionID(wpSID(20)) {
			t.Fatalf("Accept = %v, %v; want the stream session", pc, err)
		}
		if err := pc.Reject(5, "s"); err != nil {
			t.Fatal(err)
		}
		ss.expectOpenAck(wire.StatusRejected, 5)
		pp, err := ln.AcceptPacket(context.Background())
		if err != nil || pp.ID() != SessionID(wpSID(21)) {
			t.Fatalf("AcceptPacket = %v, %v; want the packet session", pp, err)
		}
		if err := pp.Reject(6, "p"); err != nil {
			t.Fatal(err)
		}
		pg.expectOpenAck(wire.StatusRejected, 6)
		for _, d := range []*wpDialer{ss, sp, ps} {
			d.close()
		}
		g.close()
		pg.close()
		rt.Close()
		wpNoState(t, rt)
		wdNoFlowRecords(t, rt)
	})
}

// TestDuplicateOpenBudget: the opening race sends a packet session's OPEN
// on more than one carrier (plan:338, JoinStagger); a carrier that routes
// to the existing pending session gets its own budget — min(its own offer,
// its own transport's limit) — before AttachOpen takes it (Revision 1,
// R1-5), so a carrier of another kind or MTU is never configured with the
// first carrier's values. Both carriers belong to one pending packet
// session holding one backlog slot.
func TestDuplicateOpenBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		w := newWDLink(t, rt, ln, 1300)
		sid := wpSID(2)
		d1 := w.dial(wpInst(0xb2), 1)
		d1.sendH1(wire.TypeOpen, wdPacketOpen(sid, 1, 1400, 1375))
		d1.expectH2(rt)
		d2 := w.dial(wpInst(0xb2), 2)
		d2.sendH1(wire.TypeOpen, wdPacketOpen(sid, 1, 1100, 1375))
		d2.expectH2(rt)
		synctest.Wait()
		if a, b := w.io(0).lastLimit(), w.io(1).lastLimit(); a != 1300 || b != 1100 {
			t.Fatalf("budgets %d and %d, want 1300 (offer 1400, limit 1300) and 1100 (offer 1100)", a, b)
		}
		if st := rt.Status(); st.AcceptBacklog != [2]int{0, 1} || st.Sessions.Pending != 1 || st.Handshakes != 0 {
			t.Fatalf("two OPEN carriers of one session: %+v", st)
		}
		d1.close()
		d2.close()
		rt.Close()
	})
}

// TestPacketOpenCarrierKind: a datagram carrier's OPEN is judged by the
// carrier's kind before any state exists (M2 design §A3.5): a stream OPEN
// on a datagram carrier is BAD_REQUEST CodeBadKind; a packet OPEN without
// a cmtu offer (window 0) on it, or with a pmtu out of range, is
// BAD_REQUEST CodeBadValue. The refusal is the datagram verdict
// REL{FirstCseq, OPEN_ACK} after H2 (M2-D21); nothing remains afterwards.
func TestPacketOpenCarrierKind(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		code    uint32
	}{
		{"stream OPEN", wpOpen(wpSID(3), wire.KindStream, 1, nil), wire.CodeBadKind},
		{"packet OPEN without a budget offer", wdPacketOpen(wpSID(3), 1, 0, 1127), wire.CodeBadValue},
		{"packet OPEN with pmtu 511", wdPacketOpen(wpSID(3), 1, 1152, 511), wire.CodeBadValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, nil)
				ln := wpListen(t, rt, ListenConfig{})
				w := newWDLink(t, rt, ln, 0)
				d := w.dial(wpInst(0xb3), 3)
				d.sendH1(wire.TypeOpen, tc.payload)
				d.expectH2(rt)
				if a := d.expectOpenAck(wire.StatusBadRequest, tc.code); a.Window != 0 || len(a.Msg) != 0 {
					t.Fatalf("non-canonical refusal %+v", a)
				}
				time.Sleep(3 * time.Second) // the verdict's repetition window (2 s) ends
				synctest.Wait()
				wpNoState(t, rt)
				d.close()
				rt.Close()
			})
		})
	}
}

// TestPacketOpenOnStreamCarrier: a well-formed packet OPEN on a stream
// carrier (its fallback carrier, plan:125) is admitted as a packet session
// — the M1 pin (CodeBadKind) flips with M2 (§A8.7). It waits in the packet
// backlog: Accept does not return it, AcceptPacket does, and Reject
// answers the dialer OPEN_ACK(REJECTED) on that carrier.
func TestPacketOpenOnStreamCarrier(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		d := wpConnect(t, ln, wpInst(0xb4), 4)
		d.hello(rt)
		sid := wpSID(4)
		d.send(wire.TypeOpen, 0, wdPacketOpen(sid, 1, 0, 1127))
		synctest.Wait()
		if st := rt.Status(); st.AcceptBacklog != [2]int{0, 1} || st.Sessions.Pending != 1 {
			t.Fatalf("the packet OPEN was not admitted into the packet backlog: %+v", st)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		if pc, err := ln.Accept(ctx); pc != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Accept returned a packet session: %v, %v", pc, err)
		}
		cancel()
		pp, err := ln.AcceptPacket(context.Background())
		if err != nil || pp.ID() != SessionID(sid) || pp.PeerInstance() != InstanceID(wpInst(0xb4)) || pp.Mode() != ModeSelector {
			t.Fatalf("AcceptPacket = %+v, %v", pp, err)
		}
		if err := pp.Reject(77, "no"); err != nil {
			t.Fatalf("Reject: %v", err)
		}
		if a := d.expectOpenAck(wire.StatusRejected, 77); string(a.Msg) != "no" {
			t.Fatalf("OPEN_ACK %+v", a)
		}
		d.close()
		synctest.Wait()
		if st := rt.Status(); st.AcceptBacklog != [2]int{} || st.Sessions.Pending != 0 {
			t.Fatalf("after Reject: %+v", st)
		}
		wdNoFlowRecords(t, rt) // the ended session's flow record went with it
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestPacketOpenPools_L48 (backlog half): each session kind has its own
// AcceptBacklog (plan §4 "每个 listener、每种会话类型"): with AcceptBacklog
// 1 one pending stream session and one pending packet session are both
// admitted, a second OPEN of either kind is answered CAPACITY(CodeBacklog),
// Status.AcceptBacklog counts both kinds apart, Accept returns only the
// stream session and AcceptPacket only the packet session. (The flood half
// — a packet-OPEN flood from the victim's own source IP over FromPacketConn
// while Accept stalls, the victim's failover JOIN completing within 1 s —
// needs working packet sessions and passes at integration 2.)
func TestPacketOpenPools_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{AcceptBacklog: 1})
		inst := wpInst(0xb5)
		open := func(id uint32, sid [16]byte, payload []byte) *wpDialer {
			d := wpConnect(t, ln, inst, id)
			d.hello(rt)
			d.send(wire.TypeOpen, 0, payload)
			return d
		}
		ds := open(1, wpSID(10), wpOpen(wpSID(10), wire.KindStream, 1, nil))
		dp := open(2, wpSID(11), wdPacketOpen(wpSID(11), 1, 0, 1127))
		synctest.Wait()
		if st := rt.Status(); st.AcceptBacklog != [2]int{1, 1} || st.Sessions.Pending != 2 {
			t.Fatalf("one pending session of each kind: %+v", st)
		}
		d3 := open(3, wpSID(12), wdPacketOpen(wpSID(12), 1, 0, 1127))
		d3.expectOpenAck(wire.StatusCapacity, wire.CodeBacklog)
		d4 := open(4, wpSID(13), wpOpen(wpSID(13), wire.KindStream, 1, nil))
		d4.expectOpenAck(wire.StatusCapacity, wire.CodeBacklog)
		pc, err := ln.Accept(context.Background())
		if err != nil || pc.ID() != SessionID(wpSID(10)) {
			t.Fatalf("Accept = %v, %v; want the stream session", pc, err)
		}
		pp, err := ln.AcceptPacket(context.Background())
		if err != nil || pp.ID() != SessionID(wpSID(11)) {
			t.Fatalf("AcceptPacket = %v, %v; want the packet session", pp, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if _, err := ln.AcceptPacket(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a second AcceptPacket: %v", err)
		}
		for _, d := range []*wpDialer{ds, dp, d3, d4} {
			d.close()
		}
		rt.Close()
		wpNoState(t, rt)
		wdNoFlowRecords(t, rt)
	})
}

// TestHandlePacketOwnership_L57 (error paths and the closes; M2-D57): on
// every synchronous error — a nil conn, a nil peer, a peer whose String
// panics, a closed Listener (unlike Handle) — HandlePacket returns an error
// and never closes the caller's conn. On success the Listener owns it: a
// handshake that never sees a valid first datagram closes it exactly once
// at Handshake.Timeout, and one evicted from a full handshake table
// (Handshake.MaxConcurrent) exactly once at once.
func TestHandlePacketOwnership_L57(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{Handshake: HandshakeLimits{MaxConcurrent: 1}}, &testhooks.Overrides{HandshakeTimeout: 2 * time.Second})
		ln := wpListen(t, rt, ListenConfig{})
		ends := make(chan net.PacketConn, 4)
		peers := make(chan net.Addr, 4)
		link := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: "own", Accept: func(pc net.PacketConn, peer net.Addr) error {
			ends <- pc
			peers <- peer
			return nil
		}})
		defer link.Close()
		conn := func() (*countPC, net.Addr) {
			if _, _, err := link.Dial(context.Background()); err != nil {
				t.Fatal(err)
			}
			return &countPC{PacketConn: <-ends}, <-peers
		}

		a, peer := conn()
		if err := ln.HandlePacket(nil, peer); !errors.Is(err, errNilPacketConn) {
			t.Fatalf("nil conn: %v", err)
		}
		if err := ln.HandlePacket(a, nil); !errors.Is(err, errNilPeer) {
			t.Fatalf("nil peer: %v", err)
		}
		if err := ln.HandlePacket(a, panicAddr{}); err == nil {
			t.Fatal("a peer whose String panics was accepted")
		}
		if n := a.closes.Load(); n != 0 || rt.Status().Handshakes != 0 {
			t.Fatalf("a refused conn was closed %d times (handshakes %d)", n, rt.Status().Handshakes)
		}

		// Success: the Listener owns the conn; no H1 → closed once at the
		// handshake deadline.
		if err := ln.HandlePacket(a, peer); err != nil {
			t.Fatal(err)
		}
		if rt.Status().Handshakes != 1 {
			t.Fatal("no handshake slot taken")
		}
		// A second conn evicts the first (MaxConcurrent 1): closed at once.
		b, peerB := conn()
		if err := ln.HandlePacket(b, peerB); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if na, nb, ev := a.closes.Load(), b.closes.Load(), rt.Status().HandshakeEvictions; na != 1 || nb != 0 || ev != 1 {
			t.Fatalf("eviction: closes %d and %d, evictions %d; want 1, 0, 1", na, nb, ev)
		}
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if na, nb := a.closes.Load(), b.closes.Load(); na != 1 || nb != 1 {
			t.Fatalf("after the handshake deadline: closes %d and %d, want 1 and 1", na, nb)
		}

		// A closed Listener refuses, and the conn stays the caller's.
		c, peerC := conn()
		ln.Close()
		if err := ln.HandlePacket(c, peerC); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed Listener: %v", err)
		}
		synctest.Wait()
		if n := c.closes.Load(); n != 0 {
			t.Fatalf("HandlePacket on a closed Listener closed the caller's conn %d times", n)
		}
		c.Close()
		rt.Close()
		wpNoState(t, rt)
	})
}
