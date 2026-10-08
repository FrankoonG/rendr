package udpflow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// badDatagrams are datagrams of unknown flows that must create no state
// (plan:324, L58): each is dropped and counted, never answered.
func badDatagrams() map[string][]byte {
	const id = 0x51
	valid := h1(id, wire.TypeOpen, 3)
	m := map[string][]byte{}
	m["short"] = []byte{wire.FlowVersion, 1, 2, 3}
	bad := append([]byte(nil), valid...)
	bad[0] = 3
	m["flow version"] = bad
	zero := append([]byte(nil), valid...)
	clear(zero[1:wire.FlowHeaderLen])
	m["flow 0"] = zero
	m["header only"] = dg(id)
	m["junk"] = dg(id, bytes.Repeat([]byte{0x5a}, 100))
	m["preface only"] = dg(id, prefaceBytes(wire.KindDatagram, 3))
	crc := append([]byte(nil), valid...)
	crc[len(crc)-1] ^= 1
	m["bad CRC"] = crc
	m["trailing byte"] = append(append([]byte(nil), valid...), 0)
	m["two frames"] = append(append([]byte(nil), valid...), pingFrame(9)...)
	pre := prefaceBytes(wire.KindDatagram, 3)
	m["wrong fseq"] = wire.AppendFrame(dg(id, pre), h1Header(wire.TypeOpen, wire.PrefaceFseq(pre)+1), h1Payload(wire.TypeOpen, wire.FirstCseq))
	m["wrong cseq"] = wire.AppendFrame(dg(id, pre), h1Header(wire.TypeOpen, wire.PrefaceFseq(pre)), h1Payload(wire.TypeOpen, wire.FirstCseq+1))
	var fin [wire.RelHeadLen + wire.FinLen]byte
	wire.PutRelHead(fin[:], &wire.RelHead{Cseq: wire.FirstCseq, Type: wire.TypeFin, Handle: wire.SessionHandle})
	m["REL FIN"] = wire.AppendFrame(dg(id, pre), wire.Header{Type: wire.TypeRel, Fseq: wire.PrefaceFseq(pre)}, fin[:])
	var ping [wire.PingFixedLen + 8]byte
	wire.PutPing(ping[:], &wire.Ping{ID: 1, Pad: 8})
	m["padded PING"] = wire.AppendFrame(dg(id, pre), wire.Header{Type: wire.TypePing, Fseq: wire.PrefaceFseq(pre)}, ping[:])
	var pong [wire.PingFixedLen]byte
	wire.PutPing(pong[:], &wire.Ping{ID: 1})
	m["PONG"] = wire.AppendFrame(dg(id, pre), wire.Header{Type: wire.TypePong, Fseq: wire.PrefaceFseq(pre)}, pong[:])
	spre := prefaceBytes(wire.KindStream, 3)
	m["stream kind"] = wire.AppendFrame(dg(id, spre), h1Header(wire.TypeOpen, wire.PrefaceFseq(spre)), h1Payload(wire.TypeOpen, wire.FirstCseq))
	ack := make([]byte, wire.PrefaceLen)
	wire.PutPrefaceAck(ack, &wire.PrefaceAck{Status: wire.PrefaceOK, Instance: [16]byte{1}, CarrierID: 3})
	m["PREFACE_ACK"] = wire.AppendFrame(dg(id, ack), h1Header(wire.TypeOpen, wire.PrefaceFseq(ack)), h1Payload(wire.TypeOpen, wire.FirstCseq))
	return m
}

func TestFlowBadDatagramsDropped_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		want := uint64(0)
		for name, b := range badDatagrams() {
			h.c.send(b, udpAddr(2, 1000))
			synctest.Wait()
			want++
			if st := h.s.Stats(); st.Dropped != want || st.Flows != 0 {
				t.Fatalf("%s: Stats %+v, want Dropped %d and no flow", name, st, want)
			}
		}
		h.c.send(nil, udpAddr(2, 1000)) // an empty datagram
		h.c.send(h1(0x52, wire.TypeOpen, 3), otherAddr{})
		h.c.send(make([]byte, wire.MaxDatagram+5), udpAddr(2, 1000)) // fills the read buffer: truncated
		synctest.Wait()
		want += 3
		st := h.s.Stats()
		if st.Dropped != want || st.Truncated != 1 || st.Flows != 0 || st.QuotaDrops != 0 {
			t.Fatalf("Stats %+v, want Dropped %d, Truncated 1, no flow", st, want)
		}
		if got := env.Dgram.Dropped.Load(); got != want {
			t.Fatalf("Env.Dgram.Dropped %d, want %d", got, want)
		}
		if n := len(h.admittedFlows()); n != 0 {
			t.Fatalf("%d flows admitted for junk", n)
		}
		if w := h.c.written(); len(w) != 0 {
			t.Fatalf("junk was answered: %d datagrams written", len(w))
		}
		if used := env.Budget.Used(); used != 0 {
			t.Fatalf("Budget holds %d bytes for junk", used)
		}
		// The control: a valid H1 creates a flow, its H1 first in the inbox.
		valid := h1(0x53, wire.TypeOpen, 3)
		h.c.send(valid, udpAddr(2, 1000))
		synctest.Wait()
		f := h.last()
		if f == nil || f.ID() != 0x53 {
			t.Fatal("a valid H1 created no flow")
		}
		b, src, ev := readOne(t, f, time.Second)
		if !bytes.Equal(b, valid[wire.FlowHeaderLen:]) || ev != carrier.ReadOK || src.AP != apOf(2, 1000) {
			t.Fatalf("H1 read back: %d bytes, event %d, source %v", len(b), ev, src)
		}
		// A known flow's datagram with the flow header alone is dropped at
		// the source: nothing reaches the inbox.
		h.c.send(dg(0x53), udpAddr(2, 1000))
		synctest.Wait()
		if st := h.s.Stats(); st.Dropped != want+1 || st.InboxDrops != 0 {
			t.Fatalf("header only on a known flow: Stats %+v, want Dropped %d", st, want+1)
		}
		expectNoRead(t, f, time.Millisecond)
	})
}

func TestFlowFloodBounded_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{MaxFlows: 64})
		defer h.shutdown()
		const liveID = 0xfeed
		var bMu sync.Mutex
		var bAdmitted time.Time
		h.admitFn = func(f *Flow) {
			if f.ID() == 0xb0b {
				bMu.Lock()
				bAdmitted = time.Now()
				bMu.Unlock()
			}
			if f.ID() == liveID {
				f.Admitted() // its session was accepted
				return
			}
			// A handshake reads the H1 and holds a pending session: the
			// flow stays admitting until a positive verdict (M2-D59).
			go func() {
				if _, _, _, err := f.ReadDatagram(nil); err == nil {
					f.Release()
				}
			}()
		}
		h.c.send(h1(liveID, wire.TypeOpen, 1), udpAddr(3, 3000))
		synctest.Wait()
		live := h.last()
		if live == nil {
			t.Fatal("the live flow was not admitted")
		}
		if _, _, ev := readOne(t, live, time.Second); ev != carrier.ReadOK {
			t.Fatalf("live H1: event %d", ev)
		}

		// Phase 1: a flood from IP A — random flow IDs, PREFACE-only
		// datagrams and valid OPEN H1s — interleaved with the live flow's
		// traffic, and one H1 from IP B in the middle.
		var bSent time.Time
		received := 0
		for i := range 200 {
			junk := dg(uint64(0x900000+i), bytes.Repeat([]byte{byte(i)}, 1+i%50))
			h.c.send(junk, udpAddr(10, uint16(5000+i)))
			h.c.send(dg(uint64(0x800000+i), prefaceBytes(wire.KindDatagram, uint32(i+1))), udpAddr(10, uint16(5000+i)))
			h.c.send(h1(uint64(0x700000+i), wire.TypeOpen, uint32(i+1)), udpAddr(10, uint16(5000+i)))
			if i%2 == 0 {
				h.c.send(dg(liveID, pingFrame(uint32(i))), udpAddr(3, 3000))
			}
			if i == 100 {
				h.c.send(h1(0xb0b, wire.TypeOpen, 9), udpAddr(11, 6000))
				bSent = time.Now()
			}
			synctest.Wait()
			for {
				if err := live.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				if _, _, _, err := live.ReadDatagram(nil); err != nil {
					break
				}
				live.Release()
				received++
			}
			if err := live.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
		perIP := map[byte]int{}
		var bFlow *Flow
		for _, f := range h.admittedFlows() {
			perIP[f.ip.As4()[3]]++
			if f.ID() == 0xb0b {
				bFlow = f
			}
		}
		if perIP[10] != DefaultPerSource {
			t.Fatalf("IP A holds %d admitting flows, want the quota %d (pending sessions count)", perIP[10], DefaultPerSource)
		}
		if bFlow == nil {
			t.Fatal("IP B's H1 was not admitted during the flood")
		}
		bMu.Lock()
		bAt := bAdmitted
		bMu.Unlock()
		if d := bAt.Sub(bSent); d < 0 || d > time.Second {
			t.Fatalf("IP B admitted %v after its H1, want ≤ 1 s", d)
		}
		if received < 90 { // 100 sent: ≥ 90 % of the baseline
			t.Fatalf("the live flow received %d of 100 datagrams during the flood", received)
		}
		st := h.s.Stats()
		if st.Flows != 34 || st.Admitting != 33 || st.QuotaDrops != 200-DefaultPerSource {
			t.Fatalf("after phase 1: Stats %+v, want 34 flows, 33 admitting, %d quota drops", st, 200-DefaultPerSource)
		}

		// Phase 2: valid H1s from four more addresses: the table stops at
		// MaxFlows.
		for g := range byte(4) {
			for i := range 40 {
				h.c.send(h1(uint64(0x600000+int(g)<<12+i), wire.TypeJoin, uint32(i+1)), udpAddr(20+g, uint16(7000+i)))
			}
			synctest.Wait()
			if n := h.s.Stats().Flows; n > 64 {
				t.Fatalf("%d flows, above MaxFlows 64", n)
			}
		}
		if st := h.s.Stats(); st.Flows != 64 {
			t.Fatalf("after phase 2: %d flows, want MaxFlows 64", st.Flows)
		}
	})
}

func TestFlowsReleased_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		for i := range 256 {
			id := uint64(0x1000 + i)
			h.c.send(h1(id, wire.TypeOpen, uint32(i+1)), udpAddr(byte(1+i%8), uint16(1000+i)))
			synctest.Wait()
			f := h.last()
			if f == nil || f.ID() != id {
				t.Fatalf("cycle %d: no flow", i)
			}
			if i%2 == 0 {
				f.Admitted()
			}
			for k := range 3 {
				h.c.send(dg(id, pingFrame(uint32(k+2))), udpAddr(byte(1+i%8), uint16(1000+i)))
			}
			synctest.Wait()
			readOne(t, f, time.Second) // the H1; two pings stay queued
			readOne(t, f, time.Second)
			held, _, _, err := f.ReadDatagram(nil) // held while Close runs
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
			// Close never releases the datagram the reader holds (it may still
			// be in use): it stays charged and intact until the reader's
			// Release or next ReadDatagram.
			if want := pingFrame(3); !bytes.Equal(held, want) || env.Budget.Used() == 0 {
				t.Fatalf("cycle %d: Close released the datagram the reader holds (Budget %d)", i, env.Budget.Used())
			}
			if i%2 == 0 {
				if _, _, _, err := f.ReadDatagram(nil); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("read after Close: %v", err)
				}
			} else {
				f.Release()
			}
			if used := env.Budget.Used(); used != 0 {
				t.Fatalf("cycle %d: Budget holds %d bytes after the reader let go", i, used)
			}
		}
		st := h.s.Stats()
		if st.Flows != 0 || st.Admitting != 0 || st.InboxDrops != 0 {
			t.Fatalf("after 256 cycles: Stats %+v, want no flow", st)
		}
		if used := env.Budget.Used(); used != 0 {
			t.Fatalf("after 256 cycles: Budget holds %d bytes", used)
		}
		h.shutdown()
		if used := env.Budget.Used() + env.Stages.Used(); used != 0 {
			t.Fatalf("after Done: %d bytes buffered", used)
		}
		if h.c.closeCount() != 1 {
			t.Fatalf("socket closed %d times", h.c.closeCount())
		}
	})
}

func TestFlowInboxFullDrops_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		h.c.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		h.c.send(h1(2, wire.TypeOpen, 2), udpAddr(2, 1001))
		synctest.Wait()
		fs := h.admittedFlows()
		if len(fs) != 2 {
			t.Fatalf("%d flows", len(fs))
		}
		full, other := fs[0], fs[1]
		readOne(t, full, time.Second)
		readOne(t, other, time.Second)
		// Nobody reads the first flow: its inbox holds Inbox datagrams and
		// tail-drops the rest; the demux goes on routing.
		for i := range DefaultInbox + 88 {
			h.c.send(dg(1, pingFrame(uint32(i+2))), udpAddr(2, 1000))
		}
		h.c.send(dg(2, pingFrame(7)), udpAddr(2, 1001))
		synctest.Wait()
		if b, _, _ := readOne(t, other, time.Second); u32(b[5:9]) != 7 {
			t.Fatal("the other flow got the wrong datagram")
		}
		if st := h.s.Stats(); st.InboxDrops != 88 || env.Dgram.InboxDrops.Load() != 88 {
			t.Fatalf("Stats %+v, want 88 inbox drops", st)
		}
		for i := range DefaultInbox {
			b, _, ev := readOne(t, full, time.Second)
			if ev != carrier.ReadOK || u32(b[5:9]) != uint32(i+2) {
				t.Fatalf("inbox datagram %d: fseq %d, event %d", i, u32(b[5:9]), ev)
			}
		}
		expectNoRead(t, full, time.Second)
	})
}

func TestFlowControlReserve_L16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(0) // the Budget refuses every inbox buffer
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		from := udpAddr(2, 1000)
		h.c.send(h1(1, wire.TypeOpen, 1), from)
		synctest.Wait()
		f := h.last()
		if f == nil {
			t.Fatal("an H1 under memory pressure created no flow")
		}
		readOne(t, f, time.Second)

		rel := wire.AppendFrame(nil, wire.Header{Type: wire.TypeRel, Fseq: 3}, h1Payload(wire.TypeJoin, 2))
		h.c.send(dg(1, dgramFrame(2, 100)), from)              // dropped: carries a DGRAM
		h.c.send(dg(1, rackFrame(2), dgramFrame(3, 10)), from) // dropped: a DGRAM behind a RACK
		h.c.send(dg(1, pingFrame(4)), from)
		h.c.send(dg(1, rel), from)
		h.c.send(dg(1, rackFrame(5), pingFrame(6)), from)
		synctest.Wait()
		if st := h.s.Stats(); st.InboxDrops != 2 {
			t.Fatalf("Stats %+v, want 2 inbox drops (the DGRAMs)", st)
		}
		for _, want := range []wire.Type{wire.TypePing, wire.TypeRel, wire.TypeRack} {
			if b, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK || wire.Type(b[0]) != want {
				t.Fatalf("got %s (event %d), want %s", wire.Type(b[0]), ev, want)
			}
		}
		// The reserve holds four datagrams per flow.
		for i := range 5 {
			h.c.send(dg(1, pingFrame(uint32(10+i))), from)
		}
		synctest.Wait()
		if st := h.s.Stats(); st.InboxDrops != 3 {
			t.Fatalf("Stats %+v, want 3 inbox drops (reserve full)", st)
		}
		for i := range 4 {
			if b, _, _ := readOne(t, f, time.Second); u32(b[5:9]) != uint32(10+i) {
				t.Fatalf("reserve datagram %d: fseq %d", i, u32(b[5:9]))
			}
		}
		expectNoRead(t, f, time.Millisecond)
		if env.Budget.Used() != 0 {
			t.Fatalf("Budget charged %d bytes", env.Budget.Used())
		}
	})
}

func TestFlowRemovalCAS_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{TombstoneTTL: 3 * time.Second})
		defer h.shutdown()
		const id = 0xabc
		h.c.send(h1(id, wire.TypeOpen, 1), udpAddr(2, 1000))
		synctest.Wait()
		old := h.last()
		old.Close()
		time.Sleep(3 * time.Second) // past the tombstone: the ID attaches again (PA-26)
		h.c.send(h1(id, wire.TypeOpen, 2), udpAddr(2, 1000))
		synctest.Wait()
		nf := h.last()
		if nf == old || nf.ID() != id {
			t.Fatal("the ID did not attach again after the tombstone")
		}
		readOne(t, nf, time.Second)
		// A late removal of the dead flow (a racing closer) must not touch
		// the new flow with the same ID (L58).
		h.s.remove(old)
		if st := h.s.Stats(); st.Flows != 1 {
			t.Fatalf("a stale removal removed the new flow: Stats %+v", st)
		}
		h.c.send(dg(id, pingFrame(2)), udpAddr(2, 1000))
		synctest.Wait()
		if _, _, ev := readOne(t, nf, time.Second); ev != carrier.ReadOK {
			t.Fatalf("event %d", ev)
		}
	})
}

func TestFlowStoppedAnswersCapacity_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		h.c.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		synctest.Wait()
		f := h.last()
		readOne(t, f, time.Second)
		h.s.Stop()
		synctest.Wait()
		if n := h.c.closeCount(); n != 0 {
			t.Fatalf("Stop closed the socket under a live flow (%d closes)", n)
		}
		h.c.send(h1(0x77, wire.TypeJoin, 0x4242), udpAddr(5, 5000))
		h.c.send(dg(0x78, bytes.Repeat([]byte{1}, 60)), udpAddr(5, 5001)) // junk: never answered
		synctest.Wait()
		w := h.c.written()
		if len(w) != 1 {
			t.Fatalf("%d datagrams written, want one CAPACITY answer", len(w))
		}
		id, ack := parseAnswer(t, w[0].b)
		if id != 0x77 || ack.Status != wire.PrefaceCapacity || ack.CarrierID != 0x4242 || ack.Instance != testLocal {
			t.Fatalf("answer: flow %x, %+v", id, ack)
		}
		if w[0].from.String() != udpAddr(5, 5000).String() {
			t.Fatalf("answer sent to %v", w[0].from)
		}
		if st := h.s.Stats(); st.Flows != 1 || len(h.admittedFlows()) != 1 {
			t.Fatalf("a stopped source admitted a flow: Stats %+v", st)
		}
		// The accepted flow keeps working.
		h.c.send(dg(1, pingFrame(2)), udpAddr(2, 1000))
		synctest.Wait()
		readOne(t, f, time.Second)
		wb := make([]byte, wire.FlowHeaderLen+5)
		if err := f.WriteDatagram(wb); err != nil {
			t.Fatalf("WriteDatagram on a stopped source: %v", err)
		}
		f.Close()
		<-h.s.Done()
		if n := h.c.closeCount(); n != 1 {
			t.Fatalf("socket closed %d times", n)
		}
		h.s.Abort()
		synctest.Wait()
		if n := h.c.closeCount(); n != 1 {
			t.Fatalf("Abort after the close: socket closed %d times", n)
		}
	})
}

func TestFlowVersionAnswered_L44(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		major := prefaceBytes(wire.KindDatagram, 0x55)
		major[4] = wire.Major + 1
		binary.BigEndian.PutUint32(major[36:40], wire.CRC(major[:36]))
		feat := make([]byte, wire.PrefaceLen)
		wire.PutPreface(feat, &wire.Preface{Kind: wire.KindDatagram, Req: 1 << 7, Instance: [16]byte{3}, CarrierID: 0x66})
		h.c.send(dg(0x11, major, bytes.Repeat([]byte{9}, 30)), udpAddr(2, 1000))
		h.c.send(dg(0x12, feat), udpAddr(2, 1001))
		synctest.Wait()
		w := h.c.written()
		if len(w) != 2 {
			t.Fatalf("%d answers, want 2", len(w))
		}
		for i, want := range []struct {
			id  uint64
			st  wire.PrefaceStatus
			cid uint32
		}{{0x11, wire.PrefaceVersion, 0x55}, {0x12, wire.PrefaceFeature, 0x66}} {
			id, ack := parseAnswer(t, w[i].b)
			if id != want.id || ack.Status != want.st || ack.CarrierID != want.cid || ack.Instance != testLocal {
				t.Fatalf("answer %d: flow %x %+v, want %+v", i, id, ack, want)
			}
		}
		if st := h.s.Stats(); st.Flows != 0 || st.Dropped != 2 {
			t.Fatalf("Stats %+v, want no flow and 2 drops", st)
		}
	})
}

func TestFlowRebindCandidate_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		a, b, c := udpAddr(2, 1000), udpAddr(3, 2000), udpAddr(4, 3000)
		h.c.send(h1(5, wire.TypeOpen, 1), a)
		synctest.Wait()
		f := h.last()
		readOne(t, f, time.Second)
		out := func(n int) fakeDgram {
			w := h.c.written()
			if len(w) != n {
				t.Fatalf("%d datagrams written, want %d", len(w), n)
			}
			return w[n-1]
		}
		wb := append(make([]byte, wire.FlowHeaderLen), 'x', 'y')
		if err := f.WriteDatagram(wb); err != nil {
			t.Fatal(err)
		}
		if d := out(1); d.from.String() != a.String() || !bytes.Equal(d.b, append(dg(5), 'x', 'y')) {
			t.Fatalf("write to %v: % x", d.from, d.b)
		}
		key := func(u *net.UDPAddr) carrier.PeerKey { return carrier.PeerKey{AP: u.AddrPort()} }
		if err := f.WriteDatagramTo(wb, key(b)); err == nil {
			t.Fatal("WriteDatagramTo before any candidate succeeded")
		}
		h.c.send(dg(5, pingFrame(2)), b)
		synctest.Wait()
		if _, src, ev := readOne(t, f, time.Second); ev != carrier.ReadCandidate || src != key(b) {
			t.Fatalf("datagram from a new source: event %d from %v, want a candidate", ev, src)
		}
		if err := f.WriteDatagramTo(wb, key(c)); err == nil {
			t.Fatal("WriteDatagramTo another address than the candidate succeeded")
		}
		if err := f.SetPeer(key(c)); err == nil {
			t.Fatal("SetPeer to another address than the candidate succeeded")
		}
		if err := f.WriteDatagramTo(wb, key(b)); err != nil {
			t.Fatal(err)
		}
		if d := out(2); d.from.String() != b.String() {
			t.Fatalf("challenge sent to %v", d.from)
		}
		if err := f.SetPeer(key(b)); err != nil {
			t.Fatal(err)
		}
		if err := f.WriteDatagram(wb); err != nil {
			t.Fatal(err)
		}
		if d := out(3); d.from.String() != b.String() {
			t.Fatalf("after the rebind: write to %v", d.from)
		}
		h.c.send(dg(5, pingFrame(3)), b)
		h.c.send(dg(5, pingFrame(4)), a)
		synctest.Wait()
		if _, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK {
			t.Fatalf("the new peer's datagram: event %d", ev)
		}
		if _, src, ev := readOne(t, f, time.Second); ev != carrier.ReadCandidate || src != key(a) {
			t.Fatalf("the old address's datagram: event %d from %v", ev, src)
		}
	})
}

func TestFlowTombstone_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{TombstoneTTL: 3 * time.Second, Tombstones: 2})
		defer h.shutdown()
		const id = 0xd00d
		first := h1(id, wire.TypeOpen, 1)
		h.c.send(first, udpAddr(2, 1000))
		synctest.Wait()
		f := h.last()
		f.Close()
		dropped := h.s.Stats().Dropped
		h.c.send(first, udpAddr(2, 1000)) // a late copy (DatagramHub.Replay(i, 0))
		synctest.Wait()
		if st := h.s.Stats(); st.Flows != 0 || st.Dropped != dropped+1 || len(h.admittedFlows()) != 1 {
			t.Fatalf("a late H1 copy of a removed flow: Stats %+v, %d admitted", st, len(h.admittedFlows()))
		}
		time.Sleep(3 * time.Second)
		h.c.send(first, udpAddr(2, 1000))
		synctest.Wait()
		if st := h.s.Stats(); st.Flows != 1 {
			t.Fatalf("after the TTL the ID did not attach again: Stats %+v", st)
		}
		h.last().Close()

		// At most Tombstones IDs are remembered, the oldest forgotten first.
		for i := range 3 {
			h.c.send(h1(uint64(0x100+i), wire.TypeOpen, 1), udpAddr(2, 1000))
			synctest.Wait()
			h.last().Close()
		}
		h.c.send(h1(0x100, wire.TypeOpen, 1), udpAddr(2, 1000))
		h.c.send(h1(0x102, wire.TypeOpen, 1), udpAddr(2, 1000))
		synctest.Wait()
		if f := h.last(); f.ID() != 0x100 || h.s.Stats().Flows != 1 {
			t.Fatalf("the oldest tombstone was not forgotten (last flow %x, %d flows)", f.ID(), h.s.Stats().Flows)
		}
	})
}

func TestFlowJoinQuota_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		host := byte(5)
		for i := range DefaultPerSource + 1 {
			h.c.send(h1(uint64(1+i), wire.TypeOpen, 1), udpAddr(host, uint16(1000+i)))
		}
		synctest.Wait()
		if st := h.s.Stats(); st.Flows != DefaultPerSource || st.QuotaDrops != 1 {
			t.Fatalf("OPEN flood: Stats %+v, want %d flows and 1 quota drop", st, DefaultPerSource)
		}
		// The same address's JOINs and probes still pass (R1-21, L48).
		h.c.send(h1(100, wire.TypeJoin, 1), udpAddr(host, 2000))
		h.c.send(h1(101, wire.TypePing, 1), udpAddr(host, 2001))
		synctest.Wait()
		if st := h.s.Stats(); st.Flows != DefaultPerSource+2 {
			t.Fatalf("a JOIN and a probe from the flooded address: Stats %+v", st)
		}
		for i := range DefaultPerSourceJoin - 1 {
			h.c.send(h1(uint64(102+i), wire.TypeJoin, 1), udpAddr(host, uint16(3000+i)))
		}
		synctest.Wait()
		if st := h.s.Stats(); st.Flows != DefaultPerSource+DefaultPerSourceJoin || st.QuotaDrops != 2 {
			t.Fatalf("JOIN quota: Stats %+v, want %d flows and 2 quota drops", st, DefaultPerSource+DefaultPerSourceJoin)
		}
		// A positive verdict frees an OPEN slot; another address has its own quotas.
		h.admittedFlows()[0].Admitted()
		h.c.send(h1(500, wire.TypeOpen, 1), udpAddr(host, 4000))
		h.c.send(h1(501, wire.TypeOpen, 1), udpAddr(host+1, 4000))
		synctest.Wait()
		st := h.s.Stats()
		if st.Flows != DefaultPerSource+DefaultPerSourceJoin+2 || st.Admitting != DefaultPerSource+DefaultPerSourceJoin+1 {
			t.Fatalf("after Admitted: Stats %+v", st)
		}
	})
}

// TestFlowSourceProven_E19 (R-C3-1; M2-D59 as amended): a flow whose
// source answered its OPEN's address check (SourceProven) leaves its IP's
// OPEN quota, so a further OPEN from that address is admitted while the
// proven flow lives on; the release happens once — a repeated
// SourceProven, or the positive verdict's Admitted after it, frees no
// second slot — and the quota's bound still holds for unproven flows.
func TestFlowSourceProven_E19(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{PerSource: 2})
		defer h.shutdown()
		host := byte(6)
		for i := range 3 {
			h.c.send(h1(uint64(1+i), wire.TypeOpen, 1), udpAddr(host, uint16(1000+i)))
		}
		synctest.Wait()
		if st := h.s.Stats(); st.Flows != 2 || st.Admitting != 2 || st.QuotaDrops != 1 {
			t.Fatalf("quota 2: Stats %+v, want 2 flows, 2 admitting, 1 quota drop", st)
		}
		p := h.admittedFlows()[0]
		p.SourceProven()
		p.SourceProven()
		p.Admitted()
		h.c.send(h1(10, wire.TypeOpen, 1), udpAddr(host, 2000))
		h.c.send(h1(11, wire.TypeOpen, 1), udpAddr(host, 2001))
		synctest.Wait()
		if st := h.s.Stats(); st.Flows != 3 || st.Admitting != 2 || st.QuotaDrops != 2 {
			t.Fatalf("after one proven flow: Stats %+v, want 3 flows, 2 admitting, 2 quota drops", st)
		}
	})
}

// TestPacketIOLimitFollowsBudget is the Flow row of M2 design Revision 1,
// R1-6: SetLimit lowers the receive limit applied to inbox datagrams, and
// Limit keeps reporting the transport's capacity.
func TestPacketIOLimitFollowsBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		h.c.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		synctest.Wait()
		f := h.last()
		readOne(t, f, time.Second)
		if f.Limit() != wire.MaxDatagram-wire.FlowHeaderLen || f.ReadSize() != 0 || f.Headroom() != wire.FlowHeaderLen {
			t.Fatalf("Limit %d, ReadSize %d, Headroom %d", f.Limit(), f.ReadSize(), f.Headroom())
		}
		f.SetLimit(1152)
		h.c.send(dg(1, make([]byte, 1153)), udpAddr(2, 1000))
		h.c.send(dg(1, make([]byte, 1152)), udpAddr(2, 1000))
		synctest.Wait()
		if b, _, ev := readOne(t, f, time.Second); ev != carrier.ReadTruncated || b != nil {
			t.Fatalf("1153 rendr bytes: event %d, %d bytes", ev, len(b))
		}
		if b, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK || len(b) != 1152 {
			t.Fatalf("1152 rendr bytes: event %d, %d bytes", ev, len(b))
		}
		if f.Limit() != wire.MaxDatagram-wire.FlowHeaderLen {
			t.Fatalf("Limit changed to %d", f.Limit())
		}
		if env.Budget.Used() != 0 {
			t.Fatalf("Budget holds %d bytes", env.Budget.Used())
		}
	})
}

func TestFlowReadUnblocks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		h.c.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		h.c.send(h1(2, wire.TypeOpen, 2), udpAddr(2, 1001))
		synctest.Wait()
		f, g := h.admittedFlows()[0], h.admittedFlows()[1]
		readOne(t, f, time.Second)
		readOne(t, g, time.Second)

		// A waiting read ends at the deadline set by another goroutine.
		start := time.Now()
		errc := make(chan error)
		go func() {
			_, _, _, err := f.ReadDatagram(nil)
			errc <- err
		}()
		synctest.Wait()
		if err := f.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := <-errc; !errors.Is(err, errDeadlineExceeded) || time.Since(start) != time.Second {
			t.Fatalf("read: %v after %v, want the deadline after 1 s", err, time.Since(start))
		}
		// A past deadline fails at once; a cleared one waits for data.
		if err := f.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := f.ReadDatagram(nil); !errors.Is(err, errDeadlineExceeded) {
			t.Fatalf("past deadline: %v", err)
		}
		if err := f.SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		go func() {
			_, _, _, err := f.ReadDatagram(nil)
			if err == nil {
				f.Release()
			}
			errc <- err
		}()
		synctest.Wait()
		h.c.send(dg(1, pingFrame(2)), udpAddr(2, 1000))
		if err := <-errc; err != nil {
			t.Fatalf("read after a cleared deadline: %v", err)
		}
		// Close wakes a waiting read with net.ErrClosed.
		go func() {
			_, _, _, err := f.ReadDatagram(nil)
			errc <- err
		}()
		synctest.Wait()
		f.Close()
		if err := <-errc; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read across Close: %v", err)
		}
		if err := f.WriteDatagram(make([]byte, 20)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after Close: %v", err)
		}
		// Abort fails every flow's reads and writes.
		if err := g.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		go func() {
			_, _, _, err := g.ReadDatagram(nil)
			errc <- err
		}()
		synctest.Wait()
		h.s.Abort()
		if err := <-errc; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read across Abort: %v", err)
		}
		if err := g.WriteDatagram(make([]byte, 20)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after Abort: %v", err)
		}
	})
}

// tempErr is a transient error of an embedder conn (Temporary()).
type tempErr struct{}

func (tempErr) Error() string   { return "transient" }
func (tempErr) Temporary() bool { return true }
func (tempErr) Timeout() bool   { return false }

func TestSourceForeignReadErrors_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		h.c.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		synctest.Wait()
		f := h.last()
		readOne(t, f, time.Second)

		// Noise backs off 5, 10, 20 ms; a datagram resets the backoff.
		start := time.Now()
		h.c.fail(tempErr{})
		h.c.fail(carrier.ErrNoise)
		h.c.fail(errDeadlineExceeded) // nobody's deadline: noise
		h.c.send(dg(1, pingFrame(2)), udpAddr(2, 1000))
		readOne(t, f, time.Second)
		if d := time.Since(start); d != 35*time.Millisecond {
			t.Fatalf("three noise errors delayed the datagram %v, want 35 ms", d)
		}
		start = time.Now()
		h.c.fail(tempErr{})
		h.c.send(dg(1, pingFrame(3)), udpAddr(2, 1000))
		readOne(t, f, time.Second)
		if d := time.Since(start); d != 5*time.Millisecond {
			t.Fatalf("backoff not reset: %v", d)
		}
		if st := h.s.Stats(); st.ReadErrors != 4 || env.Dgram.ReadErrors.Load() != 4 || st.Flows != 1 {
			t.Fatalf("Stats %+v, want 4 read errors and the flow alive", st)
		}

		// A permanent error stops this source: its flows' reads fail, the
		// socket closes once, Done follows the last flow.
		h.c.fail(errors.New("permanent"))
		synctest.Wait()
		if _, _, _, err := f.ReadDatagram(nil); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read after the source stopped: %v", err)
		}
		if n := h.c.closeCount(); n != 1 {
			t.Fatalf("socket closed %d times", n)
		}
		select {
		case <-h.s.Done():
			t.Fatal("Done before the last flow ended")
		default:
		}
		f.Close()
		<-h.s.Done()
	})
}

func TestSourceForeignReadPanic_L57(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		h.c.mu.Lock()
		h.c.panicked = true
		h.c.mu.Unlock()
		h.c.kick()
		<-h.s.Done() // contained: the source stopped, the process lives
		if n := h.c.closeCount(); n != 1 {
			t.Fatalf("socket closed %d times", n)
		}
	})
}

// TestSourceEmptyReadsBackOff_L42: a foreign conn that returns (0, addr,
// nil) forever cannot spin a core — at most emptyRun reads per emptyPause —
// and the source neither dies nor slows further (R1-27's guard, fixed so
// that an empty flood cannot starve the socket, L58).
func TestSourceEmptyReadsBackOff_L42(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		const perSecond = emptyRun * int(time.Second/emptyPause)
		h.c.mu.Lock()
		h.c.empty = true
		h.c.emptyCap = 4 * perSecond // a spinning reader stops here instead of hanging the bubble
		h.c.mu.Unlock()
		h.c.kick()
		time.Sleep(time.Second)
		synctest.Wait()
		h.c.mu.Lock()
		reads := h.c.reads
		h.c.mu.Unlock()
		if reads < perSecond-emptyRun || reads > perSecond+2*emptyRun {
			t.Fatalf("%d empty reads in 1 s, want about %d (%d per %v: neither a spin nor a doubling backoff)", reads, perSecond, emptyRun, emptyPause)
		}
		if st := h.s.Stats(); st.Dropped < uint64(perSecond-emptyRun) || st.ReadErrors != 0 {
			t.Fatalf("Stats %+v: empty datagrams not counted as drops", st)
		}
		h.shutdown()
	})
}

// TestFlowEmptyFlood_L58: a live flow keeps ≥ 90 % of its datagrams while
// 2,000 empty datagrams per second arrive on the shared socket, and the
// source keeps up with the flood (nothing piles up in the socket).
func TestFlowEmptyFlood_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		from := udpAddr(2, 1000)
		h.c.send(h1(1, wire.TypeOpen, 1), from)
		synctest.Wait()
		f := h.last()
		f.Admitted()
		readOne(t, f, time.Second)
		const rounds, empties = 20, 200 // one datagram per 100 ms against 2 kpps of empties
		received := 0
		for i := range rounds {
			for range empties {
				h.c.send(nil, udpAddr(10, 9000))
			}
			h.c.send(dg(1, pingFrame(uint32(i+2))), from)
			time.Sleep(100 * time.Millisecond)
			for {
				if err := f.SetReadDeadline(time.Now().Add(time.Microsecond)); err != nil {
					t.Fatal(err)
				}
				if _, _, _, err := f.ReadDatagram(nil); err != nil {
					break
				}
				f.Release()
				received++
			}
		}
		if received < rounds*9/10 {
			t.Fatalf("%d of %d datagrams delivered under the empty flood, %d still queued in the socket", received, rounds, h.c.queued())
		}
		if q := h.c.queued(); q > empties {
			t.Fatalf("%d datagrams queued in the socket: the source fell behind the flood", q)
		}
		if st := h.s.Stats(); st.Dropped != rounds*empties {
			t.Fatalf("Stats %+v, want %d empty datagrams dropped", st, rounds*empties)
		}
	})
}

func TestFlowForeignWriteErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		defer h.shutdown()
		h.c.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		synctest.Wait()
		f := h.last()
		b := make([]byte, wire.FlowHeaderLen+30)
		dead := errors.New("dead conn")
		h.c.mu.Lock()
		h.c.wErrs = []fakeWrite{
			{n: 0, err: tempErr{}},
			{n: 0, err: &wire.DatagramTooLargeError{Max: 1000}},
			{n: len(b) - 1},
			{n: 0, err: dead},
		}
		h.c.mu.Unlock()
		if err := f.WriteDatagram(b); err != carrier.ErrNoise {
			t.Fatalf("transient write error: %v, want ErrNoise", err)
		}
		var tl *wire.DatagramTooLargeError
		if err := f.WriteDatagram(b); !errors.As(err, &tl) || tl.Max != 1000 {
			t.Fatalf("too large: %v", err)
		}
		if err := f.WriteDatagram(b); err == nil || errors.Is(err, carrier.ErrNoise) || errors.Is(err, wire.ErrDatagramTooLarge) {
			t.Fatalf("invalid count: %v, want an error that ends the carrier", err)
		}
		if err := f.WriteDatagram(b); err != dead {
			t.Fatalf("other error: %v", err)
		}
	})
}

func TestSharedSocketClosedOnce_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		h.c.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		h.c.send(h1(2, wire.TypeOpen, 2), udpAddr(2, 1001))
		synctest.Wait()
		f, g := h.admittedFlows()[0], h.admittedFlows()[1]
		h.s.Stop() // Listener.Close
		f.Close()
		synctest.Wait()
		if n := h.c.closeCount(); n != 0 {
			t.Fatalf("socket closed under a live flow (%d)", n)
		}
		h.s.Abort() // Runtime.Close
		synctest.Wait()
		if _, _, _, err := g.ReadDatagram(nil); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("read after Abort: %v", err)
		}
		g.Close()
		<-h.s.Done()
		h.s.Stop()
		h.s.Abort()
		synctest.Wait()
		if n := h.c.closeCount(); n != 1 {
			t.Fatalf("socket closed %d times, want once", n)
		}
		if st := h.s.Stats(); st.Flows != 0 || st.Admitting != 0 {
			t.Fatalf("after Done: Stats %+v", st)
		}
	})
}

func TestSourceReadIgnoresClose_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		h := newHarness(t, env, Limits{})
		h.c.send(h1(1, wire.TypeOpen, 1), udpAddr(2, 1000))
		synctest.Wait()
		f := h.last()
		readOne(t, f, time.Second)
		if err := f.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		// From now on the conn's waiting ReadFrom ignores Close.
		h.c.mu.Lock()
		h.c.deaf = true
		h.c.mu.Unlock()
		h.c.kick()
		errc := make(chan error, 1)
		go func() {
			_, _, _, err := f.ReadDatagram(nil)
			errc <- err
		}()
		synctest.Wait()
		start := time.Now()
		h.s.Abort()
		// Abort itself fails the flow's reads: the demux goroutine is stuck
		// in the conn and cannot do it.
		select {
		case err := <-errc:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read across Abort: %v, want net.ErrClosed", err)
			}
		case <-time.After(time.Millisecond):
			t.Fatal("a waiting flow read outlived Abort while the conn ignored Close")
		}
		f.Close()
		<-h.s.Done()
		if d := time.Since(start); d != env.Timing.AbandonWait {
			t.Fatalf("Done after %v, want AbandonWait %v", d, env.Timing.AbandonWait)
		}
		if n := env.Abandon.Len(); n != 1 {
			t.Fatalf("%d abandoned calls, want the stuck ReadFrom", n)
		}
		// The stuck read finally returns a valid H1: the socket's close has
		// started, so it is dropped without a CAPACITY answer.
		h.c.send(h1(2, wire.TypeOpen, 2), udpAddr(2, 1001))
		dropped := h.s.Stats().Dropped
		close(h.c.release)
		synctest.Wait()
		if n := env.Abandon.Len(); n != 0 {
			t.Fatalf("%d abandoned calls after the ReadFrom returned", n)
		}
		if st := h.s.Stats(); st.Dropped != dropped+1 || st.Flows != 0 || len(h.c.written()) != 0 {
			t.Fatalf("a late H1 after the close: Stats %+v, %d written, want one drop and no answer", st, len(h.c.written()))
		}
		if used := env.Budget.Used() + env.Stages.Used(); used != 0 {
			t.Fatalf("%d bytes buffered after the late return", used)
		}
	})
}
