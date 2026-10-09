package rendr

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scripted raw-wire datagram dialers for the passive admission tests of
// packet sessions (M2 design §A5.10, §A5.14): a wdDialer writes the first
// datagram H1 of a carrier byte by byte over the dialer end of a
// rendrtest.DatagramLink carrier whose passive end the link handed to the
// Listener — through HandlePacket, or through wdLink's hook, which wraps it
// in a transport of a chosen receive limit (a QUIC-like 1152) that records
// the limits the admission sets (wdIO).

// wdLink is a DatagramLink whose passive ends enter ln's datagram
// handshake through a PacketIO with receive limit limit (0: HandlePacket),
// each recorded in order.
type wdLink struct {
	t    testing.TB
	link *rendrtest.DatagramLink

	mu  sync.Mutex
	ios []*wdIO
	got chan struct{} // cap 64: one token per passive end
}

func newWDLink(t testing.TB, rt *Runtime, ln *Listener, limit int) *wdLink {
	t.Helper()
	w := &wdLink{t: t, got: make(chan struct{}, 64)}
	w.link = rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{
		Name: "wd",
		Accept: func(pc net.PacketConn, peer net.Addr) error {
			if limit == 0 {
				return ln.HandlePacket(pc, peer)
			}
			pio, err := carrier.NewPacketIO(&rt.cenv, pc, peer, limit)
			if err != nil {
				return err
			}
			io := &wdIO{PacketIO: pio}
			if !ln.beginHandshake() {
				return net.ErrClosed
			}
			w.mu.Lock()
			w.ios = append(w.ios, io)
			w.mu.Unlock()
			rt.startHandshakeDatagram(ln, io, time.Now())
			w.got <- struct{}{}
			return nil
		},
	})
	t.Cleanup(func() { w.link.Close() })
	return w
}

// io returns the transport of the i-th passive end (wdLink with a limit).
func (w *wdLink) io(i int) *wdIO {
	w.t.Helper()
	for {
		w.mu.Lock()
		if i < len(w.ios) {
			io := w.ios[i]
			w.mu.Unlock()
			return io
		}
		w.mu.Unlock()
		<-w.got
	}
}

// wdIO is a passive datagram transport that records every receive limit
// set on it (Conn.SetBudget lowers it to the negotiated cmtu, R1-6).
type wdIO struct {
	carrier.PacketIO
	mu     sync.Mutex
	limits []int
}

func (w *wdIO) SetLimit(n int) {
	w.mu.Lock()
	w.limits = append(w.limits, n)
	w.mu.Unlock()
	w.PacketIO.SetLimit(n)
}

// lastLimit returns the latest SetLimit (0: none).
func (w *wdIO) lastLimit() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.limits) == 0 {
		return 0
	}
	return w.limits[len(w.limits)-1]
}

// wdDialer is one scripted dialer datagram carrier.
type wdDialer struct {
	t    testing.TB
	pc   net.PacketConn
	peer net.Addr
	inst [16]byte
	id   uint32
	h1   []byte // the last H1 written (resent verbatim)
	tx   uint32 // fseq of this dialer's next frame after H1
	rx   uint32 // fseq expected next from the passive (set by the PREFACE_ACK)

	flow  bool      // a FromPacketConn flow (wdHubDial): the H2 of an OPEN carries the address check
	first wire.Type // the first frame of the last H1 written
	check uint64    // the address check's nonce from H2 (0: none)
}

// dial opens a carrier of w as dialer inst with carrier ID id.
func (w *wdLink) dial(inst [16]byte, id uint32) *wdDialer {
	w.t.Helper()
	pc, peer, err := w.link.Dial(context.Background())
	if err != nil {
		w.t.Fatalf("DatagramLink.Dial: %v", err)
	}
	return &wdDialer{t: w.t, pc: pc, peer: peer, inst: inst, id: id}
}

// wdH1 builds a carrier's first datagram (M2-D19): PREFACE of kind
// datagram ‖ REL{FirstCseq, t, payload} at the PREFACE's first fseq.
func wdH1(inst [16]byte, id uint32, t wire.Type, payload []byte) []byte {
	pre := make([]byte, wire.PrefaceLen)
	wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindDatagram, Instance: inst, CarrierID: id})
	rel := make([]byte, wire.RelHeadLen+len(payload))
	wire.PutRelHead(rel, &wire.RelHead{Cseq: wire.FirstCseq, Type: t, Handle: wire.SessionHandle})
	copy(rel[wire.RelHeadLen:], payload)
	return wire.AppendFrame(pre, wire.Header{Type: wire.TypeRel, Fseq: wire.PrefaceFseq(pre)}, rel)
}

// sendH1 writes the H1 carrying (t, payload).
func (d *wdDialer) sendH1(t wire.Type, payload []byte) {
	d.t.Helper()
	d.h1 = wdH1(d.inst, d.id, t, payload)
	d.first, d.tx = t, wire.PrefaceFseq(d.h1[:wire.PrefaceLen])+1
	if _, err := d.pc.WriteTo(d.h1, d.peer); err != nil {
		d.t.Fatalf("writing H1: %v", err)
	}
}

// read returns the next datagram from the passive within d (virtual time),
// or nil when none came.
func (d *wdDialer) read(within time.Duration) []byte {
	d.t.Helper()
	if err := d.pc.SetReadDeadline(time.Now().Add(within)); err != nil {
		d.t.Fatalf("SetReadDeadline: %v", err)
	}
	b := make([]byte, wire.MaxDatagram+1)
	n, _, err := d.pc.ReadFrom(b)
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return nil
	case err != nil:
		d.t.Fatalf("ReadFrom: %v", err)
	}
	return b[:n]
}

// frames decodes the frames of datagram b (after a PREFACE_ACK, if any).
func (d *wdDialer) frames(b []byte) []wire.Frame {
	d.t.Helper()
	var out []wire.Frame
	for len(b) > 0 {
		f, n, err := wire.DecodeFrame(b)
		if err != nil {
			d.t.Fatalf("a frame of the passive's datagram: %v", err)
		}
		out = append(out, f)
		b = b[n:]
	}
	return out
}

// expectH2 requires H2 = PREFACE_ACK(OK, our carrier ID, from rt) ‖
// RACK{FirstCseq} (M2-D19) ‖, for an OPEN on a FromPacketConn flow and
// only there, the address check PING{id 0, nonce ≠ 0, pad 0} at the next
// fseq (carrier.SourceChecker), whose nonce it records (answerCheck).
func (d *wdDialer) expectH2(rt *Runtime) {
	d.t.Helper()
	b := d.read(time.Second)
	if len(b) < wire.PrefaceLen || !wire.IsPreface(b) {
		d.t.Fatalf("no H2: %x", b)
	}
	ack, err := wire.ParsePrefaceAck(b[:wire.PrefaceLen])
	if err != nil || ack.Status != wire.PrefaceOK || ack.CarrierID != d.id || ack.Instance != rt.InstanceID() {
		d.t.Fatalf("PREFACE_ACK %+v (%v), want OK for carrier %d from %v", ack, err, d.id, rt.InstanceID())
	}
	d.rx = wire.PrefaceFseq(b[:wire.PrefaceLen])
	fs := d.frames(b[wire.PrefaceLen:])
	want := 1
	if d.flow && d.first == wire.TypeOpen {
		want = 2
	}
	if len(fs) != want || fs[0].Type != wire.TypeRack || fs[0].Fseq != d.rx {
		d.t.Fatalf("H2 frames %+v, want a RACK at fseq %d and %d frames", fs, d.rx, want)
	}
	if r, err := wire.ParseRack(fs[0].Payload); err != nil || r.CumAck != wire.FirstCseq {
		d.t.Fatalf("H2 RACK %+v (%v), want cumAck %d", r, err, wire.FirstCseq)
	}
	d.rx++
	if want == 2 {
		p, err := wire.ParsePing(fs[1].Payload)
		if fs[1].Type != wire.TypePing || fs[1].Fseq != d.rx || err != nil || p.ID != 0 || p.Nonce == 0 || p.Pad != 0 {
			d.t.Fatalf("H2's address check %+v (%+v, %v), want PING{id 0, nonce ≠ 0} at fseq %d", fs[1], p, err, d.rx)
		}
		d.check = p.Nonce
		d.rx++
	}
}

// answerCheck answers H2's address check with PONG{id 0, nonce}, as
// Establish does (R1-14 (4)), with nonce xor (0: the check's own nonce).
func (d *wdDialer) answerCheck(xor uint64) {
	d.t.Helper()
	if d.check == 0 {
		d.t.Fatal("answerCheck: H2 carried no address check")
	}
	b := wire.AppendFrame(nil, wire.Header{Type: wire.TypePong, Fseq: d.tx}, wpPing(wire.Ping{Nonce: d.check ^ xor}))
	d.tx++
	if _, err := d.pc.WriteTo(b, d.peer); err != nil {
		d.t.Fatalf("writing the check's PONG: %v", err)
	}
}

// expectVerdict reads datagrams until the passive's REL{FirstCseq} and
// returns its inner frame type and payload (H3 or a reliable verdict,
// M2-D21); H2 repeats and RACKs before it are skipped.
func (d *wdDialer) expectVerdict() (wire.Type, []byte) {
	d.t.Helper()
	for range 16 {
		b := d.read(3 * time.Second)
		if b == nil {
			d.t.Fatal("no verdict within 3 s")
		}
		if wire.IsPreface(b) {
			continue // an H2 repeat
		}
		for _, f := range d.frames(b) {
			if f.Type != wire.TypeRel {
				continue
			}
			h, inner, err := wire.ParseRel(f.Payload)
			if err != nil || h.Cseq != wire.FirstCseq {
				d.t.Fatalf("REL %+v (%v), want cseq %d", h, err, wire.FirstCseq)
			}
			return h.Type, inner
		}
	}
	d.t.Fatal("no REL among 16 datagrams")
	return 0, nil
}

// expectOpenAck requires the verdict OPEN_ACK(st, code).
func (d *wdDialer) expectOpenAck(st wire.AckStatus, code uint32) wire.OpenAck {
	d.t.Helper()
	ty, inner := d.expectVerdict()
	if ty != wire.TypeOpenAck {
		d.t.Fatalf("verdict %v, want OPEN_ACK", ty)
	}
	a, err := wire.ParseOpenAck(inner)
	if err != nil || a.Status != st || a.Code != code {
		d.t.Fatalf("OPEN_ACK %+v (%v), want status %d code %d", a, err, st, code)
	}
	return a
}

// close closes the dialer end.
func (d *wdDialer) close() { d.pc.Close() }

// wdPacketOpen encodes a packet OPEN (M2 design §A3.5): window = the
// carrier's cmtu offer (0 on a stream carrier), pmtu = the MaxPayload
// offer.
func wdPacketOpen(sid [16]byte, mode uint8, window uint32, pmtu uint16) []byte {
	b := make([]byte, wire.OpenFixedLen)
	wire.PutOpen(b, &wire.Open{SID: sid, Kind: wire.KindDatagram, Mode: mode, RetainMs: 30000, Window: window, PMTU: pmtu})
	return b
}

// countPC counts the Close calls of an embedder net.PacketConn (L57: a
// conn rendr owns is closed exactly once; one it does not own never).
type countPC struct {
	net.PacketConn
	closes atomic.Int32
}

func (c *countPC) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

// panicAddr is a foreign net.Addr whose String panics (L38, L57).
type panicAddr struct{}

func (panicAddr) Network() string { return "panic" }
func (panicAddr) String() string  { panic("panicAddr.String called") }

// wdProbe writes a probe carrier's first datagram H1p = PREFACE ‖ PING
// (pad 0) and requires H2p = PREFACE_ACK(OK) ‖ PONG echoing it (M2-D71).
func (d *wdDialer) wdProbe(rt *Runtime) {
	d.t.Helper()
	pre := make([]byte, wire.PrefaceLen)
	wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindDatagram, Instance: d.inst, CarrierID: d.id})
	ping := wpPing(wire.Ping{ID: 1, TS: 2, Nonce: 3})
	d.h1 = wire.AppendFrame(pre, wire.Header{Type: wire.TypePing, Fseq: wire.PrefaceFseq(pre)}, ping)
	d.tx = wire.PrefaceFseq(pre) + 1
	if _, err := d.pc.WriteTo(d.h1, d.peer); err != nil {
		d.t.Fatalf("writing H1p: %v", err)
	}
	b := d.read(time.Second)
	if len(b) < wire.PrefaceLen {
		d.t.Fatalf("no H2p: %x", b)
	}
	ack, err := wire.ParsePrefaceAck(b[:wire.PrefaceLen])
	if err != nil || ack.Status != wire.PrefaceOK || ack.CarrierID != d.id || ack.Instance != rt.InstanceID() {
		d.t.Fatalf("PREFACE_ACK %+v (%v)", ack, err)
	}
	fs := d.frames(b[wire.PrefaceLen:])
	if len(fs) != 1 || fs[0].Type != wire.TypePong || string(fs[0].Payload) != string(ping) {
		d.t.Fatalf("H2p frames %+v, want the PONG of %x", fs, ping)
	}
}

// expectRefusal requires a stateless PREFACE_ACK(st) alone.
func (d *wdDialer) expectRefusal(st wire.PrefaceStatus) {
	d.t.Helper()
	b := d.read(time.Second)
	if len(b) != wire.PrefaceLen {
		d.t.Fatalf("refusal %x, want a PREFACE_ACK alone", b)
	}
	if ack, err := wire.ParsePrefaceAck(b); err != nil || ack.Status != st {
		d.t.Fatalf("PREFACE_ACK %+v (%v), want status %d", ack, err, st)
	}
}

// wdHubDial opens a client of hub as dialer inst with carrier ID id.
func wdHubDial(t testing.TB, hub *rendrtest.DatagramHub, inst [16]byte, id uint32) *wdDialer {
	t.Helper()
	pc, peer, err := hub.Dial(context.Background())
	if err != nil {
		t.Fatalf("DatagramHub.Dial: %v", err)
	}
	return &wdDialer{t: t, pc: pc, peer: peer, inst: inst, id: id, flow: true}
}

// wdProbePing sends one more PING on a started probe carrier and requires
// its PONG (a sessionless carrier answers every PING).
func (d *wdDialer) wdProbePing(rt *Runtime) {
	d.t.Helper()
	ping := wpPing(wire.Ping{ID: 2, TS: 5, Nonce: 6})
	b := wire.AppendFrame(nil, wire.Header{Type: wire.TypePing, Fseq: d.tx}, ping)
	d.tx++
	if _, err := d.pc.WriteTo(b, d.peer); err != nil {
		d.t.Fatalf("writing a PING: %v", err)
	}
	for range 4 {
		r := d.read(time.Second)
		if r == nil {
			break
		}
		for _, f := range d.frames(r) {
			if f.Type == wire.TypePong && string(f.Payload) == string(ping) {
				return
			}
		}
	}
	d.t.Fatal("no PONG for the PING")
}

// wdNoFlowRecords requires that rt holds no passive packet session's flow
// record (rt.pflows): each one leaves with its session (Registry.Ended)
// or a lost insert, so none keeps an ended session reachable (invariant 4).
func wdNoFlowRecords(t testing.TB, rt *Runtime) {
	t.Helper()
	rt.fmu.Lock()
	n := len(rt.pflows)
	rt.fmu.Unlock()
	if n != 0 {
		t.Fatalf("%d flow records left after their sessions ended", n)
	}
}

// wdFindOpenAck reads the passive's datagrams until one carries a reliable
// OPEN_ACK (GOAWAY, CLOSE and RACKs around it skipped) and returns it;
// false when none came within 3 s of the previous datagram.
func (d *wdDialer) wdFindOpenAck() (wire.OpenAck, bool) {
	d.t.Helper()
	for range 32 {
		b := d.read(3 * time.Second)
		if b == nil {
			break
		}
		if wire.IsPreface(b) {
			continue
		}
		for _, f := range d.frames(b) {
			if f.Type != wire.TypeRel {
				continue
			}
			if h, inner, err := wire.ParseRel(f.Payload); err == nil && h.Type == wire.TypeOpenAck {
				a, err := wire.ParseOpenAck(inner)
				return a, err == nil
			}
		}
	}
	return wire.OpenAck{}, false
}
