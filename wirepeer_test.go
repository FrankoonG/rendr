package rendr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Scripted raw-wire dialers for the passive admission tests (design §11.1:
// "scripted raw-wire peers for admission"). A wpDialer speaks the v2 wire
// format byte by byte against a rendr passive over the dialer end of a
// net.Pipe whose other end is handed to Listener.Handle. It reads
// everything the passive writes before it writes again (design §0.8 V1),
// so the unbuffered pipe never blocks both ends.

// wpTestRuntime builds a Runtime for a test from cfg and ov (nil: none),
// failing the test on error. The test closes it; a cleanup closes it again
// (Close is idempotent), so that a failed test still ends its bubble
// without goroutines left behind.
func wpTestRuntime(t testing.TB, cfg Config, ov *testhooks.Overrides) *Runtime {
	t.Helper()
	rt, err := newRuntime(cfg, ov)
	if err != nil {
		t.Fatalf("newRuntime: %v", err)
	}
	t.Cleanup(func() { rt.Close() })
	return rt
}

// wpListen creates a push-only Listener (fed by Handle) with cfg.
func wpListen(t testing.TB, rt *Runtime, cfg ListenConfig) *Listener {
	t.Helper()
	ln, err := rt.Listen(cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	return ln
}

// wpInst returns a dialer InstanceID whose bytes are all b (never zero for
// b ≠ 0).
func wpInst(b byte) [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = b
	}
	return id
}

// wpSID returns a session ID derived from i (never zero).
func wpSID(i int) [16]byte {
	var sid [16]byte
	sid[0] = 0x5e
	binary.BigEndian.PutUint64(sid[8:], uint64(i))
	return sid
}

// wpDialer is one scripted dialer carrier.
type wpDialer struct {
	t      testing.TB
	nc     net.Conn // the dialer end
	inst   [16]byte
	id     uint32 // carrier ID
	txFseq uint32 // fseq of the next frame this dialer sends
	rxFseq uint32 // fseq expected on the next frame from the passive
}

// wpConnect creates a pipe, hands the passive end to ln.Handle (which must
// accept it) and returns the dialer end. A cleanup closes the dialer end
// (again), so that a failed test leaves no passive write blocked on it.
func wpConnect(t testing.TB, ln *Listener, inst [16]byte, id uint32) *wpDialer {
	t.Helper()
	a, b := net.Pipe()
	if err := ln.Handle(a); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return &wpDialer{t: t, nc: b, inst: inst, id: id, txFseq: wire.FirstFseq, rxFseq: wire.FirstFseq}
}

// wpPreface encodes a valid dialer PREFACE.
func wpPreface(inst [16]byte, id uint32) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPreface(b, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Instance: inst, CarrierID: id})
	return b
}

// wpRecrc recomputes the CRC of a 40-byte preface after its bytes 0–35
// were edited (a well-formed preface with another value).
func wpRecrc(b []byte) []byte {
	binary.BigEndian.PutUint32(b[36:40], wire.CRC(b[:36]))
	return b
}

// sendPreface writes p (40 bytes or a malformed variant) and reads the
// answer: a 40-byte PREFACE_ACK, or ok == false when the passive closed the
// carrier without one (n bytes received before EOF). Each direction then
// numbers its frames from its own preface's CRC field (design §0.13 A6).
func (d *wpDialer) sendPreface(p []byte) (ack wire.PrefaceAck, ok bool, n int) {
	d.t.Helper()
	if len(p) >= wire.PrefaceLen {
		d.txFseq = wire.PrefaceFseq(p)
	}
	if _, err := d.nc.Write(p); err != nil {
		return ack, false, 0 // closed before it read the whole preface
	}
	var b [wire.PrefaceLen]byte
	n, err := io.ReadFull(d.nc, b[:])
	if err != nil {
		return ack, false, n
	}
	ack, err = wire.ParsePrefaceAck(b[:])
	if err != nil {
		d.t.Fatalf("PREFACE_ACK does not parse: %v", err)
	}
	d.rxFseq = wire.PrefaceFseq(b[:])
	return ack, true, n
}

// hello runs the PREFACE exchange and requires PREFACE_ACK(OK) from rt.
func (d *wpDialer) hello(rt *Runtime) {
	d.t.Helper()
	ack, ok, _ := d.sendPreface(wpPreface(d.inst, d.id))
	if !ok {
		d.t.Fatal("PREFACE not answered")
	}
	if ack.Status != wire.PrefaceOK || ack.Instance != rt.InstanceID() || ack.CarrierID != d.id {
		d.t.Fatalf("PREFACE_ACK %+v, want OK from %v for carrier %d", ack, rt.InstanceID(), d.id)
	}
}

// frame encodes the next frame of type ty with this dialer's fseq and the
// handle its type requires.
func (d *wpDialer) frame(ty wire.Type, flags uint8, payload []byte) []byte {
	var handle uint32
	if !ty.CarrierLevel() {
		handle = wire.SessionHandle
	}
	f := wire.AppendFrame(nil, wire.Header{Type: ty, Flags: flags, Fseq: d.txFseq, Handle: handle}, payload)
	d.txFseq++
	return f
}

// send writes one frame; the passive reads frames completely, so the write
// returns once it was read.
func (d *wpDialer) send(ty wire.Type, flags uint8, payload []byte) {
	d.t.Helper()
	if _, err := d.nc.Write(d.frame(ty, flags, payload)); err != nil {
		d.t.Fatalf("writing %v: %v", ty, err)
	}
}

// sendAsync writes one frame on its own goroutine: for a frame the passive
// answers before reading it completely (an OPEN whose metadata it refuses
// unread). The returned channel reports the write's result.
func (d *wpDialer) sendAsync(ty wire.Type, flags uint8, payload []byte) <-chan error {
	f := d.frame(ty, flags, payload)
	done := make(chan error, 1)
	go func() {
		_, err := d.nc.Write(f)
		done <- err
	}()
	return done
}

// recv reads one complete frame and checks its CRC and fseq.
func (d *wpDialer) recv() (wire.Frame, error) {
	var hb [wire.HeaderLen]byte
	if _, err := io.ReadFull(d.nc, hb[:]); err != nil {
		return wire.Frame{}, err
	}
	h, err := wire.ParseHeader(hb[:])
	if err != nil {
		return wire.Frame{}, fmt.Errorf("header: %w", err)
	}
	rest := make([]byte, int(h.Len)+wire.TrailerLen)
	if _, err := io.ReadFull(d.nc, rest); err != nil {
		return wire.Frame{}, err
	}
	payload := rest[:h.Len]
	if wire.CRCUpdate(wire.CRC(hb[:]), payload) != wire.Trailer(rest[h.Len:]) {
		return wire.Frame{}, fmt.Errorf("%v: %w", h.Type, wire.ErrCRC)
	}
	if h.Fseq != d.rxFseq {
		return wire.Frame{}, fmt.Errorf("%v: fseq %d, want %d", h.Type, h.Fseq, d.rxFseq)
	}
	d.rxFseq++
	return wire.Frame{Header: h, Payload: payload}, nil
}

// expect reads one frame and requires its type.
func (d *wpDialer) expect(ty wire.Type) wire.Frame {
	d.t.Helper()
	f, err := d.recv()
	if err != nil {
		d.t.Fatalf("waiting for %v: %v", ty, err)
	}
	if f.Type != ty {
		d.t.Fatalf("got %v (%d bytes), want %v", f.Type, len(f.Payload), ty)
	}
	return f
}

// expectOpenAck reads one OPEN_ACK and requires status and code.
func (d *wpDialer) expectOpenAck(st wire.AckStatus, code uint32) wire.OpenAck {
	d.t.Helper()
	f := d.expect(wire.TypeOpenAck)
	if f.Handle != wire.SessionHandle {
		d.t.Fatalf("OPEN_ACK on handle %d", f.Handle)
	}
	a, err := wire.ParseOpenAck(f.Payload)
	if err != nil {
		d.t.Fatalf("OPEN_ACK: %v", err)
	}
	if a.Status != st || a.Code != code {
		d.t.Fatalf("OPEN_ACK status %d code %d (%q), want status %d code %d", a.Status, a.Code, a.Msg, st, code)
	}
	return a
}

// expectJoinAck reads one JOIN_ACK and requires its status.
func (d *wpDialer) expectJoinAck(st wire.AckStatus) {
	d.t.Helper()
	f := d.expect(wire.TypeJoinAck)
	a, err := wire.ParseJoinAck(f.Payload)
	if err != nil {
		d.t.Fatalf("JOIN_ACK: %v", err)
	}
	if a.Status != st {
		d.t.Fatalf("JOIN_ACK status %d, want %d", a.Status, st)
	}
}

// expectEOF requires that the passive closes the carrier with nothing more
// written. The passive drains after its last frame until our EOF or 1 s
// (L05), so expectEOF closes our end first only when told to.
func (d *wpDialer) expectEOF() {
	d.t.Helper()
	var b [64]byte
	n, err := d.nc.Read(b[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		d.t.Fatalf("read (%d bytes %x, %v), want EOF", n, b[:n], err)
	}
}

// close closes the dialer end.
func (d *wpDialer) close() { d.nc.Close() }

// wpOpen encodes an OPEN payload.
func wpOpen(sid [16]byte, kind wire.CarrierKind, mode uint8, meta []byte) []byte {
	b := make([]byte, wire.OpenFixedLen+len(meta))
	wire.PutOpen(b, &wire.Open{SID: sid, Kind: kind, Mode: mode, RetainMs: 30000, Window: 8 << 20, Metadata: meta})
	return b
}

// wpJoin encodes a JOIN payload.
func wpJoin(sid [16]byte, mode uint8, rxNext uint64) []byte {
	b := make([]byte, wire.JoinLen)
	wire.PutJoin(b, &wire.Join{SID: sid, Mode: mode, RxNext: rxNext})
	return b
}

// wpRst encodes an RST payload.
func wpRst(code uint32, msg string) []byte {
	b := make([]byte, wire.RstFixedLen+len(msg))
	wire.PutRst(b, &wire.Rst{Code: code, Msg: []byte(msg)})
	return b
}

// drain reads frames until the passive ends the carrier and returns their
// types. The passive closes in the L05 order — its CLOSE, then it reads
// until our EOF — so drain closes our end once it read that CLOSE.
func (d *wpDialer) drain() []wire.Type {
	var seen []wire.Type
	for {
		f, err := d.recv()
		if err != nil {
			return seen
		}
		seen = append(seen, f.Type)
		if f.Type == wire.TypeClose {
			d.close()
		}
	}
}

// wpPing encodes a PING (or PONG) payload.
func wpPing(p wire.Ping) []byte {
	b := make([]byte, wire.PingFixedLen+p.Pad)
	wire.PutPing(b, &p)
	return b
}

// wpProbe connects a scripted probe carrier (first frame PING) and returns
// it with the passive's first answer: the PONG of that PING, or the
// refusal (CLOSE or GOAWAY) in f.
func wpProbe(t testing.TB, rt *Runtime, ln *Listener, inst [16]byte, id uint32) (*wpDialer, wire.Frame) {
	t.Helper()
	d := wpConnect(t, ln, inst, id)
	d.hello(rt)
	ping := wire.Ping{ID: id, TS: uint64(id) << 8, Nonce: 0xfeed0000 + uint64(id)}
	d.send(wire.TypePing, 0, wpPing(ping))
	f, err := d.recv()
	if err != nil {
		t.Fatalf("probe %d: no answer to its PING: %v", id, err)
	}
	if f.Type == wire.TypePong && !bytes.Equal(f.Payload, wpPing(ping)) {
		t.Fatalf("probe %d: PONG %x does not echo PING %x", id, f.Payload, wpPing(ping))
	}
	return d, f
}

// wpPingPong sends one more PING with pad bytes and requires the echoing
// PONG.
func (d *wpDialer) pingPong(id uint32, pad int) {
	d.t.Helper()
	ping := wire.Ping{ID: id, TS: 77, Nonce: 0xabc0000 + uint64(id), Pad: pad}
	d.send(wire.TypePing, 0, wpPing(ping))
	f := d.expect(wire.TypePong)
	if f.Flags != 0 || f.Handle != 0 || !bytes.Equal(f.Payload, wpPing(ping)) {
		d.t.Fatalf("PONG flags %d handle %d payload %x, want an echo of %+v", f.Flags, f.Handle, f.Payload, ping)
	}
}

// wpTomb inserts a tombstone answering v for (dialer, sid) into rt's table
// with ttl (a passive session that ended; the session pointer is a dummy
// that the table never dereferences).
func wpTomb(t testing.TB, rt *Runtime, dialer [16]byte, sid [16]byte, v session.Verdict, ttl time.Duration) {
	t.Helper()
	k := passiveKey(InstanceID(dialer), SessionID(sid))
	s := new(session.Session)
	if !rt.table.reserve() {
		t.Fatal("no MaxSessions unit for a tombstone")
	}
	if _, ok := rt.table.insertOrGet(k, s, ttl, time.Now()); !ok {
		t.Fatalf("key %v already present", k)
	}
	if !rt.table.ended(k, s, v, time.Now()) {
		t.Fatalf("ending %v failed", k)
	}
}

// countConn counts the embedder Close calls of a conn (L51: exactly once).
type countConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// wpNoState requires that rt holds no session, reservation, handshake or
// sessionless carrier and that the memory budget is back to zero.
func wpNoState(t testing.TB, rt *Runtime) {
	t.Helper()
	st := rt.Status()
	sc := st.Sessions
	if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || rt.table.inUse() != 0 || st.AcceptBacklog != [2]int{} ||
		st.Handshakes != 0 || st.Sessionless != 0 || st.BufferedBytes != 0 {
		t.Fatalf("state left: %+v (MaxSessions units %d)", st, rt.table.inUse())
	}
}
