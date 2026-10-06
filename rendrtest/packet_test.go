package rendrtest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketPayloadLayout_L36: a test datagram is its 24-byte header — seq,
// send time, length, CRC-32C of the datagram with the CRC field zeroed —
// and a body determined by (seed, seq) alone; dst is reused when it is
// large enough; the header alone is the smallest test datagram.
func TestPacketPayloadLayout_L36(t *testing.T) {
	at := time.Unix(1, 23)
	b := PacketPayload(nil, 7, 42, 100, at)
	if len(b) != 100 || binary.BigEndian.Uint64(b[0:]) != 42 || binary.BigEndian.Uint64(b[8:]) != uint64(at.UnixNano()) || binary.BigEndian.Uint32(b[16:]) != 100 {
		t.Fatalf("header %x", b[:PacketHeaderLen])
	}
	z := slices.Clone(b)
	clear(z[20:24])
	if wire.CRC(z) != binary.BigEndian.Uint32(b[20:]) {
		t.Fatal("CRC-32C mismatch")
	}
	later := PacketPayload(nil, 7, 42, 100, at.Add(time.Hour))
	if !bytes.Equal(b[PacketHeaderLen:], later[PacketHeaderLen:]) {
		t.Fatal("the body depends on the send time")
	}
	for _, other := range [][]byte{PacketPayload(nil, 7, 43, 100, at), PacketPayload(nil, 8, 42, 100, at)} {
		if bytes.Equal(b[PacketHeaderLen:], other[PacketHeaderLen:]) {
			t.Fatal("two (seed, seq) pairs share a body")
		}
	}
	dst := make([]byte, 200)
	if out := PacketPayload(dst, 7, 42, 100, at); &out[0] != &dst[0] || !bytes.Equal(out, b) {
		t.Fatal("a large enough dst was not used")
	}
	if h := PacketPayload(nil, 1, 1, PacketHeaderLen, at); len(h) != PacketHeaderLen || NewPacketVerifier(1).Add(h, at) != nil {
		t.Fatal("a header-only datagram is not valid")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a size below the header was accepted")
		}
	}()
	PacketPayload(nil, 1, 1, PacketHeaderLen-1, at)
}

// TestPacketVerifier_L36_L39: the verifier accepts exactly the generator's
// datagrams: a datagram that is not the length it declares (merged, split
// or truncated: L36), damaged, of another seed or beyond its range is an
// error and counted; a duplicate is counted, not an error (L39); Result
// reports the unique count, the highest seq, the missing ranges and the
// longest interval between new arrivals.
func TestPacketVerifier_L36_L39(t *testing.T) {
	v := NewPacketVerifier(7)
	if r := v.Result(); r.Unique != 0 || r.Missing != nil {
		t.Fatalf("empty verifier: %+v", r)
	}
	t0 := time.Unix(100, 0)
	for _, seq := range []uint64{0, 1, 2, 4, 5, 8, 9} {
		at := t0.Add(time.Duration(seq) * 10 * time.Millisecond)
		if err := v.Add(PacketPayload(nil, 7, seq, 64+int(seq), at), at); err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
	}
	if err := v.Add(PacketPayload(nil, 7, 5, 69, t0), t0.Add(time.Hour)); err != nil {
		t.Fatalf("a duplicate is an error: %v", err)
	}
	flipped := PacketPayload(nil, 7, 11, 64, t0)
	flipped[40] ^= 0x10
	whole := PacketPayload(nil, 7, 13, 64, t0)
	bad := []struct {
		b    []byte
		want string
	}{
		{flipped, "CRC"},
		{PacketPayload(nil, 8, 12, 64, t0), "seed"},
		{PacketPayload(nil, 7, maxVerifiedSeq, 64, t0), "range"},
		{whole[:50], "declares"},
		{slices.Concat(whole, whole), "declares"},
		{whole[:PacketHeaderLen-1], "shorter"},
	}
	for _, c := range bad {
		if err := v.Add(c.b, t0); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%d bytes: %v, want an error naming %q", len(c.b), err, c.want)
		}
	}
	r := v.Result()
	want := PacketResult{Unique: 7, Duplicates: 1, Corrupt: 3, BadSize: 3, Highest: 9,
		Missing: []SeqRange{{3, 3}, {6, 7}}, MaxGap: 30 * time.Millisecond}
	if !slices.Equal(r.Missing, want.Missing) {
		t.Fatalf("missing %v, want %v", r.Missing, want.Missing)
	}
	if !reflect.DeepEqual(r, want) {
		t.Fatalf("result %+v, want %+v", r, want)
	}
	big := NewPacketVerifier(1)
	for seq := range uint64(100000) {
		if seq%1000 != 999 {
			big.Add(PacketPayload(nil, 1, seq, PacketHeaderLen, t0), t0)
		}
	}
	if r := big.Result(); r.Unique != 99900 || r.Highest != 99998 || len(r.Missing) != 99 || r.Missing[98] != (SeqRange{98999, 98999}) {
		t.Fatalf("large stream: %d unique, highest %d, %d missing ranges", r.Unique, r.Highest, len(r.Missing))
	}
}

// TestPacketGen_L40: PacketGen sends Count test datagrams on an absolute
// schedule at Rate (a slow WriteTo does not shift the later datagrams) or
// back to back, never closes pc, records every result and the longest
// WriteTo, keeps going after a refused datagram and stops once the conn is
// closed.
func TestPacketGen_L40(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newDRig(t, DatagramLinkConfig{Name: "gen"})
		defer r.l.Close()
		c := r.dial()
		v := NewPacketVerifier(3)
		got := dCollect(c.srv, 100)
		start := time.Now()
		res := PacketGen(PacketGenConfig{Seed: 3, Size: 200, Count: 100, Rate: 1000}, c.cli, c.srvAddr)
		if d := time.Since(start); d != 99*time.Millisecond || res.Sent != 100 || res.Errors != 0 || res.MaxWrite != 0 {
			t.Fatalf("after %v: %+v", d, res)
		}
		for _, a := range got() {
			if err := v.Add(a.b, a.at); err != nil {
				t.Fatal(err)
			}
		}
		if vr := v.Result(); vr.Unique != 100 || vr.Missing != nil || vr.MaxGap != time.Millisecond {
			t.Fatalf("verifier: %+v", vr)
		}
		start = time.Now()
		if res := PacketGen(PacketGenConfig{Seed: 3, Size: 30, Count: 50}, c.cli, c.srvAddr); res.Sent != 50 || time.Since(start) != 0 {
			t.Fatalf("back to back: %+v after %v", res, time.Since(start))
		}
		slow := &slowPC{d: 5 * time.Millisecond} // each WriteTo takes half the 10-ms period
		start = time.Now()
		if res := PacketGen(PacketGenConfig{Size: 30, Count: 5, Rate: 100}, slow, fakeAddr(5, 1)); res.Sent != 5 || res.MaxWrite != 5*time.Millisecond {
			t.Fatalf("slow conn: %+v", res)
		}
		for k, at := range slow.calls {
			if d := at.Sub(start); d != time.Duration(k)*10*time.Millisecond {
				t.Fatalf("slow conn: datagram %d written after %v, want %v (the schedule is absolute)", k, d, time.Duration(k)*10*time.Millisecond)
			}
		}
		r.l.SetMTU(100, MTURefuse)
		if res := PacketGen(PacketGenConfig{Size: 200, Count: 3}, c.cli, c.srvAddr); res.Sent != 0 || res.Errors != 3 || !errors.Is(res.FirstErr, wire.ErrDatagramTooLarge) {
			t.Fatalf("refused datagrams: %+v", res)
		}
		r.l.SetMTU(0, MTURefuse)
		done := make(chan PacketGenResult)
		go func() { done <- PacketGen(PacketGenConfig{Size: 30, Count: 100, Rate: 100}, c.cli, c.srvAddr) }()
		time.Sleep(205 * time.Millisecond)
		r.l.Kill()
		start = time.Now()
		if res := <-done; res.Sent != 21 || res.Errors != 1 || !errors.Is(res.FirstErr, net.ErrClosed) || time.Since(start) != 5*time.Millisecond {
			t.Fatalf("closed conn: %+v, returned after %v", res, time.Since(start))
		}
		d := r.dial()
		PacketGen(PacketGenConfig{Size: 30, Count: 1}, d.cli, d.srvAddr)
		if _, err := d.cli.WriteTo([]byte{1}, d.srvAddr); err != nil {
			t.Fatalf("PacketGen closed its conn: %v", err)
		}
		defer func() {
			if recover() == nil {
				t.Fatal("a Size below the header was accepted")
			}
		}()
		PacketGen(PacketGenConfig{Size: 10, Count: 1}, d.cli, d.srvAddr)
	})
}

// scriptPC is a net.PacketConn that returns its datagrams, then readErr,
// and records what is written to it.
type scriptPC struct {
	in       [][]byte
	readErr  error
	out      [][]byte
	writeErr func(n int) error // the error of the n-th WriteTo (0 based)
	closed   int
}

func (s *scriptPC) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(s.in) == 0 {
		return 0, nil, s.readErr
	}
	n := copy(p, s.in[0])
	s.in = s.in[1:]
	return n, fakeAddr(5, 1), nil
}

func (s *scriptPC) WriteTo(p []byte, addr net.Addr) (int, error) {
	if s.writeErr != nil {
		if err := s.writeErr(len(s.out)); err != nil {
			s.out = append(s.out, nil)
			return 0, err
		}
	}
	if !sameAddr(addr, fakeAddr(5, 1)) {
		return 0, errors.New("echoed to another address")
	}
	s.out = append(s.out, slices.Clone(p))
	return len(p), nil
}

func (s *scriptPC) Close() error                     { s.closed++; return nil }
func (s *scriptPC) LocalAddr() net.Addr              { return fakeAddr(5, 2) }
func (s *scriptPC) SetDeadline(time.Time) error      { return nil }
func (s *scriptPC) SetReadDeadline(time.Time) error  { return nil }
func (s *scriptPC) SetWriteDeadline(time.Time) error { return nil }

// slowPC is a scriptPC whose WriteTo takes d and records when it was called.
type slowPC struct {
	scriptPC
	d     time.Duration
	calls []time.Time
}

func (s *slowPC) WriteTo(p []byte, _ net.Addr) (int, error) {
	s.calls = append(s.calls, time.Now())
	time.Sleep(s.d)
	return len(p), nil
}

// TestPacketBehaviours_L64: PacketEcho returns every datagram to its
// source — after the peer's FIN closed its writes it keeps reading to the
// end — and PacketSink counts datagrams (empty ones too); both accept only
// io.EOF as the end, report any other error with its text, and close the
// conn.
func TestPacketBehaviours_L64(t *testing.T) {
	in := func() [][]byte { return [][]byte{[]byte("a"), []byte("bb"), {}} }
	s := &scriptPC{in: in(), readErr: io.EOF}
	if err := PacketEcho()(s); err != nil || len(s.out) != 3 || string(s.out[1]) != "bb" || len(s.out[2]) != 0 || s.closed != 1 {
		t.Fatalf("echo: %v, wrote %q, closed %d", err, s.out, s.closed)
	}
	s = &scriptPC{in: in(), readErr: io.EOF, writeErr: func(n int) error {
		if n > 0 {
			return &net.OpError{Op: "write", Err: net.ErrClosed}
		}
		return nil
	}}
	if err := PacketEcho()(s); err != nil || len(s.in) != 0 || len(s.out) != 2 {
		t.Fatalf("echo after the peer's FIN: %v, %d left unread, %d writes", err, len(s.in), len(s.out))
	}
	for _, c := range []struct {
		pc   *scriptPC
		want string
	}{
		{&scriptPC{in: in(), readErr: io.ErrClosedPipe}, io.ErrClosedPipe.Error()},
		{&scriptPC{in: in(), readErr: io.EOF, writeErr: func(int) error { return errors.New("write broke") }}, "write broke"},
	} {
		if err := PacketEcho()(c.pc); err == nil || !strings.Contains(err.Error(), c.want) || c.pc.closed != 1 {
			t.Fatalf("echo: %v, want an error with %q", err, c.want)
		}
	}
	var n atomic.Int64
	s = &scriptPC{in: in(), readErr: io.EOF}
	if err := PacketSink(&n)(s); err != nil || n.Load() != 3 || s.closed != 1 {
		t.Fatalf("sink: %v, counted %d", err, n.Load())
	}
	if err := PacketSink(nil)(&scriptPC{in: in(), readErr: io.EOF}); err != nil {
		t.Fatalf("sink without a counter: %v", err)
	}
	if err := PacketSink(nil)(&scriptPC{readErr: net.ErrClosed}); err == nil || !strings.Contains(err.Error(), net.ErrClosed.Error()) {
		t.Fatalf("sink: %v, want the read error", err)
	}
}
