package carrier

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// WP3b tests of the passive datagram handshake, its refusals and verdicts,
// and datagram probe carriers (M2 design §A5.10; M2-D19, M2-D21, M2-D71;
// Revision 1, R1-3, R1-7).

// wbH1 builds an H1 of the dialer Env denv for carrier id: PREFACE(kind
// datagram) ‖ REL{F, t(payload)} at the PREFACE's first fseq, or ‖ PING
// when t is TypePing.
func wbH1(denv *Env, id uint32, t wire.Type, payload []byte) []byte {
	pre := make([]byte, wire.PrefaceLen)
	wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindDatagram, Instance: denv.Local, CarrierID: id})
	first := denv.Presets.fseqFrom(pre)
	if t == wire.TypePing {
		return append(pre, wbFrame(wire.TypePing, 0, first, 0, wbPingPayload(wire.Ping{ID: 1, Nonce: 42}))...)
	}
	return append(pre, wbFrame(wire.TypeRel, 0, first, 0, relPayloadOf(denv.Presets.firstCseq(), t, 0, wire.SessionHandle, payload))...)
}

// wbHelloRes is ReadHelloDatagram's result.
type wbHelloRes struct {
	h   *Hello
	err error
	at  time.Time
}

// wbReadHello runs ReadHelloDatagram over io on a goroutine.
func wbReadHello(env *Env, io PacketIO, gate Gate) <-chan wbHelloRes {
	ch := make(chan wbHelloRes, 1)
	go func() {
		h, err := ReadHelloDatagram(env, io, time.Now().Add(10*time.Second), 255, gate)
		ch <- wbHelloRes{h, err, time.Now()}
	}()
	return ch
}

// TestRelBeforePrefaceNoState_L44_L48: the passive answers nothing and
// keeps no state for any first datagram that is not a complete valid H1 —
// a REL without its PREFACE, garbage, a PREFACE alone or of the stream
// kind, a damaged CRC, a second frame, a wrong fseq or cseq, a REL{FIN}, a
// padded PING — and counts each as dropped; the valid H1 after them gets
// exactly one H2 (plan:324; L44, L48).
func TestRelBeforePrefaceNoState_L44_L48(t *testing.T) {
	wbBubble(t, func(t *testing.T) {
		denv, penv := wbEnvs()
		a, b := newFakeIOPair(1500)
		defer a.Close()
		ch := wbReadHello(penv, b, nil)
		F := denv.Presets.firstCseq()
		open := wbOpen(1100)
		h1 := wbH1(denv, 9, wire.TypeOpen, open)
		pre := h1[:wire.PrefaceLen]
		first := denv.Presets.fseqFrom(pre)
		streamPre := make([]byte, wire.PrefaceLen)
		wire.PutPreface(streamPre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Instance: denv.Local, CarrierID: 9})
		badCRC := bytes.Clone(h1)
		badCRC[len(badCRC)-1] ^= 1
		badPre := bytes.Clone(h1)
		badPre[20] ^= 1
		garbage := bytes.Repeat([]byte{0x52, 0x4e}, 60)
		bad := []struct {
			name string
			d    []byte
		}{
			{"REL without its PREFACE", h1[wire.PrefaceLen:]},
			{"garbage", garbage},
			{"PREFACE alone", pre},
			{"PREFACE with a bad CRC", badPre},
			{"stream-kind PREFACE", append(bytes.Clone(streamPre), wbFrame(wire.TypeRel, 0, denv.Presets.fseqFrom(streamPre), 0, relPayloadOf(F, wire.TypeOpen, 0, wire.SessionHandle, open))...)},
			{"bad frame CRC", badCRC},
			{"a second frame", append(bytes.Clone(h1), wbFrame(wire.TypePing, 0, first+1, 0, wbPingPayload(wire.Ping{ID: 1}))...)},
			{"wrong fseq", append(bytes.Clone(pre), wbFrame(wire.TypeRel, 0, first+1, 0, relPayloadOf(F, wire.TypeOpen, 0, wire.SessionHandle, open))...)},
			{"REL cseq F+1", append(bytes.Clone(pre), wbFrame(wire.TypeRel, 0, first, 0, relPayloadOf(F+1, wire.TypeOpen, 0, wire.SessionHandle, open))...)},
			{"REL{FIN}", append(bytes.Clone(pre), wbFrame(wire.TypeRel, 0, first, 0, relPayloadOf(F, wire.TypeFin, 0, wire.SessionHandle, finInner(0)))...)},
			{"padded PING", append(bytes.Clone(pre), wbFrame(wire.TypePing, 0, first, 0, wbPingPayload(wire.Ping{ID: 1, Pad: 4}))...)},
		}
		for _, x := range bad {
			_ = a.WriteDatagram(x.d)
			synctest.Wait()
			if d, ok := a.tryRead(); ok {
				t.Errorf("%s: the passive answered % x", x.name, d)
			}
			select {
			case r := <-ch:
				t.Fatalf("%s: ReadHelloDatagram returned %v, %v", x.name, r.h, r.err)
			default:
			}
		}
		if n := penv.Dgram.Dropped.Load(); n != uint64(len(bad)) {
			t.Errorf("Dropped %d, want %d", n, len(bad))
		}
		if b.closes.Load() != 0 {
			t.Errorf("the transport was closed")
		}
		_ = a.WriteDatagram(h1)
		r := <-ch
		if r.err != nil {
			t.Fatalf("valid H1: %v", r.err)
		}
		defer func() {
			r.h.Conn.Kill(CauseLocalClose, "test end")
			<-r.h.Conn.Done()
		}()
		if r.h.First.Type != wire.TypeOpen || !bytes.Equal(r.h.Payload, open) || r.h.Preface.CarrierID != 9 {
			t.Errorf("Hello %+v", r.h)
		}
		// Until the admission's SetBudget: budget and receive limit
		// MinFrameBudget, and the transport reads no more than that (an H1
		// this small fits), so a verdict closer's buffer is a small class.
		if c := r.h.Conn; c.MTU() != wire.MinFrameBudget || c.RecvLimit() != wire.MinFrameBudget || b.ReadSize() != wire.MinFrameBudget+1 {
			t.Errorf("Hello budget %d, receive limit %d, ReadSize %d; want %d, %d, %d", c.MTU(), c.RecvLimit(), b.ReadSize(), wire.MinFrameBudget, wire.MinFrameBudget, wire.MinFrameBudget+1)
		}
		synctest.Wait()
		var answers [][]byte
		for {
			d, ok := a.tryRead()
			if !ok {
				break
			}
			answers = append(answers, d)
		}
		if len(answers) != 1 || !wire.IsPreface(answers[0]) || !bytes.Equal(answers[0], r.h.Conn.dg.hs.h2()) {
			t.Fatalf("answers %x, want exactly the stored H2", answers)
		}
		if rk := racksOf(answers[0][wire.PrefaceLen:]); len(rk) != 1 || rk[0].CumAck != F {
			t.Errorf("H2 RACKs %+v, want RACK{%d}", rk, F)
		}
	})
}

// TestDatagramRefusalsStateless_L44: VERSION (another major), FEATURE
// (unknown required bits) and the gate's CAPACITY and GOING_AWAY are one
// PREFACE_ACK each, alone, repeated identically for every datagram that
// starts with the refused PREFACE until 2 s after the first, never for
// another PREFACE; then the transport closes and ReadHelloDatagram returns
// errHelloRefused (M2-D21; L44).
func TestDatagramRefusalsStateless_L44(t *testing.T) {
	major3 := func(denv *Env) []byte {
		h1 := wbH1(denv, 9, wire.TypeOpen, wbOpen(1100))
		h1[4] = 3
		binary.BigEndian.PutUint32(h1[36:40], wire.CRC(h1[:36]))
		return h1
	}
	feature := func(denv *Env) []byte {
		pre := make([]byte, wire.PrefaceLen)
		wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindDatagram, Req: 1 << 31, Instance: denv.Local, CarrierID: 9})
		return pre
	}
	plain := func(denv *Env) []byte { return wbH1(denv, 9, wire.TypeOpen, wbOpen(1100)) }
	for _, tc := range []struct {
		name   string
		h1     func(*Env) []byte
		gate   wire.PrefaceStatus
		status wire.PrefaceStatus
	}{
		{"VERSION", major3, wire.PrefaceOK, wire.PrefaceVersion},
		{"FEATURE", feature, wire.PrefaceOK, wire.PrefaceFeature},
		{"CAPACITY", plain, wire.PrefaceCapacity, wire.PrefaceCapacity},
		{"GOING_AWAY", plain, wire.PrefaceGoingAway, wire.PrefaceGoingAway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				denv, penv := wbEnvs()
				a, b := newFakeIOPair(1500)
				defer a.Close()
				var gate Gate
				if tc.gate != wire.PrefaceOK {
					gate = func(*wire.Preface) wire.PrefaceStatus { return tc.gate }
				}
				start := time.Now()
				ch := wbReadHello(penv, b, gate)
				h1 := tc.h1(denv)
				other := wbH1(denv, 10, wire.TypeOpen, wbOpen(1100))
				drain := func() [][]byte {
					synctest.Wait()
					var out [][]byte
					for {
						d, ok := a.tryRead()
						if !ok {
							return out
						}
						out = append(out, d)
					}
				}
				_ = a.WriteDatagram(h1)
				got := drain()
				if len(got) != 1 || len(got[0]) != wire.PrefaceLen {
					t.Fatalf("answers %x, want one PREFACE_ACK alone", got)
				}
				ref := got[0]
				if ack, err := wire.ParsePrefaceAck(ref); err != nil || ack.Status != tc.status || ack.CarrierID != 9 {
					t.Fatalf("refusal %+v, %v; want status %d echoing carrier 9", ack, err, tc.status)
				}
				for _, at := range []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond} {
					time.Sleep(time.Until(start.Add(at)))
					_ = a.WriteDatagram(other) // another PREFACE: never answered
					_ = a.WriteDatagram(h1)
					if got := drain(); len(got) != 1 || !bytes.Equal(got[0], ref) {
						t.Errorf("at %v: answers %x, want the same refusal once", at, got)
					}
				}
				r := <-ch
				if !errors.Is(r.err, errHelloRefused) || r.h != nil {
					t.Fatalf("ReadHelloDatagram: %v, want errHelloRefused", r.err)
				}
				if el := r.at.Sub(start); el != 2*time.Second {
					t.Errorf("refusal window %v, want 2 s", el)
				}
				synctest.Wait()
				if n := b.closes.Load(); n != 1 {
					t.Errorf("transport closed %d times, want once", n)
				}
				_ = a.WriteDatagram(h1)
				if got := drain(); len(got) != 0 {
					t.Errorf("answered after the window: %x", got)
				}
			})
		})
	}
}

// wbVerdictHello establishes a passive Conn over the fake pair (a: the raw
// dialer end, b: the passive's transport) from an OPEN H1 and returns it
// with the dialer's next fseq.
func wbVerdictHello(t *testing.T, penv, denv *Env, a *fakeIO, b PacketIO) (*Hello, uint32) {
	t.Helper()
	ch := wbReadHello(penv, b, nil)
	h1 := wbH1(denv, 9, wire.TypeOpen, wbOpen(1100))
	_ = a.WriteDatagram(h1)
	r := <-ch
	if r.err != nil {
		t.Fatalf("hello: %v", r.err)
	}
	synctest.Wait()
	for { // the H2
		if _, ok := a.tryRead(); !ok {
			break
		}
	}
	return r.h, denv.Presets.fseqFrom(h1[:wire.PrefaceLen]) + 1
}

// wbCapacity is an OPEN_ACK(CAPACITY) payload.
func wbCapacity() []byte {
	p := make([]byte, wire.OpenAckFixedLen)
	n := wire.PutOpenAck(p, &wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeBacklog})
	return p[:n]
}

// TestDatagramVerdictReliable: a datagram verdict (Conn.WriteAndClose on an
// unstarted datagram carrier) is the passive's REL{F}, resent at 0.3 s
// doubling — a new outer frame around the byte-identical REL payload —
// until a RACK covering it, or 2 s (the deadline when earlier); a duplicate
// H1 meanwhile gets the stored H2 and the verdict again; then the transport
// closes once, and the carrier ends local_close. A transport whose read
// ignores its deadline is closed by the last resort of the closer's
// abandonment (M2-D21; R1-7).
func TestDatagramVerdictReliable(t *testing.T) {
	type copyAt struct {
		at   time.Duration
		fseq uint32
		rel  []byte
	}
	verdicts := func(start time.Time, ws []dgWrite) (out []copyAt) {
		for _, w := range ws {
			fs, _ := dgDecode(w.b)
			for _, f := range fs {
				if f.Type == wire.TypeRel {
					out = append(out, copyAt{w.at.Sub(start), f.Fseq, f.Payload})
				}
			}
		}
		return out
	}
	for _, tc := range []struct {
		name     string
		lose     int           // verdict copies lost on the way
		rackAt   time.Duration // the raw dialer RACKs then (0: never)
		below    bool          // that RACK covers only F − 1: not the verdict
		dupAt    time.Duration // the raw dialer repeats its H1 then (0: never)
		deadline time.Duration
		want     []time.Duration // verdict copies
		closedAt time.Duration
	}{
		{"resent until RACKed", 2, 1000 * time.Millisecond, false, 0, 10 * time.Second, []time.Duration{0, 300 * time.Millisecond, 900 * time.Millisecond}, time.Second},
		{"never RACKed", 0, 0, false, 0, 10 * time.Second, []time.Duration{0, 300 * time.Millisecond, 900 * time.Millisecond}, 2 * time.Second},
		{"RACK below the verdict", 0, 1000 * time.Millisecond, true, 0, 10 * time.Second, []time.Duration{0, 300 * time.Millisecond, 900 * time.Millisecond}, 2 * time.Second},
		{"deadline first", 0, 0, false, 0, 500 * time.Millisecond, []time.Duration{0, 300 * time.Millisecond}, 500 * time.Millisecond},
		{"duplicate H1", 0, 200 * time.Millisecond, false, 100 * time.Millisecond, 10 * time.Second, []time.Duration{0, 100 * time.Millisecond}, 200 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				denv, penv := wbEnvs()
				a, b := newFakeIOPair(1500)
				defer a.Close()
				h, fs := wbVerdictHello(t, penv, denv, a, b)
				var lost atomic.Int32
				b.setFilter(func(d []byte) bool {
					if len(wbRelsIn(d)) > 0 && lost.Load() < int32(tc.lose) {
						lost.Add(1)
						return false
					}
					return true
				})
				b.setRec(true)
				start := time.Now()
				h.Conn.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, wbCapacity(), start.Add(tc.deadline))
				if tc.dupAt > 0 {
					time.Sleep(tc.dupAt)
					_ = a.WriteDatagram(wbH1(denv, 9, wire.TypeOpen, wbOpen(1100)))
				}
				F := penv.Presets.firstCseq()
				if tc.rackAt > 0 {
					time.Sleep(time.Until(start.Add(tc.rackAt)))
					var rk [wire.RackLen]byte
					cum := F
					if tc.below {
						cum = F - 1
					}
					wire.PutRack(rk[:], &wire.Rack{CumAck: cum})
					_ = a.WriteDatagram(wbFrame(wire.TypeRack, 0, fs, 0, rk[:]))
				}
				hWait(t, h.Conn)
				closed := time.Since(start)
				synctest.Wait()
				if closed != tc.closedAt {
					t.Errorf("closed after %v, want %v", closed, tc.closedAt)
				}
				if n := b.closes.Load(); n != 1 {
					t.Errorf("transport closed %d times, want once", n)
				}
				if c := hCause(h.Conn); c != CauseLocalClose {
					t.Errorf("cause %v, want local_close", c)
				}
				vs := verdicts(start, b.recorded())
				if len(vs) != len(tc.want) {
					t.Fatalf("%d verdict copies %+v, want at %v", len(vs), vs, tc.want)
				}
				for i, v := range vs {
					h, inner, err := wire.ParseRel(v.rel)
					if err != nil || h.Cseq != F || h.Type != wire.TypeOpenAck || !bytes.Equal(inner, wbCapacity()) {
						t.Errorf("copy %d: %+v %v", i, h, err)
					}
					if v.at != tc.want[i] {
						t.Errorf("copy %d at %v, want %v", i, v.at, tc.want[i])
					}
					if !bytes.Equal(v.rel, vs[0].rel) || (i > 0 && v.fseq == vs[i-1].fseq) {
						t.Errorf("copy %d: not a new outer frame around the same REL payload", i)
					}
				}
				if tc.dupAt > 0 {
					var h2s int
					for _, w := range b.recorded() {
						if bytes.Equal(w.b, h.Conn.dg.hs.h2()) {
							h2s++
						}
					}
					if h2s != 1 {
						t.Errorf("stored H2 written %d times for the duplicate H1, want 1", h2s)
					}
				}
				if n := h.Conn.Stats().Retransmits; n != uint64(len(tc.want)-1) {
					t.Errorf("Retransmits %d, want %d", n, len(tc.want)-1)
				}
			})
		})
	}
	t.Run("read ignores its deadline", func(t *testing.T) {
		wbBubble(t, func(t *testing.T) {
			denv, penv := wbEnvs()
			a, b := newFakeIOPair(1500)
			defer a.Close()
			deaf := &wbDeafIO{fakeIO: b}
			h, _ := wbVerdictHello(t, penv, denv, a, deaf)
			deaf.deaf.Store(true)
			start := time.Now()
			h.Conn.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, wbCapacity(), start.Add(10*time.Second))
			hWait(t, h.Conn)
			if el := time.Since(start); el != penv.Timing.AbandonWait+2*time.Second {
				t.Errorf("Done after %v, want AbandonWait + 2 s", el)
			}
			synctest.Wait()
			if n := b.closes.Load(); n != 1 {
				t.Errorf("transport closed %d times, want once (the last resort)", n)
			}
			if n := penv.Abandon.Len(); n != 0 {
				t.Errorf("abandoned-call pool %d after the close returned, want 0", n)
			}
		})
	})
}

// wbDeafIO is a fakeIO whose read ignores deadlines once deaf (Close still
// ends it).
type wbDeafIO struct {
	*fakeIO
	deaf atomic.Bool
}

func (d *wbDeafIO) SetReadDeadline(t time.Time) error {
	if d.deaf.Load() {
		return nil
	}
	return d.fakeIO.SetReadDeadline(t)
}

func (d *wbDeafIO) SetDeadline(t time.Time) error { return d.SetReadDeadline(t) }

// TestDatagramProbeCarrier (carrier level; the passive's sessionless count
// and "never adopted" are the root's TestDatagramProbesE2E): a datagram
// factory's probe carrier sends H1p = PREFACE ‖ PING and is established
// by H2p's PONG, with the frame budget MinFrameBudget on both ends; a
// passive whose
// sessionless pool is full answers REL{F, CLOSE(capacity)} after H2p, which
// the started probe carrier dispatches (R1-3): it retires, and the health
// layer marks the factory failed with reason "capacity" (plan:175); a
// probe retired by a CLOSE of another reason marks nothing.
func TestDatagramProbeCarrier(t *testing.T) {
	wbBubble(t, func(t *testing.T) {
		denv, penv := wbEnvs()
		var h1ps [2]<-chan []byte
		var pmu sync.Mutex
		var passives []*Conn // factory 0's passive probe carriers
		var links [3]*rendrtest.DatagramLink
		var fs []Factory
		for i := range 3 {
			l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: fmt.Sprintf("p%d", i), Accept: func(pc net.PacketConn, peer net.Addr) error {
				io, err := NewPacketIO(penv, pc, peer, wire.MaxDatagram)
				if err != nil {
					return err
				}
				go func() {
					h, err := ReadHelloDatagram(penv, io, time.Now().Add(10*time.Second), 0, nil)
					if err != nil {
						return
					}
					if h.First.Type != wire.TypePing {
						h.Conn.Kill(CauseProtocolViolation, "probe carriers only")
						return
					}
					if i > 0 {
						reason := wire.CloseCapacity
						if i == 2 {
							reason = wire.CloseRetire
						}
						var b [wire.ReasonLen]byte
						wire.PutReason(b[:], uint8(reason))
						h.Conn.WriteAndClose(wire.TypeClose, 0, 0, b[:], time.Now().Add(2*time.Second))
						return
					}
					pmu.Lock()
					passives = append(passives, h.Conn)
					pmu.Unlock()
					h.Conn.Start(nil, nil, StartOptions{Sessionless: true})
				}()
				return nil
			}})
			links[i] = l
			if i < 2 {
				h1ps[i] = l.CaptureNext(rendrtest.Up, rendrtest.FramePing)
			}
			fs = append(fs, Factory{Index: i, Name: l.Name(), Kind: wire.KindDatagram, DialPacket: l.Dial, MTU: 1200})
		}
		hl := NewHealth(denv, fs, prParams())
		hl.Use()
		time.Sleep(time.Second)
		synctest.Wait()
		for i := range 2 {
			select {
			case d := <-h1ps[i]:
				if !wire.IsPreface(d) || !hasType(d[wire.PrefaceLen:], wire.TypePing) || len(wbRelsIn(d)) != 0 {
					t.Errorf("factory %d H1p % x, want PREFACE ‖ PING", i, d)
				}
			default:
				t.Errorf("factory %d: no H1p", i)
			}
		}
		s := hl.Snapshot()
		if s.Failed[0] || s.Info[0].ProbeCarrier == 0 {
			t.Errorf("factory 0: failed %v, probe carrier %d; want a live probe", s.Failed[0], s.Info[0].ProbeCarrier)
		}
		if !s.Failed[1] || s.Info[1].FailReason != "capacity" {
			t.Errorf("factory 1: failed %v reason %q, want capacity", s.Failed[1], s.Info[1].FailReason)
		}
		if s.Failed[2] {
			t.Errorf("factory 2: failed (reason %q) after a CLOSE(retire), want no mark", s.Info[2].FailReason)
		}
		hl.mu.Lock()
		pc := hl.fac[0].conn
		hl.mu.Unlock()
		if pc == nil || pc.Kind() != wire.KindDatagram || pc.MTU() != wire.MinFrameBudget || pc.RecvLimit() != wire.MinFrameBudget {
			t.Errorf("probe carrier %v: want a datagram carrier of budget %d", pc, wire.MinFrameBudget)
		}
		pmu.Lock()
		ps := append([]*Conn(nil), passives...)
		pmu.Unlock()
		if len(ps) == 0 || ps[0].MTU() != wire.MinFrameBudget {
			t.Errorf("passive probe carriers %v: want budget %d", ps, wire.MinFrameBudget)
		}
		hl.Close()
		for _, c := range ps {
			c.Kill(CauseLocalClose, "test end")
			<-c.Done()
		}
		for _, l := range links {
			l.Close()
		}
	})
}
