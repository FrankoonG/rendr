package carrier

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

var hDialerInst = [16]byte{0xdd, 15: 0xdd}

// hPreface encodes a valid dialer PREFACE for carrier id.
func hPreface(id uint32) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPreface(b, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Instance: hDialerInst, CarrierID: id})
	return b
}

// recrc recomputes the CRC32C of a 40-byte preface after its bytes 0–35
// were edited (a well-formed preface with another value).
func recrc(b []byte) []byte {
	binary.BigEndian.PutUint32(b[36:40], wire.CRC(b[:36]))
	return b
}

// edit returns a copy of b changed by f.
func edit(b []byte, f func(b []byte)) []byte {
	c := bytes.Clone(b)
	f(c)
	return c
}

// hFirst encodes a first frame (fseq = the first fseq, handle by type).
func hFirst(env *Env, t wire.Type, payload []byte) []byte {
	var handle uint32
	if !t.CarrierLevel() {
		handle = wire.SessionHandle
	}
	return wire.AppendFrame(nil, wire.Header{Type: t, Fseq: env.Presets.firstFseq(), Handle: handle}, payload)
}

func openPayload(meta int) []byte {
	o := wire.Open{SID: [16]byte{1, 15: 1}, Kind: wire.KindStream, Mode: 1, RetainMs: 30000, Window: 8 << 20, Metadata: bytes.Repeat([]byte{'m'}, meta)}
	b := make([]byte, wire.OpenFixedLen+meta)
	wire.PutOpen(b, &o)
	return b
}

// TestReadHelloCanonicalAnswers_L44: ReadHello answers from ParsePreface's
// error alone, in the canonical order of design §5.1: a short, foreign
// (v1, msess, not rendr), corrupt or malformed PREFACE is closed silently;
// another major gets PREFACE_ACK(VERSION) and unknown required bits
// PREFACE_ACK(FEATURE); a valid PREFACE refused by the gate gets its status.
// Every refusal is a well-formed v2 PREFACE_ACK followed by EOF, and no
// Hello (no state) results.
func TestReadHelloCanonicalAnswers_L44(t *testing.T) {
	good := hPreface(42)
	cases := []struct {
		name   string
		in     []byte
		gate   wire.PrefaceStatus
		answer int // -1: silent close; else the PREFACE_ACK status
	}{
		{"short", good[:39], 0, -1},
		{"v1 magic", recrc(edit(good, func(b []byte) { copy(b, "RND1") })), 0, -1},
		{"msess hello", []byte("MSES\x01\x00 hello from msess, not a rendr preface!"), 0, -1},
		{"crc", edit(good, func(b []byte) { b[39] ^= 1 }), 0, -1},
		{"major 1", recrc(edit(good, func(b []byte) { b[4] = 1 })), 0, int(wire.PrefaceVersion)},
		{"major 3 with changed fields", recrc(edit(good, func(b []byte) { b[4] = 3; b[6] = 9; b[7] = 9; b[20] = 7 })), 0, int(wire.PrefaceVersion)},
		{"role", recrc(edit(good, func(b []byte) { b[7] = byte(wire.RolePassive) })), 0, -1},
		{"kind", recrc(edit(good, func(b []byte) { b[6] = 3 })), 0, -1},
		{"datagram kind on a stream conn", recrc(edit(good, func(b []byte) { b[6] = byte(wire.KindDatagram) })), 0, -1},
		{"zero instance", recrc(edit(good, func(b []byte) { clear(b[16:32]) })), 0, -1},
		{"zero carrier id", recrc(edit(good, func(b []byte) { clear(b[32:36]) })), 0, -1},
		{"unknown required bit", recrc(edit(good, func(b []byte) { b[11] = 0x20 })), 0, int(wire.PrefaceFeature)},
		{"unknown optional bit is fine but the gate says GOING_AWAY", recrc(edit(good, func(b []byte) { b[15] = 0x20 })), wire.PrefaceGoingAway, int(wire.PrefaceGoingAway)},
		{"gate CAPACITY", good, wire.PrefaceCapacity, int(wire.PrefaceCapacity)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				var reply []byte
				var rerr error
				done := make(chan struct{})
				go func() {
					defer close(done)
					if _, err := b.Write(tc.in); err != nil {
						rerr = err
						return
					}
					if len(tc.in) < wire.PrefaceLen {
						b.Close()
						return
					}
					reply, rerr = io.ReadAll(b)
				}()
				gate := func(*wire.Preface) wire.PrefaceStatus { return tc.gate }
				h, err := ReadHello(env, a, time.Now().Add(10*time.Second), 4096, gate)
				<-done
				b.Close()
				synctest.Wait()
				if h != nil || err == nil {
					t.Fatalf("ReadHello accepted: %+v", h)
				}
				if rerr != nil && !errors.Is(rerr, io.ErrClosedPipe) {
					t.Fatalf("dialer side: %v", rerr)
				}
				if tc.answer < 0 {
					if len(reply) != 0 {
						t.Fatalf("a silent close answered %d bytes", len(reply))
					}
					return
				}
				if len(reply) != wire.PrefaceLen {
					t.Fatalf("answer of %d bytes, want one PREFACE_ACK", len(reply))
				}
				ack, perr := wire.ParsePrefaceAck(reply)
				if perr != nil || int(ack.Status) != tc.answer || ack.Instance != env.Local {
					t.Fatalf("answer %+v %v, want status %d", ack, perr, tc.answer)
				}
				if tc.answer == int(wire.PrefaceFeature) && ack.CarrierID != 42 {
					t.Fatalf("FEATURE answer echoes carrier %d", ack.CarrierID)
				}
			})
		})
	}
}

// helloDialer is the dialer side of a ReadHello test: it writes the
// PREFACE, reads the PREFACE_ACK (which must arrive before the first frame
// is sent, P18), writes the first frame and then collects everything else
// until EOF.
type helloDialer struct {
	ack  wire.PrefaceAck
	rest []byte
	err  error
	done chan struct{}
}

func dialHello(nc net.Conn, preface, first []byte) *helloDialer {
	d := &helloDialer{done: make(chan struct{})}
	go func() {
		defer close(d.done)
		if _, d.err = nc.Write(preface); d.err != nil {
			return
		}
		var ab [wire.PrefaceLen]byte
		if _, d.err = io.ReadFull(nc, ab[:]); d.err != nil {
			return
		}
		if d.ack, d.err = wire.ParsePrefaceAck(ab[:]); d.err != nil {
			return
		}
		go nc.Write(first) // may stay partly unread (a refused OPEN); the close unblocks it
		d.rest, d.err = io.ReadAll(nc)
	}()
	return d
}

// TestReadHelloFirstFrame (§6.1, P18): after PREFACE_ACK(OK) — written
// before the first frame is read — ReadHello returns a verified OPEN, JOIN
// or PING with an unstarted Conn bound to the dialer's identity; an OPEN
// whose metadata exceeds maxMeta is returned unread (MetaTooLarge) and can
// be answered with WriteAndClose; a PING (also with a streamed pad) becomes
// the pending PONG; a wrong first frame type, fseq or CRC is refused.
func TestReadHelloFirstFrame(t *testing.T) {
	t.Run("OPEN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			a, b := net.Pipe()
			d := dialHello(b, hPreface(9), hFirst(env, wire.TypeOpen, openPayload(100)))
			h, err := ReadHello(env, a, time.Now().Add(time.Second), 4096, nil)
			if err != nil {
				t.Fatal(err)
			}
			if h.First.Type != wire.TypeOpen || h.MetaTooLarge || h.Preface.CarrierID != 9 || h.Preface.Instance != hDialerInst {
				t.Fatalf("hello %+v", h)
			}
			if o, err := wire.ParseOpen(h.Payload, 4096); err != nil || len(o.Metadata) != 100 || o.Window != 8<<20 {
				t.Fatalf("OPEN %+v %v", o, err)
			}
			c := h.Conn
			if c.ID() != 9 || c.PeerInstance() != hDialerInst || c.Factory() != -1 || c.Name() != "" {
				t.Fatalf("conn identity %d %v %d %q", c.ID(), c.PeerInstance(), c.Factory(), c.Name())
			}
			if d.ack.Status != wire.PrefaceOK || d.ack.CarrierID != 9 || d.ack.Instance != env.Local {
				t.Fatalf("PREFACE_ACK %+v", d.ack)
			}
			c.Kill(CauseLocalClose, "test end")
			hWait(t, c)
			<-d.done
		})
	})
	t.Run("OPEN metadata too large", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			a, b := net.Pipe()
			d := dialHello(b, hPreface(9), hFirst(env, wire.TypeOpen, openPayload(5000)))
			h, err := ReadHello(env, a, time.Now().Add(time.Second), 4096, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !h.MetaTooLarge || h.Payload != nil {
				t.Fatalf("MetaTooLarge %v, payload %d bytes", h.MetaTooLarge, len(h.Payload))
			}
			var oa [wire.OpenAckFixedLen]byte
			wire.PutOpenAck(oa[:], &wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeMetadataSize})
			h.Conn.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, oa[:], time.Now().Add(time.Second))
			hWait(t, h.Conn)
			<-d.done
			f, n, err := wire.DecodeFrame(d.rest)
			if err != nil || n != len(d.rest) || f.Type != wire.TypeOpenAck || f.Fseq != env.Presets.firstFseq() {
				t.Fatalf("verdict %+v (%d of %d bytes) %v", f.Header, n, len(d.rest), err)
			}
			if a, err := wire.ParseOpenAck(f.Payload); err != nil || a.Status != wire.StatusBadRequest || a.Code != wire.CodeMetadataSize {
				t.Fatalf("OPEN_ACK %+v %v", a, err)
			}
		})
	})
	t.Run("JOIN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Presets.FirstFseq = 0xffffffff
			a, b := net.Pipe()
			var jp [wire.JoinLen]byte
			wire.PutJoin(jp[:], &wire.Join{SID: [16]byte{2, 15: 2}, Mode: 2, RxNext: 1234})
			d := dialHello(b, hPreface(10), hFirst(env, wire.TypeJoin, jp[:]))
			h, err := ReadHello(env, a, time.Now().Add(time.Second), 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			if j, err := wire.ParseJoin(h.Payload); err != nil || j.RxNext != 1234 || h.First.Fseq != 0xffffffff {
				t.Fatalf("JOIN %+v %v (fseq %#x)", j, err, h.First.Fseq)
			}
			if h.Conn.rd.fseq != 0 || h.Conn.wr.fseq != 0xffffffff {
				t.Fatalf("next fseq rx %#x tx %#x", h.Conn.rd.fseq, h.Conn.wr.fseq)
			}
			h.Conn.Kill(CauseLocalClose, "test end")
			hWait(t, h.Conn)
			<-d.done
		})
	})
	t.Run("PING", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			a, b := net.Pipe()
			ping := wire.Ping{ID: 77, TS: 5, Nonce: 0xfeed, Pad: 30000}
			d := dialHello(b, hPreface(11), hFirst(env, wire.TypePing, pingPayload(ping)))
			h, err := ReadHello(env, a, time.Now().Add(time.Second), 4096, nil)
			if err != nil {
				t.Fatal(err)
			}
			if h.First.Type != wire.TypePing || h.Ping != ping || h.Payload != nil {
				t.Fatalf("hello %+v", h)
			}
			h.Conn.Start(nil, &hBell{}, StartOptions{Sessionless: true})
			synctest.Wait()
			h.Conn.Kill(CauseLocalClose, "test end")
			hWait(t, h.Conn)
			<-d.done
			f, _, err := wire.DecodeFrame(d.rest)
			if err != nil || f.Type != wire.TypePong {
				t.Fatalf("first frame %+v %v", f.Header, err)
			}
			if pg, err := wire.ParsePing(f.Payload); err != nil || pg != ping {
				t.Fatalf("PONG %+v %v, want the echo of %+v", pg, err, ping)
			}
		})
	})
	for _, bad := range []struct {
		name  string
		first func(env *Env) []byte
	}{
		{"DATA first", func(env *Env) []byte { return hFirst(env, wire.TypeData, dataPayload(0, 10)) }},
		{"ACK first", func(env *Env) []byte { return hFirst(env, wire.TypeAck, make([]byte, wire.AckLen)) }},
		{"wrong fseq", func(env *Env) []byte {
			return wire.AppendFrame(nil, wire.Header{Type: wire.TypeOpen, Fseq: 7, Handle: wire.SessionHandle}, openPayload(0))
		}},
		{"crc", func(env *Env) []byte {
			b := hFirst(env, wire.TypeOpen, openPayload(0))
			b[len(b)-1] ^= 1
			return b
		}},
		{"session handle 0", func(env *Env) []byte {
			return wire.AppendFrame(nil, wire.Header{Type: wire.TypeOpen, Fseq: env.Presets.firstFseq()}, openPayload(0))
		}},
		{"PING with a non-zero pad", func(env *Env) []byte {
			p := pingPayload(wire.Ping{ID: 1, Pad: 600})
			p[len(p)-1] = 1
			return hFirst(env, wire.TypePing, p)
		}},
	} {
		t.Run(bad.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				d := dialHello(b, hPreface(12), bad.first(env))
				h, err := ReadHello(env, a, time.Now().Add(time.Second), 4096, nil)
				if h != nil || err == nil {
					t.Fatalf("accepted %+v", h)
				}
				<-d.done
				b.Close()
				if len(d.rest) != 0 {
					t.Fatalf("a refused first frame was answered with %d bytes", len(d.rest))
				}
			})
		})
	}
}

// TestSessionlessCarrierLifecycle (§6.4): a passive sessionless carrier
// answers the PING recorded by ReadHello as its first frame, answers later
// PINGs, never PINGs itself, and retires with CLOSE after SessionlessIdle
// without a PING.
func TestSessionlessCarrierLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		go func() {
			b.Write(hPreface(5))
			var ab [wire.PrefaceLen]byte
			io.ReadFull(b, ab[:])
			b.Write(hFirst(env, wire.TypePing, pingPayload(wire.Ping{ID: 1})))
		}()
		h, err := ReadHello(env, a, time.Now().Add(time.Second), 4096, nil)
		if err != nil {
			t.Fatal(err)
		}
		p := startPeer(b, env.Presets.firstFseq())
		p.wmu.Lock()
		p.txFseq = env.Presets.firstFseq() + 1 // the PING above was the peer's first frame
		p.wmu.Unlock()
		var bell hBell
		h.Conn.Start(nil, &bell, StartOptions{Sessionless: true})
		for id := uint32(2); id <= 5; id++ {
			time.Sleep(10 * time.Second)
			if err := p.ping(id, false); err != nil {
				t.Fatal(err)
			}
		}
		last := time.Now()
		hWait(t, h.Conn)
		p.close()
		dead, cause, _, at := h.Conn.Death()
		if !dead || cause != CauseRetired {
			t.Fatalf("death %v %v", dead, cause)
		}
		if idle := at.Sub(last); idle < env.Timing.SessionlessIdle || idle > env.Timing.SessionlessIdle+time.Second {
			t.Fatalf("retired %v after the last PING, want SessionlessIdle (%v) plus the drain", idle, env.Timing.SessionlessIdle)
		}
		var types []wire.Type
		for _, f := range p.received() {
			types = append(types, f.Type)
		}
		want := []wire.Type{wire.TypePong, wire.TypePong, wire.TypePong, wire.TypePong, wire.TypePong, wire.TypeClose}
		if len(types) != len(want) {
			t.Fatalf("frames %v, want %v", types, want)
		}
		for i := range want {
			if types[i] != want[i] {
				t.Fatalf("frames %v, want %v", types, want)
			}
		}
	})
}
