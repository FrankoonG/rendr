package carrier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Establish and ReadHello joined by nothing but a raw net.Pipe (design §0.8
// V1). A net.Pipe has no buffer: a Write returns only once the other end
// has read every byte of it. Both ends run the production handshake, so an
// end that writes before reading what the other end writes at the same
// time holds both until the 10 s handshake deadline; these tests see that
// as virtual time passing and as a timeout instead of the typed result.

// phEnvs returns the dialer's and the passive's environments: the same
// timing and presets, distinct instances.
func phEnvs() (dialer, passive *Env) {
	dialer, passive = hEnv(), hEnv()
	passive.Local = hPassiveInst
	return dialer, passive
}

// phHello is the outcome of the passive end of a raw-pipe handshake.
type phHello struct {
	h    *Hello
	err  error
	took time.Duration
}

// phPassive runs ReadHello on nc on its own goroutine, with the handshake
// deadline 10 s ahead; answer, if non-nil, then runs there with an accepted
// Hello (the admission's part: start the carrier or write a verdict).
func phPassive(env *Env, nc net.Conn, gate Gate, answer func(h *Hello)) <-chan phHello {
	ch := make(chan phHello, 1)
	start := time.Now()
	go func() {
		h, err := ReadHello(env, nc, start.Add(10*time.Second), 4096, gate)
		took := time.Since(start)
		if err == nil && answer != nil {
			answer(h)
		}
		ch <- phHello{h, err, took}
	}()
	return ch
}

// phRewrite wraps nc so that the 40-byte preface at the head of its first
// Write is edited (then given a fresh CRC): an end of another major or with
// other feature bits, as the wire sees it.
func phRewrite(nc net.Conn, edit func(b []byte)) net.Conn {
	var done atomic.Bool
	return &hookConn{Conn: nc, onWrite: func(nc net.Conn, p []byte) (int, error) {
		if len(p) < wire.PrefaceLen || !done.CompareAndSwap(false, true) {
			return nc.Write(p)
		}
		q := bytes.Clone(p)
		edit(q)
		recrc(q[:wire.PrefaceLen])
		return nc.Write(q)
	}}
}

// phFirst is a passive session endpoint: its first Fill places the
// carrier's first response (place; nil leaves the OPEN pending), and it
// records the RST codes it receives.
type phFirst struct {
	hEP
	place  func(b *Batch) bool
	placed atomic.Bool
	rmu    sync.Mutex
	rsts   []uint32
}

func (e *phFirst) Fill(c *Conn, b *Batch) {
	if e.place != nil && !e.placed.Load() && e.place(b) {
		e.placed.Store(true)
	}
	e.hEP.Fill(c, b)
}

func (e *phFirst) Control(c *Conn, h wire.Header, p []byte) error {
	if h.Type == wire.TypeRst {
		if r, err := wire.ParseRst(p); err == nil {
			e.rmu.Lock()
			e.rsts = append(e.rsts, r.Code)
			e.rmu.Unlock()
		}
	}
	return e.hEP.Control(c, h, p)
}

func (e *phFirst) rstCodes() []uint32 {
	e.rmu.Lock()
	defer e.rmu.Unlock()
	return append([]uint32(nil), e.rsts...)
}

func phOpenAck(a wire.OpenAck) []byte {
	b := make([]byte, wire.OpenAckFixedLen+len(a.Msg))
	return b[:wire.PutOpenAck(b, &a)]
}

func phJoin() []byte {
	b := make([]byte, wire.JoinLen)
	wire.PutJoin(b, &wire.Join{SID: [16]byte{4, 15: 4}, Mode: 1})
	return b
}

// TestHandshakeOverRawPipe_L44 (design §0.8 V1): over a raw net.Pipe,
// Establish and ReadHello complete every answer at once, far inside the
// 10 s handshake deadline, with the typed result on both ends: OK for OPEN,
// JOIN and a probe PING (the passive carrier writes the response as its
// first frame); a PREFACE_ACK of VERSION — the passive refusing a dialer of
// another major, or a passive of another major answering — FEATURE,
// CAPACITY and GOING_AWAY (the passive's instance reported for every v2
// answer); and the admission's verdict frames written with WriteAndClose.
func TestHandshakeOverRawPipe_L44(t *testing.T) {
	place := func(f func(b *Batch) bool) func(h *Hello) {
		return func(h *Hello) { h.Conn.Start(&phFirst{place: f}, &hBell{}, StartOptions{Hold: true}) }
	}
	verdict := func(t wire.Type, handle uint32, payload []byte) func(h *Hello) {
		return func(h *Hello) { h.Conn.WriteAndClose(t, 0, handle, payload, time.Now().Add(time.Second)) }
	}
	gate := func(s wire.PrefaceStatus) Gate { return func(*wire.Preface) wire.PrefaceStatus { return s } }
	major3 := func(b []byte) { b[4] = 3 }
	var unknown [wire.JoinAckLen]byte
	wire.PutJoinAck(unknown[:], &wire.JoinAck{Status: wire.StatusUnknownSession})
	cases := []struct {
		name    string
		first   wire.Type
		gate    Gate
		dialer  func(b []byte)       // edits the dialer's PREFACE on the wire
		passive func(b []byte)       // edits the passive's PREFACE_ACK on the wire
		answer  func(h *Hello)       // the admission's answer to an accepted first frame
		status  wire.PrefaceStatus   // OK: established; else the EstablishError status
		named   bool                 // a refused attempt names the passive's instance
		refused bool                 // ReadHello refuses with a non-OK PREFACE_ACK
		racy    bool                 // the passive's own outcome races the dialer's close
		resp    wire.Type            // the established response
		check   func(p []byte) error // its payload
	}{
		{name: "OK", first: wire.TypeOpen, answer: place(func(b *Batch) bool {
			return b.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20})
		}), resp: wire.TypeOpenAck, check: func(p []byte) error {
			if a, err := wire.ParseOpenAck(p); err != nil || a.Status != wire.StatusOK || a.Window != 1<<20 {
				return fmt.Errorf("OPEN_ACK %+v %v", a, err)
			}
			return nil
		}},
		{name: "JOIN OK", first: wire.TypeJoin, answer: place(func(b *Batch) bool {
			return b.AddJoinAck(wire.SessionHandle, &wire.JoinAck{Status: wire.StatusOK, RxNext: 7})
		}), resp: wire.TypeJoinAck, check: func(p []byte) error {
			if a, err := wire.ParseJoinAck(p); err != nil || a.Status != wire.StatusOK || a.RxNext != 7 {
				return fmt.Errorf("JOIN_ACK %+v %v", a, err)
			}
			return nil
		}},
		{name: "probe PING", first: wire.TypePing, answer: func(h *Hello) {
			h.Conn.Start(nil, &hBell{}, StartOptions{Sessionless: true})
		}, resp: wire.TypePong},
		{name: "VERSION to a dialer of another major", first: wire.TypeOpen, dialer: major3,
			status: wire.PrefaceVersion, named: true, refused: true},
		{name: "VERSION from a passive of another major", first: wire.TypeOpen, passive: major3,
			status: wire.PrefaceVersion, racy: true},
		{name: "FEATURE", first: wire.TypeOpen, dialer: func(b []byte) { b[11] |= 0x20 },
			status: wire.PrefaceFeature, named: true, refused: true},
		{name: "CAPACITY", first: wire.TypeOpen, gate: gate(wire.PrefaceCapacity),
			status: wire.PrefaceCapacity, named: true, refused: true},
		{name: "GOING_AWAY", first: wire.TypeOpen, gate: gate(wire.PrefaceGoingAway),
			status: wire.PrefaceGoingAway, named: true, refused: true},
		{name: "OPEN_ACK CAPACITY verdict", first: wire.TypeOpen,
			answer: verdict(wire.TypeOpenAck, wire.SessionHandle, phOpenAck(wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeMaxSessions})),
			resp:   wire.TypeOpenAck, check: func(p []byte) error {
				if a, err := wire.ParseOpenAck(p); err != nil || a.Status != wire.StatusCapacity || a.Code != wire.CodeMaxSessions {
					return fmt.Errorf("OPEN_ACK %+v %v", a, err)
				}
				return nil
			}},
		{name: "OPEN_ACK GOING_AWAY verdict", first: wire.TypeOpen,
			answer: verdict(wire.TypeOpenAck, wire.SessionHandle, phOpenAck(wire.OpenAck{Status: wire.StatusGoingAway})),
			resp:   wire.TypeOpenAck, check: func(p []byte) error {
				if a, err := wire.ParseOpenAck(p); err != nil || a.Status != wire.StatusGoingAway {
					return fmt.Errorf("OPEN_ACK %+v %v", a, err)
				}
				return nil
			}},
		{name: "JOIN_ACK UNKNOWN_SESSION verdict", first: wire.TypeJoin,
			answer: verdict(wire.TypeJoinAck, wire.SessionHandle, unknown[:]),
			resp:   wire.TypeJoinAck, check: func(p []byte) error {
				if a, err := wire.ParseJoinAck(p); err != nil || a.Status != wire.StatusUnknownSession {
					return fmt.Errorf("JOIN_ACK %+v %v", a, err)
				}
				return nil
			}},
		{name: "CLOSE capacity for a probe", first: wire.TypePing,
			answer: verdict(wire.TypeClose, 0, []byte{byte(wire.CloseCapacity)}), resp: wire.TypeClose},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				envD, envP := phEnvs()
				a, b := net.Pipe()
				var dc, pc net.Conn = a, b
				if tc.dialer != nil {
					dc = phRewrite(a, tc.dialer)
				}
				if tc.passive != nil {
					pc = phRewrite(b, tc.passive)
				}
				pass := phPassive(envP, pc, tc.gate, tc.answer)
				var payload []byte
				switch tc.first {
				case wire.TypeOpen:
					payload = openPayload(0)
				case wire.TypeJoin:
					payload = phJoin()
				}
				f := Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return dc, nil }}
				start := time.Now()
				est, err := Establish(context.Background(), envD, f, envD.IDs.Next(), tc.first, payload, nil)
				if took := time.Since(start); took != 0 {
					t.Fatalf("Establish took %v of the 10 s handshake deadline (%v)", took, err)
				}
				ph := <-pass
				if tc.status == wire.PrefaceOK {
					if err != nil {
						t.Fatalf("Establish: %v", err)
					}
					if est.Resp.Type != tc.resp || est.Ack.Instance != hPassiveInst || est.Conn.PeerInstance() != hPassiveInst {
						t.Fatalf("established %v from %v, want %v from the passive", est.Resp.Type, est.Ack.Instance, tc.resp)
					}
					if tc.check != nil {
						if err := tc.check(est.Payload); err != nil {
							t.Fatal(err)
						}
					}
					est.Conn.Kill(CauseLocalClose, "test end")
					hWait(t, est.Conn)
				} else {
					var ee *EstablishError
					if est != nil || !errors.As(err, &ee) {
						t.Fatalf("Establish: %v %v", est, err)
					}
					if ee.Stage != "preface" || ee.Status != tc.status || ee.Cause != CauseTransportError || ee.PrefaceOK {
						t.Fatalf("error %+v, want status %v", ee, tc.status)
					}
					if tc.named != (ee.Instance == hPassiveInst) {
						t.Fatalf("instance %v reported (want the passive's: %v)", ee.Instance, tc.named)
					}
				}
				switch {
				case tc.refused:
					if ph.h != nil || !errors.Is(ph.err, errHelloRefused) {
						t.Fatalf("ReadHello: %+v %v, want a refusal", ph.h, ph.err)
					}
				case !tc.racy && (ph.err != nil || ph.h == nil):
					t.Fatalf("ReadHello: %v", ph.err)
				}
				if !tc.racy && ph.took != 0 {
					t.Fatalf("ReadHello took %v of the 10 s handshake deadline", ph.took)
				}
				if ph.h != nil {
					ph.h.Conn.Kill(CauseLocalClose, "test end")
					hWait(t, ph.h.Conn)
				}
				synctest.Wait()
				if envD.IDs.inUse() != 0 || envD.Abandon.Len() != 0 || envP.Abandon.Len() != 0 {
					t.Fatalf("IDs in use %d, abandoned %d + %d", envD.IDs.inUse(), envD.Abandon.Len(), envP.Abandon.Len())
				}
				if envD.Budget.Used() != 0 || envP.Budget.Used() != 0 {
					t.Fatalf("budget %d + %d", envD.Budget.Used(), envP.Budget.Used())
				}
			})
		})
	}
}

// TestRawPipeCarriersCarryData_L43: after a handshake over a raw net.Pipe
// both carriers run over that same unbuffered pipe — the frame counters
// continue across the handshake in both directions (presets two frames
// before the u32 wrap, so every later frame crosses it) — and 1 MiB moves
// each way intact with no death; both carriers then join with the Budget
// back at zero.
func TestRawPipeCarriersCarryData_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		envD, envP := phEnvs()
		envD.Presets.FirstFseq, envP.Presets.FirstFseq = 0xfffffffe, 0xfffffffe
		a, b := net.Pipe()
		srcP := newSource(envP, 16<<10, false)
		srcP.keepData = true
		placed := false // touched only by the passive's writer goroutine
		srcP.setFill(func(c *Conn, bt *Batch) {
			if !placed {
				placed = bt.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20})
				return
			}
			srcP.fillData(c, bt)
		})
		pass := phPassive(envP, b, nil, func(h *Hello) { h.Conn.Start(srcP, &hBell{}, StartOptions{Hold: true}) })
		f := Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return a, nil }}
		est, err := Establish(context.Background(), envD, f, envD.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
		if err != nil {
			t.Fatalf("Establish: %v", err)
		}
		ph := <-pass
		if ph.err != nil {
			t.Fatalf("ReadHello: %v", ph.err)
		}
		srcD := newSource(envD, 16<<10, false)
		srcD.keepData = true
		est.Conn.Start(srcD, &hBell{}, StartOptions{})
		const n = 1 << 20
		srcD.offer(n)
		srcP.offer(n)
		est.Conn.Wake()
		ph.h.Conn.Wake()
		synctest.Wait()
		for _, side := range []struct {
			name string
			c    *Conn
			got  *hSource // the endpoint that received the other side's bytes
			sent *hSource
		}{{"dialer", est.Conn, srcD, srcP}, {"passive", ph.h.Conn, srcP, srcD}} {
			if dead, cause, detail, _ := side.c.Death(); dead {
				t.Fatalf("%s carrier died: %v %s", side.name, cause, detail)
			}
			if side.sent.pending() != 0 {
				t.Fatalf("stimulus: %d bytes not yet sent towards the %s", side.sent.pending(), side.name)
			}
			var next uint64
			for _, d := range side.got.received() {
				if d.off != next {
					t.Fatalf("%s received offset %d, want %d", side.name, d.off, next)
				}
				for i, x := range d.b {
					if x != hPattern(d.off+uint64(i)) {
						t.Fatalf("%s received a wrong byte at offset %d", side.name, d.off+uint64(i))
					}
				}
				next += uint64(d.n)
			}
			if next != n {
				t.Fatalf("%s received %d bytes, want %d", side.name, next, n)
			}
		}
		est.Conn.Kill(CauseLocalClose, "test end")
		ph.h.Conn.Kill(CauseLocalClose, "test end")
		hWait(t, est.Conn)
		hWait(t, ph.h.Conn)
		srcD.chunk.Release()
		srcP.chunk.Release()
		synctest.Wait()
		if envD.Budget.Used() != 0 || envP.Budget.Used() != 0 || envD.IDs.inUse() != 0 {
			t.Fatalf("budget %d + %d, IDs in use %d", envD.Budget.Used(), envP.Budget.Used(), envD.IDs.inUse())
		}
	})
}

// TestWithdrawOverRawPipe_L49: over a raw net.Pipe to a real ReadHello
// carrier — started held, its OPEN pending — an OPEN the dialer withdraws
// (ctx cause ErrWithdrawn) and one whose PREFACE_ACK instance the dialer's
// check refuses are followed on the wire by RST(withdrawn), which the
// passive carrier reads right after the OPEN; Establish returns without
// waiting for it.
func TestWithdrawOverRawPipe_L49(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withdraw time.Duration // 0: check refuses the instance at the PREFACE_ACK
	}{{"instance check", 0}, {"withdrawn while pending", 100 * time.Millisecond}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				envD, envP := phEnvs()
				a, b := net.Pipe()
				ep := &phFirst{} // never answers: the OPEN stays pending
				pass := phPassive(envP, b, nil, func(h *Hello) { h.Conn.Start(ep, &hBell{}, StartOptions{Hold: true}) })
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				errOther := errors.New("not the bound instance")
				var check func(*wire.PrefaceAck) error
				if tc.withdraw == 0 {
					check = func(*wire.PrefaceAck) error { return errOther }
				} else {
					time.AfterFunc(tc.withdraw, func() { cancel(ErrWithdrawn) })
				}
				f := Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return a, nil }}
				start := time.Now()
				_, err := Establish(ctx, envD, f, envD.IDs.Next(), wire.TypeOpen, openPayload(0), check)
				took := time.Since(start)
				var ee *EstablishError
				switch {
				case !errors.As(err, &ee):
					t.Fatalf("Establish: %v", err)
				case tc.withdraw == 0 && (ee.Cause != CauseInstanceMismatch || !errors.Is(err, errOther) || took != 0):
					t.Fatalf("instance check after %v: %v", took, err)
				case tc.withdraw > 0 && (ee.Cause != CauseLocalClose || !errors.Is(err, ErrWithdrawn) || took != tc.withdraw):
					t.Fatalf("withdrawal returned after %v: %v", took, err)
				}
				ph := <-pass
				if ph.err != nil || ph.took != 0 {
					t.Fatalf("ReadHello after %v: %v", ph.took, ph.err)
				}
				synctest.Wait()
				if codes := ep.rstCodes(); len(codes) != 1 || codes[0] != wire.RstWithdrawn {
					t.Fatalf("the passive carrier read RST codes %v, want one RST(withdrawn)", codes)
				}
				if dead, cause, detail, _ := ph.h.Conn.Death(); dead {
					t.Fatalf("the passive carrier died before the dialer's close: %v %s", cause, detail)
				}
				ph.h.Conn.Kill(CauseLocalClose, "test end")
				hWait(t, ph.h.Conn)
				synctest.Wait()
				if envD.IDs.inUse() != 0 || envD.Abandon.Len() != 0 || envP.Budget.Used() != 0 {
					t.Fatalf("IDs in use %d, abandoned %d, passive budget %d", envD.IDs.inUse(), envD.Abandon.Len(), envP.Budget.Used())
				}
			})
		})
	}
}

// TestWithdrawCutsUnreadHello_L49: an OPEN still being written when the
// dialer withdraws — the passive read only the PREFACE, or also answered
// PREFACE_ACK(OK), and then stalls — is cut on a plain pipe end and on one
// that ignores write deadlines but honours Close (design §0.8 V2):
// Establish returns at the withdrawal, the conn is closed exactly once,
// right then, and nothing follows the partial first frame on the wire (an
// RST there would sit inside a broken frame); nothing is abandoned. Waiting
// for a hello writer that only the close can end would hold both until
// AbandonWait.
func TestWithdrawCutsUnreadHello_L49(t *testing.T) {
	const withdraw = 100 * time.Millisecond
	for _, tc := range []struct {
		name           string
		writeDeadlines bool // false: the conn ignores write deadlines
		ack            bool // the passive answers PREFACE_ACK(OK) before it stalls
	}{
		{"pipe, PREFACE read", true, false},
		{"pipe, PREFACE_ACK answered", true, true},
		{"write deadline ignored, PREFACE read", false, false},
		{"write deadline ignored, PREFACE_ACK answered", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				nc := newLRConn(a, false)
				nc.writeDeadlines = tc.writeDeadlines
				id := env.IDs.Next()
				var rest []byte
				var restErr error
				passive := make(chan struct{})
				stalled := make(chan struct{})
				var unstall sync.Once
				release := func() { unstall.Do(func() { close(stalled) }) }
				defer func() { // a failed assertion still ends the passive, so the bubble can end
					release()
					b.Close()
				}()
				go func() {
					defer close(passive)
					var pb [wire.PrefaceLen]byte
					if _, restErr = io.ReadFull(b, pb[:]); restErr != nil {
						return
					}
					if tc.ack {
						if _, restErr = b.Write(hPrefaceAck(wire.PrefaceOK, id)); restErr != nil {
							return
						}
					}
					<-stalled // the first frame stays unread until the dialer gave up
					rest, restErr = io.ReadAll(b)
				}()
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				time.AfterFunc(withdraw, func() { cancel(ErrWithdrawn) })
				f := Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return nc, nil }}
				start := time.Now()
				_, err := Establish(ctx, env, f, id, wire.TypeOpen, openPayload(0), nil)
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Cause != CauseLocalClose || !errors.Is(err, ErrWithdrawn) || time.Since(start) != withdraw {
					t.Fatalf("after %v: %v, want the withdrawal at once", time.Since(start), err)
				}
				nc.waitClosed(t)
				release()
				<-passive
				b.Close()
				if restErr != nil || len(rest) != 0 {
					t.Fatalf("after the PREFACE the passive read %d bytes (%v), want nothing after a cut first frame", len(rest), restErr)
				}
				synctest.Wait()
				if n, at := nc.closes.Load(), nc.closedAfter(start); n != 1 || at != withdraw {
					t.Fatalf("conn closed %d times, first after %v; want once, at the withdrawal", n, at)
				}
				if nc.writes.Load() != 1 || env.IDs.inUse() != 0 || env.Abandon.Len() != 0 {
					t.Fatalf("writes %d, IDs in use %d, abandoned %d", nc.writes.Load(), env.IDs.inUse(), env.Abandon.Len())
				}
			})
		})
	}
}

// TestHelloWriteFailureEndsAttempt_L42_L51: a hello Write that fails — an
// error, (0, nil), a count outside [0, len], a short count with an error, a
// panic or runtime.Goexit inside the embedder's Write — ends the attempt at
// once as a transport error of the preface stage carrying the Write's
// failure, although the passive never answers (the PREFACE_ACK read would
// otherwise wait for the 10 s deadline); the conn is closed exactly once,
// the carrier ID is released and nothing is abandoned.
func TestHelloWriteFailureEndsAttempt_L42_L51(t *testing.T) {
	errBoom := errors.New("boom")
	for _, tc := range []struct {
		name  string
		write func(nc net.Conn, p []byte) (int, error)
		want  string
	}{
		{"error", func(net.Conn, []byte) (int, error) { return 0, errBoom }, "boom"},
		{"(0, nil)", func(net.Conn, []byte) (int, error) { return 0, nil }, "(0, nil)"},
		{"(-1, nil)", func(net.Conn, []byte) (int, error) { return -1, nil }, "invalid count"},
		{"(len+1, nil)", func(_ net.Conn, p []byte) (int, error) { return len(p) + 1, nil }, "invalid count"},
		{"(len-1, err)", func(nc net.Conn, p []byte) (int, error) {
			n, _ := nc.Write(p[:len(p)-1])
			return n, errBoom
		}, "boom"},
		{"panic", func(net.Conn, []byte) (int, error) { panic("write") }, "Write panicked"},
		{"Goexit", func(net.Conn, []byte) (int, error) { runtime.Goexit(); return 0, nil }, "Goexit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				go io.Copy(io.Discard, b) // a passive that never answers; EOF once the dialer closes
				hc := &hookConn{Conn: a, onWrite: tc.write}
				f := Factory{Name: "w", Dial: func(context.Context) (net.Conn, error) { return hc, nil }}
				start := time.Now()
				_, err := Establish(context.Background(), env, f, env.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
				took := time.Since(start)
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Stage != "preface" || ee.Cause != CauseTransportError || ee.PrefaceOK || ee.Status != wire.PrefaceOK {
					t.Fatalf("Establish: %v (%+v)", err, ee)
				}
				if !strings.Contains(err.Error(), tc.want) || took != 0 {
					t.Fatalf("after %v: %v, want the Write's failure (%q) at once", took, err, tc.want)
				}
				synctest.Wait()
				b.Close()
				if hc.writes.Load() != 1 || hc.closes.Load() != 1 {
					t.Fatalf("writes %d, conn closed %d times", hc.writes.Load(), hc.closes.Load())
				}
				if env.IDs.inUse() != 0 || env.Abandon.Len() != 0 {
					t.Fatalf("IDs in use %d, abandoned %d", env.IDs.inUse(), env.Abandon.Len())
				}
			})
		})
	}
}

// TestHelloWriteFailsAfterPrefaceAck_L51: the passive read the PREFACE and
// answered PREFACE_ACK(OK), which Establish read, and then the hello Write
// fails on the first frame: Establish, waiting for the first frame to be
// written, ends at once with the Write's failure (stage preface, not a
// completed PREFACE exchange); nothing follows the PREFACE on the wire, the
// conn is closed exactly once and nothing is abandoned.
func TestHelloWriteFailsAfterPrefaceAck_L51(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		errBoom := errors.New("boom")
		id := env.IDs.Next()
		acked := make(chan struct{})
		var rest []byte
		passive := make(chan error, 1)
		go func() {
			defer b.Close()
			var pb [wire.PrefaceLen]byte
			if _, err := io.ReadFull(b, pb[:]); err != nil {
				passive <- err
				return
			}
			_, err := b.Write(hPrefaceAck(wire.PrefaceOK, id)) // returns once Establish read it
			close(acked)
			if err != nil {
				passive <- err
				return
			}
			rest, err = io.ReadAll(b)
			passive <- err
		}()
		hc := &hookConn{Conn: a, onWrite: func(nc net.Conn, p []byte) (int, error) {
			n, err := nc.Write(p[:wire.PrefaceLen])
			if err != nil {
				return n, err
			}
			<-acked // Establish has the PREFACE_ACK(OK): it now waits for the first frame
			return n, errBoom
		}}
		f := Factory{Name: "w", Dial: func(context.Context) (net.Conn, error) { return hc, nil }}
		start := time.Now()
		_, err := Establish(context.Background(), env, f, id, wire.TypeOpen, openPayload(0), nil)
		var ee *EstablishError
		if !errors.As(err, &ee) || ee.Stage != "preface" || ee.Cause != CauseTransportError || ee.PrefaceOK || !errors.Is(err, errBoom) || time.Since(start) != 0 {
			t.Fatalf("after %v: %v (%+v), want the Write's failure at once", time.Since(start), err, ee)
		}
		if perr := <-passive; perr != nil || len(rest) != 0 {
			t.Fatalf("the passive read %d bytes after the PREFACE (%v), want nothing", len(rest), perr)
		}
		synctest.Wait()
		if hc.writes.Load() != 1 || hc.closes.Load() != 1 || env.IDs.inUse() != 0 || env.Abandon.Len() != 0 {
			t.Fatalf("writes %d, closes %d, IDs in use %d, abandoned %d", hc.writes.Load(), hc.closes.Load(), env.IDs.inUse(), env.Abandon.Len())
		}
	})
}

// TestHelloWriterAbandonedBounded_L52: a hello Write stuck in an embedder
// call that ignores its deadline and Close does not hold Establish: when
// the passive's VERSION answer ends the attempt, the conn is closed, the
// join waits AbandonWait and then counts the writer in the abandoned-call
// pool, and Establish returns the typed result; the writer leaves the pool
// when its Write finally returns, and the conn was closed exactly once.
func TestHelloWriterAbandonedBounded_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		defer b.Close()
		release := make(chan struct{})
		hc := &hookConn{Conn: a, onWrite: func(net.Conn, []byte) (int, error) {
			<-release // ignores deadlines and Close
			return 0, net.ErrClosed
		}}
		id := env.IDs.Next()
		go b.Write(hPrefaceAck(wire.PrefaceVersion, id))
		f := Factory{Name: "stuck", Dial: func(context.Context) (net.Conn, error) { return hc, nil }}
		start := time.Now()
		_, err := Establish(context.Background(), env, f, id, wire.TypeOpen, openPayload(0), nil)
		took := time.Since(start)
		var ee *EstablishError
		if !errors.As(err, &ee) || ee.Stage != "preface" || ee.Status != wire.PrefaceVersion {
			t.Fatalf("Establish: %v", err)
		}
		if took != env.Timing.AbandonWait {
			t.Fatalf("returned after %v, want AbandonWait (%v)", took, env.Timing.AbandonWait)
		}
		synctest.Wait()
		if hc.writes.Load() != 1 || hc.closes.Load() != 1 || env.Abandon.Len() != 1 {
			t.Fatalf("writes %d, closes %d, abandoned %d: want the stuck writer counted", hc.writes.Load(), hc.closes.Load(), env.Abandon.Len())
		}
		close(release)
		synctest.Wait()
		if env.Abandon.Len() != 0 || hc.closes.Load() != 1 || env.IDs.inUse() != 0 {
			t.Fatalf("after the Write returned: abandoned %d, closes %d, IDs in use %d", env.Abandon.Len(), hc.closes.Load(), env.IDs.inUse())
		}
	})
}
