package carrier

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The first flight (M4 design §A3.2, M4-D4, R1-4, R1-5; WP8):
// PREFACE ‖ OPEN(EARLY) ‖ DATA(handle 1, offset 0, k bytes) in one conn
// Write, or after a DialEarly factory's PREFACE ‖ OPEN(EARLY) in the hello
// writer's next Write; the withdrawal RST only after the whole flight; the
// passive's admission refusal drains while it writes its answer.

// efEarly returns n early bytes with a recognisable pattern.
func efEarly(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*13 + 5)
	}
	return b
}

// efFrames decodes every whole frame of b (the bytes after a PREFACE); the
// payloads are copies. A trailing partial frame is reported as rest.
func efFrames(t testing.TB, b []byte) (fs []wire.Frame, rest int) {
	t.Helper()
	for len(b) > 0 {
		f, n, err := wire.DecodeFrame(b)
		if errors.Is(err, wire.ErrShort) {
			return fs, len(b)
		}
		if err != nil {
			t.Fatalf("frame %d: %v", len(fs), err)
		}
		f.Payload = bytes.Clone(f.Payload)
		fs = append(fs, f)
		b = b[n:]
	}
	return fs, 0
}

// efCheckFlight checks the dialer's bytes b: a PREFACE, then an OPEN with
// EARLY at fseq first and one DATA frame (handle 1, offset 0, early) at
// first + 1, then the frames of more (each type at the next fseq).
func efCheckFlight(t testing.TB, b []byte, first uint32, early []byte, more ...wire.Type) []wire.Frame {
	t.Helper()
	if len(b) < wire.PrefaceLen {
		t.Fatalf("%d bytes, want a PREFACE first", len(b))
	}
	if _, err := wire.ParsePreface(b[:wire.PrefaceLen]); err != nil {
		t.Fatalf("PREFACE: %v", err)
	}
	fs, rest := efFrames(t, b[wire.PrefaceLen:])
	if rest != 0 || len(fs) != 2+len(more) {
		t.Fatalf("%d frames and %d trailing bytes after the PREFACE, want %d frames", len(fs), rest, 2+len(more))
	}
	o, err := wire.ParseOpen(fs[0].Payload, wire.MaxMetadata)
	if fs[0].Type != wire.TypeOpen || err != nil || o.Flags != wire.OpenFlagEarly || fs[0].Fseq != first || fs[0].Handle != wire.SessionHandle {
		t.Fatalf("first frame %v fseq %d handle %d flags %#x (%v), want OPEN(EARLY) at fseq %d", fs[0].Type, fs[0].Fseq, fs[0].Handle, o.Flags, err, first)
	}
	d := fs[1]
	off, derr := wire.ParseDataOffset(d.Payload)
	if d.Type != wire.TypeData || derr != nil || d.Fseq != first+1 || d.Handle != wire.SessionHandle || off != 0 || !bytes.Equal(d.Payload[wire.DataPrefixLen:], early) {
		t.Fatalf("second frame %v fseq %d handle %d offset %d, %d bytes; want DATA(1, 0, %d bytes) at fseq %d", d.Type, d.Fseq, d.Handle, off, len(d.Payload)-wire.DataPrefixLen, len(early), first+1)
	}
	for i, typ := range more {
		if f := fs[2+i]; f.Type != typ || f.Fseq != first+2+uint32(i) {
			t.Fatalf("frame %d: %v at fseq %d, want %v at fseq %d", 2+i, f.Type, f.Fseq, typ, first+2+uint32(i))
		}
	}
	return fs
}

// efRec records every byte the dialer writes on a conn (and each Write).
type efRec struct {
	net.Conn
	mu     sync.Mutex
	b      []byte
	writes [][]byte
}

func (r *efRec) Write(p []byte) (int, error) {
	n, err := r.Conn.Write(p)
	if n > 0 && n <= len(p) {
		r.mu.Lock()
		r.b = append(r.b, p[:n]...)
		r.writes = append(r.writes, bytes.Clone(p[:n]))
		r.mu.Unlock()
	}
	return n, err
}

func (r *efRec) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.b)
}

func (r *efRec) calls() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.writes...)
}

// efOKAnswer is a scripted passive's answer: PREFACE_ACK(OK) for carrier
// id, then OPEN_ACK(OK) at the passive's first fseq (presets).
func efOKAnswer(id uint32) []byte {
	return append(hPrefaceAck(wire.PrefaceOK, id), frameAt(wire.TypeOpenAck, 0, wire.FirstFseq, wire.SessionHandle, okOpenAck())...)
}

// efGolden reads testdata/first-flight.txt: name, then the hex bytes.
func efGolden(t testing.TB) map[string][]byte {
	t.Helper()
	f, err := os.Open("testdata/first-flight.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]byte{}
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, h, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("golden line %q", line)
		}
		b, err := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
		if err != nil {
			t.Fatalf("golden %s: %v", name, err)
		}
		out[name] = b
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestFirstFlightGolden (§A3.5, M4-D4, M4-D7, R1-4): from fixed presets
// (the first fseq, the instance, carrier ID 7, the OPEN of openPayload),
// the dialer's bytes are byte-identical to testdata/first-flight.txt:
// PREFACE ‖ OPEN(EARLY) ‖ DATA(1, 0, "hello"), and the same followed by
// RST(withdrawn) when the instance check refuses the PREFACE_ACK; the M1
// decoder reads them frame by frame at fseq f, f + 1 (and f + 2). The
// established carrier reports the early bytes in flight (Early == 5) and
// continues its tx fseq at f + 2.
func TestFirstFlightGolden(t *testing.T) {
	golden := efGolden(t)
	early := []byte("hello")
	errOther := errors.New("not the bound instance")
	for _, tc := range []struct {
		name  string
		check func(*wire.PrefaceAck) error
		more  []wire.Type
	}{
		{"open-early-data", nil, nil},
		{"open-early-data-withdrawn", func(*wire.PrefaceAck) error { return errOther }, []wire.Type{wire.TypeRst}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				rec := &efRec{Conn: a}
				const id = 7
				sp := runPassive(b, func(wire.Preface, wire.Frame) []byte { return efOKAnswer(id) })
				f := Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return rec, nil }}
				est, err := EstablishEarly(context.Background(), env, f, id, wire.TypeOpen, openPayload(0), early, tc.check)
				if tc.check == nil {
					if err != nil || est.Early != len(early) || !isOK(est) {
						t.Fatalf("EstablishEarly: %v (Early %d), want OPEN_ACK(OK) with %d early bytes in flight", err, est.Early, len(early))
					}
					if est.Conn.wr.fseq != wire.FirstFseq+2 {
						t.Fatalf("tx fseq continues at %d, want %d", est.Conn.wr.fseq, wire.FirstFseq+2)
					}
					est.Conn.Kill(CauseLocalClose, "test end")
					hWait(t, est.Conn)
				} else {
					var ee *EstablishError
					if !errors.As(err, &ee) || ee.Cause != CauseInstanceMismatch {
						t.Fatalf("EstablishEarly: %v, want the instance refusal", err)
					}
				}
				<-sp.done
				synctest.Wait()
				got := rec.bytes()
				efCheckFlight(t, got, wire.FirstFseq, early, tc.more...)
				if want, ok := golden[tc.name]; !ok || !bytes.Equal(got, want) {
					t.Fatalf("first flight\n got %x\nwant %x", got, want)
				}
				if sp.err != nil || !bytes.Equal(sp.after, got[len(got)-len(sp.after):]) {
					t.Fatalf("the passive read %d bytes after the OPEN (%v)", len(sp.after), sp.err)
				}
			})
		})
	}
}

// TestEarlyFirstFlightOneWrite_L41 (M4-D4, L41): without DialEarly the
// whole first flight with 64 KiB of early data is one conn Write; with
// DialEarly the factory's first bytes are PREFACE ‖ OPEN(EARLY) and the
// DATA frame is the conn's next (and only) Write before the response.
// BeforeFirstFlight runs once, with k, before any of it is written.
func TestEarlyFirstFlightOneWrite_L41(t *testing.T) {
	early := efEarly(wire.EarlyWindow)
	dataLen := wire.FrameOverhead + wire.DataPrefixLen + len(early)
	for _, dialEarly := range []bool{false, true} {
		name := "Dial"
		if dialEarly {
			name = "DialEarly"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				const id = 9
				var rec *efRec
				var factoryFirst []byte
				var hookK []int
				var hookWrites int
				env.Hooks = &testhooks.Hooks{BeforeFirstFlight: func(k int) {
					hookK = append(hookK, k)
					if rec != nil {
						hookWrites = len(rec.calls())
					}
					if factoryFirst != nil {
						hookWrites++
					}
				}}
				var sp *scriptedPassive
				f := Factory{Name: "pipe"}
				if dialEarly {
					f.Dial = func(context.Context) (net.Conn, error) { return nil, errors.New("Dial with DialEarly set") }
					f.DialEarly = func(_ context.Context, first []byte) (net.Conn, error) {
						a, b := net.Pipe()
						sp = runPassive(b, func(wire.Preface, wire.Frame) []byte { return efOKAnswer(id) })
						factoryFirst = bytes.Clone(first)
						if _, err := a.Write(first); err != nil {
							return nil, err
						}
						rec = &efRec{Conn: a}
						return rec, nil
					}
				} else {
					f.Dial = func(context.Context) (net.Conn, error) {
						a, b := net.Pipe()
						sp = runPassive(b, func(wire.Preface, wire.Frame) []byte { return efOKAnswer(id) })
						rec = &efRec{Conn: a}
						return rec, nil
					}
				}
				est, err := EstablishEarly(context.Background(), env, f, id, wire.TypeOpen, openPayload(0), early, nil)
				if err != nil || !isOK(est) || est.Early != len(early) {
					t.Fatalf("EstablishEarly: %v", err)
				}
				calls := rec.calls()
				est.Conn.Kill(CauseLocalClose, "test end")
				hWait(t, est.Conn)
				<-sp.done
				if len(hookK) != 1 || hookK[0] != len(early) || hookWrites != 0 {
					t.Fatalf("BeforeFirstFlight calls %v after %d writes, want one call with k = %d before any", hookK, hookWrites, len(early))
				}
				var flight []byte
				if dialEarly {
					fs, rest := efFrames(t, factoryFirst[wire.PrefaceLen:])
					if rest != 0 || len(fs) != 1 || fs[0].Type != wire.TypeOpen {
						t.Fatalf("the factory's first bytes hold %d frames (+%d bytes), want PREFACE ‖ OPEN", len(fs), rest)
					}
					if len(calls) != 1 || len(calls[0]) != dataLen {
						t.Fatalf("conn Writes before the response: %d (%v bytes), want the DATA frame alone in one Write", len(calls), lens(calls))
					}
					flight = append(factoryFirst, calls[0]...)
				} else {
					if len(calls) != 1 {
						t.Fatalf("conn Writes before the response: %d (%v bytes), want one (L41)", len(calls), lens(calls))
					}
					flight = calls[0]
				}
				efCheckFlight(t, flight, wire.FirstFseq, early)
			})
		})
	}
}

func lens(bs [][]byte) []int {
	out := make([]int, len(bs))
	for i, b := range bs {
		out[i] = len(b)
	}
	return out
}

// TestEstablishEarlyPartialWrite_L42 (§A3.2, L42): a hello Write that
// writes half of the DATA frame and fails — the whole flight's one Write,
// or the DialEarly writer's DATA Write — ends the attempt at once as the
// stage "preface" transport failure (no Established, so no early bytes in
// flight), and nothing is written after the partial frame: the passive
// reads exactly the partial bytes, then EOF.
func TestEstablishEarlyPartialWrite_L42(t *testing.T) {
	early := efEarly(4096)
	dataLen := wire.FrameOverhead + wire.DataPrefixLen + len(early)
	errBoom := errors.New("boom")
	for _, dialEarly := range []bool{false, true} {
		name := "Dial"
		if dialEarly {
			name = "DialEarly"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				var got []byte
				var gotErr error
				read := make(chan struct{})
				go func() {
					defer close(read)
					got, gotErr = io.ReadAll(b)
				}()
				var firstLen int
				half := func(nc net.Conn, p []byte) (int, error) {
					if len(p) < dataLen {
						return nc.Write(p)
					}
					n := len(p) - dataLen/2 // half of the DATA frame (the frame ends p)
					k, err := nc.Write(p[:n])
					if err != nil {
						return k, err
					}
					return k, errBoom
				}
				hc := &hookConn{Conn: a, onWrite: half}
				f := Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return hc, nil }}
				if dialEarly {
					f.DialEarly = func(_ context.Context, first []byte) (net.Conn, error) {
						firstLen = len(first)
						if _, err := a.Write(first); err != nil {
							return nil, err
						}
						return hc, nil
					}
				}
				start := time.Now()
				est, err := EstablishEarly(context.Background(), env, f, env.IDs.Next(), wire.TypeOpen, openPayload(0), early, nil)
				var ee *EstablishError
				if est != nil || !errors.As(err, &ee) || ee.Stage != "preface" || ee.Cause != CauseTransportError || ee.PrefaceOK || !errors.Is(err, errBoom) || time.Since(start) != 0 {
					t.Fatalf("after %v: %v %v, want the preface-stage failure at once", time.Since(start), est, err)
				}
				<-read
				b.Close()
				hello := wire.PrefaceLen + wire.FrameOverhead + wire.OpenFixedLen
				if want := hello + dataLen - dataLen/2; gotErr != nil || len(got) != want {
					t.Fatalf("the passive read %d bytes (%v), want %d: the partial flight and nothing after it", len(got), gotErr, want)
				}
				if dialEarly && firstLen != hello {
					t.Fatalf("the factory's first bytes: %d, want PREFACE ‖ OPEN (%d)", firstLen, hello)
				}
				synctest.Wait()
				if env.IDs.inUse() != 0 || env.Abandon.Len() != 0 || hc.writes.Load() != 1 {
					t.Fatalf("IDs in use %d, abandoned %d, conn Writes %d", env.IDs.inUse(), env.Abandon.Len(), hc.writes.Load())
				}
			})
		})
	}
}

// efOrdered is a DialEarly conn: first is written on a goroutine of its
// own, and every Write waits until it was.
type efOrdered struct {
	net.Conn
	sent chan struct{}
}

func newEfOrdered(nc net.Conn, first []byte) *efOrdered {
	c := &efOrdered{Conn: nc, sent: make(chan struct{})}
	go func() {
		defer close(c.sent)
		_, _ = nc.Write(first)
	}()
	return c
}

func (c *efOrdered) Write(p []byte) (int, error) {
	<-c.sent
	return c.Conn.Write(p)
}

// efPassive runs ReadHello on nc with metadata bound maxMeta and the
// handshake deadline 10 s ahead; answer then runs with the accepted Hello.
func efPassive(env *Env, nc net.Conn, maxMeta int, answer func(h *Hello)) <-chan phHello {
	ch := make(chan phHello, 1)
	start := time.Now()
	go func() {
		h, err := ReadHello(env, nc, start.Add(10*time.Second), maxMeta, nil)
		took := time.Since(start)
		if err == nil && answer != nil {
			answer(h)
		}
		ch <- phHello{h, err, took}
	}()
	return ch
}

// efEP is a passive session endpoint whose first response (place) may wait
// for the early DATA: Data wakes the writer once want bytes arrived.
type efEP struct {
	phFirst
	want int64
}

func (e *efEP) Data(c *Conn, off uint64, p []byte, buf *Buf) error {
	err := e.phFirst.Data(c, off, p, buf)
	if e.rxBytes.Load() >= e.want {
		c.Wake()
	}
	return err
}

// efCountConn counts the bytes read from a passive conn and how many had
// been read when it was first closed.
type efCountConn struct {
	net.Conn
	read    atomic.Int64
	atClose atomic.Int64 // -1 until the first Close
}

func newEfCountConn(nc net.Conn) *efCountConn {
	c := &efCountConn{Conn: nc}
	c.atClose.Store(-1)
	return c
}

func (c *efCountConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.read.Add(int64(n))
	}
	return n, err
}

func (c *efCountConn) Close() error {
	c.atClose.CompareAndSwap(-1, c.read.Load())
	return c.Conn.Close()
}

// TestEstablishEarlySyncConn (§A3.2, §A5.1, R1-5, M4-D58): over a raw
// net.Pipe — a Write returns only as the other end reads — a first flight
// with 64 KiB of early data completes at once: the passive's held carrier
// reads the DATA before it answers OPEN_ACK(OK), so the dialer's hello
// Write never waits for the held writer. The admission's refusals —
// written with WriteAndClose before any session reader exists: CAPACITY
// (backlog, MaxSessions), BAD_REQUEST CodeMetadataSize (the OPEN's
// metadata not even read) and GOING_AWAY — reach the dialer at once as the
// typed OPEN_ACK, never as a "preface" transport failure at the deadline:
// the refusal's closer drains the first flight while it writes the answer
// (Hooks.Drained reports exactly the unread rest of the flight).
func TestEstablishEarlySyncConn(t *testing.T) {
	early := efEarly(wire.EarlyWindow)
	dataLen := wire.FrameOverhead + wire.DataPrefixLen + len(early)
	const bigMeta = 1000
	for _, tc := range []struct {
		name    string
		meta    int           // the OPEN's metadata bytes
		maxMeta int           // the passive's bound
		refusal *wire.OpenAck // nil: the passive confirms after reading the early DATA
		drained int           // the bytes the refusal's drain discards
	}{
		{name: "OK after the early DATA", maxMeta: 4096},
		{name: "CAPACITY backlog", maxMeta: 4096, refusal: &wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeBacklog}, drained: dataLen},
		{name: "CAPACITY MaxSessions", maxMeta: 4096, refusal: &wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeMaxSessions}, drained: dataLen},
		{name: "BAD_REQUEST metadata size", meta: bigMeta, maxMeta: 64, refusal: &wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeMetadataSize},
			drained: wire.OpenFixedLen + bigMeta + wire.TrailerLen + dataLen},
		{name: "GOING_AWAY", maxMeta: 4096, refusal: &wire.OpenAck{Status: wire.StatusGoingAway}, drained: dataLen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				envD, envP := phEnvs()
				var drained []int
				var dmu sync.Mutex
				envP.Hooks = &testhooks.Hooks{Drained: func(n int) {
					dmu.Lock()
					drained = append(drained, n)
					dmu.Unlock()
				}}
				a, b := net.Pipe()
				ep := &efEP{want: int64(len(early))}
				var answer func(h *Hello)
				if tc.refusal == nil {
					ep.place = func(bt *Batch) bool {
						if ep.rxBytes.Load() < int64(len(early)) {
							return false // the verdict follows the early DATA
						}
						return bt.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20})
					}
					answer = func(h *Hello) { h.Conn.Start(ep, &hBell{}, StartOptions{Hold: true, Early: true}) }
				} else {
					refusal := *tc.refusal
					answer = func(h *Hello) {
						if h.MetaTooLarge != (tc.meta > tc.maxMeta) {
							t.Errorf("MetaTooLarge %v", h.MetaTooLarge)
						}
						h.Conn.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, phOpenAck(refusal), time.Now().Add(time.Second))
					}
				}
				pass := efPassive(envP, b, tc.maxMeta, answer)
				f := Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return a, nil }}
				start := time.Now()
				est, err := EstablishEarly(context.Background(), envD, f, envD.IDs.Next(), wire.TypeOpen, openPayload(tc.meta), early, nil)
				if took := time.Since(start); err != nil || took != 0 {
					t.Fatalf("EstablishEarly after %v of the 10 s handshake deadline: %v", took, err)
				}
				st, code, ok := responseStatus(est.Resp, est.Payload)
				want := wire.OpenAck{Status: wire.StatusOK}
				if tc.refusal != nil {
					want = *tc.refusal
				}
				if !ok || st != want.Status || code != want.Code || est.Early != len(early) {
					t.Fatalf("response %v code %d (Early %d), want %v code %d with the whole flight written", st, code, est.Early, want.Status, want.Code)
				}
				ph := <-pass
				if ph.err != nil || ph.took != 0 {
					t.Fatalf("ReadHello after %v: %v", ph.took, ph.err)
				}
				if tc.refusal == nil {
					if d := ep.received(); len(d) != 1 || d[0].off != 0 || d[0].n != len(early) {
						t.Fatalf("the passive endpoint received %+v, want the early span [0, %d)", d, len(early))
					}
				}
				est.Conn.Kill(CauseLocalClose, "test end")
				hWait(t, est.Conn)
				ph.h.Conn.Kill(CauseLocalClose, "test end")
				hWait(t, ph.h.Conn)
				synctest.Wait()
				dmu.Lock()
				got := append([]int(nil), drained...)
				dmu.Unlock()
				if tc.refusal != nil && (len(got) != 1 || got[0] != tc.drained) {
					t.Fatalf("Drained reports %v, want one report of %d bytes (the unread rest of the flight)", got, tc.drained)
				}
				if envD.IDs.inUse() != 0 || envD.Abandon.Len() != 0 || envP.Abandon.Len() != 0 || envP.Budget.Used() != 0 {
					t.Fatalf("IDs in use %d, abandoned %d + %d, passive budget %d", envD.IDs.inUse(), envD.Abandon.Len(), envP.Abandon.Len(), envP.Budget.Used())
				}
			})
		})
	}
}

// TestEarlyRefusalDrain_L05 (M4-D8, M4-D58, R1-5, L05; the synctest half,
// the real-socket half is in internal/scenario/realsock): a refused EARLY
// session's carrier reads the whole first flight before its conn is
// closed, so a real socket never answers unread early data with a TCP
// reset that could destroy the refusal, and the dialer reads the typed
// answer. Rows: an admission refusal (WriteAndClose, no session reader)
// and a session refusal (OPEN_ACK(REJECTED), then the carrier retires)
// whose reader BeforeEarlyRead held until the refusal was decided, each on
// a dedicated carrier and on handle 1 of a fresh MUX trunk. The stimulus:
// Hooks.Drained reports the early DATA as drained after the refusal.
func TestEarlyRefusalDrain_L05(t *testing.T) {
	early := efEarly(wire.EarlyWindow)
	for _, mux := range []bool{false, true} {
		for _, admission := range []bool{true, false} {
			name := "session refusal"
			if admission {
				name = "admission refusal"
			}
			if mux {
				name += ", fresh trunk"
			} else {
				name += ", dedicated"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					envD, envP := phEnvs()
					var drained atomic.Int64
					release := make(chan struct{})
					var held atomic.Int32
					envP.Hooks = &testhooks.Hooks{
						Drained: func(n int) { drained.Add(int64(n)) },
						BeforeEarlyRead: func() {
							held.Add(1)
							<-release // until the refusal was decided
						},
					}
					a, b := net.Pipe()
					pc := newEfCountConn(b)
					var answer func(h *Hello)
					if admission {
						close(release)
						answer = func(h *Hello) {
							h.Conn.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, phOpenAck(wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeBacklog}), time.Now().Add(time.Second))
						}
					} else {
						answer = func(h *Hello) {
							ep := &phFirst{place: func(bt *Batch) bool {
								return bt.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusRejected, Code: 4242})
							}}
							h.Conn.Start(ep, &hBell{}, StartOptions{Hold: true, Early: true})
							h.Conn.Retire(wire.CloseRetire) // the refused session's end (terminateLocked)
							close(release)
						}
					}
					pass := efPassive(envP, pc, 4096, answer)
					rec := &efRec{Conn: a}
					f := Factory{Name: "pipe", Mux: mux, Dial: func(context.Context) (net.Conn, error) { return rec, nil }}
					est, err := EstablishEarly(context.Background(), envD, f, envD.IDs.Next(), wire.TypeOpen, openPayload(0), early, nil)
					if err != nil {
						t.Fatalf("EstablishEarly: %v", err)
					}
					st, code, ok := responseStatus(est.Resp, est.Payload)
					if admission && (!ok || st != wire.StatusCapacity || code != wire.CodeBacklog) ||
						!admission && (!ok || st != wire.StatusRejected || code != 4242) {
						t.Fatalf("the dialer read %v code %d (%v), want the typed refusal", st, code, ok)
					}
					// The dialer reads what follows (the passive's CLOSE)
					// until the passive closed, then lets its carrier go.
					_, _ = io.Copy(io.Discard, a)
					est.Conn.Kill(CauseLocalClose, "test end")
					hWait(t, est.Conn)
					ph := <-pass
					if ph.err != nil {
						t.Fatalf("ReadHello: %v", ph.err)
					}
					hWait(t, ph.h.Conn)
					synctest.Wait()
					sent := int64(len(rec.bytes()))
					if at := pc.atClose.Load(); at != sent {
						t.Fatalf("the passive closed after reading %d of the dialer's %d bytes, want all of them first", at, sent)
					}
					dataLen := int64(wire.FrameOverhead + wire.DataPrefixLen + len(early))
					if d := drained.Load(); d < int64(len(early)) || d > dataLen {
						t.Fatalf("Drained reports %d bytes, want the early DATA (stimulus)", d)
					}
					if !admission && held.Load() != 1 {
						t.Fatalf("BeforeEarlyRead ran %d times, want once", held.Load())
					}
				})
			})
		}
	}
}

// TestEarlyWithdrawalRstFseq_L49 (R1-4, M4-D4, L49): the withdrawal RST
// follows only the whole first flight. A withdrawal while EstablishEarly
// awaits the response — with or without DialEarly — writes RST(withdrawn)
// at fseq f + 2, which the passive's held carrier reads right after the
// early DATA (its endpoint records the RST; no fseq violation kills the
// carrier). The hello guard's rule itself: with DialEarly an RST decided
// before the DATA frame's Write began cancels that Write and takes
// f + 1; after the DATA frame was written it takes f + 2; while the DATA
// frame's Write is in progress nothing follows it.
func TestEarlyWithdrawalRstFseq_L49(t *testing.T) {
	early := efEarly(4096)
	for _, dialEarly := range []bool{false, true} {
		name := "awaiting the response, Dial"
		if dialEarly {
			name = "awaiting the response, DialEarly"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const withdraw = 100 * time.Millisecond
				envD, envP := phEnvs()
				a, b := net.Pipe()
				ep := &phFirst{} // never answers: the OPEN stays pending
				pass := phPassive(envP, b, nil, func(h *Hello) { h.Conn.Start(ep, &hBell{}, StartOptions{Hold: true, Early: true}) })
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				time.AfterFunc(withdraw, func() { cancel(ErrWithdrawn) })
				rec := &efRec{Conn: a}
				f := Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return rec, nil }}
				if dialEarly {
					// A 0-RTT-like factory: its first bytes leave on a
					// goroutine of its own (the passive answers PREFACE_ACK
					// between PREFACE and OPEN, P18), and the conn's Writes
					// follow them.
					f.DialEarly = func(_ context.Context, first []byte) (net.Conn, error) {
						return newEfOrdered(rec, first), nil
					}
				}
				_, err := EstablishEarly(ctx, envD, f, envD.IDs.Next(), wire.TypeOpen, openPayload(0), early, nil)
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Cause != CauseLocalClose || !errors.Is(err, ErrWithdrawn) {
					t.Fatalf("EstablishEarly: %v, want the withdrawal", err)
				}
				ph := <-pass
				if ph.err != nil {
					t.Fatalf("ReadHello: %v", ph.err)
				}
				synctest.Wait()
				efCheckFlight(t, rec.bytes(), wire.FirstFseq, early, wire.TypeRst)
				if codes := ep.rstCodes(); len(codes) != 1 || codes[0] != wire.RstWithdrawn {
					t.Fatalf("the passive carrier read RST codes %v, want one RST(withdrawn) after the early DATA", codes)
				}
				if d := ep.received(); len(d) != 1 || d[0].n != len(early) {
					t.Fatalf("the passive endpoint received %+v, want the early DATA", d)
				}
				if dead, cause, detail, _ := ph.h.Conn.Death(); dead {
					t.Fatalf("the passive carrier died: %v %s", cause, detail)
				}
				ph.h.Conn.Kill(CauseLocalClose, "test end")
				hWait(t, ph.h.Conn)
				synctest.Wait()
				if envD.IDs.inUse() != 0 || envD.Abandon.Len() != 0 {
					t.Fatalf("IDs in use %d, abandoned %d", envD.IDs.inUse(), envD.Abandon.Len())
				}
			})
		})
	}
	// The guard's rule, unit rows (DialEarly: PREFACE ‖ OPEN written by
	// the factory, the DATA frame the hello writer's).
	const first = 41
	data := appendEarlyData(nil, first+1, early)
	for _, tc := range []struct {
		name string
		run  func(g *hsGuard) // ends with the RST decision
		want []byte           // what follows PREFACE ‖ OPEN on the wire
	}{
		{"RST before the DATA Write began", func(g *hsGuard) {
			g.closeWith(true, false)
			g.startHello(data, true) // cancelled: never written
			g.join()
		}, withdrawFrame(first + 1)},
		{"RST after the DATA frame", func(g *hsGuard) {
			g.startHello(data, true)
			if err := g.awaitHello(); err != nil {
				panic(err)
			}
			g.closeWith(true, false)
			g.join()
		}, append(bytes.Clone(data), withdrawFrame(first+2)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				var got []byte
				read := make(chan struct{})
				go func() {
					defer close(read)
					got, _ = io.ReadAll(b)
				}()
				g := newHsGuard(context.Background(), env, a, true)
				g.rstOpen, g.first, g.early = true, first, true
				tc.run(g)
				<-read
				synctest.Wait()
				if !bytes.Equal(got, tc.want) {
					t.Fatalf("after PREFACE ‖ OPEN the wire carries %d bytes, want %d", len(got), len(tc.want))
				}
				if fs, rest := efFrames(t, got); rest != 0 || fs[len(fs)-1].Type != wire.TypeRst {
					t.Fatalf("frames %d (+%d bytes), want the RST last", len(fs), rest)
				}
			})
		})
	}
	t.Run("RST while the DATA Write is in progress", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			a, b := net.Pipe()
			var got []byte
			read := make(chan struct{})
			started := make(chan struct{})
			resume := make(chan struct{})
			go func() {
				defer close(read)
				var one [1]byte
				if _, err := io.ReadFull(b, one[:]); err != nil { // the DATA Write began
					return
				}
				close(started)
				<-resume // the Write stays in progress until the RST was decided
				rest, _ := io.ReadAll(b)
				got = append(one[:], rest...)
			}()
			g := newHsGuard(context.Background(), env, a, true)
			g.rstOpen, g.first, g.early = true, first, true
			g.startHello(data, true)
			<-started
			// The handshake left the conn (as after a cut awaitHello) and
			// the RST is decided while the Write is still in progress:
			// it never follows the partial frame.
			g.finish()
			g.closeWith(true, true)
			g.join()
			close(resume)
			<-read
			synctest.Wait()
			if len(got) >= len(data) {
				t.Fatalf("the wire carries %d bytes, want a cut DATA frame and nothing after it", len(got))
			}
			if g.rstFrame() != nil {
				t.Fatal("rstFrame offers an RST after a partial DATA frame")
			}
		})
	})
}

// TestPoolEarlyOnlyOnFreshDial (M4-D3, M4-D17, AM-2): the pool hands the
// early span to its own fresh dials only — the first dial, and a coalesced
// OPEN waiter that dials beside a slow claimant once its grace ran out —
// whose first flight carries OPEN(EARLY) ‖ DATA and whose Established
// reports the early bytes in flight; a fast-path view and a coalesced wait
// served by the claimant's published trunk get the caller's plain OPEN
// (flags 0 at the passive's admission) and Early == 0.
func TestPoolEarlyOnlyOnFreshDial(t *testing.T) {
	early := efEarly(1000)
	type rig struct {
		pt     *poolT
		mu     sync.Mutex
		recs   map[int]*efRec
		vflags []uint16 // OPEN flags of the views the passive admitted on live trunks
	}
	newRig := func(t *testing.T, late func(n int) time.Duration) *rig {
		r := &rig{pt: newPoolT(t, nil, nil), recs: map[int]*efRec{}}
		srv := r.pt.srv
		srv.mu.Lock()
		srv.wrap = func(n int, nc net.Conn) net.Conn {
			rec := &efRec{Conn: nc}
			r.mu.Lock()
			r.recs[n] = rec
			r.mu.Unlock()
			if late != nil && late(n) > 0 {
				return &lateVerdict{Conn: rec, delay: late(n)}
			}
			return rec
		}
		srv.mu.Unlock()
		admit := srv.env.Admit
		srv.env.Admit = func(v *Conn, h wire.Header, p []byte) {
			if h.Type == wire.TypeOpen {
				r.mu.Lock()
				r.vflags = append(r.vflags, binary.BigEndian.Uint16(p[18:20]))
				r.mu.Unlock()
			}
			admit(v, h, p)
		}
		return r
	}
	attempt := func(r *rig, sid byte) (*Established, error) {
		est, err := r.pt.p.AttemptEarly(context.Background(), 0, r.pt.env.IDs.Next(), wire.TypeOpen, poolPayload(wire.TypeOpen, sid), nil, [16]byte{}, uintptr(sid), wire.TypeData, early)
		if est != nil {
			r.pt.mu.Lock()
			r.pt.ests = append(r.pt.ests, est)
			r.pt.mu.Unlock()
		}
		return est, err
	}
	goAttempt := func(r *rig, sid byte, ch chan<- poolRes) {
		go func() {
			est, err := attempt(r, sid)
			ch <- poolRes{sid: sid, est: est, err: err, at: time.Now()}
		}()
	}
	// fresh checks a fresh dial's result and the first flight of dial n.
	fresh := func(t *testing.T, r *rig, est *Established, err error, n int) {
		t.Helper()
		if err != nil || !est.Fresh || !isOK(est) || est.Early != len(early) {
			t.Fatalf("fresh dial: %v (fresh %v, Early %d), want a fresh trunk with %d early bytes in flight", err, est != nil && est.Fresh, est.Early, len(early))
		}
		r.mu.Lock()
		rec := r.recs[n]
		r.mu.Unlock()
		b := rec.bytes()
		openLen := wire.FrameOverhead + wire.OpenFixedLen
		dataLen := wire.FrameOverhead + wire.DataPrefixLen + len(early)
		if len(b) < wire.PrefaceLen+openLen+dataLen {
			t.Fatalf("dial %d wrote %d bytes, want the whole first flight", n, len(b))
		}
		efCheckFlight(t, b[:wire.PrefaceLen+openLen+dataLen], wire.FirstFseq, early)
	}
	// plain checks a view that got no early span.
	plain := func(t *testing.T, r *rig, est *Established, err error, views int) {
		t.Helper()
		if err != nil || est.Fresh || !isOK(est) || est.Early != 0 {
			t.Fatalf("view: %v (fresh %v, Early %d), want a view of the live trunk without early data", err, est != nil && est.Fresh, est.Early)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.vflags) != views {
			t.Fatalf("the passive admitted %d views, want %d", len(r.vflags), views)
		}
		for _, f := range r.vflags {
			if f != 0 {
				t.Fatalf("a view's OPEN carried flags %#x, want 0 (no EARLY on a live trunk)", f)
			}
		}
	}
	t.Run("fresh dial, then a fast path", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newRig(t, nil)
			est, err := attempt(r, 1)
			fresh(t, r, est, err, 1)
			r.pt.attach(est)
			est2, err := attempt(r, 2)
			plain(t, r, est2, err, 1)
			r.pt.attach(est2)
			if d := r.pt.srv.dials.Load(); d != 1 {
				t.Fatalf("%d factory calls, want 1", d)
			}
		})
	})
	t.Run("coalesced wait served by the published trunk", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newRig(t, nil)
			gate := make(chan struct{})
			r.pt.srv.setGate(gate)
			ch := make(chan poolRes, 2)
			goAttempt(r, 1, ch)
			synctest.Wait()
			goAttempt(r, 2, ch) // waits for the claimant's dial (not proven: no grace)
			synctest.Wait()
			close(gate)
			first := collect(t, ch, 1)[0]
			if first.sid != 1 {
				t.Fatalf("the waiter returned first: %v", first.err)
			}
			fresh(t, r, first.est, first.err, 1)
			r.pt.attach(first.est)
			w := collect(t, ch, 1)[0]
			plain(t, r, w.est, w.err, 1)
			r.pt.attach(w.est)
			if d := r.pt.srv.dials.Load(); d != 1 {
				t.Fatalf("%d factory calls, want 1", d)
			}
		})
	})
	t.Run("a waiter dials beside the slow claimant", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const late = time.Second
			r := newRig(t, func(n int) time.Duration {
				if n == 1 {
					return late
				}
				return 0
			})
			claim := make(chan poolRes, 1)
			goAttempt(r, 1, claim)
			synctest.Wait()
			beside := make(chan poolRes, 1)
			goAttempt(r, 2, beside)
			w := collect(t, beside, 1)[0]
			fresh(t, r, w.est, w.err, 2)
			r.pt.attach(w.est)
			c := collect(t, claim, 1)[0]
			fresh(t, r, c.est, c.err, 1)
			r.pt.attach(c.est)
			if d := r.pt.srv.dials.Load(); d != 2 {
				t.Fatalf("%d factory calls, want 2", d)
			}
		})
	})
}

// TestMuxEarlyOpenRefused (M4-D3, §A3.1): an OPEN with EARLY for a new
// handle on a live MUX trunk — EARLY belongs only in a carrier's first
// frame — is refused BAD_REQUEST CodeBadValue through the refusal ring;
// the trunk, its other view and later views live.
func TestMuxEarlyOpenRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
		if err != nil || !est1.Fresh {
			t.Fatalf("first attempt: %v", err)
		}
		mv1 := pt.attach(est1)
		payload := poolPayload(wire.TypeOpen, 2)
		binary.BigEndian.PutUint16(payload[18:20], wire.OpenFlagEarly)
		est2, err := pt.p.Attempt(context.Background(), 0, pt.env.IDs.Next(), wire.TypeOpen, payload, nil, [16]byte{}, 2, wire.TypeData)
		if err != nil || est2 == nil || est2.Fresh {
			t.Fatalf("EARLY view: %v, want a refused view of the live trunk", err)
		}
		st, code, ok := responseStatus(est2.Resp, est2.Payload)
		if !ok || st != wire.StatusBadRequest || code != wire.CodeBadValue {
			t.Fatalf("EARLY view answered %v code %d, want BAD_REQUEST CodeBadValue", st, code)
		}
		if n := len(pt.srv.admitted()); n != 0 {
			t.Fatalf("the passive admitted %d views, want the EARLY OPEN refused before admission", n)
		}
		est3, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 3, [16]byte{})
		if err != nil || est3.Fresh || !isOK(est3) {
			t.Fatalf("a plain OPEN after the refusal: %v (fresh %v), want a view of the same trunk", err, est3 != nil && est3.Fresh)
		}
		pt.attach(est3)
		synctest.Wait()
		for i, c := range append([]*Conn{est1.Conn, est3.Conn}, pt.srv.accepted()...) {
			if dead, cause, detail, _ := c.Death(); dead {
				t.Fatalf("carrier %d died: %v %s", i, cause, detail)
			}
		}
		if mv1.done.n.Load() != 0 {
			t.Fatal("the first view ended")
		}
		if d := pt.srv.dials.Load(); d != 1 {
			t.Fatalf("%d factory calls, want 1 (the trunk lives)", d)
		}
	})
}
