package carrier

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// WP3b tests of the embedder datagram adapter (NewPacketIO), the guarded
// datagram factory call (GuardedDialPacket), the DialInfo of factory calls
// and the withdrawal of a datagram OPEN (M2 design §A5.10, §A6.4; M2-D4,
// M2-D55; Revision 1, R1-6; L38, L49, L51, L57).

// wbCountAddr is a pointer net.Addr that counts its String calls.
type wbCountAddr struct {
	s string
	n atomic.Int32
}

func (a *wbCountAddr) Network() string { return "wb" }
func (a *wbCountAddr) String() string  { a.n.Add(1); return a.s }

// wbPanicAddr is a net.Addr whose String panics.
type wbPanicAddr struct{}

func (wbPanicAddr) Network() string { return "wb" }
func (wbPanicAddr) String() string  { panic("wbPanicAddr.String") }

// wbSliceAddr is a net.Addr value type that cannot be compared with ==.
type wbSliceAddr struct{ b []byte }

func (a wbSliceAddr) Network() string { return "wb" }
func (a wbSliceAddr) String() string  { return string(a.b) }

// TestPacketIOPeerKey_L38_L57: NewPacketIO normalises the peer once; a
// datagram is the peer's when its source is the same value, a
// *net.UDPAddr of the same address and port (an IPv4-mapped one
// included), or — for other address types only — an address whose
// guarded String() equals the peer's; nil, typed-nil, other and panicking
// sources are foreign and no method of an address is called beyond those
// rules; a panicking peer, a nil peer or conn and a limit outside the
// frame budget range fail construction, which never closes the conn;
// writes pass the embedder's original peer value; a read allocates nothing
// of rendr's (L38, L57).
func TestPacketIOPeerKey_L38_L57(t *testing.T) {
	env := dgEnv()
	read := func(t *testing.T, io PacketIO, pc *wbPC, src net.Addr) ReadEvent {
		t.Helper()
		pc.push(wbRead{b: []byte("rendr bytes"), src: src})
		b := make([]byte, io.ReadSize())
		data, _, ev, err := io.ReadDatagram(b)
		if err != nil {
			t.Fatalf("ReadDatagram: %v", err)
		}
		if ev == ReadOK && string(data) != "rendr bytes" {
			t.Fatalf("data %q", data)
		}
		return ev
	}
	t.Run("UDP peer", func(t *testing.T) {
		pc := newWBPC()
		peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 4000}
		io, err := NewPacketIO(env, pc, peer, 1500)
		if err != nil {
			t.Fatal(err)
		}
		other := &wbCountAddr{s: peer.String()}
		for _, tc := range []struct {
			name string
			src  net.Addr
			want ReadEvent
		}{
			{"same pointer", peer, ReadOK},
			{"same address, mapped", &net.UDPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 4000}, ReadOK},
			{"other port", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4001}, ReadForeign},
			{"typed nil", (*net.UDPAddr)(nil), ReadForeign},
			{"nil", nil, ReadForeign},
			{"another type with the same text", other, ReadForeign},
			{"panicking String", wbPanicAddr{}, ReadForeign},
		} {
			if ev := read(t, io, pc, tc.src); ev != tc.want {
				t.Errorf("%s: %v, want %v", tc.name, ev, tc.want)
			}
		}
		if n := other.n.Load(); n != 0 {
			t.Errorf("String of a non-UDP source called %d times for a UDP peer", n)
		}
	})
	t.Run("other peer type", func(t *testing.T) {
		pc := newWBPC()
		peer := &wbCountAddr{s: "peer-a"}
		io, err := NewPacketIO(env, pc, peer, 1500)
		if err != nil {
			t.Fatal(err)
		}
		if n := peer.n.Load(); n != 1 {
			t.Fatalf("peer String called %d times by the construction, want once", n)
		}
		twin := &wbCountAddr{s: "peer-a"}
		for _, tc := range []struct {
			name string
			src  net.Addr
			want ReadEvent
		}{
			{"same pointer", peer, ReadOK},
			{"same text", twin, ReadOK},
			{"other text", &wbCountAddr{s: "peer-b"}, ReadForeign},
			{"panicking String", wbPanicAddr{}, ReadForeign},
			{"UDP source", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}, ReadForeign},
		} {
			if ev := read(t, io, pc, tc.src); ev != tc.want {
				t.Errorf("%s: %v, want %v", tc.name, ev, tc.want)
			}
		}
		if n := peer.n.Load(); n != 1 {
			t.Errorf("peer String called %d times, want only at construction", n)
		}
		if err := io.WriteDatagram([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if w := pc.written(); len(w) != 1 || w[0].addr != net.Addr(peer) {
			t.Errorf("WriteTo got %v, want the original peer value", w)
		}
	})
	t.Run("uncomparable peer type", func(t *testing.T) {
		pc := newWBPC()
		io, err := NewPacketIO(env, pc, wbSliceAddr{[]byte("p")}, 1500)
		if err != nil {
			t.Fatal(err)
		}
		if ev := read(t, io, pc, wbSliceAddr{[]byte("p")}); ev != ReadOK {
			t.Errorf("same text: %v", ev)
		}
		if ev := read(t, io, pc, wbSliceAddr{[]byte("q")}); ev != ReadForeign {
			t.Errorf("other text: %v", ev)
		}
	})
	t.Run("construction fails", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			peer  net.Addr
			limit int
		}{
			{"panicking peer String", wbPanicAddr{}, 1500},
			{"nil peer", nil, 1500},
			{"typed nil peer", (*net.UDPAddr)(nil), 1500},
			{"limit below the floor", &net.UDPAddr{Port: 1}, wire.MinFrameBudget - 1},
			{"limit above a datagram", &net.UDPAddr{Port: 1}, wire.MaxDatagram + 1},
		} {
			pc := newWBPC()
			if io, err := NewPacketIO(env, pc, tc.peer, tc.limit); err == nil || io != nil {
				t.Errorf("%s: %v, %v; want an error", tc.name, io, err)
			}
			if pc.closes.Load() != 0 {
				t.Errorf("%s: the caller's conn was closed", tc.name)
			}
		}
		if _, err := NewPacketIO(env, nil, &net.UDPAddr{Port: 1}, 1500); err == nil {
			t.Errorf("nil conn accepted")
		}
	})
	t.Run("no allocation", func(t *testing.T) {
		if carrierRace {
			t.Log("allocation gate: non-race lane only")
			return
		}
		pc := newWBPC()
		peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 4000}
		io, _ := NewPacketIO(env, pc, peer, 1500)
		for range 200 {
			pc.push(wbRead{b: []byte("rendr bytes"), src: peer})
		}
		b := make([]byte, io.ReadSize())
		if n := testing.AllocsPerRun(100, func() {
			if _, _, ev, err := io.ReadDatagram(b); ev != ReadOK || err != nil {
				panic("read failed")
			}
		}); n != 0 {
			t.Errorf("ReadDatagram allocates %v per datagram", n)
		}
	})
}

// TestPacketIOLimitFollowsBudget: an adapter whose Limit is 65,507 reads
// with 65,508 bytes until the negotiated cmtu 1152 lowers its receive limit
// (SetBudget → SetLimit, R1-6): the started reader's buffer is then a 2 KiB
// class of the datagram pool (as is the writer's scratch), every ReadFrom
// gets exactly 1153 bytes, a datagram of 1153 rendr bytes is truncated and
// dropped, one of 1152 is delivered — while Limit keeps reporting the
// transport's capacity.
func TestPacketIOLimitFollowsBudget(t *testing.T) {
	wbBubble(t, func(t *testing.T) {
		env := dgEnv()
		pc := newWBPC()
		peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 4000}
		io, err := NewPacketIO(env, pc, peer, wire.MaxDatagram)
		if err != nil {
			t.Fatal(err)
		}
		if io.ReadSize() != wire.MaxDatagram+1 {
			t.Fatalf("ReadSize %d before the budget, want %d", io.ReadSize(), wire.MaxDatagram+1)
		}
		// SetLimit stays within [MinFrameBudget, Limit].
		if io2, _ := NewPacketIO(env, newWBPC(), peer, 1500); io2 != nil {
			io2.SetLimit(100)
			lo := io2.ReadSize()
			io2.SetLimit(wire.MaxDatagram)
			if hi := io2.ReadSize(); lo != wire.MinFrameBudget+1 || hi != 1501 {
				t.Errorf("SetLimit clamps: ReadSize %d and %d, want %d and 1501", lo, hi, wire.MinFrameBudget+1)
			}
		}
		c := newDatagramConn(env, io, 7, hPeerInst, -1, "", false)
		c.SetBudget(1152)
		first := env.Presets.firstFseq()
		c.dg.rwin.Init(first)
		c.dg.rel.initSend(env.Presets.firstCseq())
		c.dg.rel.initRecv(env.Presets.firstCseq() - 1)
		if io.ReadSize() != 1153 || io.Limit() != wire.MaxDatagram {
			t.Fatalf("after SetBudget: ReadSize %d, Limit %d; want 1153, %d", io.ReadSize(), io.Limit(), wire.MaxDatagram)
		}
		probe := NewBudget(1 << 30)
		cls := NewDatagramBufPool().Get(1153, probe)
		classSize := probe.Used()
		cls.Release()
		before := env.Stages.Used()
		ep := &dEP{}
		c.Start(ep, &hBell{}, StartOptions{})
		defer func() {
			c.Kill(CauseLocalClose, "test end")
			<-c.Done()
		}()
		synctest.Wait()
		if d := env.Stages.Used() - before; d != 2*classSize {
			t.Errorf("stage charge %d, want two %d-byte classes (reader buffer, writer scratch)", d, classSize)
		}
		ping := func(fseq uint32, size int) []byte {
			pad := size - wire.FrameOverhead - wire.PingFixedLen
			return wbFrame(wire.TypePing, 0, fseq, 0, wbPingPayload(wire.Ping{ID: 3, Pad: pad}))
		}
		pc.push(wbRead{b: ping(first, 1153), src: peer})
		pc.push(wbRead{b: ping(first+1, 1152), src: peer})
		synctest.Wait()
		s := c.Stats()
		if s.Truncated != 1 || s.DatagramsRx != 1 {
			t.Errorf("Truncated %d, DatagramsRx %d; want 1 and 1", s.Truncated, s.DatagramsRx)
		}
		pc.mu.Lock()
		last := pc.lastLen
		pc.mu.Unlock()
		if last != 1153 {
			t.Errorf("ReadFrom got %d bytes, want 1153", last)
		}
	})
}

// TestDatagramFactoryMisbehaviour_L51: a datagram factory that returns no
// conn, a conn without a peer (also a typed nil *net.UDPAddr), a conn with
// an error, a peer whose String panics, panics, calls runtime.Goexit,
// ignores its context or succeeds too late fails the attempt at stage
// "dial" — at DialTimeout + grace at most —, releases the CarrierID, closes
// every conn it returned exactly once, and leaves the abandoned-call pool
// empty once a stuck call returned (L51, L52, L57).
func TestDatagramFactoryMisbehaviour_L51(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 4000}
	errBoom := errors.New("boom")
	for _, tc := range []struct {
		name    string
		dial    func(ctx context.Context, pc *wbPC, release <-chan struct{}) (net.PacketConn, net.Addr, error)
		closes  int32
		want    error
		stuck   bool // the call ignores ctx until released
		ended   time.Duration
		release bool
	}{
		{"nil conn", func(context.Context, *wbPC, <-chan struct{}) (net.PacketConn, net.Addr, error) { return nil, nil, nil }, 0, ErrNilConn, false, 0, false},
		{"nil peer", func(_ context.Context, pc *wbPC, _ <-chan struct{}) (net.PacketConn, net.Addr, error) {
			return pc, nil, nil
		}, 1, ErrNilConn, false, 0, false},
		{"typed nil peer", func(_ context.Context, pc *wbPC, _ <-chan struct{}) (net.PacketConn, net.Addr, error) {
			return pc, (*net.UDPAddr)(nil), nil
		}, 1, ErrNilConn, false, 0, false},
		{"conn with an error", func(_ context.Context, pc *wbPC, _ <-chan struct{}) (net.PacketConn, net.Addr, error) {
			return pc, peer, errBoom
		}, 1, errBoom, false, 0, false},
		{"panicking peer", func(_ context.Context, pc *wbPC, _ <-chan struct{}) (net.PacketConn, net.Addr, error) {
			return pc, wbPanicAddr{}, nil
		}, 1, nil, false, 0, false},
		{"panic", func(context.Context, *wbPC, <-chan struct{}) (net.PacketConn, net.Addr, error) { panic("factory") }, 0, ErrFactoryPanic, false, 0, false},
		{"Goexit", func(context.Context, *wbPC, <-chan struct{}) (net.PacketConn, net.Addr, error) {
			runtime.Goexit()
			return nil, nil, nil
		}, 0, ErrFactoryPanic, false, 0, false},
		{"ignores ctx", func(_ context.Context, pc *wbPC, rel <-chan struct{}) (net.PacketConn, net.Addr, error) {
			<-rel
			return pc, peer, nil
		}, 1, nil, true, 10*time.Second + dialGrace, true},
		{"late success", func(ctx context.Context, pc *wbPC, _ <-chan struct{}) (net.PacketConn, net.Addr, error) {
			<-ctx.Done()
			return pc, peer, nil
		}, 1, nil, false, 10 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				env := dgEnv()
				pc := newWBPC()
				rel := make(chan struct{})
				f := Factory{Index: 0, Name: "m", Kind: wire.KindDatagram, MTU: 1200, DialPacket: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
					return tc.dial(ctx, pc, rel)
				}}
				start := time.Now()
				_, err := Establish(context.Background(), env, f, env.IDs.Next(), wire.TypeOpen, wbOpen(1100), nil)
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Stage != "dial" || ee.Cause != CauseTransportError {
					t.Fatalf("got %v, want a transport error at stage dial", err)
				}
				if tc.want != nil && !errors.Is(err, tc.want) {
					t.Errorf("got %v, want %v", err, tc.want)
				}
				if el := time.Since(start); el != tc.ended {
					t.Errorf("ended after %v, want %v", el, tc.ended)
				}
				if tc.stuck && env.Abandon.Len() != 1 {
					t.Errorf("abandoned %d while the call is stuck, want 1", env.Abandon.Len())
				}
				if tc.release {
					close(rel)
				}
				synctest.Wait()
				if n := pc.closes.Load(); n != tc.closes {
					t.Errorf("conn closed %d times, want %d", n, tc.closes)
				}
				if env.IDs.inUse() != 0 || env.Abandon.Len() != 0 {
					t.Errorf("ids in use %d, abandoned %d; want 0, 0", env.IDs.inUse(), env.Abandon.Len())
				}
			})
		})
	}
}

// TestDialInfoAttached: every factory call Establish makes carries the
// attempt's DialInfo — the CarrierID, the factory kind (a Kind of 0 is a
// stream factory, R1-32), whether it is a probe and, for an OPEN or JOIN,
// the session ID — on stream factories (Dial and DialEarly) and datagram
// factories alike, and the call stays bounded by the attempt (M2-D55;
// integration 1, D20).
func TestDialInfoAttached(t *testing.T) {
	errStop := errors.New("stop after the factory call")
	for _, tc := range []struct {
		name  string
		kind  wire.CarrierKind
		early bool
		typ   wire.Type
		want  wire.CarrierKind
	}{
		{"stream Dial OPEN, kind 0", 0, false, wire.TypeOpen, wire.KindStream},
		{"stream Dial JOIN", wire.KindStream, false, wire.TypeJoin, wire.KindStream},
		{"stream DialEarly OPEN", wire.KindStream, true, wire.TypeOpen, wire.KindStream},
		{"stream probe", 0, false, wire.TypePing, wire.KindStream},
		{"datagram OPEN", wire.KindDatagram, false, wire.TypeOpen, wire.KindDatagram},
		{"datagram JOIN", wire.KindDatagram, false, wire.TypeJoin, wire.KindDatagram},
		{"datagram probe", wire.KindDatagram, false, wire.TypePing, wire.KindDatagram},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := dgEnv()
			var got DialInfo
			var ok, bounded bool
			record := func(ctx context.Context) {
				got, ok = DialInfoFrom(ctx)
				_, bounded = ctx.Deadline()
			}
			f := Factory{Index: 0, Name: "f", Kind: tc.kind, MTU: 1200}
			switch {
			case tc.kind == wire.KindDatagram:
				f.DialPacket = func(ctx context.Context) (net.PacketConn, net.Addr, error) { record(ctx); return nil, nil, errStop }
			case tc.early:
				f.DialEarly = func(ctx context.Context, _ []byte) (net.Conn, error) { record(ctx); return nil, errStop }
			default:
				f.Dial = func(ctx context.Context) (net.Conn, error) { record(ctx); return nil, errStop }
			}
			var payload []byte
			switch tc.typ {
			case wire.TypeOpen:
				payload = wbOpen(1100)
			case wire.TypeJoin:
				payload = wbJoin()
			}
			id := env.IDs.Next()
			if _, err := Establish(context.Background(), env, f, id, tc.typ, payload, nil); !errors.Is(err, errStop) {
				t.Fatalf("Establish: %v", err)
			}
			want := DialInfo{Carrier: id, Kind: tc.want, Probe: tc.typ == wire.TypePing}
			if tc.typ != wire.TypePing {
				want.Session = wbSID
			}
			if !ok || got != want || !bounded {
				t.Errorf("DialInfo %+v (attached %v, bounded %v), want %+v", got, ok, bounded, want)
			}
		})
	}
	if _, ok := DialInfoFrom(context.Background()); ok {
		t.Errorf("DialInfo outside a factory call")
	}
}

// TestDatagramWithdrawn_L49: a datagram OPEN whose Dial was withdrawn after
// its H1 was written is followed by one best-effort REL{F + 1,
// RST(withdrawn)} datagram, as is a failed instance check; a plain
// cancellation sends none (L49).
func TestDatagramWithdrawn_L49(t *testing.T) {
	rstOf := func(gs []wbGot, F uint32) int {
		n := 0
		for _, g := range gs {
			for _, h := range wbRelsIn(g.b) {
				if h.Type == wire.TypeRst && h.Cseq == F+1 {
					n++
				}
			}
		}
		return n
	}
	for _, tc := range []struct {
		name  string
		cause error // the cancellation cause (nil: the check fails)
		rsts  int
		want  Cause
	}{
		{"withdrawn", ErrWithdrawn, 1, CauseLocalClose},
		{"cancelled", context.Canceled, 0, CauseLocalClose},
		{"check failed", nil, 1, CauseInstanceMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				r, raws := wbRawRig(t, 1200)
				F := r.denv.Presets.firstCseq()
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				var check func(*wire.PrefaceAck) error
				if tc.cause == nil {
					check = func(*wire.PrefaceAck) error { return errors.New("another instance") }
				}
				ch := make(chan error, 1)
				go func() {
					_, err := Establish(ctx, r.denv, r.f, r.denv.IDs.Next(), wire.TypeOpen, wbOpen(1100), check)
					ch <- err
				}()
				w := <-raws
				h1 := w.waitN(t, 1)[0].b
				if tc.cause != nil {
					time.Sleep(100 * time.Millisecond)
					cancel(tc.cause)
				} else {
					h2, _ := wbH2(r.penv, h1, F)
					w.send(h2)
				}
				err := <-ch
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Cause != tc.want {
					t.Fatalf("got %v, want cause %v", err, tc.want)
				}
				synctest.Wait()
				if n := rstOf(w.received(), F); n != tc.rsts {
					t.Errorf("%d RST(withdrawn) datagrams, want %d", n, tc.rsts)
				}
				if r.denv.IDs.inUse() != 0 {
					t.Errorf("the CarrierID was not released")
				}
			})
		})
	}
}

// wbGoexitAddr is a net.Addr whose String calls runtime.Goexit.
type wbGoexitAddr struct{}

func (wbGoexitAddr) Network() string { return "wb" }
func (wbGoexitAddr) String() string  { runtime.Goexit(); return "" }

// TestDatagramEstablishGoexit_L51: an embedder call that runs
// runtime.Goexit on the attempt's goroutine — the peer's String inside
// NewPacketIO, the conn's ReadFrom during the handshake — unwinds
// Establish, and its deferred cleanup still closes the factory's conn
// exactly once and releases the CarrierID (L51).
func TestDatagramEstablishGoexit_L51(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 4000}
	for _, tc := range []struct {
		name string
		addr net.Addr
		pc   func(*wbPC) net.PacketConn
	}{
		{"peer String", wbGoexitAddr{}, func(pc *wbPC) net.PacketConn { return pc }},
		{"ReadFrom", peer, func(pc *wbPC) net.PacketConn { return wbGoexitReadPC{pc} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wbBubble(t, func(t *testing.T) {
				env := dgEnv()
				pc := newWBPC()
				f := Factory{Index: 0, Name: "g", Kind: wire.KindDatagram, MTU: 1200, DialPacket: func(context.Context) (net.PacketConn, net.Addr, error) {
					return tc.pc(pc), tc.addr, nil
				}}
				returned := make(chan bool, 1)
				go func() {
					ok := false
					defer func() { returned <- ok }()
					_, _ = Establish(context.Background(), env, f, env.IDs.Next(), wire.TypeOpen, wbOpen(1100), nil)
					ok = true
				}()
				if <-returned {
					t.Fatalf("Establish returned: the Goexit did not unwind it")
				}
				synctest.Wait()
				if n := pc.closes.Load(); n != 1 {
					t.Errorf("conn closed %d times, want once", n)
				}
				if env.IDs.inUse() != 0 {
					t.Errorf("the CarrierID was not released")
				}
			})
		})
	}
}

// wbGoexitReadPC is a wbPC whose ReadFrom calls runtime.Goexit.
type wbGoexitReadPC struct{ *wbPC }

func (wbGoexitReadPC) ReadFrom([]byte) (int, net.Addr, error) { runtime.Goexit(); return 0, nil, nil }
