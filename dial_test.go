package rendr

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// countReg is a session.Registry that counts its calls.
type countReg struct {
	mu    sync.Mutex
	ended []*session.Session
	other int // Opened, Lingering and Orphaned calls
}

func (r *countReg) Opened(*session.Session)          { r.count() }
func (r *countReg) Lingering(*session.Session, bool) { r.count() }
func (r *countReg) Orphaned(*session.Session, bool)  { r.count() }

func (r *countReg) count() {
	r.mu.Lock()
	r.other++
	r.mu.Unlock()
}

func (r *countReg) Ended(s *session.Session, _ session.Verdict) {
	r.mu.Lock()
	r.ended = append(r.ended, s)
	r.mu.Unlock()
}

func (r *countReg) calls() (ended []*session.Session, other int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*session.Session(nil), r.ended...), r.other
}

// TestSessionDialEntryContract pins the contract of session.Dial that
// Peer.Dial relies on to know whether a failed Dial left a session that
// withdraws in the background and that Runtime.Close must join (design
// §6.6, §6.8; the root learns it from the first Err call of the context it
// passes, entryCtx). When ctx is already done at that first Err call, or
// when the spec has no factory, session.Dial creates no session and makes
// no Registry call; otherwise the session it created calls Registry.Ended
// exactly once, also when Dial fails. Peer.open reports created
// accordingly: false for a done context, true for a failed Dial (and it
// counts a spec without factories, impossible from NewPeer, as no
// session). A change of this contract on the session side fails here.
func TestSessionDialEntryContract(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{NoPathGrace: 200 * time.Millisecond})
		f := &countingFactory{name: "f", err: errors.New("refused")}
		p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{f.carrier()}})
		if err != nil {
			t.Fatal(err)
		}
		reg := &countReg{}
		env := p.env
		env.Registry = reg
		spec := p.spec(SessionID(wpSID(1)), DialOptions{}, false)
		done, cancel := context.WithCancel(context.Background())
		cancel()

		// A context done at the entry check: no session, no Registry call.
		ec := &entryCtx{Context: done}
		if s, err := session.Dial(ec, &env, spec); s != nil || !errors.Is(err, context.Canceled) || ec.live.Load() {
			t.Fatalf("Dial with a done context = %v, %v (entry check live %v)", s, err, ec.live.Load())
		}
		// No factory: no session, no Registry call, although the context
		// was live at the entry check.
		ec = &entryCtx{Context: context.Background()}
		empty := spec
		empty.Factories = nil
		if s, err := session.Dial(ec, &env, empty); s != nil || !errors.Is(err, ErrNoPath) {
			t.Fatalf("Dial without a factory = %v, %v", s, err)
		}
		synctest.Wait()
		if ended, other := reg.calls(); len(ended) != 0 || other != 0 || f.calls.Load() != 0 {
			t.Fatalf("Dials that created no session: %d Ended, %d other Registry calls, %d factory calls", len(ended), other, f.calls.Load())
		}

		// A Dial that fails after it created its session (every attempt is
		// refused until the 200 ms grace): exactly one Ended, of that
		// session, once it withdrew.
		ec = &entryCtx{Context: context.Background()}
		if s, err := session.Dial(ec, &env, spec); s != nil || !errors.Is(err, ErrNoPath) || !ec.live.Load() {
			t.Fatalf("Dial with a refusing factory = %v, %v (entry check live %v)", s, err, ec.live.Load())
		}
		synctest.Wait()
		ended, _ := reg.calls()
		if len(ended) != 1 || f.calls.Load() == 0 {
			t.Fatalf("a failed Dial's session: %d Ended calls, %d factory calls; want exactly one Ended", len(ended), f.calls.Load())
		}
		select {
		case <-ended[0].Done():
		default:
			t.Fatal("the failed Dial's session is not done after it withdrew")
		}

		// Peer.open reports what Peer.Dial hands over to the session's Ended.
		if _, created, err := p.open(done, SessionID(wpSID(2)), DialOptions{}, false, &dialReg{rt: rt, sid: SessionID(wpSID(2))}); created || err == nil {
			t.Fatalf("open with a done context: created %v, %v", created, err)
		}
		dr := &dialReg{rt: rt, sid: SessionID(wpSID(3))}
		if _, created, err := p.open(context.Background(), SessionID(wpSID(3)), DialOptions{}, false, dr); !created || !errors.Is(err, ErrNoPath) {
			t.Fatalf("open with a refusing factory: created %v, %v", created, err)
		}
		synctest.Wait()
		dr.mu.Lock()
		endedOnce := dr.ended
		dr.mu.Unlock()
		if !endedOnce {
			t.Fatal("the created session never called its dialReg's Ended")
		}
		rt.Close()
		wpNoState(t, rt)
	})
}

// scriptedPassive is a factory whose every carrier is answered by a
// scripted passive (the far end of a net.Pipe) instead of a Runtime: it
// reads the dialer's PREFACE and first frame — Establish writes both in
// one Write while it waits for the PREFACE_ACK (design §0.8 V1) — writes
// answer(preface, first) byte for byte, then reads until the dialer
// closes. Every goroutine it starts has ended once wg is waited for.
type scriptedPassive struct {
	t      testing.TB
	answer func(p wire.Preface, first wire.Frame) []byte
	wg     sync.WaitGroup
	dials  atomic.Int32
}

func (s *scriptedPassive) carrier(name string) StreamCarrier {
	return StreamCarrier{Name: name, Dial: func(context.Context) (net.Conn, error) {
		s.dials.Add(1)
		a, b := net.Pipe()
		s.wg.Go(func() {
			defer b.Close()
			var pb [wire.PrefaceLen]byte
			if _, err := io.ReadFull(b, pb[:]); err != nil {
				return
			}
			p, err := wire.ParsePreface(pb[:])
			if err != nil {
				s.t.Errorf("the dialer sent an invalid PREFACE: %v", err)
				return
			}
			var hb [wire.HeaderLen]byte
			if _, err := io.ReadFull(b, hb[:]); err != nil {
				return
			}
			h, err := wire.ParseHeader(hb[:])
			if err != nil {
				s.t.Errorf("the dialer's first frame: %v", err)
				return
			}
			rest := make([]byte, int(h.Len)+wire.TrailerLen)
			if _, err := io.ReadFull(b, rest); err != nil {
				return
			}
			if _, err := b.Write(s.answer(p, wire.Frame{Header: h, Payload: rest[:h.Len]})); err != nil {
				return
			}
			io.Copy(io.Discard, b)
		})
		return a, nil
	}}
}

// prefaceAck encodes a PREFACE_ACK answering p; edit may change bytes 0–35,
// after which the CRC is recomputed (a well-formed answer of that shape).
func prefaceAck(p wire.Preface, st wire.PrefaceStatus, inst [16]byte, edit func(b []byte)) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPrefaceAck(b, &wire.PrefaceAck{Minor: wire.Minor, Status: st, Instance: inst, CarrierID: p.CarrierID})
	if edit != nil {
		edit(b)
		binary.BigEndian.PutUint32(b[36:40], wire.CRC(b[:36]))
	}
	return b
}

// frameAfterAck appends one passive frame to a PREFACE_ACK, with the first
// fseq of the passive's direction: the PREFACE_ACK's CRC field (§0.13 A6).
func frameAfterAck(ack []byte, ty wire.Type, flags uint8, payload []byte) []byte {
	var handle uint32
	if !ty.CarrierLevel() {
		handle = wire.SessionHandle
	}
	return wire.AppendFrame(ack, wire.Header{Type: ty, Flags: flags, Fseq: wire.PrefaceFseq(ack), Handle: handle}, payload)
}

// TestHandshakeNegotiationTyped_L44 (as amended by P19): a dialer meeting
// scripted passives that answer the way an incompatible or broken peer
// would gets the typed error within 200 ms (L44, design §5.1, §6.6, §9).
// A well-formed PREFACE_ACK of major 1 or 3 (magic, major byte and CRC
// valid, other fields arbitrary), PREFACE_ACK VERSION and FEATURE are
// ErrVersion; OPEN_ACK BAD_REQUEST is ErrProtocol, with CodeMetadataSize
// ErrMetadataTooLarge. A zero InstanceID in the PREFACE_ACK and a DATA
// frame before OPEN_ACK are malformed answers — carrier errors, retried
// until NoPathGrace (here 150 ms) — and end as ErrNoPath wrapping the
// protocol-violation carrier error, within 200 ms. Every error is a
// net.Error with Timeout false; no session or MaxSessions unit remains.
func TestHandshakeNegotiationTyped_L44(t *testing.T) {
	passive := wpInst(0x44)
	cases := []struct {
		name   string
		answer func(p wire.Preface, first wire.Frame) []byte
		want   error
		retry  bool // a carrier error: the dialer retries until the grace
	}{
		{"major 1", func(p wire.Preface, _ wire.Frame) []byte {
			return prefaceAck(p, wire.PrefaceOK, passive, func(b []byte) { b[4] = 1 })
		}, ErrVersion, false},
		{"major 3 with other fields", func(p wire.Preface, _ wire.Frame) []byte {
			return prefaceAck(p, wire.PrefaceOK, passive, func(b []byte) { b[4] = 3; b[6] = 0x77; clear(b[16:32]) })
		}, ErrVersion, false},
		{"PREFACE_ACK VERSION", func(p wire.Preface, _ wire.Frame) []byte {
			return prefaceAck(p, wire.PrefaceVersion, passive, nil)
		}, ErrVersion, false},
		{"PREFACE_ACK FEATURE", func(p wire.Preface, _ wire.Frame) []byte {
			return prefaceAck(p, wire.PrefaceFeature, passive, nil)
		}, ErrVersion, false},
		{"OPEN_ACK BAD_REQUEST", func(p wire.Preface, _ wire.Frame) []byte {
			var b [wire.OpenAckFixedLen]byte
			n := wire.PutOpenAck(b[:], &wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeBadValue})
			return frameAfterAck(prefaceAck(p, wire.PrefaceOK, passive, nil), wire.TypeOpenAck, 0, b[:n])
		}, ErrProtocol, false},
		{"OPEN_ACK BAD_REQUEST metadata", func(p wire.Preface, _ wire.Frame) []byte {
			var b [wire.OpenAckFixedLen]byte
			n := wire.PutOpenAck(b[:], &wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeMetadataSize})
			return frameAfterAck(prefaceAck(p, wire.PrefaceOK, passive, nil), wire.TypeOpenAck, 0, b[:n])
		}, ErrMetadataTooLarge, false},
		{"zero InstanceID", func(p wire.Preface, _ wire.Frame) []byte {
			return prefaceAck(p, wire.PrefaceOK, [16]byte{}, func([]byte) {})
		}, ErrNoPath, true},
		{"DATA before OPEN_ACK", func(p wire.Preface, _ wire.Frame) []byte {
			var b [wire.DataPrefixLen + 4]byte
			wire.PutDataOffset(b[:], 0)
			return frameAfterAck(prefaceAck(p, wire.PrefaceOK, passive, nil), wire.TypeData, 0, b[:])
		}, ErrNoPath, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{NoPathGrace: 150 * time.Millisecond})
				sp := &scriptedPassive{t: t, answer: tc.answer}
				p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{sp.carrier("scripted")}})
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				c, err := p.Dial(context.Background(), DialOptions{})
				el := time.Since(start)
				var ne net.Error
				if c != nil || !errors.Is(err, tc.want) || !errors.As(err, &ne) || ne.Timeout() || el > 200*time.Millisecond {
					t.Fatalf("Dial = %v, %v after %v; want %v within 200 ms", c, err, el, tc.want)
				}
				if tc.retry {
					var ee *carrier.EstablishError
					if !errors.As(err, &ee) || ee.Cause != carrier.CauseProtocolViolation {
						t.Fatalf("%v does not wrap a protocol-violation carrier error", err)
					}
					if el < 150*time.Millisecond || sp.dials.Load() < 1 {
						t.Fatalf("ErrNoPath after %v and %d dials, want at the 150 ms grace", el, sp.dials.Load())
					}
				} else if n := sp.dials.Load(); n != 1 {
					t.Fatalf("a typed answer was retried: %d dials", n)
				}
				rt.Close()
				sp.wg.Wait()
				wpNoState(t, rt)
			})
		})
	}
}

// TestOpenFitTooSmall (W4 L3-1): a packet Dial maps ErrNoPath to
// ErrMetadataTooLarge only when every datagram factory returned a carrier
// whose budget — min(factory MTU, the rendr-owned socket's limit) — is too
// small for the OPEN. The wrapped factory records the budget of a
// rendr-owned UDP carrier it returns (stimulus: one real loopback socket
// of MaxDatagram 1472 behind a factory of MTU 3991); an embedder conn, a
// failed dial and a factory never dialled record nothing, and nothing then
// maps. Stream factories are left as they are.
func TestOpenFitTooSmall(t *testing.T) {
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	owned := carrier.NewOwnedUDP(u, netip.MustParseAddrPort("127.0.0.1:9"), 7, 1472)
	defer owned.Close()
	emb, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer emb.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	dialTo := func(pc net.PacketConn, err error) func(context.Context) (net.PacketConn, net.Addr, error) {
		return func(context.Context) (net.PacketConn, net.Addr, error) { return pc, peer, err }
	}
	stream := func(context.Context) (net.Conn, error) { return nil, net.ErrClosed }
	fs := []carrier.Factory{
		{Index: 0, Name: "owned", Kind: wire.KindDatagram, MTU: 3991, DialPacket: dialTo(owned, nil)},
		{Index: 1, Name: "embedder", Kind: wire.KindDatagram, MTU: 3991, DialPacket: dialTo(emb, nil)},
		{Index: 2, Name: "failed", Kind: wire.KindDatagram, MTU: 3991, DialPacket: dialTo(nil, net.ErrClosed)},
		{Index: 3, Name: "stream", Kind: wire.KindStream, Dial: stream},
	}
	f := newOpenFit(len(fs))
	w := wrapDatagram(fs, f, false)
	if &w[0] == &fs[0] || w[3].Dial == nil || w[3].DialPacket != nil {
		t.Fatal("wrap changed the Peer's snapshot or a stream factory")
	}
	for i := range 3 {
		_, _, _ = w[i].DialPacket(context.Background())
	}
	want := []int32{1472 - wire.FlowHeaderLen, 0, 0, 0}
	for i := range want {
		if got := f.budget[i].Load(); got != want[i] {
			t.Errorf("factory %s recorded budget %d, want %d", fs[i].Name, got, want[i])
		}
	}
	fit := 1463 - openOverhead // the most metadata the owned carrier's OPEN carries
	for _, c := range []struct {
		name   string
		budget []int32
		meta   int
		want   bool
	}{
		{"one factory, too small", []int32{1463}, fit + 1, true},
		{"one factory, fits", []int32{1463}, fit, false},
		{"another factory never returned a carrier", []int32{1463, 0}, 2000, false},
		{"another factory carries it", []int32{1463, 3991}, 2000, false},
		{"both too small", []int32{1463, 1200}, 2000, true},
		{"no factory", nil, 2000, false},
	} {
		g := newOpenFit(len(c.budget))
		for i, b := range c.budget {
			g.budget[i].Store(b)
		}
		if got := g.tooSmall(c.meta); got != c.want {
			t.Errorf("%s: tooSmall(%d) = %v, want %v", c.name, c.meta, got, c.want)
		}
	}
	var none *openFit
	if none.tooSmall(1 << 16) {
		t.Error("a nil openFit (a Peer with a stream factory) maps an error")
	}
}

// TestOfferFromBudgets (W4 L3-1, wave-4 review G3): the MaxPayload offer
// comes from the datagram budgets — and the OPEN's pmtu may follow a lower
// carrier budget — for a selector session with a datagram factory and for
// a bond session without a stream factory; a bond session with a stream
// factory offers Packet.MaxPayload for its stream carriers, and its
// datagram factories are not wrapped (nothing is marked). packetOffer
// follows the same rule.
func TestOfferFromBudgets(t *testing.T) {
	dg := carrier.Factory{Kind: wire.KindDatagram, MTU: 3991, DialPacket: func(context.Context) (net.PacketConn, net.Addr, error) { return nil, nil, net.ErrClosed }}
	st := carrier.Factory{Kind: wire.KindStream, Dial: func(context.Context) (net.Conn, error) { return nil, net.ErrClosed }}
	for _, c := range []struct {
		name       string
		fs         []carrier.Factory
		bond       bool
		maxPayload int
		want       bool
		offer      int
	}{
		{"selector, datagram only", []carrier.Factory{dg}, false, 2000, true, 2000},
		{"selector, datagram and stream", []carrier.Factory{dg, st}, false, 2000, true, 2000},
		{"bond, datagram only", []carrier.Factory{dg}, true, 2000, true, 2000},
		{"bond, datagram and stream", []carrier.Factory{dg, st}, true, 2000, false, 2000},
		{"bond, datagram and stream, large MaxPayload", []carrier.Factory{dg, st}, true, 60000, false, 60000},
		{"selector, stream only", []carrier.Factory{st}, false, 2000, false, 2000},
		{"selector, datagram budget below MaxPayload", []carrier.Factory{dg}, false, 60000, true, 3966},
	} {
		if got := offerFromBudgets(c.fs, c.bond); got != c.want {
			t.Errorf("%s: offerFromBudgets = %v, want %v", c.name, got, c.want)
		}
		if got := packetOffer(c.fs, c.bond, c.maxPayload); got != c.offer {
			t.Errorf("%s: packetOffer = %d, want %d", c.name, got, c.offer)
		}
		if w := wrapDatagram(c.fs, nil, offerFromBudgets(c.fs, c.bond)); c.want != (&w[0] != &c.fs[0]) {
			t.Errorf("%s: wrapped %v, want %v", c.name, &w[0] != &c.fs[0], c.want)
		}
	}
}

// trackedConns wraps every conn a factory returns and counts their Close
// calls (L49, L51: every carrier is closed exactly once). block, when set,
// makes each Close block until release is closed.
type trackedConns struct {
	mu      sync.Mutex
	conns   []*trackedConn
	block   bool
	release chan struct{}
}

type trackedConn struct {
	net.Conn
	tc     *trackedConns
	closes atomic.Int32
}

func (c *trackedConn) Close() error {
	c.closes.Add(1)
	err := c.Conn.Close()
	if c.tc.block {
		<-c.tc.release
	}
	return err
}

func newTrackedConns(block bool) *trackedConns {
	return &trackedConns{block: block, release: make(chan struct{})}
}

// wrap is a factory over dial whose conns are tracked.
func (tc *trackedConns) wrap(name string, dial func(context.Context) (net.Conn, error)) StreamCarrier {
	return StreamCarrier{Name: name, Dial: func(ctx context.Context) (net.Conn, error) {
		c, err := dial(ctx)
		if c == nil {
			return nil, err
		}
		w := &trackedConn{Conn: c, tc: tc}
		tc.mu.Lock()
		tc.conns = append(tc.conns, w)
		tc.mu.Unlock()
		return w, err
	}}
}

// closes returns the Close count of every tracked conn.
func (tc *trackedConns) closes() []int32 {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	out := make([]int32, len(tc.conns))
	for i, c := range tc.conns {
		out[i] = c.closes.Load()
	}
	return out
}

// requireClosedOnce requires at least one tracked conn and exactly one
// Close of each.
func (tc *trackedConns) requireClosedOnce(t testing.TB) {
	t.Helper()
	cs := tc.closes()
	if len(cs) == 0 {
		t.Fatal("no carrier was dialled")
	}
	for i, n := range cs {
		if n != 1 {
			t.Fatalf("carrier %d closed %d times, want 1", i, n)
		}
	}
}

// TestDialCancelSilentPeer_L49: a Dial whose peer never answers returns
// within 200 ms of its context ending (L49: the contract is 100 ms) with
// the context's error — cancellation and deadline alike — while the
// carrier it opened is closed exactly once in the background, and nothing
// is left in the Runtime. Two silent peers: a blackholed link (the bytes
// vanish) and a peer that reads the PREFACE and OPEN but never answers.
func TestDialCancelSilentPeer_L49(t *testing.T) {
	for _, silent := range []string{"blackhole", "reads only"} {
		t.Run(silent, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, nil)
				var dial func(context.Context) (net.Conn, error)
				var link *rendrtest.Link
				var wg sync.WaitGroup
				if silent == "blackhole" {
					link = rendrtest.NewLink(rendrtest.LinkConfig{Name: "void"})
					link.SetBlackhole(true)
					dial = link.Dial
				} else {
					dial = func(context.Context) (net.Conn, error) {
						a, b := net.Pipe()
						wg.Go(func() {
							io.Copy(io.Discard, b)
							b.Close()
						})
						return a, nil
					}
				}
				tc := newTrackedConns(false)
				p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{tc.wrap("silent", dial)}})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				res := e2eDialAsync(ctx, p, DialOptions{})
				time.Sleep(time.Second)
				cancel()
				t0 := time.Now()
				r := <-res
				if r.c != nil || !errors.Is(r.err, context.Canceled) || time.Since(t0) > 200*time.Millisecond {
					t.Fatalf("cancelled Dial = %v, %v after %v", r.c, r.err, time.Since(t0))
				}
				ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
				defer cancel()
				r = <-e2eDialAsync(ctx, p, DialOptions{})
				if r.c != nil || !errors.Is(r.err, context.DeadlineExceeded) || r.at > 500*time.Millisecond {
					t.Fatalf("Dial past its deadline = %v, %v after %v", r.c, r.err, r.at)
				}
				// The withdrawal writes RST(withdrawn) after the OPEN, then
				// closes in the L05 order: a drain of what the silent peer
				// sent, bounded by 1 s, then Close.
				time.Sleep(1500 * time.Millisecond)
				synctest.Wait()
				tc.requireClosedOnce(t)
				if units := rt.table.inUse(); units != 0 {
					t.Fatalf("%d MaxSessions units after the cancelled Dials", units)
				}
				rt.Close()
				if link != nil {
					link.Close()
				}
				wg.Wait()
				wpNoState(t, rt)
			})
		})
	}
}

// TestDialCancelAfterAccept_L49: cancelling a Dial whose OPEN the passive
// already admitted (L49). Before the passive application decides, Dial
// returns the context error within 200 ms, the dialer withdraws its OPEN
// (RST(withdrawn)) and the passive learns it within 1 s: Confirm returns
// ErrSessionLost and the session leaves a tombstone, no pending slot.
// Cancelling after Dial returned has no effect on the session. When the
// cancellation races the passive's Confirm, exactly one CAS decides: the
// Dial either returns the session, which then works, or the context error,
// and then the passive end learns the withdrawal within 1 s.
func TestDialCancelAfterAccept_L49(t *testing.T) {
	t.Run("before Confirm", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			ctx, cancel := context.WithCancel(context.Background())
			res := e2eDialAsync(ctx, e.peer(), DialOptions{})
			pc, err := e.ln.Accept(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			t0 := time.Now()
			if r := <-res; r.c != nil || !errors.Is(r.err, context.Canceled) || time.Since(t0) > 200*time.Millisecond {
				t.Fatalf("Dial = %v, %v after %v", r.c, r.err, time.Since(t0))
			}
			select {
			case <-pc.s.Done(): // the withdrawal reached the passive and ended its session
			case <-time.After(time.Second):
				t.Fatal("the passive did not learn the withdrawal within 1 s")
			}
			if _, err := pc.Confirm(); !errors.Is(err, ErrSessionLost) || time.Since(t0) > time.Second {
				t.Fatalf("Confirm after the withdrawal: %v after %v", err, time.Since(t0))
			}
			synctest.Wait()
			if st := e.p.Status(); st.Sessions != (SessionCounts{Tombstones: 1}) || st.AcceptBacklog[0] != 0 {
				t.Fatalf("passive after the withdrawal: %+v", st)
			}
			e.close()
		})
	})
	t.Run("after Dial returned", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			ctx, cancel := context.WithCancel(context.Background())
			res := e2eDialAsync(ctx, e.peer(), DialOptions{})
			sc := e2eConfirm(t, e.ln)
			r := <-res
			if r.err != nil {
				t.Fatal(r.err)
			}
			cancel()
			synctest.Wait()
			e2eExchange(t, r.c, sc, 256<<10, 3)
			e2eFinish(t, r.c, sc)
			e.close()
		})
	})
	t.Run("racing Confirm", func(t *testing.T) {
		won, lost := 0, 0
		for i := range 20 {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
				ctx, cancel := context.WithCancel(context.Background())
				res := e2eDialAsync(ctx, e.peer(), DialOptions{})
				pc, err := e.ln.Accept(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				confirmed := make(chan *Conn, 1)
				go func() {
					c, _ := pc.Confirm()
					confirmed <- c
				}()
				if i%2 == 0 {
					synctest.Wait() // let the Confirm reach the actor first in half of the runs
				}
				cancel()
				r := <-res
				sc := <-confirmed
				t0 := time.Now()
				switch {
				case r.err == nil:
					won++
					if sc == nil {
						t.Fatal("Dial succeeded but Confirm failed")
					}
					e2eExchange(t, r.c, sc, 64<<10, uint64(i))
					e2eFinish(t, r.c, sc)
				case !errors.Is(r.err, context.Canceled):
					t.Fatalf("Dial: %v", r.err)
				default:
					lost++
					if sc != nil {
						var ae *AbortError
						if _, err := sc.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != AbortWithdrawn || time.Since(t0) > time.Second {
							t.Fatalf("the passive end of a withdrawn session: %v after %v", err, time.Since(t0))
						}
					}
				}
				synctest.Wait()
				e.close()
			})
		}
		t.Logf("the Dial won %d and the cancellation %d of 20 races", won, lost)
	})
}

// TestDialCancelBlockedClose_L49: a carrier whose Close blocks cannot hold
// a cancelled Dial (L49): Dial returns within 200 ms, the carrier's Close is
// called exactly once on a goroutine of its own, which is counted in
// Status.Abandoned while it is stuck (L52); Runtime.Close stays bounded,
// and when the embedder's Close returns nothing is left.
func TestDialCancelBlockedClose_L49(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: 500 * time.Millisecond})
		link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "void"})
		link.SetBlackhole(true)
		tc := newTrackedConns(true)
		p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{tc.wrap("stuck-close", link.Dial)}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		res := e2eDialAsync(ctx, p, DialOptions{})
		time.Sleep(500 * time.Millisecond)
		cancel()
		t0 := time.Now()
		if r := <-res; r.c != nil || !errors.Is(r.err, context.Canceled) || time.Since(t0) > 200*time.Millisecond {
			t.Fatalf("Dial = %v, %v after %v", r.c, r.err, time.Since(t0))
		}
		// The withdrawal's closer (RST(withdrawn), a drain ≤ 1 s, Close) is
		// counted when it is still running AbandonWait + 3 × 1 s after it
		// started (its write, unblock and drain bounds).
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if cs := tc.closes(); len(cs) != 1 || cs[0] != 1 {
			t.Fatalf("Close calls %v, want exactly one on the one carrier", cs)
		}
		if n := rt.Status().Abandoned; n != 1 {
			t.Fatalf("abandoned %d, want the stuck Close", n)
		}
		t0 = time.Now()
		rt.Close()
		if el := time.Since(t0); el > 2500*time.Millisecond {
			t.Fatalf("Runtime.Close took %v", el)
		}
		close(tc.release)
		synctest.Wait()
		if st := rt.Status(); st.Abandoned != 0 {
			t.Fatalf("abandoned %d after the Close returned", st.Abandoned)
		}
		tc.requireClosedOnce(t)
		link.Close()
		wpNoState(t, rt)
	})
}

// TestTerminalOutcomeWithdrawsParkedOpens_L49: every terminal outcome of
// the opening phase withdraws the OPENs that may be parked on the passive
// (design §6.6 C25), so a pending session there is never confirmed as an
// orphan: the passive learns the withdrawal, Confirm returns
// ErrSessionLost and the session leaves only a tombstone. Two terminal
// outcomes: ErrNoPath at NoPathGrace while the OPEN waits for the
// application, and ErrVersion from another factory while the first
// factory's OPEN is parked.
func TestTerminalOutcomeWithdrawsParkedOpens_L49(t *testing.T) {
	t.Run("ErrNoPath at grace", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ov := &testhooks.Overrides{NoPathGrace: 2 * time.Second}
			e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
			res := e2eDialAsync(context.Background(), e.peer(), DialOptions{})
			pc, err := e.ln.Accept(context.Background()) // the application takes it but does not decide
			if err != nil {
				t.Fatal(err)
			}
			r := <-res
			if r.c != nil || !errors.Is(r.err, ErrNoPath) || r.at < 2*time.Second || r.at > 2200*time.Millisecond {
				t.Fatalf("Dial = %v, %v after %v; want ErrNoPath at the 2 s grace", r.c, r.err, r.at)
			}
			synctest.Wait()
			if _, err := pc.Confirm(); !errors.Is(err, ErrSessionLost) {
				t.Fatalf("Confirm of the parked OPEN: %v", err)
			}
			if st := e.p.Status(); st.Sessions != (SessionCounts{Tombstones: 1}) || st.AcceptBacklog[0] != 0 {
				t.Fatalf("passive %+v", st)
			}
			e.close()
		})
	})
	t.Run("ErrVersion from another factory", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ov := &testhooks.Overrides{JoinStagger: 200 * time.Millisecond}
			e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
			e.links[0].SetDelay(time.Millisecond, 0)
			old := &scriptedPassive{t: t, answer: func(p wire.Preface, _ wire.Frame) []byte {
				return prefaceAck(p, wire.PrefaceVersion, wpInst(0x01), nil)
			}}
			peer, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{e2eCarrier(e.links[0]), old.carrier("old")}})
			if err != nil {
				t.Fatal(err)
			}
			res := e2eDialAsync(context.Background(), peer, DialOptions{})
			pc, err := e.ln.Accept(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			r := <-res
			if r.c != nil || !errors.Is(r.err, ErrVersion) {
				t.Fatalf("Dial = %v, %v; want ErrVersion", r.c, r.err)
			}
			time.Sleep(10 * time.Millisecond) // the RST(withdrawn) crosses the 1 ms link
			synctest.Wait()
			if _, err := pc.Confirm(); !errors.Is(err, ErrSessionLost) {
				t.Fatalf("Confirm of the parked OPEN: %v", err)
			}
			if st := e.p.Status(); st.Sessions.Tombstones != 1 || st.Sessions.Pending != 0 || st.AcceptBacklog[0] != 0 {
				t.Fatalf("passive %+v", st)
			}
			e.close()
			old.wg.Wait()
		})
	})
}

// gatedHelloConn delivers its first Write (the hello: PREFACE ‖ OPEN) at
// once but returns it only when gate is closed, ignoring every deadline:
// the hello writer preempted after the passive read the OPEN.
type gatedHelloConn struct {
	net.Conn
	gate  <-chan struct{}
	first atomic.Bool
}

func (c *gatedHelloConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.first.CompareAndSwap(false, true) {
		<-c.gate
	}
	return n, err
}

// TestDialCancelAfterHelloReturnLate_L49 (L49, R1-4; WP13 A-1, the I3
// racing-Confirm failure): a Dial cancelled after the passive admitted its
// OPEN — and, in one row, Confirmed it — while the dialer's hello Write
// has delivered its bytes but returns only 5 ms after the cancellation.
// The Dial returns the context error within 200 ms, and the passive learns
// the withdrawal within 1 s: the Confirmed Conn's Read returns
// *AbortError{AbortWithdrawn}; an unconfirmed session ends and its Confirm
// returns ErrSessionLost. Before the fix no RST followed the OPEN and the
// passive kept the session until PassiveRetain (ErrNoPath after 34 s).
func TestDialCancelAfterHelloReturnLate_L49(t *testing.T) {
	for _, confirm := range []bool{true, false} {
		name := "pending"
		if confirm {
			name = "confirmed"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
				gate := make(chan struct{})
				var gateOnce sync.Once
				release := func() { gateOnce.Do(func() { close(gate) }) }
				t.Cleanup(release) // a failed test still ends its bubble
				l := e.links[0]
				p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{StreamCarrier{Name: l.Name(), Dial: func(ctx context.Context) (net.Conn, error) {
					c, err := l.Dial(ctx)
					if c == nil {
						return nil, err
					}
					return &gatedHelloConn{Conn: c, gate: gate}, err
				}}}})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				res := e2eDialAsync(ctx, p, DialOptions{})
				pc, err := e.ln.Accept(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				confirmed := make(chan *Conn, 1)
				if confirm {
					go func() {
						c, _ := pc.Confirm()
						confirmed <- c
					}()
				}
				synctest.Wait() // the passive admitted (and confirmed) the OPEN; the hello Write has not returned
				cancel()
				time.AfterFunc(5*time.Millisecond, release)
				t0 := time.Now()
				if r := <-res; r.c != nil || !errors.Is(r.err, context.Canceled) || time.Since(t0) > 200*time.Millisecond {
					t.Fatalf("Dial = %v, %v after %v", r.c, r.err, time.Since(t0))
				}
				if confirm {
					sc := <-confirmed
					if sc == nil {
						t.Fatal("stimulus: Confirm failed before the cancellation")
					}
					var ae *AbortError
					if _, err := sc.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != AbortWithdrawn || !ae.Remote || time.Since(t0) > time.Second {
						t.Fatalf("the Confirmed passive end of a withdrawn session: %v after %v", err, time.Since(t0))
					}
				} else {
					select {
					case <-pc.s.Done():
					case <-time.After(time.Second):
						t.Fatal("the passive did not learn the withdrawal within 1 s")
					}
					if _, err := pc.Confirm(); !errors.Is(err, ErrSessionLost) {
						t.Fatalf("Confirm after the withdrawal: %v", err)
					}
				}
				synctest.Wait()
				e.close()
			})
		})
	}
}

// TestFactoryMisbehaviour_L51: an embedder factory is untrusted (L51). A
// factory that returns (nil, nil), panics or calls runtime.Goexit cannot
// crash the process: every attempt fails, and Dial ends with ErrNoPath at
// NoPathGrace wrapping ErrNilConn or ErrFactoryPanic. A factory that ignores
// its context, and one that succeeds only after Runtime.Close, cannot hold
// Runtime.Close: it returns within 200 ms, the in-flight Dial returns
// net.ErrClosed, the stuck factory calls are counted in Status.Abandoned
// until they return, and a conn returned late is closed exactly once.
func TestFactoryMisbehaviour_L51(t *testing.T) {
	cases := []struct {
		name string
		beh  rendrtest.DialBehavior
		want error // nil: the factory blocks; the Dial is still in flight at Close
	}{
		{"nil conn and nil error", rendrtest.DialNilNil, carrier.ErrNilConn},
		{"panic", rendrtest.DialPanic, carrier.ErrFactoryPanic},
		{"Goexit", rendrtest.DialGoexit, carrier.ErrFactoryPanic},
		{"ignores ctx", rendrtest.DialHangForever, nil},
		{"succeeds after Close", rendrtest.DialLateSuccess, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				grace := time.Second // the failing factories: ErrNoPath at the grace
				if tc.want == nil {
					grace = 5 * time.Second // the blocking ones: the Dial is still in flight at Close
				}
				ov := &testhooks.Overrides{NoPathGrace: grace, DialTimeout: 300 * time.Millisecond}
				e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
				link := e.links[0]
				link.SetDial(tc.beh)
				tc2 := newTrackedConns(false)
				p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{tc2.wrap("a", link.Dial)}})
				if err != nil {
					t.Fatal(err)
				}
				res := e2eDialAsync(context.Background(), p, DialOptions{})
				if tc.want != nil {
					r := <-res
					if r.c != nil || !errors.Is(r.err, ErrNoPath) || !errors.Is(r.err, tc.want) || r.at < time.Second {
						t.Fatalf("Dial = %v, %v after %v; want ErrNoPath wrapping %v at the grace", r.c, r.err, r.at, tc.want)
					}
					if n := link.Stats().Dials; n < 2 {
						t.Fatalf("%d factory calls: the slot did not retry", n)
					}
				} else {
					time.Sleep(time.Second) // several attempts time out on the hanging factory
				}
				start := time.Now()
				e.d.Close()
				if el := time.Since(start); el > 200*time.Millisecond {
					t.Fatalf("Runtime.Close took %v with a misbehaving factory", el)
				}
				if tc.want != nil {
					synctest.Wait()
					if st := e.d.Status(); st.Abandoned != 0 {
						t.Fatalf("abandoned %d", st.Abandoned)
					}
					e.close()
					return
				}
				// Every factory call is stuck in the embedder and already
				// counted when Close returns: a call is counted when its
				// attempt gives up (after the dial grace), so Close's join of
				// the session already sees it (design §0.10 Y8, §0.11 Z2).
				if n, calls := e.d.Status().Abandoned, link.Stats().Dials; n != int(calls) {
					t.Fatalf("abandoned %d when Runtime.Close returned, want every one of the %d stuck factory calls", n, calls)
				}
				if r := <-res; r.c != nil || !errors.Is(r.err, net.ErrClosed) {
					t.Fatalf("in-flight Dial at Close: %v, %v", r.c, r.err)
				}
				calls := link.Stats().Dials
				time.Sleep(2 * e.d.eff.timing.AbandonWait) // past every stuck call's abandonment bound
				synctest.Wait()
				if n := e.d.Status().Abandoned; n != int(calls) || calls < 2 {
					t.Fatalf("abandoned %d, want every one of the %d factory calls stuck in the embedder", n, calls)
				}
				link.Release() // the calls return: an error, or a conn after the caller gave up
				synctest.Wait()
				time.Sleep(time.Second) // a late conn's close drains at most 1 s
				synctest.Wait()
				if n := e.d.Status().Abandoned; n != 0 {
					t.Fatalf("abandoned %d after the factory calls returned", n)
				}
				if tc.beh == rendrtest.DialLateSuccess {
					if cs := tc2.closes(); len(cs) != int(calls) {
						t.Fatalf("%d late conns for %d calls", len(cs), calls)
					}
					tc2.requireClosedOnce(t)
				}
				e.close()
			})
		})
	}
}

// WP6 of milestone M3: race dials through the root (M3 design §A2.1,
// §A10).

// wp6M2Passive returns a factory Dial whose carriers reach a stand-in for
// an M2 passive: it answers the PREFACE with PREFACE_ACK(OK) and an OPEN
// with mode 3 with OPEN_ACK(BAD_REQUEST, CodeBadMode), as rendr 2.0 builds
// before M3 do (M3-D28), then holds the carrier until the dialer closes it.
// modes records the mode byte of every OPEN it read (the stimulus).
func wp6M2Passive(modes *[]uint8, served *atomic.Int32) func(context.Context) (net.Conn, error) {
	inst := wpInst(0xe2)
	return func(context.Context) (net.Conn, error) {
		cli, srv := net.Pipe()
		go func() {
			defer srv.Close()
			var pb [wire.PrefaceLen]byte
			if _, err := io.ReadFull(srv, pb[:]); err != nil {
				return
			}
			pre, err := wire.ParsePreface(pb[:])
			if err != nil {
				return
			}
			var ab [wire.PrefaceLen]byte
			wire.PutPrefaceAck(ab[:], &wire.PrefaceAck{Minor: wire.Minor, Status: wire.PrefaceOK, Opt: wire.EchoOpt(pre.Opt) &^ wire.OptMux, Instance: inst, CarrierID: pre.CarrierID})
			if _, err := srv.Write(ab[:]); err != nil {
				return
			}
			var hb [wire.HeaderLen]byte
			if _, err := io.ReadFull(srv, hb[:]); err != nil {
				return
			}
			h, err := wire.ParseHeader(hb[:])
			if err != nil || h.Type != wire.TypeOpen {
				return
			}
			rest := make([]byte, int(h.Len)+wire.TrailerLen)
			if _, err := io.ReadFull(srv, rest); err != nil {
				return
			}
			o, err := wire.ParseOpen(rest[:h.Len], wire.MaxMetadata)
			if err != nil {
				return
			}
			*modes = append(*modes, o.Mode)
			code := uint32(0)
			st := wire.StatusOK
			if o.Mode > 2 {
				st, code = wire.StatusBadRequest, wire.CodeBadMode
			}
			var pl [wire.OpenAckFixedLen]byte
			n := wire.PutOpenAck(pl[:], &wire.OpenAck{Status: st, Code: code})
			f := wire.AppendFrame(nil, wire.Header{Type: wire.TypeOpenAck, Fseq: wire.PrefaceFseq(ab[:]), Handle: wire.SessionHandle}, pl[:n])
			if _, err := srv.Write(f); err != nil {
				return
			}
			served.Add(1)
			_, _ = io.Copy(io.Discard, srv)
		}()
		return cli, nil
	}
}

// TestDialRaceAgainstM2Passive (M3-D28, §A10.1): a passive without race
// answers an OPEN in mode 3 BAD_REQUEST CodeBadMode; Dial and DialPacket
// then fail at once with ErrProtocol (not ErrNoPath after the grace), and
// the dialer sent mode 3 on the wire (the stimulus). The Runtime keeps no
// session afterwards.
func TestDialRaceAgainstM2Passive(t *testing.T) {
	for _, packet := range []bool{false, true} {
		name := "stream"
		if packet {
			name = "packet"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var modes []uint8
				var served atomic.Int32
				rt := wpTestRuntime(t, Config{}, nil)
				p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{StreamCarrier{Name: "m2", Dial: wp6M2Passive(&modes, &served)}}})
				if err != nil {
					t.Fatalf("NewPeer: %v", err)
				}
				start := time.Now()
				if packet {
					_, err = p.DialPacket(context.Background(), DialOptions{Mode: ModeRace})
				} else {
					_, err = p.Dial(context.Background(), DialOptions{Mode: ModeRace})
				}
				took := time.Since(start)
				if !errors.Is(err, ErrProtocol) {
					t.Fatalf("Dial(ModeRace) against an M2 passive: %v, want ErrProtocol", err)
				}
				if took > time.Second {
					t.Fatalf("ErrProtocol after %v, want it at the refusal", took)
				}
				synctest.Wait()
				if served.Load() == 0 || len(modes) == 0 || modes[0] != wire.ModeRace {
					t.Fatalf("stimulus: the stand-in answered %d OPENs with modes %v, want mode 3", served.Load(), modes)
				}
				p.Close()
				rt.Close()
				wpNoState(t, rt)
			})
		})
	}
}

// wp6Until polls cond at 10 ms of virtual time, failing after within.
func wp6Until(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(within); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(10 * time.Millisecond)
		synctest.Wait()
	}
}

// wp6Members counts the live member carriers of a session.
func wp6Members(st SessionStatus) int {
	n := 0
	for _, c := range st.Carriers {
		if c.State == CarrierMember {
			n++
		}
	}
	return n
}

// TestDialRaceE2E (M3-D28, §A2.1): the root accepts ModeRace on both
// sides. A stream race session over two links opens with mode race on
// both ends, takes both factories as members, and 1 MiB each way arrives
// intact while both members carry copies (the dialer's CopyBytes and both
// carriers' TxBytes grow, the session's TxBytes counts each byte once). A
// packet race session (DialPacket) opens likewise, takes both members,
// places copies on each and delivers its datagrams exactly once.
func TestDialRaceE2E(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const n = 1 << 20
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
			p := e.peer()
			res := e2eDialAsync(context.Background(), p, DialOptions{Mode: ModeRace})
			pend, err := e.ln.Accept(context.Background())
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			if pend.Mode() != ModeRace {
				t.Fatalf("pending session mode %v, want race", pend.Mode())
			}
			pc, err := pend.Confirm()
			if err != nil {
				t.Fatalf("Confirm: %v", err)
			}
			r := <-res
			if r.err != nil {
				t.Fatalf("Dial(ModeRace): %v", r.err)
			}
			dc := r.c
			wp6Until(t, 10*time.Second, "two race members on both ends", func() bool {
				return wp6Members(dc.Status()) == 2 && wp6Members(pc.Status()) == 2
			})
			e2eExchange(t, dc, pc, n, 71)
			// The last ACK may still be on its way when the reader has
			// every byte.
			wp6Until(t, 10*time.Second, "the dialer's last ACK", func() bool { return dc.Status().AckedBytes == n })
			ds, ps := dc.Status(), pc.Status()
			if ds.Mode != ModeRace || ps.Mode != ModeRace {
				t.Fatalf("modes %v and %v, want race on both ends", ds.Mode, ps.Mode)
			}
			if ds.TxBytes != n || ds.AckedBytes != n || ps.DeliveredBytes != n {
				t.Fatalf("unique accounting: dialer TxBytes %d AckedBytes %d, passive DeliveredBytes %d, want %d each", ds.TxBytes, ds.AckedBytes, ps.DeliveredBytes, n)
			}
			if ds.Race.CopyBytes == 0 {
				t.Fatalf("load: the dialer placed no race copies: %+v", ds.Race)
			}
			for _, c := range ds.Carriers {
				if c.State == CarrierMember && c.TxBytes == 0 {
					t.Fatalf("load: race member %d carried nothing: %+v", c.ID, ds.Carriers)
				}
			}
			e2eFinish(t, dc, pc)
			p.Close()
			e.close()
		})
	})
	t.Run("packet", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const count, size = 200, 300
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
			p := e.peer()
			res := make(chan error, 1)
			var dc *PacketConn
			go func() {
				var err error
				dc, err = p.DialPacket(context.Background(), DialOptions{Mode: ModeRace})
				res <- err
			}()
			pend, err := e.ln.AcceptPacket(context.Background())
			if err != nil {
				t.Fatalf("AcceptPacket: %v", err)
			}
			if pend.Mode() != ModeRace {
				t.Fatalf("pending packet session mode %v, want race", pend.Mode())
			}
			pc, err := pend.Confirm()
			if err != nil {
				t.Fatalf("Confirm: %v", err)
			}
			if err := <-res; err != nil {
				t.Fatalf("DialPacket(ModeRace): %v", err)
			}
			if st := dc.Status(); st.Mode != ModeRace || st.Kind != KindPacket {
				t.Fatalf("dialer: mode %v kind %v, want race and packet", st.Mode, st.Kind)
			}
			wp6Until(t, 10*time.Second, "two race members on both ends", func() bool {
				return wp6Members(dc.Status()) == 2 && wp6Members(pc.Status()) == 2
			})
			peSend(t, dc, 73, 0, count, size)
			r := peRecv(t, pc, 73, count, 10*time.Second).Result()
			if r.Unique != count || r.Duplicates != 0 || r.Corrupt != 0 || r.BadSize != 0 {
				t.Fatalf("integrity: %+v, want %d unique datagrams, none twice or damaged", r, count)
			}
			ds := dc.Status()
			if ds.Packet == nil || ds.Packet.Sent != count {
				t.Fatalf("unique accounting: dialer packet counters %+v, want %d sent", ds.Packet, count)
			}
			if ds.Race.Copies == 0 {
				t.Fatalf("load: the dialer placed no race copies: %+v", ds.Race)
			}
			if wp6Members(ds) != 2 {
				t.Fatalf("load: %d race members after the exchange, want 2: %+v", wp6Members(ds), ds.Carriers)
			}
			for _, c := range ds.Carriers {
				if c.State == CarrierMember && c.TxBytes == 0 {
					t.Fatalf("load: race member %d carried nothing: %+v", c.ID, ds.Carriers)
				}
			}
			peEnd(t, dc, pc)
			p.Close()
			e.close()
		})
	})
}

// TestDialPacketRaceOffer (M3-D32, M2-D49): a packet race session offers
// its MaxPayload as a bond does, because every member carries data: on a
// Peer with a stream factory the stream members carry what the datagram
// members cannot, so the offer is Packet.MaxPayload; without one it is the
// datagram budget (MTU − 25). A selector session on the mixed Peer offers
// the datagram budget.
func TestDialPacketRaceOffer(t *testing.T) {
	rt := wpTestRuntime(t, Config{}, nil)
	defer rt.Close()
	mixed, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{wp6Dgram("d", Props{}), wp6Stream("s", Props{})}})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	defer mixed.Close()
	dgOnly, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{wp6Dgram("d", Props{})}})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	defer dgOnly.Close()
	full, budget := rt.eff.cfg.Packet.MaxPayload, 1400-wire.DgramOverhead
	if full <= budget {
		t.Fatalf("premise: Packet.MaxPayload %d not above the datagram budget %d", full, budget)
	}
	for _, tc := range []struct {
		name string
		p    *Peer
		mode Mode
		want int
	}{
		{"race, mixed", mixed, ModeRace, full},
		{"bond, mixed", mixed, ModeBond, full},
		{"selector, mixed", mixed, ModeSelector, budget},
		{"race, datagram only", dgOnly, ModeRace, budget},
	} {
		if got := tc.p.spec(SessionID{3}, DialOptions{Mode: tc.mode}, true).Params.Packet.MaxPayload; got != tc.want {
			t.Fatalf("%s: MaxPayload offer %d, want %d", tc.name, got, tc.want)
		}
	}
}
