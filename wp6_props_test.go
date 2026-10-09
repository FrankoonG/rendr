package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// WP6 of milestone M3: the root surface of race and carrier properties
// (M3 design §A2.1, §A7.1, §A10).

// wp6Dial is a factory Dial that is never called (NewPeer only validates).
func wp6Dial(context.Context) (net.Conn, error) { return nil, errors.New("not dialled") }

// wp6DialPC is a datagram factory Dial that is never called.
func wp6DialPC(context.Context) (net.PacketConn, net.Addr, error) {
	return nil, nil, errors.New("not dialled")
}

func wp6Stream(name string, pr Props) StreamCarrier {
	return StreamCarrier{Name: name, Dial: wp6Dial, Props: pr}
}

func wp6Dgram(name string, pr Props) DatagramCarrier {
	return DatagramCarrier{Name: name, Dial: wp6DialPC, MTU: 1400, Props: pr}
}

// TestPropsValidation (M3-D36, §A7.1): NewPeer accepts a FateGroup of up
// to 64 bytes, HoLCoupled only with a FateGroup, and the factories of one
// FateGroup only when they agree on HoLCoupled; every refusal names the
// offending factory. Props are read from both factory kinds, as values and
// as pointers; a group may mix stream and datagram factories, and equal
// HoLCoupled settings in different groups never conflict.
func TestPropsValidation(t *testing.T) {
	g64, g65 := strings.Repeat("g", 64), strings.Repeat("g", 65)
	cases := []struct {
		name string
		cs   []Carrier
		bad  string // "" accepted; else a substring of the error (the factory's name)
	}{
		{"zero Props", []Carrier{wp6Stream("a", Props{}), wp6Dgram("b", Props{})}, ""},
		{"64-byte group", []Carrier{wp6Stream("a", Props{FateGroup: g64})}, ""},
		{"65-byte group", []Carrier{wp6Stream("a", Props{}), wp6Stream("long", Props{FateGroup: g65})}, `"long"`},
		{"65-byte group on a datagram pointer", []Carrier{&DatagramCarrier{Name: "dp", Dial: wp6DialPC, MTU: 1400, Props: Props{FateGroup: g65}}}, `"dp"`},
		{"coupled without a group", []Carrier{wp6Stream("a", Props{}), wp6Stream("lone", Props{HoLCoupled: true})}, `"lone"`},
		{"coupled without a group, stream pointer", []Carrier{&StreamCarrier{Name: "sp", Dial: wp6Dial, Props: Props{HoLCoupled: true}}}, `"sp"`},
		{"coupled group", []Carrier{
			wp6Stream("a", Props{FateGroup: "tls", HoLCoupled: true}),
			wp6Dgram("b", Props{FateGroup: "tls", HoLCoupled: true}),
			wp6Stream("c", Props{FateGroup: "relay"}),
		}, ""},
		{"group disagrees", []Carrier{
			wp6Stream("a", Props{FateGroup: "tls", HoLCoupled: true}),
			wp6Stream("b", Props{FateGroup: "relay"}),
			wp6Stream("c", Props{FateGroup: "tls"}),
		}, `"c"`},
		{"group disagrees the other way", []Carrier{
			wp6Dgram("a", Props{FateGroup: "tls"}),
			wp6Dgram("b", Props{FateGroup: "tls", HoLCoupled: true}),
		}, `"b"`},
		{"cheap subflows mixed", []Carrier{
			wp6Stream("a", Props{FateGroup: "x", CheapSubflow: true}),
			wp6Stream("b", Props{FateGroup: "x"}),
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			p, err := rt.NewPeer(PeerConfig{Carriers: tc.cs})
			switch {
			case tc.bad == "" && err != nil:
				t.Fatalf("NewPeer: %v, want it accepted", err)
			case tc.bad != "" && err == nil:
				p.Close()
				t.Fatalf("NewPeer accepted invalid Props, want an error naming %s", tc.bad)
			case tc.bad != "" && !strings.Contains(err.Error(), tc.bad):
				t.Fatalf("NewPeer: %v, want it to name %s", err, tc.bad)
			}
			if p != nil {
				p.Close()
			}
			rt.Close()
		})
	}
}

// TestPropsGroupsInterned (§A7.1; M3-D37, M3-D39): equal non-empty
// FateGroups share one index, numbered from 1 in configuration order; every
// factory with an empty FateGroup gets index 0 (a group of its own); a
// coupled group sets the bit of each of its factories. Every dialer
// session's spec carries the Peer's groups, and the dialer reports each
// factory's FateGroup name. CheapSubflow factories stay off rendr mux
// (carrier.Factory.Mux is the complement).
func TestPropsGroupsInterned(t *testing.T) {
	cs := []Carrier{
		wp6Stream("a", Props{FateGroup: "edge"}),
		wp6Stream("b", Props{}),
		&StreamCarrier{Name: "c", Dial: wp6Dial, Props: Props{FateGroup: "edge"}},
		wp6Dgram("d", Props{FateGroup: "tls", HoLCoupled: true, CheapSubflow: true}),
		&DatagramCarrier{Name: "e", Dial: wp6DialPC, MTU: 1400, Props: Props{FateGroup: "tls", HoLCoupled: true}},
		wp6Stream("f", Props{CheapSubflow: true}),
		wp6Stream("g", Props{FateGroup: "relay"}),
	}
	rt := wpTestRuntime(t, Config{}, nil)
	defer rt.Close()
	p, err := rt.NewPeer(PeerConfig{Carriers: cs})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	defer p.Close()
	want := [maxFactories]uint8{1, 0, 1, 2, 2, 0, 3}
	const wantCoupled = 1<<3 | 1<<4
	for _, packet := range []bool{false, true} {
		spec := p.spec(SessionID{1}, DialOptions{Mode: ModeRace}, packet)
		if spec.Groups != want || spec.Coupled != wantCoupled {
			t.Fatalf("packet %v: DialSpec.Groups %v Coupled %#x, want %v and %#x", packet, spec.Groups, spec.Coupled, want, wantCoupled)
		}
		if spec.Params.Mode != session.ModeRace {
			t.Fatalf("packet %v: DialSpec.Params.Mode %v, want race", packet, spec.Params.Mode)
		}
	}
	for i, name := range []string{"edge", "", "edge", "tls", "tls", "", "relay"} {
		if got := p.props.fateGroup(i); got != name {
			t.Fatalf("fateGroup(%d) = %q, want %q", i, got, name)
		}
	}
	if got := p.props.fateGroup(len(cs)); got != "" {
		t.Fatalf("fateGroup beyond the factories = %q", got)
	}
	fs := make([]carrier.Factory, len(cs))
	p.props.muxFactories(fs)
	for i, f := range fs {
		if cheap := i == 3 || i == 5; f.Mux == cheap {
			t.Fatalf("factory %d: Mux %v, CheapSubflow %v", i, f.Mux, cheap)
		}
	}
	// A zero-Props Peer keeps every factory independent (M2's behaviour).
	q, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{wp6Stream("x", Props{}), wp6Stream("y", Props{})}})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	defer q.Close()
	if spec := q.spec(SessionID{2}, DialOptions{}, false); spec.Groups != ([maxFactories]uint8{}) || spec.Coupled != 0 {
		t.Fatalf("zero Props: Groups %v Coupled %#x, want zero", spec.Groups, spec.Coupled)
	}
}

// TestModeRaceString (§A2.1): ModeRace is 3, the wire's and the session's
// value, and prints "race".
func TestModeRaceString(t *testing.T) {
	if ModeRace != 3 || uint8(ModeRace) != wire.ModeRace || int(ModeRace) != int(session.ModeRace) {
		t.Fatalf("ModeRace = %d, wire %d, session %d", ModeRace, wire.ModeRace, session.ModeRace)
	}
	if s := ModeRace.String(); s != "race" {
		t.Fatalf("ModeRace.String() = %q, want race", s)
	}
}

// TestStatusConvertM3 (§A10.2, M3-D35, M3-D49): the conversion copies the
// receiver's DupBytes, the race sender's copies and each carrier's Handle
// and Shared; a dialer's CarrierStatus.FateGroup comes from its Peer's
// Props by factory name, the passive's stays empty. End to end, for a
// stream (Dial) and a packet (DialPacket) session, a live unshared carrier
// reports Handle 1 and Shared 1 on both sides and its factory's FateGroup
// on the dialer only.
func TestStatusConvertM3(t *testing.T) {
	in := session.Status{
		Mode: session.ModeRace, DupBytes: 4096, Race: session.RaceCounters{CopyBytes: 8192, Copies: 3},
		Carriers: []session.CarrierStatus{
			{ID: 1, Name: "edge-a", State: session.LaneMember, Stats: carrier.Stats{Handle: 1, Shared: 1}},
			{ID: 2, Name: "solo", State: session.LaneMember, Stats: carrier.Stats{Handle: 9, Shared: 4}},
			{ID: 3, Name: "edge-b", State: session.LaneDead},
		},
	}
	base := sessionStatusFrom(in)
	if base.Mode != ModeRace || base.DupBytes != 4096 || base.Race != (RaceCounters{CopyBytes: 8192, Copies: 3}) {
		t.Fatalf("session fields: mode %v DupBytes %d Race %+v", base.Mode, base.DupBytes, base.Race)
	}
	type row struct {
		Handle    uint32
		Shared    int
		FateGroup string
	}
	rows := func(st SessionStatus) []row {
		var out []row
		for _, c := range st.Carriers {
			out = append(out, row{c.Handle, c.Shared, c.FateGroup})
		}
		return out
	}
	if got, want := rows(base), []row{{1, 1, ""}, {9, 4, ""}, {0, 0, ""}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("carrier rows %+v, want %+v", got, want)
	}
	var passive *peerProps
	if got := passive.status(in); !reflect.DeepEqual(got, base) {
		t.Fatalf("a nil peerProps changed the conversion:\n got %+v\nwant %+v", got, base)
	}
	pp, err := newPeerProps([]Carrier{
		wp6Stream("edge-a", Props{FateGroup: "edge"}), wp6Stream("solo", Props{}), wp6Stream("edge-b", Props{FateGroup: "edge"}),
	}, []string{"edge-a", "solo", "edge-b"})
	if err != nil {
		t.Fatalf("newPeerProps: %v", err)
	}
	if got, want := rows(pp.status(in)), []row{{1, 1, "edge"}, {9, 4, ""}, {0, 0, "edge"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dialer carrier rows %+v, want %+v", got, want)
	}

	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "edge")
		c := e2eCarrier(e.links[0])
		c.Props = Props{FateGroup: "first-hop"}
		p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{c}})
		if err != nil {
			t.Fatalf("NewPeer: %v", err)
		}
		dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
		e2eExchange(t, dc, pc, 64<<10, 61)
		for _, x := range []struct {
			c     *Conn
			group string
		}{{dc, "first-hop"}, {pc, ""}} {
			cs := x.c.Status().Carriers
			if len(cs) != 1 || cs[0].State != CarrierActive {
				t.Fatalf("stimulus: carriers %+v, want one active", cs)
			}
			if cs[0].Handle != 1 || cs[0].Shared != 1 || cs[0].FateGroup != x.group {
				t.Fatalf("live carrier: Handle %d Shared %d FateGroup %q, want 1, 1 and %q", cs[0].Handle, cs[0].Shared, cs[0].FateGroup, x.group)
			}
		}
		e2eFinish(t, dc, pc)
		if cs := dc.Status().Carriers; len(cs) != 1 || cs[0].FateGroup != "first-hop" {
			t.Fatalf("ended session's carrier rows %+v, want its fate group kept", cs)
		}
		p.Close()

		// A packet session (DialPacket) on a Peer of its own over the same
		// factory: its dialer *PacketConn reports the factory's fate group
		// as well, its passive none.
		pp, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{c}})
		if err != nil {
			t.Fatalf("NewPeer: %v", err)
		}
		dpc, ppc := peOpen(t, pp, e.ln, DialOptions{})
		peSend(t, dpc, 67, 0, 16, 200)
		if r := peRecv(t, ppc, 67, 16, 10*time.Second).Result(); r.Unique != 16 || r.Duplicates != 0 || r.Corrupt != 0 {
			t.Fatalf("packet integrity: %+v, want 16 unique datagrams", r)
		}
		for _, x := range []struct {
			c     *PacketConn
			group string
		}{{dpc, "first-hop"}, {ppc, ""}} {
			cs := peLive(x.c)
			if len(cs) != 1 || cs[0].State != CarrierActive {
				t.Fatalf("packet stimulus: carriers %+v, want one active", x.c.Status().Carriers)
			}
			if cs[0].Handle != 1 || cs[0].Shared != 1 || cs[0].FateGroup != x.group {
				t.Fatalf("packet live carrier: Handle %d Shared %d FateGroup %q, want 1, 1 and %q", cs[0].Handle, cs[0].Shared, cs[0].FateGroup, x.group)
			}
		}
		peEnd(t, dpc, ppc)
		pp.Close()
		e.close()
	})
}

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
