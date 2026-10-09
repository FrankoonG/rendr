package quic

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestQUICPropsReachFactory (§A11.4, R-10, M3-D36; WP15): the quic
// module's factories carry rendr.Props like every other factory — the
// constructors return the zero value and the role sets .Props on the
// returned struct (no option of the quic module) — and what it sets
// reaches the scheduler, for both kinds of factory and both settings of
// CheapSubflow:
//
//   - FateGroup: two QUIC stream factories of one fate group give a bond
//     session one member (one per group, M3-D37), the dialer's carrier row
//     names the group; in two groups the session holds two members.
//   - CheapSubflow on a DATAGRAM factory: false (the default) puts two
//     packet sessions on one QUIC connection's carrier (one session dial,
//     Shared 2, Status.Mux one carrier with two views), true gives each its
//     own (two dials, Shared 1, no MUX trunk).
//   - HoLCoupled without a FateGroup is refused by NewPeer, naming the
//     QUIC factory.
func TestQUICPropsReachFactory(t *testing.T) {
	t.Run("FateGroup", func(t *testing.T) {
		for _, groups := range [][2]string{{"g", "g"}, {"g", "h"}} {
			t.Run(groups[0]+groups[1], func(t *testing.T) {
				t.Cleanup(rendrtest.AssertNoLeak(t))
				e := newMxEnv(t)
				peer := e.peer(e.stream("qa", rendr.Props{FateGroup: groups[0]}), e.stream("qb", rendr.Props{FateGroup: groups[1]}))
				dc, pc := e.openBond(peer)
				want := 2
				if groups[0] == groups[1] {
					want = 1
				}
				// Two groups: the second member attaches after the open (a
				// positive gate). One group: no second member ever, which the
				// checks after the exchange see over the session's lifetime.
				mxWait(t, 5*time.Second, "the bond's members", func() bool { return mxMembers(dc.Status()) >= want })
				st := dc.Status()
				for _, c := range st.Carriers {
					if c.State != rendr.CarrierDead && c.FateGroup != map[string]string{"qa": groups[0], "qb": groups[1]}[c.Name] {
						t.Errorf("carrier %s reports FateGroup %q, want its factory's", c.Name, c.FateGroup)
					}
				}
				exSt := dc.Status() // before the exchange closes the session
				ds := make(chan rendr.SessionStatus, 1)
				go func() { <-pc.Done(); ds <- dc.Status() }()
				mxExchange(t, []*rendr.Conn{dc}, []*rendr.Conn{pc}, 1<<20)
				st = <-ds
				if got := mxMembers(exSt); got != want {
					t.Fatalf("fate groups %v: the bond holds %d members %+v, want %d", groups, got, exSt.Carriers, want)
				}
				if total := e.dialsOf("qa") + e.dialsOf("qb"); total != want || len(st.Carriers) != want {
					t.Errorf("fate groups %v: %d session dials, carriers %+v over the session's life; want %d", groups, total, st.Carriers, want)
				}
				e.close()
			})
		}
	})
	t.Run("CheapSubflowDatagram", func(t *testing.T) {
		for _, cheap := range []bool{false, true} {
			name := "default"
			if cheap {
				name = "cheap"
			}
			t.Run(name, func(t *testing.T) {
				t.Cleanup(rendrtest.AssertNoLeak(t))
				e := newMxEnv(t)
				peer := e.peer(e.datagram("qd", rendr.Props{CheapSubflow: cheap}))
				dcs, pcs := e.openPackets(peer, 2)
				wantConns, wantShared, wantMux := 1, 2, 1
				if cheap {
					wantConns, wantShared, wantMux = 2, 1, 0
				}
				mxWait(t, 5*time.Second, "the passive's carriers", func() bool { return int(e.ql.Stats().Datagrams) == wantConns })
				if got := e.dialsOf("qd"); got != wantConns {
					t.Fatalf("%d session dials for 2 packet sessions, want %d", got, wantConns)
				}
				for i := range dcs {
					cs := dcs[i].Status().Carriers
					if len(cs) != 1 || cs[0].Kind != rendr.KindDatagram || cs[0].Shared != wantShared {
						t.Fatalf("packet session %d carriers %+v, want one DATAGRAM carrier Shared by %d", i, cs, wantShared)
					}
				}
				for _, rt := range []*rendr.Runtime{e.d, e.p} {
					if m := rt.Status().Mux; m.Carriers != wantMux || m.Views != 2*wantMux {
						t.Fatalf("Status.Mux %+v, want %d carriers with 2 views each", m, wantMux)
					}
				}
				// Each session still carries its own datagrams: one each way,
				// echoed by content.
				for i := range dcs {
					msg := []byte("datagram of session " + string(rune('0'+i)))
					if _, err := dcs[i].WriteTo(msg, nil); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 64)
					pcs[i].SetReadDeadline(time.Now().Add(5 * time.Second))
					k, _, err := pcs[i].ReadFrom(buf)
					if err != nil || string(buf[:k]) != string(msg) {
						t.Fatalf("packet session %d: read %q, %v; want %q", i, buf[:k], err, msg)
					}
				}
				for i := range dcs {
					dcs[i].Close()
					for _, c := range []*rendr.PacketConn{dcs[i], pcs[i]} {
						select {
						case <-c.Done():
						case <-time.After(30 * time.Second):
							t.Fatalf("packet session %d not done 30 s after Close", i)
						}
					}
				}
				for i := range pcs {
					pcs[i].Close()
				}
				mxWait(t, 10*time.Second, "the MUX trunks closed at their last view", func() bool {
					return e.d.Status().Mux.Carriers == 0 && e.p.Status().Mux.Carriers == 0
				})
				e.close()
			})
		}
	})
	t.Run("HoLCoupledNeedsFateGroup", func(t *testing.T) {
		_, cli := testTLS(t)
		d, err := rendr.NewRuntime(rendr.Config{})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		for _, c := range []rendr.Carrier{mxProps(t, cli, rendr.KindStream), mxProps(t, cli, rendr.KindDatagram)} {
			if _, err := d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{c}}); err == nil || !strings.Contains(err.Error(), `"qh"`) ||
				!strings.Contains(err.Error(), "HoLCoupled") {
				t.Errorf("NewPeer with a HoLCoupled QUIC factory without FateGroup: %v, want an error naming the factory", err)
			}
		}
	})
}

// mxProps returns a QUIC factory "qh" of kind with Props{HoLCoupled: true}
// and no FateGroup.
func mxProps(t *testing.T, tc *tls.Config, kind rendr.Kind) rendr.Carrier {
	t.Helper()
	cli := Options{TLS: tc}
	if kind == rendr.KindStream {
		c, err := StreamCarrier("qh", "127.0.0.1:1", cli)
		if err != nil {
			t.Fatal(err)
		}
		c.Props.HoLCoupled = true
		return c
	}
	c, err := DatagramCarrier("qh", "127.0.0.1:1", cli)
	if err != nil {
		t.Fatal(err)
	}
	c.Props.HoLCoupled = true
	return c
}

// openBond opens one bond stream session on peer.
func (e *mxEnv) openBond(peer *rendr.Peer) (dc, pc *rendr.Conn) {
	e.t.Helper()
	type dialed struct {
		c   *rendr.Conn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := peer.Dial(e.t.Context(), rendr.DialOptions{Mode: rendr.ModeBond})
		ch <- dialed{c, err}
	}()
	pend, err := e.rl.Accept(e.t.Context())
	if err == nil {
		pc, err = pend.Confirm()
	}
	if err != nil {
		e.t.Fatalf("Accept: %v", err)
	}
	r := <-ch
	if r.err != nil {
		e.t.Fatalf("Dial: %v", r.err)
	}
	return r.c, pc
}

// mxMembers counts the live carriers of a session.
func mxMembers(st rendr.SessionStatus) int {
	n := 0
	for _, c := range st.Carriers {
		if c.State != rendr.CarrierDead {
			n++
		}
	}
	return n
}
