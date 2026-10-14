package packet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// passiveEnds records the passive end of every carrier of a world's links,
// so a row can close the passive's conn of one carrier: the mirror of the
// dialer's local close (world.localClose).
type passiveEnds struct {
	mu     sync.Mutex
	byAddr map[string]net.PacketConn  // the passive's conn by link name and its own address (a link numbers its carriers' addresses)
	addrOf map[rendr.CarrierID]string // the same key of each dialer session carrier
}

// newTapWorld is newWorld whose links (one per name) record the passive end
// of every carrier they create before the Listener's HandlePacket takes it.
func newTapWorld(t testing.TB, o worldOpts, names ...string) (*world, *passiveEnds) {
	t.Helper()
	w := newWorld(t, o)
	pe := &passiveEnds{byAddr: map[string]net.PacketConn{}, addrOf: map[rendr.CarrierID]string{}}
	for _, n := range names {
		l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: n, Queue: 16384, Accept: func(pc net.PacketConn, peer net.Addr) error {
			pe.mu.Lock()
			pe.byAddr[n+" "+pc.LocalAddr().String()] = pc
			pe.mu.Unlock()
			return w.ln.HandlePacket(pc, peer)
		}})
		for _, d := range bothDirs {
			l.SetDelay(d, o.oneWay, 0)
		}
		w.links = append(w.links, l)
	}
	return w, pe
}

// peer returns a dialer Peer over the links named whose factories record,
// for every session carrier, the dialer's conn (world.localClose) and the
// passive's address.
func (pe *passiveEnds) peer(w *world, names ...string) *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	for _, n := range names {
		l := w.link(n)
		cs = append(cs, rendr.DatagramCarrier{Name: n, MTU: w.mtu, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			pc, a, err := l.Dial(ctx)
			if di, ok := rendr.CarrierDialInfo(ctx); err == nil && ok && !di.Probe {
				w.mu.Lock()
				w.conns[di.Carrier] = pc
				w.mu.Unlock()
				pe.mu.Lock()
				pe.addrOf[di.Carrier] = n + " " + a.String()
				pe.mu.Unlock()
			}
			return pc, a, err
		}})
	}
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// closePassive closes the passive's conn of carrier id under rendr: the
// passive's local close of that carrier. It fails the test unless the
// carrier's passive end was recorded and its Close returned nil.
func (pe *passiveEnds) closePassive(t testing.TB, id rendr.CarrierID) {
	t.Helper()
	pe.mu.Lock()
	pc := pe.byAddr[pe.addrOf[id]]
	pe.mu.Unlock()
	if pc == nil {
		t.Fatalf("stimulus: carrier %d has no recorded passive end", id)
	}
	if err := pc.Close(); err != nil {
		t.Fatalf("stimulus: closing the passive end of carrier %d: %v", id, err)
	}
}

// TestPacketPassiveTrunkCloseDialerMoves_L45_L39 (PA-86, the mirror of
// TestPacketTrunkCloseEverySessionLearns_L45_L39): the passive closes its
// conn of a shared datagram trunk, as a passive's local death of the trunk
// (a socket error, its own deadline). Its end dies with transport_error;
// the dialer's end would live until the dialer's own death deadline (its
// ping timeout, seconds) and keep carrying forward traffic into the dead
// trunk. PA-86 makes the passive report it: its DOWN on the other trunk of
// the pair kills the dialer's end (cause peer_down) one one-way delay after
// the close, so every session's dialer moves its requests to its other
// member at once.
//
// The row: 32 bond packet sessions of one Peer over two shared trunks
// (G6's natu path: 5 ms one way, a request every millisecond per session
// and its echo), the passive's conn of trunk u1 closed between two
// requests. For every session: the dialer drops the closed trunk from its
// live carriers within one one-way delay (plus the observation's two
// polls), every request it writes after that instant arrives, and its end
// of the trunk ended with peer_down. Premise: every session's u1 member is
// the one shared trunk, on both ends; stimulus: the passive's CarrierDown
// of it is transport_error at the close.
func TestPacketPassiveTrunkCloseDialerMoves_L45_L39(t *testing.T) {
	synctest.Test(t, func(t *testing.T) { passiveTrunkClose(t, 32) })
}

func passiveTrunkClose(t *testing.T, n int) {
	w, pe := newTapWorld(t, worldOpts{oneWay: clOneWay}, "u1", "u2")
	p := pe.peer(w, "u1", "u2")
	ss := make([]*trunkSess, n)
	for i := range ss {
		dc, pc := w.open(p, rendr.DialOptions{Mode: rendr.ModeBond})
		ss[i] = &trunkSess{dc: dc, pc: pc, got: map[uint64]bool{}, rdone: make(chan error, 1)}
	}
	for i, s := range ss {
		waitFor(t, 5*time.Second, fmt.Sprintf("two members on both ends of session %d", i), func() bool {
			return len(liveOf(s.dc.Status())) == 2 && len(liveOf(s.pc.Status())) == 2
		})
	}
	vic, ok := liveNamed(ss[0].dc.Status(), "u1")
	if !ok {
		t.Fatalf("session 0 has no live carrier on u1: %+v", ss[0].dc.Status().Carriers)
	}
	for i, s := range ss {
		if c, ok := liveNamed(s.dc.Status(), "u1"); !ok || c.ID != vic.ID {
			t.Fatalf("premise: session %d's u1 member is %+v (found %v), not the shared trunk %d", i, c, ok, vic.ID)
		}
		if c, ok := carrierOf(s.pc.Status(), vic.ID); !ok || (c.State != rendr.CarrierActive && c.State != rendr.CarrierMember) {
			t.Fatalf("premise: the passive of session %d does not carry it on the shared trunk %d: %+v", i, vic.ID, c)
		}
	}
	for i, s := range ss {
		seed := uint64(0x9000 + i)
		s.echo = startEcho(s.pc, seed)
		s.ver = rendrtest.NewPacketVerifier(seed)
		go func() {
			buf := make([]byte, s.dc.MaxPayload()+1)
			for {
				m, _, err := s.dc.ReadFrom(buf)
				if err != nil {
					s.rdone <- err
					return
				}
				if verr := s.ver.Add(buf[:m], time.Now()); verr != nil {
					s.rdone <- verr
					return
				}
				s.mu.Lock()
				s.got[seqOf(buf)] = true
				s.mu.Unlock()
			}
		}()
	}

	// The observer: whether each session's dialer still lists the trunk as
	// a live carrier, every clPoll.
	type poll struct {
		at    time.Time
		dLive []bool
	}
	var obs []poll
	stop, odone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(odone)
		for {
			o := poll{at: time.Now(), dLive: make([]bool, n)}
			for i, s := range ss {
				c, ok := carrierOf(s.dc.Status(), vic.ID)
				o.dLive[i] = ok && (c.State == rendr.CarrierActive || c.State == rendr.CarrierMember)
			}
			obs = append(obs, o)
			select {
			case <-stop:
				return
			case <-time.After(clPoll):
			}
		}
	}()

	start := time.Now()
	writeAt := func(seq uint64) time.Time { return start.Add(time.Duration(seq) * clGap) }
	var wg sync.WaitGroup
	for i, s := range ss {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, clSize)
			for seq := range uint64(clRequests) {
				sleepUntil(writeAt(seq))
				if _, err := s.dc.WriteTo(rendrtest.PacketPayload(buf, uint64(0x9000+i), seq, clSize, time.Now()), nil); err != nil {
					t.Errorf("session %d: WriteTo of request %d: %v", i, seq, err)
					return
				}
			}
		}()
	}
	sleepUntil(start.Add(10*clGap + clGap/2))
	tClose := time.Now()
	pe.closePassive(t, vic.ID)
	wg.Wait()
	sleepUntil(start.Add(clRequests*clGap + 300*time.Millisecond))
	close(stop)
	<-odone

	// Stimulus: the passive's end died with transport_error at the close.
	if down, ok := w.pev.downOf(vic.ID); !ok || down.Cause != rendr.CauseTransportError || down.Time.Sub(tClose) > clPoll {
		t.Fatalf("stimulus: the passive's CarrierDown of trunk %d is %+v (found %v), want transport_error at the close", vic.ID, down, ok)
	}
	bound := clOneWay + 2*clPoll
	learn := make([]time.Duration, n)
	for i := range ss {
		learn[i] = -1
		for _, o := range obs {
			if o.at.After(tClose) && !o.dLive[i] {
				learn[i] = o.at.Sub(tClose)
				break
			}
		}
	}
	sorted := slices.Clone(learn)
	slices.Sort(sorted)
	t.Logf("%d sessions on trunk %d (closed at the passive) and its mate: the dialer dropped it after the close: min %v, median %v, max %v (bound %v)",
		n, vic.ID, sorted[0], sorted[n/2], sorted[n-1], bound)
	var late []string
	for i, d := range learn {
		switch {
		case d < 0:
			late = append(late, fmt.Sprintf("session %d's dialer kept the closed trunk", i))
		case d > bound:
			late = append(late, fmt.Sprintf("session %d's dialer after %v", i, d))
		}
	}
	// Every request written after its dialer moved off arrives.
	for i, s := range ss {
		if learn[i] < 0 {
			continue
		}
		moved := tClose.Add(learn[i] + clPoll)
		for seq := range uint64(clRequests) {
			if _, echoed := s.echo.echoedAt(seq); writeAt(seq).After(moved) && !echoed {
				late = append(late, fmt.Sprintf("session %d: request %d written %v after the close (moved off %v) never arrived", i, seq, writeAt(seq).Sub(tClose), learn[i]))
				break
			}
		}
	}
	if len(late) > 0 {
		t.Fatalf("the dialers did not move off the trunk the passive closed within one one-way delay (%v; L45, PA-86): %d: %v",
			bound, len(late), late[:min(len(late), 8)])
	}
	// The mechanism: every dialer session's end of the trunk ended by the
	// passive's DOWN (rendr.CausePeerDown, compared by its name so that the
	// row builds on the merge-base too).
	for _, ev := range w.dev.of(rendr.EventCarrierDown) {
		if ev.Carrier == vic.ID && ev.Cause.String() != "peer_down" {
			t.Fatalf("the dialer's CarrierDown of trunk %d: %+v, want peer_down (the passive's DOWN)", vic.ID, ev)
		}
	}
	for _, s := range ss {
		s.dc.Close()
	}
	for i, s := range ss {
		select {
		case <-s.echo.done:
		case <-time.After(30 * time.Second):
			t.Fatalf("session %d's echo did not end", i)
		}
		if err := <-s.rdone; !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
			t.Fatalf("session %d's reader: %v", i, err)
		}
	}
	w.close()
}
