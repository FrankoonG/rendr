package realsock

import (
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestRealUDPSelectorSwitchSame_L55 (M5 design A8 row 2 at session level,
// R3-22; L55: batching on and off are the same to the application; plan
// invariant 2): a selector packet session over carrier/udp on loopback
// with two factories, a and b, each reaching the passive's udp.Listen
// socket through its own delaying UDP relay, both sides at MaxBatch 32 in
// one arm and 1 in the other. Bursts go both ways (32 datagrams up and 8
// down every 10 ms; half under -race), so the batched paths always find a
// backlog. The session starts on a (b's relay delays 30 ms each way);
// 1.5 s in, a's relay delays 40 ms each way and b's none, and the
// selector moves the session to b by a quality switch. Stimulus: the
// dialer started on a, made at least one quality migration and no death
// migration, ended on b, and b carried data. In both arms, both
// directions: every datagram is intact and read at most once, the
// session's counters add up (§A7.2), at least 90 % arrived, and no
// datagram was lost outside the switch's window (sent between the delay
// step less the pre window and the switch plus the post window,
// msLossWindows) — the application sees the same session whatever
// MaxBatch is. Counters: at MaxBatch 1 both Runtimes moved one datagram
// per call; at 32 on a target that batches, both Runtimes' sends were
// batched (SentDatagrams > SendCalls). Runtime.Close leaves nothing.
func TestRealUDPSelectorSwitchSame_L55(t *testing.T) {
	got := map[int]ssResult{}
	for _, mb := range []int{32, 1} {
		t.Run("MaxBatch"+strconv.Itoa(mb), func(t *testing.T) {
			t.Cleanup(rendrtest.AssertNoLeak(t))
			got[mb] = ssRun(t, mb)
		})
	}
	if t.Failed() {
		return
	}
	if a, b := got[32], got[1]; a.lostAway != b.lostAway || a.lostAway != [2]uint64{} {
		t.Errorf("datagrams lost outside the switch window: MaxBatch 32 %v, MaxBatch 1 %v; want none in both", a.lostAway, b.lostAway)
	}
}

// ssResult is one arm's outcome per direction (up, down): the datagrams
// lost outside the switch window and the distinct datagrams read.
type ssResult struct {
	lostAway [2]uint64
	unique   [2]uint64
}

func ssRun(t *testing.T, maxBatch int) ssResult {
	o := udp.Options{MaxBatch: maxBatch}
	sock, err := udp.Listen("udp4", "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	ra := newSsRelay(t, sock.LocalAddr().(*net.UDPAddr).AddrPort(), 0)
	rb := newSsRelay(t, sock.LocalAddr().(*net.UDPAddr).AddrPort(), 30*time.Millisecond)
	cfg := rendr.Config{
		Selector: rendr.SelectorPolicy{Band: 0.25, Floor: 5 * time.Millisecond, Dwell: 500 * time.Millisecond, Cooldown: time.Second},
		Probe:    rendr.ProbePolicy{Interval: 500 * time.Millisecond, Fresh: 2 * time.Second},
	}
	m := newMsPair(t, cfg, nil, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}},
		[]rendr.Carrier{udp.Carrier("a", "udp4", ra.addr(), o), udp.Carrier("b", "udp4", rb.addr(), o)})
	dc, pc := m.openPacket(rendr.ModeSelector)
	msUntil(t, 10*time.Second, "the session active on a", func() bool { c, ok := ssActive(dc.Status()); return ok && c.Name == "a" })

	up, down := 32, 8
	if msRace {
		up, down = 16, 4
	}
	const every = 10 * time.Millisecond
	sides := [2]*ssSide{newSsSide(0x5e1ec7, 4000), newSsSide(0xd0e1ec7, 1000)}
	var gens, readers sync.WaitGroup
	stop := make(chan struct{})
	start := time.Now()
	gens.Add(2)
	readers.Add(2)
	go sides[0].generate(dc, up, every, stop, &gens)
	go sides[1].generate(pc, down, every, stop, &gens)
	go sides[0].s.receive(pc, &readers)
	go sides[1].s.receive(dc, &readers)

	time.Sleep(time.Until(start.Add(1500 * time.Millisecond)))
	step := time.Now()
	ra.setDelay(40 * time.Millisecond)
	rb.setDelay(0)
	var te time.Time
	msUntil(t, 15*time.Second, "a quality switch from a to b", func() bool {
		st := dc.Status()
		c, ok := ssActive(st)
		if st.Migrations.Quality > 0 && ok && c.Name == "b" {
			te = time.Now()
			return true
		}
		return false
	})
	time.Sleep(1500 * time.Millisecond)
	close(stop)
	gens.Wait()
	end := time.Now()
	ups, downs := []*msSide{sides[0].s}, []*msSide{sides[1].s}
	msDrain(t, []*rendr.PacketConn{dc}, []*rendr.PacketConn{pc}, ups, downs)

	ds := dc.Status()
	if ds.Migrations.Quality == 0 || ds.Migrations.Death != 0 {
		t.Errorf("stimulus: migrations %+v, want a quality switch and no death", ds.Migrations)
	}
	var bTx uint64
	for _, c := range ds.Carriers {
		if c.Name == "b" {
			bTx += c.TxBytes
		}
	}
	if bTx == 0 {
		t.Errorf("stimulus: carrier b carried no data: %+v", ds.Carriers)
	}
	t.Logf("MaxBatch %d: step at %v, switch %v later; run %v", maxBatch, step.Sub(start).Round(time.Millisecond), te.Sub(step).Round(time.Millisecond), end.Sub(start).Round(time.Millisecond))

	dc.Close()
	msDone(t, dc.Done(), "the dialer session")
	readers.Wait()
	pc.Close()
	msDone(t, pc.Done(), "the passive session")
	dEnd, pEnd := dc.Status(), pc.Status()
	pre, post := msLossWindows()
	var res ssResult
	for i, d := range []struct {
		name   string
		tx, rx rendr.SessionStatus
	}{{"up", dEnd, pEnd}, {"down", pEnd, dEnd}} {
		s := sides[i]
		res.lostAway[i], res.unique[i] = s.judge(t, d.name, step.Add(-pre), te.Add(post), d.tx, d.rx)
	}
	m.muxZero()
	m.close()

	dio, pio := m.d.Status().Datagram, m.p.Status().Datagram
	t.Logf("MaxBatch %d: dialer %s; passive %s", maxBatch, beIO(dio), beIO(pio))
	for name, s := range map[string]rendr.DatagramStatus{"dialer": dio, "passive": pio} {
		switch {
		case maxBatch == 1 || !beBatching:
			if s.SendCalls != s.SentDatagrams || s.RecvCalls != s.RecvDatagrams {
				t.Errorf("%s (MaxBatch %d, %s/%s): %s, want one datagram per call", name, maxBatch, runtime.GOOS, runtime.GOARCH, beIO(s))
			}
		default:
			if s.SentDatagrams <= s.SendCalls {
				t.Errorf("%s (MaxBatch %d, %s/%s): %s, want its sends batched", name, maxBatch, runtime.GOOS, runtime.GOARCH, beIO(s))
			}
		}
	}
	return res
}

// ssActive returns the active carrier of st.
func ssActive(st rendr.SessionStatus) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// ssSide is one direction: msSide's verifier and counts, and the time
// each datagram was written (sent[seq], Unix nanoseconds).
type ssSide struct {
	s    *msSide
	seed uint64
	mu   sync.Mutex
	sent []int64
}

func newSsSide(seed uint64, capHint int) *ssSide {
	return &ssSide{s: &msSide{v: rendrtest.NewPacketVerifier(seed)}, seed: seed, sent: make([]int64, 0, capHint)}
}

// generate writes burst datagrams every every until stop closes.
func (d *ssSide) generate(c *rendr.PacketConn, burst int, every time.Duration, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 1024)
	tk := time.NewTicker(every)
	defer tk.Stop()
	var seq uint64
	for {
		select {
		case <-stop:
			return
		case now := <-tk.C:
			for range burst {
				if _, err := c.WriteTo(rendrtest.PacketPayload(buf, d.seed, seq, msSize(seq), now), nil); err != nil {
					d.s.verr.CompareAndSwap(nil, err)
					return
				}
				d.mu.Lock()
				d.sent = append(d.sent, now.UnixNano())
				d.mu.Unlock()
				d.s.accepted.Add(1)
				seq++
			}
		}
	}
}

// judge checks one direction after both ends ended: no generator or
// verifier error, no corrupt, resized or twice-read datagram, the send
// counters adding up to what WriteTo accepted and the receive counters to
// what the reader read, at least 90 % arrived; it returns the datagrams
// lost outside [from, to] (by their write time) and the distinct
// datagrams read.
func (d *ssSide) judge(t *testing.T, name string, from, to time.Time, tx, rx rendr.SessionStatus) (away, unique uint64) {
	t.Helper()
	s := d.s
	if e := s.verr.Load(); e != nil {
		t.Errorf("%s: %v", name, e)
	}
	res := s.v.Result()
	if res.Corrupt != 0 || res.BadSize != 0 || res.Duplicates != 0 {
		t.Errorf("%s: corrupt %d, resized %d, read twice %d", name, res.Corrupt, res.BadSize, res.Duplicates)
	}
	sent := s.accepted.Load()
	if res.Unique*10 < sent*9 {
		t.Errorf("load %s: %d of %d datagrams arrived, want ≥ 90 %%", name, res.Unique, sent)
	}
	d.mu.Lock()
	times := d.sent
	d.mu.Unlock()
	lost := func(seq uint64) {
		if seq >= uint64(len(times)) {
			return
		}
		if at := time.Unix(0, times[seq]); at.Before(from) || at.After(to) {
			away++
		}
	}
	for _, m := range res.Missing {
		for seq := m.From; seq <= m.To; seq++ {
			lost(seq)
		}
	}
	for seq := res.Highest + 1; seq < sent; seq++ {
		lost(seq) // sent after the highest one received
	}
	tp, rp := tx.Packet, rx.Packet
	if tp == nil || rp == nil {
		t.Fatalf("%s: no PacketCounters", name)
	}
	if sum := tp.Sent + tp.DropQueue + tp.DropAge + tp.DropNoPath + tp.DropTooLarge; sum != sent {
		t.Errorf("%s: accepted %d ≠ Sent %d + DropQueue %d + DropAge %d + DropNoPath %d + DropTooLarge %d", name, sent, tp.Sent, tp.DropQueue, tp.DropAge, tp.DropNoPath, tp.DropTooLarge)
	}
	if got := s.read.Load() + rp.DropRecvQueue; rp.Received != got {
		t.Errorf("%s: Received %d ≠ read %d + DropRecvQueue %d", name, rp.Received, s.read.Load(), rp.DropRecvQueue)
	}
	if rp.Received > tp.Sent || rp.Duplicates != 0 {
		t.Errorf("%s: Received %d of Sent %d, Duplicates %d", name, rp.Received, tp.Sent, rp.Duplicates)
	}
	t.Logf("%s: accepted %d, unique %d, lost %d (%d outside the switch window), max gap %v; tx %+v; rx %+v",
		name, sent, res.Unique, sent-res.Unique, away, res.MaxGap, *tp, *rp)
	return away, res.Unique
}

// ssRelay forwards UDP datagrams between rendr's dialer sockets and one
// destination, each after the relay's current one-way delay, in order: a
// client's datagrams go out from a socket of its own (so the passive sees
// one address per client) and the answers come back to the client from
// the relay's listening socket.
type ssRelay struct {
	ln       *net.UDPConn
	dst      netip.AddrPort
	delay    atomic.Int64
	q        chan ssItem
	mu       sync.Mutex
	ups      map[netip.AddrPort]*net.UDPConn
	readers  sync.WaitGroup // accept and every back
	lineDone chan struct{}
}

// ssItem is one datagram in the relay's delay line: written at at on
// conn, to to (or on a connected conn when to is invalid).
type ssItem struct {
	at   time.Time
	conn *net.UDPConn
	to   netip.AddrPort
	b    []byte
}

func newSsRelay(t testing.TB, dst netip.AddrPort, delay time.Duration) *ssRelay {
	t.Helper()
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &ssRelay{ln: ln, dst: dst, q: make(chan ssItem, 1<<16), ups: map[netip.AddrPort]*net.UDPConn{}, lineDone: make(chan struct{})}
	r.delay.Store(int64(delay))
	r.readers.Add(1)
	go r.accept()
	go r.line()
	t.Cleanup(r.close)
	return r
}

func (r *ssRelay) addr() string { return r.ln.LocalAddr().String() }

// setDelay sets the one-way delay of the datagrams the relay reads from
// now on.
func (r *ssRelay) setDelay(d time.Duration) { r.delay.Store(int64(d)) }

func (r *ssRelay) enqueue(conn *net.UDPConn, to netip.AddrPort, b []byte) {
	select {
	case r.q <- ssItem{at: time.Now().Add(time.Duration(r.delay.Load())), conn: conn, to: to, b: b}:
	default: // a full delay line drops, as a link would
	}
}

// accept reads the clients' datagrams and queues them toward dst.
func (r *ssRelay) accept() {
	defer r.readers.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := r.ln.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		up, ok := r.ups[from]
		if !ok && r.ups != nil {
			if up, err = net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(r.dst)); err != nil {
				r.mu.Unlock()
				continue
			}
			r.ups[from] = up
			r.readers.Add(1) // accept's own count keeps the group above zero
			go r.back(up, from)
		}
		r.mu.Unlock()
		if up != nil {
			r.enqueue(up, netip.AddrPort{}, append([]byte(nil), buf[:n]...))
		}
	}
}

// back reads dst's answers to client and queues them toward it.
func (r *ssRelay) back(up *net.UDPConn, client netip.AddrPort) {
	defer r.readers.Done()
	buf := make([]byte, 65536)
	for {
		n, err := up.Read(buf)
		if err != nil {
			return
		}
		r.enqueue(r.ln, client, append([]byte(nil), buf[:n]...))
	}
}

// line writes each queued datagram at its time, in queue order.
func (r *ssRelay) line() {
	defer close(r.lineDone)
	for it := range r.q {
		if d := time.Until(it.at); d > 0 {
			time.Sleep(d)
		}
		if it.to.IsValid() {
			_, _ = it.conn.WriteToUDPAddrPort(it.b, it.to)
		} else {
			_, _ = it.conn.Write(it.b)
		}
	}
}

// close stops the relay and waits for its goroutines: the readers end at
// their closed sockets, then the delay line at its closed queue.
func (r *ssRelay) close() {
	r.ln.Close()
	r.mu.Lock()
	for _, up := range r.ups {
		up.Close()
	}
	r.ups = nil
	r.mu.Unlock()
	r.readers.Wait()
	close(r.q)
	<-r.lineDone
}
