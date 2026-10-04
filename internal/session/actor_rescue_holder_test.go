package session

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Holder-alone rescue between two sessions over rendrtest.Link (design
// §4.11, §0.8 V3; L34). A bond member falls behind while the members' frames
// interleave frame by frame: the receiver holds the other member's frames
// out of order, each in its own 16 KiB run, until its 2·W receive cap drops
// the rest (D13, V3). The member that fell behind then dies and its factory
// refuses every redial, so the surviving member is the only data lane and
// holds every byte the receiver dropped. Stream carriers have no
// retransmission timer, so only the holder itself can resend them: without
// that the session stalls for good on a healthy carrier. The selector
// analogue cannot arise (its receiver never holds out-of-order data); the
// last test pins that. Package-level helpers of these tests start with
// "rh".

const (
	rhSeg    = 2 << 10  // the sender's DATA segment and batch budget: one DATA frame per write
	rhCap    = 32 << 10 // the sender's per-carrier in-flight cap (floor = ceiling)
	rhWindow = 64 << 10 // the receiver's window W: its receive cap 2·W holds 7 runs
	rhTotal  = 16 << 20
	// rhTick is the virtual time every sender write takes: each member's
	// writer places at most one DATA frame per tick, so the two members'
	// frames alternate on the stream frame by frame.
	rhTick = 20 * time.Microsecond
	// rhSlow is the one-way delay of the member that falls behind.
	rhSlow = 50 * time.Millisecond
)

// rhPaced is a conn whose every Write first takes rhTick of virtual time.
type rhPaced struct{ net.Conn }

func (c rhPaced) Write(p []byte) (int, error) {
	time.Sleep(rhTick)
	return c.Conn.Write(p)
}

// rhLink makes a link to w's passive (closed by the teardown); with
// pacePassive the passive's ends of its carriers are paced.
func rhLink(w *acWorld, name string, pacePassive bool) *rendrtest.Link {
	accept := w.b.accept
	if pacePassive {
		accept = func(nc net.Conn) error { return w.b.accept(rhPaced{nc}) }
	}
	l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: accept})
	l.SetDelay(acLinkDelay, 0)
	w.links = append(w.links, l)
	return l
}

// rhOpen dials a session in mode over links — the dialer's ends of the
// carriers paced with paceDialer — and confirms the passive side.
func rhOpen(t testing.TB, w *acWorld, mode Mode, paceDialer bool, links ...*rendrtest.Link) (dialer, passive *Session) {
	t.Helper()
	spec := w.spec(mode, links...)
	if paceDialer {
		for i := range spec.Factories {
			dial := spec.Factories[i].Dial
			spec.Factories[i].Dial = func(ctx context.Context) (net.Conn, error) {
				c, err := dial(ctx)
				if err != nil {
					return nil, err
				}
				return rhPaced{c}, nil
			}
		}
	}
	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := w.dial(context.Background(), spec, nil)
		ch <- res{s, err}
	}()
	passive = w.confirmNext()
	r := <-ch
	if r.err != nil {
		t.Fatalf("Dial: %v", r.err)
	}
	return r.s, passive
}

// rhResult is one transfer's outcome: the writer's and the verifier's
// errors and the SHA-256 of every byte the reader received.
type rhResult struct {
	w, r error
	sum  [32]byte
}

// rhTransfer writes n bytes of PRNG(seed) on from — the first first bytes,
// then, once gate closes, the rest — and then CloseWrite, while to reads
// them to EOF through a Verifier and a SHA-256 of what it received.
func rhTransfer(from, to *Session, n, first int64, seed uint64, gate <-chan struct{}) rhResult {
	var res rhResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		g := rendrtest.PRNG(seed)
		buf := make([]byte, 48<<10)
		for sent := int64(0); sent < n && res.w == nil; {
			if sent == first {
				<-gate
			}
			k := min(int64(len(buf)), n-sent)
			if sent < first {
				k = min(k, first-sent)
			}
			g.Read(buf[:k])
			_, res.w = from.Write(buf[:k])
			sent += k
		}
		if res.w == nil {
			res.w = from.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		h := sha256.New()
		res.r = rendrtest.NewVerifier(seed, n).ReadAll(io.TeeReader(to, h))
		h.Sum(res.sum[:0])
	}()
	wg.Wait()
	return res
}

// rhRescues counts the rescue duplicates a session's lanes placed
// (rescueSendHook): by the holder of the stuck head while it was the only
// data lane, by another lane, and by the holder while another data lane
// existed (the L34 exclusion: always 0).
type rhRescues struct {
	mu                  sync.Mutex
	holder, other, both int
}

func rhWatchRescues(t testing.TB, s *Session) *rhRescues {
	c := &rhRescues{}
	rescueSendHook.Store(&rescueHook{s: s, fn: func(l *lane, holder bool) {
		others := 0 // under s.mu
		for _, o := range s.st.order {
			if o != l && o.data {
				others++
			}
		}
		c.mu.Lock()
		switch {
		case holder && others > 0:
			c.both++
		case holder:
			c.holder++
		default:
			c.other++
		}
		c.mu.Unlock()
	}})
	t.Cleanup(func() { rescueSendHook.Store(nil) })
	return c
}

func (c *rhRescues) counts() (holder, other, both int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.holder, c.other, c.both
}

// rhDropped returns the out-of-order bytes s's receive cap dropped or shed.
func rhDropped(s *Session) uint64 {
	return stLocked(s, func(st *stream) uint64 { return st.oooDropped })
}

// rhCarrier returns the CarrierID of the dialer's live carrier of factory
// name (both ends share CarrierIDs).
func rhCarrier(t testing.TB, dialer *Session, name string) uint32 {
	t.Helper()
	for _, c := range dialer.Status().Carriers {
		if c.Name == name && c.State != LaneDead {
			return c.ID
		}
	}
	t.Fatalf("no live carrier of %s", name)
	return 0
}

// rhTx returns the DATA bytes s sent on carrier id.
func rhTx(s *Session, id uint32) uint64 {
	for _, c := range s.Status().Carriers {
		if c.ID == id {
			return c.Stats.TxBytes
		}
	}
	return 0
}

// TestActorRescueHolderAlone_L34: 16 MiB over a bond of two members (2 KiB
// segments, one DATA frame per paced write, each member capped at 32 KiB in
// flight, the receiver's window 64 KiB). The first MiB crosses both members
// until both are idle with their capacity proven free; then p2 falls 50 ms
// behind and the rest of the stream is released. Its first window goes out
// frame by frame alternately on both members (the commit wakes both: one
// member's cap cannot cover the window), so the receiver holds p1's 16
// frames out of order in at least 8 isolated 16 KiB runs (no run spans
// more than two of them) until its receive cap (7 runs) drops the rest; at
// least one of p1's frames is dropped. p2 then dies and its factory refuses
// every redial: its spans are replayed on p1, the receiver delivers up to
// the first byte it dropped, and p1 — the only data lane, holding every
// dropped byte — resends them as rescue duplicates itself. The transfer
// completes with SHA-256 intact within a bounded virtual time; the rescue
// counter proves the holder resent, and that it never did while another
// data lane existed. Both directions: the passive rescues its own sends
// exactly like the dialer.
func TestActorRescueHolderAlone_L34(t *testing.T) {
	for _, passiveSends := range []bool{false, true} {
		name := "dialer-sends"
		if passiveSends {
			name = "passive-sends"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { rhHolderAlone(t, passiveSends) })
		})
	}
}

func rhHolderAlone(t *testing.T, passiveSends bool) {
	w := acNewWorld(t, nil)
	defer w.teardown()
	sender, receiver := w.a, w.b.acSide
	if passiveSends {
		sender, receiver = w.b.acSide, w.a
	}
	tm := &sender.cenv.Timing
	tm.Segment, tm.BatchBudget = rhSeg, rhSeg
	tm.Window, tm.CapFloor = rhCap, rhCap
	receiver.p.Window = rhWindow
	l1, l2 := rhLink(w, "p1", passiveSends), rhLink(w, "p2", passiveSends)
	a, b := rhOpen(t, w, ModeBond, !passiveSends, l1, l2)
	acWaitFor(t, time.Second, "both members carry data on both ends", func() bool {
		return a.dataMembers() == 2 && b.dataMembers() == 2
	})
	src, dst := a, b
	if passiveSends {
		src, dst = b, a
	}
	rescues := rhWatchRescues(t, src)
	const (
		seed  = 73
		first = 1 << 20
	)
	want, err := rendrtest.Digest(rendrtest.PRNG(seed), rhTotal)
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	done := make(chan rhResult, 1)
	go func() { done <- rhTransfer(src, dst, rhTotal, first, seed, gate) }()
	members := func() (n int, tx [2]uint64, idle bool) {
		idle = true
		for _, c := range src.Status().Carriers {
			if c.State == LaneMember && n < 2 {
				tx[n] = c.Stats.TxBytes
				idle = idle && c.Stats.Inflight == 0
				n++
			}
		}
		return n, tx, idle
	}
	acWaitFor(t, 5*time.Second, "the first MiB acknowledged, both members idle", func() bool {
		n, _, idle := members()
		return n == 2 && idle && src.Status().AckedBytes == first
	})
	if _, tx, _ := members(); tx[0] == 0 || tx[1] == 0 {
		t.Fatalf("member DATA bytes %v: the first MiB did not cross both members (stimulus)", tx)
	}
	if d := rhDropped(dst); d != 0 {
		t.Fatalf("the receiver dropped %d bytes before any member fell behind", d)
	}

	// p2 falls behind, and the rest of the stream is released.
	p2 := rhCarrier(t, a, "p2")
	tx2 := rhTx(src, p2)
	l2.SetDelay(rhSlow, 0)
	close(gate)
	acWaitFor(t, 100*time.Millisecond, "out-of-order bytes dropped at the receive cap", func() bool { return rhDropped(dst) > 0 })
	dropped := rhDropped(dst)
	if rhTx(src, p2) == tx2 {
		t.Fatal("p2 carried none of the interleaved window (stimulus)")
	}
	if h, o, both := rescues.counts(); h+o+both != 0 {
		t.Fatalf("rescues before the fault: holder %d, other %d, holder with others %d", h, o, both)
	}

	// p2 dies and stays dead: p1 is the only data lane left.
	l2.SetRefuse(true)
	refused := l2.Stats().DialFailures
	killed := time.Now()
	if l2.Kill() == 0 {
		t.Fatal("the kill hit no carrier")
	}
	// Recovery: at worst every frame of the window was dropped, and once
	// more on its replay; each is rescued after RescueWait (RescueMin: the
	// srtt is a few ms) plus the ACK delay and a round trip. Then the rest
	// of the stream crosses p1 at its 32 KiB-per-round-trip cap.
	bound := 2*rhWindow/rhSeg*(w.a.p.RescueMin+w.a.p.AckDelay+10*time.Millisecond) + 10*time.Second
	var r rhResult
	select {
	case r = <-done:
	case <-time.After(bound):
		h, o, both := rescues.counts()
		t.Fatalf("transfer stalled: %d of %d bytes delivered %v after the member died (receiver dropped %d bytes; rescues: holder %d, other %d, holder with others %d)",
			dst.Status().DeliveredBytes, rhTotal, bound, rhDropped(dst), h, o, both)
	}
	took := time.Since(killed)
	if r.w != nil || r.r != nil {
		t.Fatalf("transfer: write %v, read %v", r.w, r.r)
	}
	if r.sum != want {
		t.Fatalf("SHA-256 of the received stream %x, want %x", r.sum, want)
	}
	holder, other, both := rescues.counts()
	if holder == 0 {
		t.Fatal("the holder never resent a dropped byte (rescue counter)")
	}
	if both != 0 {
		t.Fatalf("the holder sent its own rescue %d times while another data lane existed (L34)", both)
	}
	if l2.Stats().DialFailures == refused {
		t.Fatal("no redial of p2 was refused: p1 was never the only data lane (stimulus)")
	}
	if st := a.Status(); st.Rejoins != 0 {
		t.Fatalf("%d rejoins: p2 came back (stimulus)", st.Rejoins)
	}
	if st := src.Status(); st.MigDeath != 1 {
		t.Fatalf("sender death migrations %d, want 1: p2's death moved its spans to p1", st.MigDeath)
	}
	t.Logf("receiver dropped %d bytes before the death (%d by the end); %d holder rescues (%d by another lane); complete %v after the death",
		dropped, rhDropped(dst), holder, other, took)
}

// TestActorRescueSelectorStaysInOrder (§4.11, §7.2, §7.5; L10): the
// selector analogue of the holder-alone stall — a single active lane
// holding bytes its receiver dropped — cannot arise, because a selector
// receiver never holds out-of-order data, so its receive cap drops nothing.
// One lane at a time sends; a new sender replays from the acknowledged
// front sBase, which the receiver has passed (sBase ≤ rRead ≤ rTail), and
// the old sender's late frames are contiguous with its earlier ones. Here a
// planned switch moves a 2 KiB-frame transfer from p1, whose frames are
// 50 ms late, to p2 while p1 still has up to a window in flight; p1 keeps
// delivering after the switch, and every DATA placement leaves the
// receiver with nothing out of order and nothing dropped. Both directions:
// the passive follows the dialer's SCHED.
func TestActorRescueSelectorStaysInOrder(t *testing.T) {
	for _, passiveSends := range []bool{false, true} {
		name := "dialer-sends"
		if passiveSends {
			name = "passive-sends"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { rhSelectorInOrder(t, passiveSends) })
		})
	}
}

func rhSelectorInOrder(t *testing.T, passiveSends bool) {
	w := acNewWorld(t, nil)
	defer w.teardown()
	sender := w.a
	if passiveSends {
		sender = w.b.acSide
	}
	sender.cenv.Timing.Segment = rhSeg
	h := acNewHealth(2, w.a.p.Selector.Fresh)
	h.set(30*time.Millisecond, 0)
	l1, l2 := w.link("p1"), w.link("p2")
	l1.SetDelay(rhSlow, 0)
	a, b := w.open(ModeSelector, h, l1, l2)
	first := acActive(a)
	if first == 0 || a.Status().Carriers[0].Name != "p1" {
		t.Fatalf("opened on %+v, want p1", a.Status().Carriers)
	}
	src, dst := a, b
	if passiveSends {
		src, dst = b, a
	}
	var placed, unordered int
	var dropped uint64
	recvCopyHook.Store(&recvHook{s: dst, fn: func(int) { // under dst.mu
		placed++
		if len(dst.st.ooq.s) > 0 || dst.st.oooDropped > 0 {
			unordered++
			dropped = dst.st.oooDropped
		}
	}})
	t.Cleanup(func() { recvCopyHook.Store(nil) })
	defer acFreshen(h)()
	h.set(30*time.Millisecond, 2*time.Millisecond) // p2 is better: a planned switch after Dwell

	const seed = 79
	want, err := rendrtest.Digest(rendrtest.PRNG(seed), rhTotal)
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	close(gate)
	done := make(chan rhResult, 1)
	go func() { done <- rhTransfer(src, dst, rhTotal, rhTotal, seed, gate) }()
	acWaitFor(t, 5*time.Second, "the planned switch on both ends", func() bool {
		return a.Status().MigQuality == 1 && b.Status().MigQuality == 1
	})
	// The bytes p1 had delivered to the receiver when the switch reached
	// the sender: p1 still holds frames 50 ms in flight.
	p1rx := func() uint64 {
		for _, c := range dst.Status().Carriers {
			if c.ID == first {
				return c.Stats.RxBytes
			}
		}
		t.Fatalf("the receiver keeps no status of p1 (%d)", first)
		return 0
	}
	atSwitch := p1rx()
	if d := dst.Status().DeliveredBytes; d >= rhTotal/2 {
		t.Fatalf("%d of %d bytes delivered at the switch: no load across it", d, rhTotal)
	}
	var r rhResult
	select {
	case r = <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("transfer not complete: %d of %d bytes delivered", dst.Status().DeliveredBytes, rhTotal)
	}
	if r.w != nil || r.r != nil {
		t.Fatalf("transfer: write %v, read %v", r.w, r.r)
	}
	if r.sum != want {
		t.Fatalf("SHA-256 of the received stream %x, want %x", r.sum, want)
	}
	if late := p1rx() - atSwitch; late == 0 {
		t.Fatal("p1 delivered nothing after the switch: no overlap of the old and new sender (stimulus)")
	}
	if src.Status().RetransmittedBytes == 0 {
		t.Fatal("the new sender replayed nothing (stimulus)")
	}
	dst.mu.Lock()
	n, bad, d := placed, unordered, dst.st.oooDropped
	dst.mu.Unlock()
	if n == 0 {
		t.Fatal("no DATA placement observed")
	}
	if bad != 0 || d != 0 {
		t.Fatalf("%d of %d placements left the receiver holding out-of-order data (%d bytes dropped): a selector receiver must stay in order", bad, n, max(d, dropped))
	}
	t.Logf("%d DATA placements, all in order; p1 delivered %d bytes after the switch; %d bytes replayed", n, p1rx()-atSwitch, src.Status().RetransmittedBytes)
}
