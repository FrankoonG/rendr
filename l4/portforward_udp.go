package l4

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// ServeUDP reads sock until ctx is done or sock is closed and forwards the
// datagrams of every client source address to target as one flow. A
// datagram from a new client opens a flow: it rides the OPEN when it fits
// (DialUDP), the client's later datagrams wait (at most 8 and 16 KiB, at
// most 1 s) until the flow is open (at most 12 s); a client whose open
// failed, or whose flow the far end closed within 5 s of its open, is not
// dialled again for 5 s; replies go to the client's address. When MaxFlows
// is reached, a new client takes the place of an idle (≥ 1 s) flow that
// never became a stream, or its datagram is dropped and counted (a client
// still held after a failed open makes room first). A datagram longer than
// the flow's MaxPayload is dropped and counted. Socket errors of the
// system-call class are counted and backed off. ServeUDP owns sock from
// the call on and closes it when it returns, after every flow it started
// ended. At the stop each flow waits for its session's end, at most 2.1 s
// (that long while no carrier lives), so that SessionDrops holds what the
// sessions dropped after the close.
//
// ServeUDP returns ctx.Err() once ctx is done, the socket's error when its
// reads fail (net.ErrClosed after a Close by someone else), or
// net.ErrClosed when the Peer or its Runtime was closed. Before the first
// read it returns at once, sock closed: an error when Peer is nil, the
// metadata error of an invalid target (ErrBadAddress), ErrNonLoopback, or
// an error for a connected sock.
func (f *PortForward) ServeUDP(ctx context.Context, sock UDPSocket, target string) error {
	s, err := f.newUDPServe(sock, target)
	if err != nil {
		sock.Close()
		return err
	}
	f.mu.Lock()
	if f.serves == nil {
		f.serves = make(map[*udpServe]struct{})
	}
	f.serves[s] = struct{}{}
	f.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { s.halt(ctx.Err()) })
	s.read()
	stop()
	s.shutdown()
	s.closeSock()
	f.mu.Lock()
	delete(f.serves, s)
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.cause
}

// Flows returns a snapshot of the UDP flows (diagnostics: it allocates and
// calls Status on every open flow's session).
func (f *PortForward) Flows() []FlowInfo {
	f.mu.Lock()
	serves := make([]*udpServe, 0, len(f.serves))
	for s := range f.serves {
		serves = append(serves, s)
	}
	f.mu.Unlock()
	var out []FlowInfo
	var pcs []ingressSession
	for _, s := range serves {
		s.tab.mu.Lock()
		for _, e := range s.tab.m {
			out = append(out, FlowInfo{
				Client: e.client,
				Target: s.target,
				State:  e.state,
				Stream: e.class.isStream(),
				Since:  s.base.Add(e.since),
				Last:   s.base.Add(time.Duration(e.last.Load())),
			})
			var pc ingressSession
			if e.state == FlowOpen {
				pc = e.pc
			}
			pcs = append(pcs, pc)
		}
		s.tab.mu.Unlock()
	}
	for i, pc := range pcs {
		if pc != nil {
			out[i].Session = pc.Status()
		}
	}
	return out
}

// ingressSession is what the ingress uses of a flow's packet session: the
// forward's methods, Status (Flows, SessionDrops) and Metadata (whether
// the first datagram rode the OPEN).
type ingressSession interface {
	packetSession
	Status() rendr.SessionStatus
	Metadata() []byte
}

// dialIngress opens one flow's session for the ingress: DialUDP up to the
// open (openUDP). A first datagram that did not ride the OPEN (DialUDP's
// retry without it, R1-4) is the ingress's to write: the flush sends it
// ahead of the queue. It is a variable only so that tests can wrap the
// session (a blocking fake, M6 design §A16.1
// TestPortForwardNeverBlocks_L40); nothing else sets it.
var dialIngress = func(ctx context.Context, p *rendr.Peer, addr string, first []byte, o rendr.DialOptions) (ingressSession, error) {
	pc, _, err := openUDP(ctx, p, addr, first, o)
	if err != nil {
		return nil, err
	}
	return pc, nil
}

// udpServe is one ServeUDP call: its socket, table, reader and flows.
type udpServe struct {
	f             *PortForward
	sock          UDPSocket
	target        string
	opts          rendr.DialOptions // the PortForward's, EarlyReturn off
	bare          int               // the flows' L4 metadata without a first datagram
	rule          promoteMode       // fixed for the serve (the full-table rule)
	short, stream time.Duration     // the classes' SetIdleTimeout values (0: off)
	base          time.Time         // the offsets' origin

	// ctx ends at the halt: it cancels every open in progress and ends
	// every hold.
	ctx    context.Context
	cancel context.CancelFunc

	tab flowTable
	wg  sync.WaitGroup // the flows' goroutines

	haltOnce sync.Once
	cause    error // the halt's cause (set once, read after the reader returned)
	sockOnce sync.Once
}

// newUDPServe runs ServeUDP's checks (M6-D21, M6-D22, A8.1) before the
// first read.
func (f *PortForward) newUDPServe(sock UDPSocket, target string) (*udpServe, error) {
	if f.Peer == nil {
		return nil, errNoPeer
	}
	app := f.Options.Metadata
	md, err := AppendMetadata(nil, Request{Cmd: CmdUDP, Addr: target, App: app})
	if err != nil {
		return nil, err
	}
	if err := f.checkIngress(sock.LocalAddr()); err != nil {
		return nil, err
	}
	// Connected: read through that one method, never used for I/O (L57).
	if rc, ok := sock.(interface{ RemoteAddr() net.Addr }); ok && !isNilAddr(rc.RemoteAddr()) {
		return nil, errConnectedSocket
	}
	s := &udpServe{f: f, sock: sock, target: target, opts: f.Options, bare: len(md), rule: activeRule(), base: time.Now()}
	s.opts.EarlyReturn = false
	s.short, s.stream = f.Idle.limits()
	s.tab.m = make(map[netip.AddrPort]*ingressFlow)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

// now is the offset of the current instant from the serve's base.
func (s *udpServe) now() time.Duration { return time.Since(s.base) }

// halt stops the serve once (ctx done, a fatal socket error, the Peer or
// Runtime closed): the reader's read returns at once (a deadline in the
// past; a socket that refuses deadlines is closed instead), and every open
// and hold ends.
func (s *udpServe) halt(err error) {
	s.haltOnce.Do(func() {
		s.cause = err
		s.cancel()
		if s.sock.SetReadDeadline(time.Unix(1, 0)) != nil {
			s.closeSock()
		}
	})
}

// closeSock closes the socket exactly once.
func (s *udpServe) closeSock() { s.sockOnce.Do(func() { s.sock.Close() }) }

// read is the reader (M6-D25, §A8.2): one 64-KiB buffer; read noise is
// counted and backed off after a run; a fatal error halts the serve.
func (s *udpServe) read() {
	buf := make([]byte, ingressReadBuf)
	var run noiseRun
	var wait *time.Timer
	defer func() {
		if wait != nil {
			wait.Stop()
		}
	}()
	for {
		n, src, err := s.sock.ReadFromUDPAddrPort(buf)
		if s.ctx.Err() != nil {
			return
		}
		if err == nil && (n < 0 || n > len(buf)) {
			err = errBadDatagramCount // L42: a broken socket
		}
		if err != nil {
			if errClass(err) == classFatal {
				s.halt(err)
				return
			}
			// Noise (ICMP-class errors, WSAECONNRESET, no buffer space):
			// counted; a run of them backs off (L58, L73).
			s.f.udp.readNoise.Add(1)
			if d := run.fail(); d > 0 {
				if wait == nil {
					wait = time.NewTimer(d)
				} else {
					wait.Reset(d)
				}
				select {
				case <-wait.C:
				case <-s.ctx.Done():
					return
				}
			}
			continue
		}
		run.ok()
		if !src.IsValid() {
			s.f.udp.readNoise.Add(1) // no source to map or answer
			continue
		}
		s.datagram(buf[:n], src)
	}
}

// datagram handles one client datagram (§A8.2). b is the reader's buffer:
// it is copied only for an opening flow; an open flow's WriteTo copies it.
func (s *udpServe) datagram(b []byte, src netip.AddrPort) {
	u := &s.f.udp
	t := &s.tab
	t.mu.Lock()
	e := t.m[src]
	if e == nil {
		s.admit(b, src) // unlocks
		return
	}
	switch e.state {
	case FlowOpening:
		// Its latest datagram, also while it waits: the eviction's idle
		// floor (victim) and FlowInfo.Last count from it, not from the
		// first, so a flow that a slow open delays is not idle.
		now := s.now()
		e.last.Store(int64(now))
		dropped := e.push(b, now)
		t.mu.Unlock()
		if dropped > 0 {
			u.dropOpenQueue.Add(uint64(dropped))
		}
	case FlowHeld:
		e.last.Store(int64(s.now())) // FlowInfo.Last: its datagrams are dropped, its client is active
		t.mu.Unlock()
		u.dropHeld.Add(1)
	default: // FlowOpen: WriteTo never blocks, and never under the lock (R1-13)
		pc := e.pc
		t.mu.Unlock()
		now := time.Now()
		e.last.Store(int64(now.Sub(s.base)))
		switch _, err := pc.WriteTo(b, nil); {
		case err == nil:
			u.toSession.Add(1)
			if !e.class.isStream() && e.class.out(now) {
				s.promote(pc)
			}
		case errors.Is(err, rendr.ErrPacketTooLarge):
			u.noteTooLarge(len(b))
		default:
			s.replace(e, b, src, err)
		}
	}
}

// admit makes a new client's entry (the table's mutex held at the call,
// released before it returns): in a full table a victim's place or
// DropFull; beyond the opening stage DropOpening. The datagram is the
// entry's first: it rides the OPEN when the whole metadata stays within
// firstBudget, else it is the entry's first queued datagram (R1-9). A
// victim is removed under the mutex and closed after it (R1-5).
func (s *udpServe) admit(b []byte, src netip.AddrPort) {
	f, u, t := s.f, &s.f.udp, &s.tab
	now := s.now()
	full := !acquire(&f.flows, int64(f.maxFlows()))
	var victim *ingressFlow
	if full {
		if victim = s.victim(now); victim == nil {
			t.mu.Unlock()
			u.dropFull.Add(1)
			return
		}
	}
	if !acquire(&f.opening, ingressOpeningMax) {
		t.mu.Unlock()
		if !full {
			f.flows.Add(-1)
		}
		u.dropOpening.Add(1)
		return
	}
	// The victim's unit becomes the newcomer's. An open victim is evicted;
	// a held one only ends its hold early (§A8.6), so its end keeps the
	// cause its session reported. Either may still have a session: an
	// open flow's, or a held one's whose WriteTo met the far end's close
	// (replace) and whose goroutine may still wait in ReadFrom.
	var vpc ingressSession
	evicted := false
	if victim != nil {
		vpc, evicted = victim.pc, victim.state == FlowOpen
		s.remove(victim)
		victim.evicted = evicted
	}
	e := s.newEntry(b, src, now)
	t.put(e)
	t.mu.Unlock()
	if victim != nil {
		close(victim.done)
		if vpc != nil {
			victim.closeSession(vpc) // returns at once; the victim's goroutine leaves ReadFrom
		}
	}
	s.start(e)
}

// newEntry makes an opening entry for src whose first datagram is b (the
// mutex held; its opening unit already taken).
func (s *udpServe) newEntry(b []byte, src netip.AddrPort, now time.Duration) *ingressFlow {
	e := &ingressFlow{client: src, since: now, done: make(chan struct{}), state: FlowOpening}
	e.last.Store(int64(now))
	if len(b) > 0 && s.bare+len(b) <= firstBudget {
		e.first = ingressCopy(b)
	} else {
		e.firstQ = &queuedDatagram{b: ingressCopy(b), at: now}
	}
	return e
}

// replace handles an open flow whose WriteTo returned its session's end
// (M6-D13, §A5.4): if the entry is still the flow's, a new opening flow
// takes its place and its MaxFlows unit with this datagram as its first
// (Replaced) — or, with the opening stage full, the entry goes, its unit
// is released and the datagram is DropOpening (R1-19). A flow whose far
// end closed it within ingressReopenHold of its open holds the source
// instead (the reopen rate limit, R1-2); an entry its goroutine already
// removed makes the datagram a newcomer's.
func (s *udpServe) replace(e *ingressFlow, b []byte, src netip.AddrPort, err error) {
	f, u, t := s.f, &s.f.udp, &s.tab
	t.mu.Lock()
	switch {
	case t.m[src] != e:
		t.mu.Unlock()
		s.datagram(b, src) // the entry went meanwhile: a newcomer (at most once: only the reader adds entries)
		return
	case e.state == FlowHeld:
		t.mu.Unlock()
		u.dropHeld.Add(1)
		return
	case errors.Is(err, net.ErrClosed) && s.now()-e.opened < ingressReopenHold:
		// net.ErrClosed from an entry still in the table is the far end's
		// close: this side closes a flow's session only after taking the
		// entry out (an eviction, the flow's end) or while stopping.
		s.setState(e, FlowHeld)
		e.peerEnd = true
		t.mu.Unlock()
		u.dropHeld.Add(1)
		return
	}
	// The old session ended: its goroutine reads the end (and counts its
	// cause) and leaves the table alone.
	if !acquire(&f.opening, ingressOpeningMax) {
		s.remove(e)
		t.mu.Unlock()
		f.flows.Add(-1)
		u.dropOpening.Add(1)
		return
	}
	s.remove(e)
	ne := s.newEntry(b, src, s.now())
	t.put(ne)
	t.mu.Unlock()
	u.replaced.Add(1)
	s.start(ne)
}

// start runs e's goroutine (only the reader starts goroutines, so the
// shutdown's Wait follows every Add).
func (s *udpServe) start(e *ingressFlow) {
	s.wg.Add(1)
	go s.flow(e)
}

// promote applies the stream class to pc (one call, none when both
// classes are equal).
func (s *udpServe) promote(pc ingressSession) {
	if s.stream != s.short {
		pc.SetIdleTimeout(s.stream) // net.ErrClosed after the end: ignored, the flow ends normally
	}
}

// flow is the entry's one goroutine (M6-D26, §A8.3): the open (bounded by
// ingressOpenBound), the queue's flush outside the lock, then session →
// client until the session ends; a failed open, or an early PeerClosed
// end, holds the source.
func (s *udpServe) flow(e *ingressFlow) {
	defer s.wg.Done()
	u, t := &s.f.udp, &s.tab
	ctx, cancel := context.WithTimeout(s.ctx, ingressOpenBound)
	pc, err := dialIngress(ctx, s.f.Peer, s.target, e.first, s.opts)
	cancel()
	first := e.first != nil
	if err != nil {
		ingressFree(e.first) // openUDP does not retain it
		e.first = nil
		s.openFailed(e, err, first)
		return
	}
	opened := s.now()
	u.opened.Add(1)
	u.maxPayload.Store(int64(pc.MaxPayload()))
	pc.SetIdleTimeout(s.short) // net.ErrClosed only: the session already ended, which ReadFrom reports
	if first {
		if len(pc.Metadata()) > s.bare {
			// It rode the OPEN: sent.
			ingressFree(e.first) // openUDP does not retain it
			u.firstInOpen.Add(1)
			u.toSession.Add(1)
			if e.class.out(s.base.Add(e.since)) {
				s.promote(pc)
			}
		} else {
			// The OPEN with it was refused ErrMetadataTooLarge and the retry
			// opened without it (R1-4): it heads the flush, which counts its
			// write's outcome as the queue's (R1-20: its age too).
			t.mu.Lock()
			e.firstQ = &queuedDatagram{b: e.first, at: e.since}
			t.mu.Unlock()
		}
		e.first = nil
	}
	// The flush (R1-13): take the queue under the lock, write it outside,
	// until the queue is empty under the lock; then the entry is open. A
	// datagram above MaxPayload is TooLarge whatever else holds (the
	// user's L71 signal; C5 A2): its size is checked before its age.
	mp := pc.MaxPayload()
	for ended := false; ; {
		t.mu.Lock()
		if t.stopped {
			q := e.takeQueue()
			t.mu.Unlock()
			u.dropOpenQueue.Add(uint64(len(q)))
			freeQueue(q)
			s.end(e, pc, net.ErrClosed) // end closes the session (once)
			return
		}
		q := e.takeQueue()
		if len(q) == 0 {
			e.pc, e.opened = pc, opened
			s.setState(e, FlowOpen)
			t.mu.Unlock()
			break
		}
		t.mu.Unlock()
		for _, d := range q {
			switch {
			case len(d.b) > mp:
				u.noteTooLarge(len(d.b)) // the flow lives (R1-9)
			case ended:
				u.dropOpenQueue.Add(1)
			case s.now()-d.at > ingressQueueAge:
				u.dropOpenAge.Add(1)
			default:
				switch _, werr := pc.WriteTo(d.b, nil); {
				case werr == nil:
					u.toSession.Add(1)
					if !e.class.isStream() && e.class.out(s.base.Add(d.at)) {
						s.promote(pc)
					}
				case errors.Is(werr, rendr.ErrPacketTooLarge):
					u.noteTooLarge(len(d.b)) // cannot happen after the size check (MaxPayload is fixed at the OPEN)
				default:
					ended = true // the session ended: ReadFrom reports it below
					u.dropOpenQueue.Add(1)
				}
			}
			ingressFree(d.b)
		}
	}
	s.end(e, pc, s.pump(e, pc))
}

// pump moves session → client until the session ends and returns its end
// (§A8.3). A socket write error loses the reply, which WriteNoise counts
// whatever the error's class (an embedder's socket may refuse a write with
// an error of its own), and never ends the flow; a dead socket halts the
// serve through the reader.
func (s *udpServe) pump(e *ingressFlow, pc ingressSession) error {
	u := &s.f.udp
	buf := make([]byte, pc.MaxPayload()) // the flow's only buffer
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.ErrShortBuffer) {
				continue // cannot happen: no session delivers more than MaxPayload
			}
			return err
		}
		if _, werr := s.sock.WriteToUDPAddrPort(buf[:n], e.client); werr != nil {
			u.writeNoise.Add(1)
			continue
		}
		u.toClient.Add(1)
		now := time.Now()
		e.last.Store(int64(now.Sub(s.base)))
		if !e.class.isStream() && e.class.in(now) {
			s.promote(pc)
		}
	}
}

// end closes the flow's session and accounts its end (cause, SessionDrops,
// SessionUnreported), then leaves the table: the entry is removed and its
// unit released, unless it is gone already (evicted, replaced) or it is
// held — by the reader's expiry race or here when the far end closed the
// flow within ingressReopenHold of its open (R1-2) — and then waits out
// the hold. An eviction counts only when its close ended the session: a
// victim whose session had ended on its own before (its goroutine late)
// counts that end. After this side's stop the session still sends or
// drops what it queued, so its drops are read at its end, at most
// ingressSettle later (R1-38); an evicted flow, idle for at least
// ingressEvictIdle, is read at once (its goroutine returns at once, R1-5).
func (s *udpServe) end(e *ingressFlow, pc ingressSession, err error) {
	t := &s.tab
	t.mu.Lock()
	evicted, hold := e.evicted && errors.Is(err, net.ErrClosed), false
	if e.peerEnd {
		err = io.EOF // the far end closed it; a local close since (an eviction, the stop) only woke the goroutine
	}
	switch {
	case e.gone:
	case e.state == FlowHeld:
		hold = true
	case !t.stopped && errors.Is(err, io.EOF) && s.now()-e.opened < ingressReopenHold:
		s.setState(e, FlowHeld)
		hold = true
	default:
		s.remove(e)
		s.f.flows.Add(-1)
	}
	t.mu.Unlock()
	e.closeSession(pc)
	cause := s.f.udp.ends.count(err, evicted)
	if evicted {
		s.f.udp.evicted.Add(1)
	}
	pk := pc.Status().Packet
	if cause.unreported() {
		s.f.udp.sessionUnreported.Add(unreportedOf(pk))
	}
	if cause == endStopped {
		pk = settle(pc)
	}
	if pk != nil {
		s.f.udp.sessionDrops.Add(sessionDrops(pk))
	}
	if hold {
		s.hold(e)
	}
}

// settle waits for the end of pc, which this side closed, at most
// ingressSettle, and returns its packet counters then (R1-38): a session
// with a carrier ends about one round trip after the close; one without
// has dropped every datagram it held once Packet.MaxAge has passed.
func settle(pc ingressSession) *rendr.PacketCounters {
	tm := time.NewTimer(ingressSettle)
	select {
	case <-pc.Done():
	case <-tm.C:
	}
	tm.Stop()
	return pc.Status().Packet
}

// openFailed holds the source of a failed open (M6-D28): its queued
// datagrams — and its first datagram, which rode the failed OPEN or would
// have followed the open — are DropHeld, the failure is counted (Failed,
// ByCode, LastErr). A first datagram that rode may have reached the
// target all the same: a passive writes it before it confirms, and its
// Confirm can still fail (UDPServerStatus.FirstSent and Unconfirmed). An
// open the stop cancelled counts no failure, its datagrams DropOpenQueue,
// and leaves the table at once; an open that failed with the bare
// net.ErrClosed (the Peer or the Runtime closed: DialUDP returns
// DialPacket's sentinel unwrapped) halts the serve. A wrapped one is a
// carrier's (ErrNoPath's last carrier error: an embedder tunnel that is
// down), so it is this flow's failure, as in ServeTCP.
func (s *udpServe) openFailed(e *ingressFlow, err error, first bool) {
	u, t := &s.f.udp, &s.tab
	if err == net.ErrClosed {
		s.halt(err)
	}
	stopping := s.ctx.Err() != nil
	if !stopping {
		u.openFailed(err)
	}
	t.mu.Lock()
	q := e.takeQueue()
	n := len(q)
	if first {
		n++
	}
	if stopping || t.stopped {
		s.remove(e)
		t.mu.Unlock()
		s.f.flows.Add(-1)
		u.dropOpenQueue.Add(uint64(n)) // discarded at the stop
	} else {
		s.setState(e, FlowHeld)
		t.mu.Unlock()
		u.dropHeld.Add(uint64(n))
	}
	freeQueue(q)
	if !stopping {
		s.hold(e)
	}
}

// hold waits out e's hold (ingressHold), its eviction (done) or the stop,
// then removes the entry unless an eviction already did (R1-5).
func (s *udpServe) hold(e *ingressFlow) {
	tm := time.NewTimer(ingressHold)
	select {
	case <-tm.C:
	case <-e.done:
	case <-s.ctx.Done():
	}
	tm.Stop()
	t := &s.tab
	t.mu.Lock()
	gone := e.gone
	s.remove(e)
	t.mu.Unlock()
	if !gone {
		s.f.flows.Add(-1)
	}
}

// shutdown ends every flow after the reader returned (L52): no entry
// becomes open or held any more, the opens and holds are cancelled, every
// session in the table closed (the open flows', and a held one's whose
// goroutine may still wait in ReadFrom); it returns when every flow
// goroutine has.
func (s *udpServe) shutdown() {
	s.cancel()
	t := &s.tab
	t.mu.Lock()
	t.stopped = true
	type open struct {
		e  *ingressFlow
		pc ingressSession
	}
	var es []open
	for _, e := range t.m {
		if e.pc != nil {
			es = append(es, open{e, e.pc})
		}
	}
	t.mu.Unlock()
	for _, o := range es {
		o.e.closeSession(o.pc)
	}
	s.wg.Wait()
}

// count adds one ended flow by the cause its session reported and returns
// that cause: err is ReadFrom's end (or net.ErrClosed when the stop closed
// it before it was open); evicted: the close of an eviction ended it.
func (c *flowEndCounts) count(err error, evicted bool) endCause {
	var abort *rendr.AbortError
	switch {
	case evicted:
		c.evicted.Add(1)
		return endEvicted
	case errors.Is(err, rendr.ErrIdleTimeout):
		c.idle.Add(1)
		return endIdle
	case errors.As(err, &abort) && abort.Code == rendr.AbortIdle:
		c.peerIdle.Add(1)
		return endPeerIdle
	case errors.As(err, &abort) && abort.Code == rendr.AbortGoingAway:
		c.goingAway.Add(1)
		return endGoingAway
	case errors.Is(err, io.EOF):
		c.peerClosed.Add(1)
		return endPeerClosed
	case errors.Is(err, rendr.ErrNoPath):
		c.noPath.Add(1)
		return endNoPath
	case errors.Is(err, rendr.ErrSessionLost):
		c.sessionLost.Add(1)
		return endSessionLost
	case errors.Is(err, net.ErrClosed):
		c.stopped.Add(1) // closed on this side: the stop, or this side's Runtime closed
		return endStopped
	}
	c.other.Add(1)
	return endOther
}

// sessionDrops sums a packet session's drop counters (R1-38).
func sessionDrops(p *rendr.PacketCounters) uint64 {
	return p.DropQueue + p.DropAge + p.DropTooLarge + p.DropNoPath + p.DropRecvQueue + p.DropLate
}
