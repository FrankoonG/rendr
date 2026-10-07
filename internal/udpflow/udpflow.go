// Package udpflow demultiplexes one shared datagram socket into raw-UDP
// carrier flows: the passive side of rendr.FromPacketConn (M2-D5, M2-D59;
// L50, L57, L58). Every datagram of a flow starts with rendr's 9-byte flow
// header (wire.FlowHeaderLen: version, 64-bit flow ID drawn by the dialer
// from crypto/rand); the rest is rendr bytes.
//
// One goroutine per Source reads the socket and routes each datagram by its
// flow ID into that flow's bounded inbox (tail drop when full or when the
// Budget refuses the buffer, counted). A datagram of an unknown flow
// creates a flow only when its rendr bytes are a complete valid first
// datagram H1 (a PREFACE of kind datagram and exactly one first frame whose
// header and CRC verify): before that nothing is allocated (plan:324).
// Admission is bounded per source IP address (admitting flows: from H1
// until a positive verdict was written, so held carriers of pending
// sessions count too) — separately for flows whose H1 carries an OPEN and
// for those whose H1 carries a JOIN or a probe PING, so that an OPEN flood
// from an address never blocks the JOINs and probes of that address's
// sessions (L48; M2 design Revision 1, R1-21) — and in total; every
// overflow drops silently (no amplification). A closed Listener answers a
// new flow's H1 with a stateless PREFACE_ACK(CAPACITY). Removal deletes a
// flow from the table only if the table still maps its ID to that *Flow
// (pointer compare) and leaves a tombstone of the ID for
// Limits.TombstoneTTL: a late copy of the flow's H1 is dropped instead of
// creating a new flow (R1-11). The package never imports package session
// or the root package.
package udpflow

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Default bounds (M2-D59; testhooks may change them).
const (
	DefaultPerSource     = 32   // admitting OPEN flows per source IP address
	DefaultPerSourceJoin = 32   // admitting JOIN and probe flows per source IP address (R1-21)
	DefaultInbox         = 512  // datagrams queued per flow
	DefaultTombstones    = 4096 // removed flow IDs remembered per source (oldest forgotten first; R1-11)
	MaxFlowsCap          = 65536
)

// Internal bounds of the demultiplexer.
const (
	// defaultTombstoneTTL is the TombstoneTTL of a zero Limits:
	// max(Handshake.Timeout, DialTimeout) + 2 s with the default 10-s
	// timeouts (R1-11). package rendr always sets it.
	defaultTombstoneTTL = 12 * time.Second
	// reserveBufs is the control reserve of one flow: datagrams without a
	// DGRAM frame it may hold in Stages-charged buffers while the Budget
	// refuses inbox buffers (M2-D59; L16).
	reserveBufs = 4
	// minRing is the inbox ring a new flow starts with; it doubles up to
	// Limits.Inbox and never shrinks (no allocation per datagram in steady
	// state, no 512-entry ring per idle flow). The ring is not charged to a
	// Budget: one entry is about 80 bytes, so a flow that once burst to the
	// full inbox keeps about 40 KiB (Inbox 512) until it closes, at most
	// MaxFlows times that per source — bounded by Limits, not counted (the
	// queued datagrams' buffers are charged to Env.Budget).
	minRing = 8
	// backoffMin and backoffMax bound the noise backoff of the demux loop
	// (L58: 5 ms doubling to 100 ms).
	backoffMin = 5 * time.Millisecond
	backoffMax = 100 * time.Millisecond
	// emptyRun and emptyPause are a foreign conn's spin guard: after
	// emptyRun consecutive empty reads the demux pauses emptyPause (fixed,
	// not doubling), so a conn that returns (0, addr, nil) forever cannot
	// spin a core (PA-18, R1-27) and a flood of real empty datagrams cannot
	// slow the shared socket below about emptyRun reads per millisecond
	// (L58). rendr's own socket drops empties without a pause: the kernel
	// returns one only for a real datagram. M2-D86's doubling backoff is the
	// carrier reader's rule; applied to the shared socket's reader it would
	// let a cheap empty flood starve every flow.
	emptyRun   = 64
	emptyPause = time.Millisecond
)

// Limits bound one Source.
type Limits struct {
	// MaxFlows bounds live flows: min(MaxFlowsCap, MaxSessions ×
	// MaxCarriersPerSession + Sessionless.Total + Handshake.MaxConcurrent).
	MaxFlows int
	// PerSource bounds admitting flows per source IP address whose H1
	// carries an OPEN.
	PerSource int
	// PerSourceJoin bounds admitting flows per source IP address whose H1
	// carries a JOIN or a probe PING (R1-21): an OPEN flood never uses it.
	PerSourceJoin int
	// Inbox bounds the datagrams queued per flow (buffers charged to
	// Env.Budget with TryAcquire: a refusal drops the datagram).
	Inbox int
	// TombstoneTTL is how long a removed flow's ID stays refused:
	// max(Handshake.Timeout, DialTimeout) + 2 s, the longest a correct
	// dialer's copies of its H1 can still arrive (R1-11); Tombstones bounds
	// the IDs remembered (DefaultTombstones).
	TombstoneTTL time.Duration
	Tombstones   int
}

// Admit receives every new flow on the demux goroutine, its H1 already in
// its inbox; it must not block (package rendr starts the handshake in a
// handshake slot, or closes the flow).
type Admit func(f *Flow)

// Source is the demultiplexer of one shared socket.
//
// Locks: Source.mu guards the flow table, the per-IP admitting counts, the
// tombstones and the lifecycle; Flow.mu guards one flow's inbox, peer and
// deadlines. The order is Source.mu → Flow.mu; neither is held across a
// socket call or a callback (M2 design §A4.2).
type Source struct {
	env *carrier.Env
	pc  net.PacketConn // a *carrier.OwnedUDPSocket gets the AddrPort fast path; any other conn is used through its methods only (L57)
	lim Limits

	own       *carrier.OwnedUDPSocket // pc when it is exactly rendr's own listening socket, else nil
	maxDgram  int                     // the largest datagram read: own.MaxDatagram(), else wire.MaxDatagram
	dbufs     *carrier.BufPool        // Env.DBufs (a private pool when the Env has none)
	stages    *carrier.Budget         // the account of the spare and the control reserve (Env.Stages, else Env.Budget)
	firstCseq uint32                  // the REL cseq of a valid H1 (Presets.FirstCseq or wire.FirstCseq)
	firstFseq uint32                  // Presets.FirstFseq (0: an H1's first frame carries its PREFACE's fseq)

	halted atomic.Bool   // the socket close started: Run returns, flow writes fail
	killed atomic.Bool   // Abort, a permanent read error or the end of Run: every flow's reads fail
	quit   chan struct{} // closed with halted: ends a backoff sleep

	mu         sync.Mutex
	flows      map[uint64]*Flow
	perIP      map[netip.Addr][2]int32 // admitting flows per source IP address and class
	admitting  int
	tombs      map[uint64]time.Time // removed flow IDs → refused until (R1-11)
	tq         []tomb               // the same IDs, oldest first (from tqHead)
	tqHead     int
	stopped    bool // no admission: Stop, Abort or a permanent error
	closing    bool // the socket close started (exactly once)
	sockDone   bool // the socket's Close returned or was abandoned
	run        runState
	runWatch   *watch
	doneClosed bool
	done       chan struct{}

	dropped, truncated, inboxDrops, readErrors, quotaDrops atomic.Uint64

	ans [wire.FlowHeaderLen + wire.PrefaceLen]byte // the stateless PREFACE_ACK answer (Run goroutine only)
}

// runState is the life of a Source's Run goroutine.
type runState uint8

const (
	runIdle      runState = iota // Run not called yet
	runRunning                   // Run is reading
	runExited                    // Run returned
	runAbandoned                 // Run was stuck in the conn's ReadFrom AbandonWait after the close (L50)
)

// tomb is one removed flow ID and the end of its refusal.
type tomb struct {
	id    uint64
	until time.Time
}

// Admission classes of a new flow (R1-21).
const (
	classOpen = 0 // the H1 carries an OPEN
	classJoin = 1 // the H1 carries a JOIN or a probe PING
)

// NewSource wraps pc; ownership of pc moves to the Source (closed by Stop
// once the last flow ended, or by Abort).
func NewSource(env *carrier.Env, pc net.PacketConn, lim Limits) *Source {
	s := &Source{env: env, pc: pc, lim: lim.normalized(), maxDgram: wire.MaxDatagram,
		dbufs: env.DBufs, stages: env.Stages, firstCseq: env.Presets.FirstCseq, firstFseq: env.Presets.FirstFseq,
		quit: make(chan struct{}), flows: make(map[uint64]*Flow), perIP: make(map[netip.Addr][2]int32),
		tombs: make(map[uint64]time.Time), done: make(chan struct{})}
	if own, ok := pc.(*carrier.OwnedUDPSocket); ok {
		s.own, s.maxDgram = own, own.MaxDatagram()
	}
	if s.dbufs == nil {
		s.dbufs = carrier.NewDatagramBufPool()
	}
	if s.stages == nil {
		s.stages = env.Budget
	}
	if s.firstCseq == 0 {
		s.firstCseq = wire.FirstCseq
	}
	return s
}

// normalized returns l with every unset bound at its default and MaxFlows
// capped at MaxFlowsCap.
func (l Limits) normalized() Limits {
	if l.MaxFlows <= 0 || l.MaxFlows > MaxFlowsCap {
		l.MaxFlows = MaxFlowsCap
	}
	if l.PerSource <= 0 {
		l.PerSource = DefaultPerSource
	}
	if l.PerSourceJoin <= 0 {
		l.PerSourceJoin = DefaultPerSourceJoin
	}
	if l.Inbox <= 0 {
		l.Inbox = DefaultInbox
	}
	if l.TombstoneTTL <= 0 {
		l.TombstoneTTL = defaultTombstoneTTL
	}
	if l.Tombstones <= 0 {
		l.Tombstones = DefaultTombstones
	}
	return l
}

// quota returns the per-IP admitting bound of class c.
func (l *Limits) quota(c uint8) int32 {
	if c == classOpen {
		return int32(l.PerSource)
	}
	return int32(l.PerSourceJoin)
}

// Run is the demux loop (M2 design §A6.2): it reads pc until Abort, Stop
// with no flow left, or a permanent read error (then this source stops; the
// other sources of the Listener go on, L50), admits flows through admit and
// routes datagrams to their inboxes. Transient errors (ICMP class,
// ECONNABORTED on a listening socket, Temporary) back off 5 → 100 ms (L58).
// An *carrier.OwnedUDPSocket classifies its own errors; a foreign conn's
// read and write errors are classified by carrier.ClassifyPacketErr, an
// abort (PacketErrAbort) being noise on the shared socket (integration 1).
func (s *Source) Run(admit Admit) {
	s.mu.Lock()
	if s.run != runIdle {
		s.mu.Unlock()
		return // one loop per source
	}
	s.run = runRunning
	s.mu.Unlock()
	r := &reader{s: s, admit: admit}
	defer r.exit() // also on runtime.Goexit inside the conn's ReadFrom
	if s.own != nil {
		r.loopOwned()
	} else {
		r.loopForeign()
	}
}

// Stop ends admission (a new flow's H1 gets a stateless
// PREFACE_ACK(CAPACITY)); the socket closes once the last flow ended
// (Listener.Close: accepted sessions keep their carriers, plan:471).
func (s *Source) Stop() {
	s.mu.Lock()
	s.stopped = true
	if len(s.flows) == 0 {
		s.closeSocketLocked()
	}
	s.mu.Unlock()
}

// Abort closes the socket at once; every flow's reads fail (Runtime.Close's
// last step).
func (s *Source) Abort() {
	s.mu.Lock()
	s.killLocked()
	s.closeSocketLocked()
	s.mu.Unlock()
}

// Done is closed when Run returned, the socket is closed and every flow
// ended.
func (s *Source) Done() <-chan struct{} { return s.done }

// Stats returns the source's counters (rendr.Status.Datagram).
func (s *Source) Stats() Stats {
	s.mu.Lock()
	st := Stats{Flows: len(s.flows), Admitting: s.admitting}
	s.mu.Unlock()
	st.Dropped = s.dropped.Load()
	st.Truncated = s.truncated.Load()
	st.InboxDrops = s.inboxDrops.Load()
	st.ReadErrors = s.readErrors.Load()
	st.QuotaDrops = s.quotaDrops.Load()
	return st
}

// Stats are one Source's counters.
type Stats struct {
	Flows      int    // live flows, admitting ones included
	Admitting  int    // flows before a positive verdict was written for them (both per-source quotas)
	Dropped    uint64 // datagrams dropped before reaching a flow (malformed, unknown or tombstoned flow, no valid H1, quota, cap)
	Truncated  uint64 // of Dropped: truncated or oversize datagrams
	InboxDrops uint64 // datagrams a full or Budget-refused inbox dropped
	ReadErrors uint64 // transient read errors (backed off)
	QuotaDrops uint64 // of Dropped: valid H1 refused by a per-source quota or MaxFlows
}

// killLocked ends the source for its flows: no admission, and every flow's
// reads fail from now on (Abort, a permanent read error, the end of Run).
func (s *Source) killLocked() {
	s.stopped = true
	if s.killed.Swap(true) {
		return
	}
	for _, f := range s.flows {
		f.wake()
	}
}

// closeSocketLocked starts the socket's close exactly once — whichever of
// Stop's last flow, Abort or the end of Run comes first (A12 #17: the
// shared socket is closed once, never under live flows by Listener.Close).
// The close runs on its own goroutine: a foreign conn's Close may hang
// (abandoned after AbandonWait, L50), and Run, whose read the close should
// end, is abandoned the same way if its ReadFrom ignores the close.
func (s *Source) closeSocketLocked() {
	if s.closing {
		return
	}
	s.closing = true
	s.halted.Store(true)
	close(s.quit)
	if s.run == runRunning {
		s.runWatch = startWatch(s.env.Abandon, s.abandonWait(), s.runStuck)
	}
	go s.closeSocket()
}

// closeSocket closes pc (guarded: a panic is contained, a hang abandoned).
func (s *Source) closeSocket() {
	w := startWatch(s.env.Abandon, s.abandonWait(), s.sockClosed)
	defer func() {
		_ = recover() // a panicking Close still counts as closed
		if w.finish() {
			s.sockClosed()
		}
	}()
	_ = s.pc.Close()
}

// sockClosed records that the socket's Close returned or was abandoned.
func (s *Source) sockClosed() {
	s.mu.Lock()
	s.sockDone = true
	s.checkDoneLocked()
	s.mu.Unlock()
}

// runStuck is the run watch's expiry: Run's ReadFrom ignored the close for
// AbandonWait; it is counted as abandoned and no longer holds up Done.
func (s *Source) runStuck() {
	s.mu.Lock()
	if s.run == runRunning {
		s.run = runAbandoned
		s.checkDoneLocked()
	}
	s.mu.Unlock()
}

// checkDoneLocked closes done once Run returned (or was abandoned), the
// socket is closed and every flow ended.
func (s *Source) checkDoneLocked() {
	if s.doneClosed || !s.sockDone || len(s.flows) != 0 {
		return
	}
	if s.run != runExited && s.run != runAbandoned {
		return
	}
	s.doneClosed = true
	close(s.done)
}

// abandonWait is the bound on joining a goroutine stuck in the conn.
func (s *Source) abandonWait() time.Duration {
	if d := s.env.Timing.AbandonWait; d > 0 {
		return d
	}
	return time.Second
}

// remove deletes f from the table — only if the table still maps f's ID
// to f (pointer compare, L58: a late removal of a dead flow never removes
// a newer flow with the same ID) — and leaves a tombstone of the ID for
// TombstoneTTL (R1-11). f leaves its IP's admitting count either way. The
// socket closes when it was the last flow of a stopped source.
func (s *Source) remove(f *Flow) {
	now := time.Now()
	s.mu.Lock()
	if s.flows[f.id] == f {
		delete(s.flows, f.id)
		s.addTombLocked(f.id, now)
	}
	if f.admitting {
		f.admitting = false
		s.unadmitLocked(f)
	}
	if s.stopped && len(s.flows) == 0 {
		s.closeSocketLocked()
	}
	s.checkDoneLocked()
	s.mu.Unlock()
}

// unadmitLocked takes f out of its IP's admitting count.
func (s *Source) unadmitLocked(f *Flow) {
	s.admitting--
	c := s.perIP[f.ip]
	c[f.cls]--
	if c == [2]int32{} {
		delete(s.perIP, f.ip)
	} else {
		s.perIP[f.ip] = c
	}
}

// addTombLocked refuses id until now + TombstoneTTL, forgetting the
// oldest tombstone when Tombstones are remembered (R1-11).
func (s *Source) addTombLocked(id uint64, now time.Time) {
	for s.tqHead < len(s.tq) && !now.Before(s.tq[s.tqHead].until) {
		s.forgetTombLocked()
	}
	if len(s.tq)-s.tqHead >= s.lim.Tombstones {
		s.forgetTombLocked()
	}
	if s.tqHead > 0 && s.tqHead >= len(s.tq)/2 {
		n := copy(s.tq, s.tq[s.tqHead:])
		clear(s.tq[n:])
		s.tq, s.tqHead = s.tq[:n], 0
	}
	until := now.Add(s.lim.TombstoneTTL)
	s.tq = append(s.tq, tomb{id: id, until: until})
	s.tombs[id] = until
}

// forgetTombLocked drops the oldest tombstone (its map entry only if no
// newer tombstone of the same ID replaced it).
func (s *Source) forgetTombLocked() {
	t := s.tq[s.tqHead]
	s.tq[s.tqHead] = tomb{}
	s.tqHead++
	if u, ok := s.tombs[t.id]; ok && u.Equal(t.until) {
		delete(s.tombs, t.id)
	}
}

// tombLocked reports whether id is tombstoned at now.
func (s *Source) tombLocked(id uint64, now time.Time) bool {
	u, ok := s.tombs[id]
	if !ok {
		return false
	}
	if now.Before(u) {
		return true
	}
	delete(s.tombs, id)
	return false
}

// watch bounds the wait for a goroutine inside an embedder call (L50,
// L52): if finish is not called within d, the goroutine is counted in the
// abandoned-call pool and onAbandon runs (on the timer's goroutine); a
// later finish leaves the pool.
type watch struct {
	state atomic.Uint32 // 0 running, 1 finished in time, 2 abandoned
	timer *time.Timer
	pool  *carrier.AbandonPool
}

func startWatch(pool *carrier.AbandonPool, d time.Duration, onAbandon func()) *watch {
	w := &watch{pool: pool}
	w.timer = time.AfterFunc(d, func() {
		if !w.state.CompareAndSwap(0, 2) {
			return
		}
		if w.pool != nil {
			w.pool.Adopt()
		}
		onAbandon()
	})
	return w
}

// finish reports whether the call returned before its abandonment.
func (w *watch) finish() bool {
	if w.state.CompareAndSwap(0, 1) {
		w.timer.Stop()
		return true
	}
	if w.pool != nil {
		w.pool.Leave()
	}
	return false
}
