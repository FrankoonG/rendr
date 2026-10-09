package rendrtest

import (
	"context"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// DatagramHubConfig configures a DatagramHub.
type DatagramHubConfig struct {
	Name string
	MTU  int // largest datagram (default 65,507)
	// Queue bounds the datagrams of each client and direction (default
	// 1024) from WriteTo until a reader takes them, transit included, and
	// the foreign datagrams (Spoof, Replay, Flood) the passive socket holds
	// unread; more are dropped.
	Queue int
}

// DatagramHub is an in-memory shared datagram socket (M2 design §A8.1):
// PacketConn is the passive socket for rendr.FromPacketConn; every Dial is
// a client endpoint with its own fake address whose conn adds rendr's
// raw-UDP flow header (a fresh flow ID per Dial) to every datagram it sends
// and strips it from every datagram it receives, as carrier/udp's sockets
// do. Rebind, Spoof, Replay and Flood exercise the demultiplexer inside a
// synctest bubble (L58, L59); real-socket twins of those tests run outside
// bubbles.
//
// Addresses: the passive socket has one address; every client has a port
// of its dialing host's IP address — Dial's clients share host 0's,
// DialFrom(n)'s host n's — and the address under which the passive sees it
// can move (Rebind). A client conn drops
// what arrives with another flow ID, and a datagram the passive sends to
// an address no client has (any longer) is lost. MTU applies to the
// datagram on the wire, flow header included: a client conn refuses a
// larger one with *wire.DatagramTooLargeError{Max: MTU − 9} (the largest
// rendr datagram it takes), the passive socket with {Max: MTU}.
//
// Counters: the client datagrams of both directions are counted per class
// of their client (classified by its first datagram, as DatagramLink);
// Spoofed counts every datagram the hub put into the passive socket from a
// foreign address (Spoof, Replay, Flood), and a Replay also counts as
// Injected in the class of the client it repeats. Spoof and Flood
// datagrams belong to no class.
//
// Memory: for Replay the hub keeps the first 16 datagrams each client sent,
// and every address a client had, for as long as it lives: up to 16 × MTU
// bytes per client (under 20 KiB at carrier/udp's 1232-byte datagrams).
//
// Create a DatagramHub inside the synctest bubble that uses it; Close it
// before the bubble ends.
type DatagramHub struct {
	cfg DatagramHubConfig
	n   *dnet

	sock   *endpoint // the passive socket
	sowner *hsock
	rng    *rand.Rand // flow IDs
	seed   uint64

	// guarded by n.mu
	clients  []*hclient
	addrs    map[netip.AddrPort]*hclient // every address a client had: the current and the moved-away ones
	ports    int                         // client ports handed out
	fq       int                         // foreign datagrams queued at the passive socket
	floodSrc [4]int                      // flood source addresses handed out per address group
	fsent    int                         // flood datagrams sent
	fjoin    int                         // flood JOINs moved off the clients' IP address
	floods   []*hflood
	nflood   uint64

	replayed atomic.Uint64 // datagrams ReplayFlow delivered
}

// Hub address plan (loopback addresses that nothing real answers): the
// passive socket, the clients' shared IP address (client ports below
// floodPortBase, the flood's ports on it from floodPortBase), the foreign
// pool of Spoof and Replay, and the flood's three foreign IP addresses.
const (
	hubSockPool   = 12
	hubClientPool = 11
	hubForeign    = 13
	hubFloodPool  = 14
	floodPortBase = 32000
	hubKeep       = 16   // datagrams per client kept for Replay
	floodCMTU     = 1223 // the frame budget a flood's first datagrams offer (carrier/udp's default)
	floodRetainMs = 34000
)

// hclient is one client endpoint of a hub.
type hclient struct {
	h     *DatagramHub
	ep    *endpoint
	host  int // its dialing host (its IP address)
	flow  uint64
	hdr   [wire.FlowHeaderLen]byte
	ext   *net.UDPAddr // where the passive sees it (moved by Rebind)
	q     [2]int       // datagrams in the hub per direction
	kind  int32
	typed bool
	rec   [][]byte // its first hubKeep datagrams, flow header included
}

// hsock owns the passive socket.
type hsock struct {
	h    *DatagramHub
	kind int32 // kindNone: the socket's own calls count in no class
}

// hflood is one running Flood.
type hflood struct {
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// NewDatagramHub returns a hub.
func NewDatagramHub(cfg DatagramHubConfig) *DatagramHub {
	f := fnv.New64a()
	f.Write([]byte(cfg.Name))
	s := f.Sum64() ^ 0x5bd1e9955bd1e995
	h := &DatagramHub{cfg: cfg, n: newDnet(cfg.Name, cfg.Queue, cfg.MTU, hubForeign),
		rng: rand.New(rand.NewPCG(s, s^0x2545f4914f6cdd1d)), seed: s,
		addrs: make(map[netip.AddrPort]*hclient)}
	h.sowner = &hsock{h: h, kind: kindNone}
	h.sock = h.n.newEndpoint(fakeAddr(hubSockPool, 0), Up.index(), 1, &h.sowner.kind, h.sowner)
	return h
}

// PacketConn returns the hub's passive socket (pass it to
// rendr.FromPacketConn).
func (h *DatagramHub) PacketConn() net.PacketConn { return h.sock }

// Dial is a rendr.DatagramCarrier.Dial: a new client endpoint of dialing
// host 0, returned with the passive socket's address. Its flow ID is fresh
// and never 0.
func (h *DatagramHub) Dial(ctx context.Context) (net.PacketConn, net.Addr, error) {
	return h.dial(ctx, 0)
}

// DialFrom returns a Dial whose clients belong to dialing host n (0–255):
// the clients of one host share its IP address. Host 0 is Dial's and the
// address a Flood's first share comes from, so a session dialled from
// another host takes no room in the per-source OPEN quota that share fills
// (R1-21: a new DialPacket while the victim's own address is flooded). It
// panics for another n.
func (h *DatagramHub) DialFrom(n int) func(ctx context.Context) (net.PacketConn, net.Addr, error) {
	if n < 0 || n > 255 {
		panic("rendrtest: DialFrom: no such host")
	}
	return func(ctx context.Context) (net.PacketConn, net.Addr, error) { return h.dial(ctx, n) }
}

// dial creates a client of host.
func (h *DatagramHub) dial(ctx context.Context, host int) (net.PacketConn, net.Addr, error) {
	n := h.n
	n.dials.Add(1)
	if err := ctx.Err(); err != nil {
		n.dialFails.Add(1)
		return nil, nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		n.dialFails.Add(1)
		return nil, nil, net.ErrClosed
	}
	c := &hclient{h: h, host: host, kind: kindUnknown, flow: h.newFlow()}
	wire.PutFlowHeader(c.hdr[:], c.flow)
	h.move(c)
	c.ep = n.newEndpoint(c.ext, Down.index(), 0, &c.kind, c)
	h.clients = append(h.clients, c)
	n.carriers.Add(1)
	return c.ep, h.sock.laddr, nil
}

// newFlow draws a non-zero flow ID. n.mu held.
func (h *DatagramHub) newFlow() uint64 {
	for {
		if f := h.rng.Uint64(); f != 0 {
			return f
		}
	}
}

// move gives c a fresh address on its host's IP address and maps it; the
// old one stays mapped to c, so that a reply to it is counted as c's loss.
// n.mu held.
func (h *DatagramHub) move(c *hclient) {
	a := hostAddr(c.host, 2000+h.ports%(floodPortBase-2000))
	h.ports++
	ap, _ := apOf(a)
	h.addrs[ap] = c
	c.ext = a
}

// hostAddr is the given port of dialing host n's IP address.
func hostAddr(n, port int) *net.UDPAddr {
	ip := netip.AddrFrom4([4]byte{127, hubClientPool, 0, byte(n)})
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
}

func (c *hclient) first(_ *endpoint, p []byte) {
	if !c.typed {
		c.typed, c.kind = true, classifyDatagram(p)
	}
}

// out sends to the passive socket only, from the client's current
// external address, behind the flow header.
func (c *hclient) out(_ *endpoint, _ []byte, addr net.Addr) (droute, bool) {
	h := c.h
	return droute{dst: h.sock, src: c.ext, dir: Up.index(), cls: c.kind, q: &c.q[Up.index()], pre: c.hdr[:], rec: c},
		sameAddr(addr, h.sock.laddr)
}

// arrive keeps a reply sent to the client's current address with its flow
// ID, without the flow header.
func (c *hclient) arrive(_ *endpoint, dg *dgram) ([]byte, bool) {
	if cur, _ := apOf(c.ext); dg.ext != cur {
		return nil, false // sent to an address the client no longer has
	}
	flow, rest, err := wire.ParseFlowHeader(dg.b)
	if err != nil || flow != c.flow {
		return nil, false
	}
	return rest, true
}

func (c *hclient) gone(*endpoint) {}

// record keeps the client's first datagrams for Replay. n.mu held.
func (c *hclient) record(pre, p []byte) {
	if len(c.rec) < hubKeep {
		c.rec = append(c.rec, append(slices.Clone(pre), p...))
	}
}

func (s *hsock) first(*endpoint, []byte) {}

// out routes a datagram of the passive socket to the client that has (or
// had) the address.
func (s *hsock) out(_ *endpoint, _ []byte, addr net.Addr) (droute, bool) {
	h := s.h
	ap, ok := apOf(addr)
	c := h.addrs[ap]
	if !ok || c == nil {
		return droute{cls: kindOther}, false
	}
	return droute{dst: c.ep, src: h.sock.laddr, dir: Down.index(), cls: c.kind, q: &c.q[Down.index()], ext: ap}, true
}

func (s *hsock) arrive(_ *endpoint, dg *dgram) ([]byte, bool) { return dg.b, true }

func (s *hsock) gone(*endpoint) {}

// SetLoss drops datagrams of direction d with probability p.
func (h *DatagramHub) SetLoss(d Dir, p float64) {
	h.n.mu.Lock()
	h.n.dirs[d.index()].loss = p
	h.n.mu.Unlock()
}

// SetDelay sets the one-way delay and jitter of direction d.
func (h *DatagramHub) SetDelay(d Dir, delay, jitter time.Duration) {
	h.n.mu.Lock()
	p := &h.n.dirs[d.index()]
	p.delay, p.jitter = max(delay, 0), max(jitter, 0)
	h.n.mu.Unlock()
}

// Rebind makes later datagrams of client i (in Dial order) arrive from a
// new address, as a NAT rebinding; replies to the old address are lost.
// The client's own conn keeps its LocalAddr. It panics for an unknown i.
func (h *DatagramHub) Rebind(i int) {
	n := h.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if i < 0 || i >= len(h.clients) {
		panic("rendrtest: Rebind: no such client")
	}
	h.move(h.clients[i])
	n.rebinds.Add(1)
}

// Spoof delivers b to the passive socket from a fresh foreign address.
func (h *DatagramHub) Spoof(b []byte) {
	h.n.mu.Lock()
	defer h.n.mu.Unlock()
	h.foreignIn(time.Now(), b, h.n.foreignAddr(), kindNone)
}

// Replay re-delivers the k-th datagram client i sent (0 = its first) from
// a fresh foreign address (L59: a replay must not move the reply address),
// flow header included. The hub keeps the first 16 datagrams of every
// client; Replay panics for an unknown client or datagram.
func (h *DatagramHub) Replay(i, k int) {
	n := h.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if i < 0 || i >= len(h.clients) || k < 0 || k >= len(h.clients[i].rec) {
		panic("rendrtest: Replay: no such datagram (the first 16 of each client are kept)")
	}
	c := h.clients[i]
	n.count(c.kind, dcInjected, 1)
	if !h.foreignIn(time.Now(), c.rec[k], n.foreignAddr(), c.kind) {
		n.count(c.kind, dcLost, 1)
	}
}

// ReplayFlow re-delivers the datagrams client from sent as client to's,
// rewriting their flow header to to's flow: datagram replay across flows
// (M3 design §A9.2). The datagrams are the first 16 from sent (the ones
// kept for Replay), in order; they arrive at the passive socket at once
// from to's current address, each counted as Injected in to's class and
// in Stats().Replayed (or Lost when to's queue is full or the socket is
// closed). from may equal to. It panics for an unknown client.
func (h *DatagramHub) ReplayFlow(from, to int) {
	n := h.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if from < 0 || from >= len(h.clients) || to < 0 || to >= len(h.clients) {
		panic("rendrtest: ReplayFlow: no such client")
	}
	src, dst := h.clients[from], h.clients[to]
	now, up := time.Now(), Up.index()
	for _, b := range slices.Clone(src.rec) {
		n.count(dst.kind, dcInjected, 1)
		q := &dst.q[up]
		if h.sock.closed || h.sock.killed || *q >= n.queue {
			n.count(dst.kind, dcLost, 1)
			continue
		}
		dg := n.newDgram(len(b))
		copy(dg.b, b)
		wire.PutFlowHeader(dg.b, dst.flow)
		dg.src, dg.cls, dg.q, dg.dir = dst.ext, dst.kind, q, up
		*q++
		h.sock.inject(now, dg)
		h.replayed.Add(1)
	}
}

// foreignIn puts b into the passive socket from src at now, bypassing the
// path; false when the socket is closed or its foreign queue is full.
// n.mu held.
func (h *DatagramHub) foreignIn(now time.Time, b []byte, src *net.UDPAddr, cls int32) bool {
	n := h.n
	if h.sock.closed || h.sock.killed || h.fq >= n.queue {
		return false
	}
	dg := n.newDgram(len(b))
	copy(dg.b, b)
	dg.src, dg.cls, dg.q, dg.dir = src, cls, &h.fq, Up.index()
	h.fq++
	h.sock.inject(now, dg)
	n.spoofed.Add(1)
	return true
}

// FloodMix is the share of each datagram class of a flood (percent).
// Preface is a valid OPEN first datagram, Join a valid JOIN first datagram
// (random session and flow IDs; R1-21: JOIN and probe flows have their own
// per-source quota).
type FloodMix struct {
	Random, BadCRC, Preface, Join int
}

// Flood sends rate datagrams per second to the passive socket from
// rotating foreign addresses: random bytes, valid flow headers with a bad
// frame CRC, and valid first datagrams (OPEN or JOIN) with random IDs
// (L58). stop ends it.
//
// The shares are weights (all zero: Random only). A valid first datagram
// is the flow header, a PREFACE of kind datagram and REL{wire.FirstCseq}
// around an OPEN of a packet session (selector, frame budget offer 1223,
// MaxPayload offer 1198, no metadata) or a JOIN (offer 1223); BadCRC is
// such an OPEN with one bit of its CRC flipped; Random is 1–256 random
// bytes. Sources rotate over four IP addresses: one datagram in four comes
// from the clients' IP address (a port no client has: R1-21's flood "from
// the victim session's own source IP"), the others from three foreign IP
// addresses, each source port used once in a long while. A valid JOIN
// never comes from the clients' IP address — it takes the next foreign one
// instead — because a per-source quota cannot tell a flood's JOINs from a
// client's own (R1-21 floods the victim's address with OPENs, and its JOIN
// must still pass). Every client of host 0 shares that address: once the
// flood's OPENs fill its per-source OPEN quota at a FromPacketConn listener
// (an Accept that takes no session keeps it full), the OPEN of a new
// session dialled from host 0 is dropped like the flood's surplus OPENs
// until the quota has room, while JOINs and probes, which have their own
// quota, pass; a session dialled from another host (DialFrom) is outside
// that quota.
//
// The datagrams arrive at once and count as Spoofed; while the passive
// socket holds Queue foreign datagrams, new ones are dropped uncounted
// (and a flood sends at most Queue datagrams per millisecond). stop waits
// until the flood's goroutine exited (Close stops every flood).
func (h *DatagramHub) Flood(rate float64, mix FloodMix) (stop func()) {
	n := h.n
	n.mu.Lock()
	if n.closed || !(rate > 0) {
		n.mu.Unlock()
		return func() {}
	}
	f := &hflood{stop: make(chan struct{}), done: make(chan struct{})}
	h.floods = append(h.floods, f)
	h.nflood++
	rng := rand.New(rand.NewPCG(h.seed^h.nflood, h.seed+h.nflood))
	n.wg.Add(1)
	n.mu.Unlock()
	go h.floodLoop(f, rate, mix, rng)
	return f.halt
}

// halt ends the flood and waits for its goroutine.
func (f *hflood) halt() {
	f.once.Do(func() { close(f.stop) })
	<-f.done
}

// floodDg is one flood datagram and whether it is a valid JOIN.
type floodDg struct {
	b    []byte
	join bool
}

// floodLoop sends the flood's datagrams on schedule: datagram k at start +
// k/rate, in batches at most every millisecond.
func (h *DatagramHub) floodLoop(f *hflood, rate float64, mix FloodMix, rng *rand.Rand) {
	n := h.n
	defer n.wg.Done()
	defer close(f.done)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	start := time.Now()
	var sent int64
	var batch []floodDg
	for {
		now := time.Now()
		due := int64(float64(now.Sub(start))*rate/float64(time.Second)) + 1
		batch = batch[:0]
		for ; sent < due && len(batch) < n.queue; sent++ { // more could not be queued anyway
			b, join := floodDatagram(rng, mix)
			batch = append(batch, floodDg{b, join})
		}
		n.mu.Lock()
		for _, d := range batch {
			h.foreignIn(now, d.b, h.floodAddr(d.join), kindNone)
		}
		n.mu.Unlock()
		next := start.Add(time.Duration(float64(sent) * float64(time.Second) / rate))
		timer.Reset(max(next.Sub(now), time.Millisecond))
		select {
		case <-f.stop:
			return
		case <-timer.C:
		}
	}
}

// floodAddr hands out the next flood source address: groups 0–3 in turn,
// group 0 on host 0's IP address — a valid JOIN takes the next of
// groups 1–3 instead (see Flood). n.mu held.
func (h *DatagramHub) floodAddr(join bool) *net.UDPAddr {
	g := h.fsent % 4
	h.fsent++
	if g == 0 && join {
		g = 1 + h.fjoin%3
		h.fjoin++
	}
	k := h.floodSrc[g]
	h.floodSrc[g]++
	if g == 0 {
		return hostAddr(0, floodPortBase+k%(65536-floodPortBase))
	}
	ip := netip.AddrFrom4([4]byte{127, hubFloodPool, 0, byte(g)})
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(2000+k%60000)))
}

// floodDatagram draws one flood datagram of the mix; join reports a valid
// JOIN first datagram.
func floodDatagram(rng *rand.Rand, mix FloodMix) (b []byte, join bool) {
	r, bad, pre, jn := max(mix.Random, 0), max(mix.BadCRC, 0), max(mix.Preface, 0), max(mix.Join, 0)
	total := r + bad + pre + jn
	if total == 0 {
		r, total = 1, 1
	}
	switch x := rng.IntN(total); {
	case x < r:
		b := make([]byte, 1+rng.IntN(256))
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		return b, false
	case x < r+bad:
		return firstDatagram(rng, false, true), false
	case x < r+bad+pre:
		return firstDatagram(rng, false, false), false
	default:
		return firstDatagram(rng, true, false), true
	}
}

// firstDatagram builds a dialer's complete first datagram on a raw-UDP
// flow with random IDs: the flow header, a PREFACE of kind datagram and
// REL{wire.FirstCseq} around an OPEN of a packet session or a JOIN, its
// first frame at the PREFACE's fseq; badCRC flips one bit of the frame's
// CRC.
func firstDatagram(rng *rand.Rand, join, badCRC bool) []byte {
	b := make([]byte, wire.FlowHeaderLen+wire.PrefaceLen, wire.FlowHeaderLen+wire.PrefaceLen+wire.FrameOverhead+wire.RelHeadLen+wire.OpenFixedLen)
	wire.PutFlowHeader(b, nonZero64(rng))
	var inst, sid [16]byte
	fillNonZero(rng, inst[:])
	fillNonZero(rng, sid[:])
	pre := b[wire.FlowHeaderLen:]
	wire.PutPreface(pre, &wire.Preface{Kind: wire.KindDatagram, Instance: inst, CarrierID: uint32(nonZero64(rng))})
	var rel [wire.RelHeadLen + wire.OpenFixedLen]byte
	h := wire.RelHead{Cseq: wire.FirstCseq, Type: wire.TypeOpen, Handle: wire.SessionHandle}
	k := wire.RelHeadLen
	if join {
		h.Type = wire.TypeJoin
		k += wire.PutJoin(rel[k:], &wire.Join{SID: sid, Mode: 1, RxNext: floodCMTU})
	} else {
		k += wire.PutOpen(rel[k:], &wire.Open{SID: sid, Kind: wire.KindDatagram, Mode: 1, RetainMs: floodRetainMs,
			Window: floodCMTU, PMTU: floodCMTU - wire.DgramOverhead})
	}
	wire.PutRelHead(rel[:], &h)
	b = wire.AppendFrame(b, wire.Header{Type: wire.TypeRel, Fseq: wire.PrefaceFseq(pre)}, rel[:k])
	if badCRC {
		b[len(b)-1] ^= 0x01
	}
	return b
}

func nonZero64(rng *rand.Rand) uint64 {
	for {
		if v := rng.Uint64(); uint32(v) != 0 {
			return v
		}
	}
}

func fillNonZero(rng *rand.Rand, b []byte) {
	for {
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		for _, x := range b {
			if x != 0 {
				return
			}
		}
	}
}

// Stats returns the hub's counters.
func (h *DatagramHub) Stats() DatagramStats {
	s := h.n.stats()
	s.Replayed = h.replayed.Load()
	return s
}

// Close closes every endpoint and joins every goroutine the hub started.
// The conns fail with net.ErrClosed from then on (their first Close still
// succeeds), floods stop and later Dials fail. Idempotent.
func (h *DatagramHub) Close() error {
	n := h.n
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	floods := h.floods
	h.floods = nil
	for _, e := range slices.Clone(n.eps) {
		e.shut(true)
	}
	n.mu.Unlock()
	for _, f := range floods {
		f.halt()
	}
	n.wg.Wait()
	return nil
}
