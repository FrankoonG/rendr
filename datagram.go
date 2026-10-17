package rendr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// DatagramCarrier is a factory of datagram carriers to the Peer's rendr
// instance: a net.PacketConn plus the peer address rendr writes to (an L7
// datagram tunnel, a QUIC DATAGRAM connection from the quic module, a raw
// UDP socket from carrier/udp). rendr treats both as untrusted, as
// StreamCarrier: calls are bounded by DialTimeout even when ctx is ignored,
// panics and Goexit are contained, (nil, _, nil) and (pc, nil, nil) are
// errors (pc is closed once), a conn returned late is closed exactly once,
// and conns are used only through the net.PacketConn interface, except the
// sockets package carrier/udp creates.
//
// rendr reads with pc.ReadFrom (datagrams from any source other than peer
// are dropped and counted) and writes every datagram with
// pc.WriteTo(b, peer), so pc must not be a connected UDP socket. One WriteTo
// is one datagram: the conn delivers it whole or not at all and never
// splits or merges datagrams (embedding contract, plan:59). A WriteTo
// refused because the datagram is too large must return an error matching
// ErrDatagramTooLarge (DatagramTooLargeError): the carrier then lowers its
// budget instead of dying. ReadFrom returning (0, addr, nil) is an empty
// datagram, not an error. The conn's own keepalives and idle timeouts must
// exceed PassiveRetain (embedding contract, L26).
//
// Datagram carriers built here serve a passive that uses
// Listener.HandlePacket; carrier/udp's carriers serve a passive that uses
// FromPacketConn (they prefix each datagram with rendr's raw-UDP flow
// header).
type DatagramCarrier struct {
	// Name identifies the factory in Status, PeerStatus and ranking ties;
	// unique and non-empty within a Peer.
	Name string
	// Dial opens one carrier. Required.
	Dial func(ctx context.Context) (net.PacketConn, net.Addr, error)
	// MTU is the largest datagram rendr passes to one WriteTo, in bytes —
	// the carrier's frame budget offer: required, 537–65,507 (NewPeer
	// rejects other values). A packet session carries application datagrams
	// of up to MTU − 25 bytes on it. The quic module sets 1152; carrier/udp
	// sets its MaxDatagram − 9 (its sockets add the 9-byte flow header
	// themselves), clamped in advance to the interface MTU for an IP
	// literal.
	//
	// MTU should be what every carrier of the factory carries: DialPacket's
	// metadata check (an OPEN takes MTU − 99 bytes of metadata at most), the
	// MaxPayload offer and the opening race read it before any carrier
	// exists. A carrier whose transport carries less (a carrier/udp socket
	// clamped at Dial to its interface MTU) offers its own lower budget.
	// When the session's MaxPayload offer came from the datagram factories'
	// budgets (a selector session, or a bond session without a
	// StreamCarrier) that carrier's OPEN lowers it to the carrier's budget
	// − 25, so the session's MaxPayload still fits the carrier that opened
	// it; a bond session with a StreamCarrier keeps Packet.MaxPayload for
	// its stream carriers. Metadata that fits MTU but not such a carrier's
	// budget ends DialPacket with ErrMetadataTooLarge once NoPathGrace
	// passed (on a Peer without a StreamCarrier), instead of at once.
	MTU int
	// Props describe the factory to the scheduler: fate group, cheap
	// subflows, head-of-line coupling. The zero value shares the factory's
	// carriers between the Peer's packet sessions in a fate group of its
	// own.
	Props Props
}

func (DatagramCarrier) isCarrier() {}

// packetSource is a FromPacketConn source.
type packetSource struct{ pc net.PacketConn }

func (packetSource) isSource() {}

// FromPacketConn is a pull source of raw-UDP datagram carriers: one
// goroutine reads pc and demultiplexes the datagrams by rendr's 64-bit flow
// ID (the 9-byte flow header carrier/udp's dialers put in front of every
// datagram). A datagram of an unknown flow creates a flow only when it is a
// complete valid first datagram of a carrier; anything else is dropped and
// counted, and nothing is allocated for it. Flows are bounded: at most 32
// admitting flows per source IP address for OPENs and 32 for JOINs and
// probes, and MaxSessions × MaxCarriersPerSession + Sessionless.Total +
// Handshake.MaxConcurrent flows in all (at most 65,536); a flow's inbox
// holds the datagrams its reader has not taken yet: up to 512 on any
// net.PacketConn, and on a socket from carrier/udp's Listen up to as many
// as fit the socket's read buffer when that is more (see its
// Options.ReadBuffer; drops are counted in Status.Datagram). A flow is
// admitting from its first datagram until a positive verdict was written
// for it or, for an OPEN, until its dialer answered the address check of
// the passive's first answer, which proves that the source receives the
// passive's datagrams: a pending session whose dialer answered it waits
// for Accept in the Listener's AcceptBacklog, not in its address's quota,
// so the dialers behind one NAT address never starve each other, while a
// source that never reads the answers (a blind or spoofed flood) keeps at
// most 32 OPEN flows, pending sessions included. The per-address quota
// therefore protects the backlog only against blind floods: a source that
// answers the check is bounded like a stream Listener's clients — by
// AcceptBacklog per session kind, MaxSessions and the flow bound above —
// so one such address can hold the whole packet backlog, and further
// OPENs, from any address, are then answered CAPACITY. A datagram beyond a
// quota is dropped silently. The defence against such a source is the
// embedder's: authentication in front of the socket and its Accept policy.
//
// Ownership of pc moves to the Listener: Listener.Close stops admitting new
// flows (a new carrier is refused with CAPACITY) and closes pc once its
// last flow ended, so accepted sessions keep their carriers; Runtime.Close
// closes it at once. A pc from carrier/udp's Listen gets allocation-free
// reads and writes and truncation detection; any other net.PacketConn is
// used through its methods only (its ReadFrom may allocate an address per
// datagram).
func FromPacketConn(pc net.PacketConn) Source { return packetSource{pc: pc} }

// HandlePacket pushes one embedder-accepted datagram carrier — a
// net.PacketConn whose datagrams come only from peer, such as a QUIC
// connection's DATAGRAM facade or a per-peer tunnel — into the handshake and
// returns at once. rendr reads with ReadFrom (datagrams from any other
// source are dropped) and writes with WriteTo(b, peer); the conn contract of
// DatagramCarrier applies. On success the Listener owns pc and closes it
// when the carrier ends. On an error — a nil pc or peer, a peer address
// whose String panics, the Listener closed — pc stays the caller's and is
// not closed (unlike Handle, which closes its conn after Close; L57).
func (ln *Listener) HandlePacket(pc net.PacketConn, peer net.Addr) error {
	switch {
	case pc == nil:
		return errNilPacketConn
	case peer == nil:
		return errNilPeer
	}
	// The receive limit is unknown (any offer is accepted, M2-D60); the
	// negotiated budget lowers it before the carrier starts (R1-6). A peer
	// whose String panics fails here, and pc stays the caller's (L57).
	io, err := carrier.NewPacketIO(&ln.rt.cenv, pc, peer, wire.MaxDatagram)
	if err != nil {
		return fmt.Errorf("rendr: HandlePacket: %w", err)
	}
	if !ln.beginHandshake() {
		return net.ErrClosed // unlike Handle, pc stays the caller's (M2-D57)
	}
	ln.rt.startHandshakeDatagram(ln, io, time.Now())
	return nil
}

// Errors of HandlePacket (pc stays the caller's).
var (
	errNilPacketConn = errors.New("rendr: HandlePacket: nil net.PacketConn")
	errNilPeer       = errors.New("rendr: HandlePacket: nil peer address")
)

// DialInfo describes the carrier a factory call is for.
type DialInfo struct {
	Carrier CarrierID // the CarrierID this attempt uses (it appears in Status on both ends)
	Kind    Kind      // the factory's kind
	Probe   bool      // a probe carrier of the Peer health layer (no session)
	Session SessionID // the session the carrier is for; zero for probes
}

// CarrierDialInfo returns the DialInfo of the factory call whose context
// this is (StreamCarrier.Dial and DialEarly, DatagramCarrier.Dial) and true,
// or false for any other context. It lets an embedder label its tunnel
// requests and logs with rendr's carrier and session IDs.
func CarrierDialInfo(ctx context.Context) (DialInfo, bool) {
	d, ok := carrier.DialInfoFrom(ctx)
	if !ok {
		return DialInfo{}, false
	}
	k := Kind(d.Kind)
	if k == 0 {
		k = KindStream // a factory without an explicit kind is a stream factory
	}
	return DialInfo{Carrier: CarrierID(d.Carrier), Kind: k, Probe: d.Probe, Session: SessionID(d.Session)}, true
}

// The packet half of a Listener (M2 design §A5.14): FromPacketConn sources
// and the admitting quota of their flows.
//
// A FromPacketConn socket becomes one udpflow.Source at Listen; its demux
// goroutine (Source.Run, started here for every source, so that its Done
// can close) hands every new flow to newFlow, which starts the flow's
// handshake in a handshake slot. Listener.Close stops the source's
// admission (a new flow's H1 is answered CAPACITY by the source; its socket
// closes after its last flow ended); Runtime.Close aborts it once the
// sessions ended or had the close bound, and joins its Done (M2-D58). The
// Runtime keeps every source whose Done has not closed (Status.Datagram);
// Listen and Status drop the finished ones.

// newSourcesLocked wraps the FromPacketConn sockets of one Listen call in
// sources with the Runtime's flow bounds (M2-D59) and records them; the
// caller holds rt.mu and starts them with the Listener. Finished sources
// are dropped first, so that repeated Listen and Listener.Close keep the
// record bounded by the live sources even when Status is never read.
func (rt *Runtime) newSourcesLocked(pcs []net.PacketConn) []*udpflow.Source {
	if len(pcs) == 0 {
		return nil
	}
	rt.pruneSourcesLocked()
	out := make([]*udpflow.Source, len(pcs))
	for i, pc := range pcs {
		out[i] = udpflow.NewSource(&rt.cenv, pc, rt.eff.flow)
		rt.sources[out[i]] = struct{}{}
	}
	return out
}

// startPacketSources starts the demux loop of every packet source. Run is
// joined through the source's Done (its own bound abandons a ReadFrom that
// ignores the close, L50), not through the Listener's loops: a stopped
// source keeps serving the flows of accepted sessions after Listener.Close.
func (ln *Listener) startPacketSources() {
	for _, src := range ln.psrcs {
		go src.Run(ln.newFlow)
	}
}

// newFlow starts the handshake of a new raw-UDP flow, whose H1 is already
// in its inbox (udpflow.Admit: called on the demux goroutine, never
// blocks). On a closed Listener the flow is closed instead.
func (ln *Listener) newFlow(f *udpflow.Flow) {
	if !ln.beginHandshake() {
		_ = f.Close()
		return
	}
	ln.rt.startHandshakeDatagram(ln, f, time.Now())
}

// liveSourcesLocked returns the FromPacketConn sources whose Done has not
// closed, dropping the others. The caller holds rt.mu (a leaf: the
// sources' own locks are taken afterwards, by datagramStatus).
func (rt *Runtime) liveSourcesLocked() []*udpflow.Source {
	rt.pruneSourcesLocked()
	return mapKeys(rt.sources)
}

// pruneSourcesLocked drops the sources whose Done has closed. The caller
// holds rt.mu.
func (rt *Runtime) pruneSourcesLocked() {
	for src := range rt.sources {
		if isClosed(src.Done()) {
			delete(rt.sources, src)
		}
	}
}

// datagramStatus returns Status.Datagram (M2 design §A5.14): the live
// sources srcs and the sums of their flow counts, and the Runtime-wide
// datagram counters to which sources and datagram carriers add.
func (rt *Runtime) datagramStatus(srcs []*udpflow.Source) DatagramStatus {
	ds := DatagramStatus{Sources: len(srcs)}
	for _, src := range srcs {
		st := src.Stats()
		ds.Flows += st.Flows
		ds.Admitting += st.Admitting
	}
	if d := rt.cenv.Dgram; d != nil {
		ds.Dropped = d.Dropped.Load()
		ds.Truncated = d.Truncated.Load()
		ds.InboxDrops = d.InboxDrops.Load()
		ds.ReadErrors = d.ReadErrors.Load()
		ds.Rebinds = d.Rebinds.Load()
		ds.SendCalls, ds.SentDatagrams, ds.RecvCalls, ds.RecvDatagrams, ds.BatchFallbacks = d.IO.Load()
		ds.ChargeRefused = d.ChargeRefused.Load()
	}
	return ds
}

// flowSet is the record of one passive packet session's raw-UDP flows that
// may still count against their sources' admitting quotas (M2-D59): the
// flows of its OPEN carriers, until Confirm writes their OPEN_ACK(OK)
// (opened). A flow whose dialer answered the address check left its quota
// already (Flow.SourceProven); Admitted is then a no-op.
type flowSet struct {
	flows  []*udpflow.Flow
	opened bool
}

// trackFlows creates the flow record of packet session s, before s becomes
// visible in the table, with the flow of its first OPEN carrier (fl may be
// nil: a HandlePacket conn or a stream carrier). Only the admission creates
// records; Ended (or a lost insert) removes them, so none outlives its
// session.
func (rt *Runtime) trackFlows(s *session.Session, fl *udpflow.Flow) {
	fs := &flowSet{}
	if fl != nil {
		fs.flows = append(fs.flows, fl)
	}
	rt.fmu.Lock()
	rt.pflows[s] = fs
	rt.fmu.Unlock()
}

// untrackFlows removes the record of s (its end, or a lost insert-or-get):
// flows still in it end with their carriers, which leaves the quota.
func (rt *Runtime) untrackFlows(s *session.Session) {
	rt.fmu.Lock()
	delete(rt.pflows, s)
	rt.fmu.Unlock()
}

// holdFlow records the flow of an OPEN carrier that session s took
// (AttachOpen): a pending session's flow waits for Confirm; an opened
// session's OPEN_ACK(OK) follows at once, so the flow leaves its quota
// now, as when s has no record (it ended: the carrier closes anyway).
// A pending session outlives its carriers, so the flows of OPEN carriers
// that died meanwhile (removed: they left the quota already) are dropped
// first: the record holds only flows not yet closed — those of the
// carriers s holds (at most MaxCarriersPerSession) or that are still
// closing, plus this one — however often a dialer parks and retires OPEN
// carriers within AcceptTimeout (invariant 4, W4-L2-1).
func (rt *Runtime) holdFlow(s *session.Session, fl *udpflow.Flow) {
	if fl == nil {
		return
	}
	rt.fmu.Lock()
	fs := rt.pflows[s]
	if fs != nil && !fs.opened {
		fs.flows = slices.DeleteFunc(fs.flows, (*udpflow.Flow).Removed)
		fs.flows = append(fs.flows, fl)
		rt.fmu.Unlock()
		return
	}
	rt.fmu.Unlock()
	fl.Admitted()
}

// flowsOpened releases the quota of every flow of s at Confirm (its
// OPEN_ACK(OK) is the positive verdict, M2-D59); later OPEN carriers of s
// are released when they attach (holdFlow).
func (rt *Runtime) flowsOpened(s *session.Session) {
	rt.fmu.Lock()
	fs := rt.pflows[s]
	if fs == nil {
		rt.fmu.Unlock()
		return
	}
	fs.opened = true
	flows := fs.flows
	fs.flows = nil
	rt.fmu.Unlock()
	for _, fl := range flows {
		fl.Admitted()
	}
}

// sessionKind returns the kind of the passive session s (routeOpen's
// kind check, M2 design §A3.5): datagram for a packet session, which the
// admission records in pflows before it becomes visible and until its
// entry is a tombstone, or which reports it itself (Session.Kind).
func (rt *Runtime) sessionKind(s *session.Session) wire.CarrierKind {
	if s.Kind() == wire.KindDatagram {
		return wire.KindDatagram
	}
	rt.fmu.Lock()
	_, packet := rt.pflows[s]
	rt.fmu.Unlock()
	if packet {
		return wire.KindDatagram
	}
	return wire.KindStream
}

// flowOf returns the raw-UDP flow behind a datagram transport, or nil.
func flowOf(io carrier.PacketIO) *udpflow.Flow {
	fl, _ := io.(*udpflow.Flow)
	return fl
}
