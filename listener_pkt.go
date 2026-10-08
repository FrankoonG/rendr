package rendr

import (
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

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
func (rt *Runtime) holdFlow(s *session.Session, fl *udpflow.Flow) {
	if fl == nil {
		return
	}
	rt.fmu.Lock()
	fs := rt.pflows[s]
	if fs != nil && !fs.opened {
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
