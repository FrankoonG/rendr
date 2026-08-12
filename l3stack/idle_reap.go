package l3stack

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/l3ingress"
)

const (
	defaultUDPIdleLifetime          = 30 * time.Second
	defaultTCPUnestablishedLifetime = 10 * time.Second
	defaultClosedFlowRetention      = 5 * time.Minute
	minimumFlowReapCadence          = 10 * time.Millisecond
	maximumFlowReapCadence          = time.Second
)

// FlowLifetimeTuning controls bounded L3 flow retention. Every duration is
// mandatory: zero selects its default and negative values are rejected.
type FlowLifetimeTuning struct {
	// UDPIdle is the maximum interval without ingress or a delivered reply.
	// Zero selects 30 seconds.
	UDPIdle time.Duration
	// TCPUnestablishedIdle bounds pending, denied, orphan, and otherwise
	// unestablished TCP state. Zero selects 10 seconds. Established TCP is
	// retained until its own transport lifecycle closes it.
	TCPUnestablishedIdle time.Duration
	// ClosedRetention bounds diagnostic closed-flow snapshots. Zero selects
	// five minutes.
	ClosedRetention time.Duration
}

// DefaultFlowLifetimeTuning returns the immutable defaults copied by New.
func DefaultFlowLifetimeTuning() FlowLifetimeTuning {
	return FlowLifetimeTuning{
		UDPIdle:              defaultUDPIdleLifetime,
		TCPUnestablishedIdle: defaultTCPUnestablishedLifetime,
		ClosedRetention:      defaultClosedFlowRetention,
	}
}

func normalizeFlowLifetimeTuning(tuning FlowLifetimeTuning) (FlowLifetimeTuning, error) {
	fields := []struct {
		name  string
		value time.Duration
	}{
		{name: "UDPIdle", value: tuning.UDPIdle},
		{name: "TCPUnestablishedIdle", value: tuning.TCPUnestablishedIdle},
		{name: "ClosedRetention", value: tuning.ClosedRetention},
	}
	for _, field := range fields {
		if field.value < 0 {
			return FlowLifetimeTuning{}, fmt.Errorf("l3stack: invalid Config.FlowLifetime.%s: must not be negative", field.name)
		}
	}
	defaults := DefaultFlowLifetimeTuning()
	if tuning.UDPIdle == 0 {
		tuning.UDPIdle = defaults.UDPIdle
	}
	if tuning.TCPUnestablishedIdle == 0 {
		tuning.TCPUnestablishedIdle = defaults.TCPUnestablishedIdle
	}
	if tuning.ClosedRetention == 0 {
		tuning.ClosedRetention = defaults.ClosedRetention
	}
	return tuning, nil
}

func flowReapCadence(tuning FlowLifetimeTuning) time.Duration {
	shortest := tuning.UDPIdle
	if tuning.TCPUnestablishedIdle < shortest {
		shortest = tuning.TCPUnestablishedIdle
	}
	if tuning.ClosedRetention < shortest {
		shortest = tuning.ClosedRetention
	}
	cadence := shortest / 4
	if cadence < minimumFlowReapCadence {
		return minimumFlowReapCadence
	}
	if cadence > maximumFlowReapCadence {
		return maximumFlowReapCadence
	}
	return cadence
}

type gatewayFlowState struct {
	mu          sync.Mutex
	inFlight    map[l3ingress.FlowRef]uint32
	established map[l3ingress.FlowRef]struct{}
	reaping     map[l3ingress.L3Identity]*flowReapClaim
}

type flowReapClaim struct {
	ref  l3ingress.FlowRef
	done chan struct{}
}

// ReapIdle applies protocol-aware idle semantics with one explicit cutoff.
// It is retained as a deterministic administrative hook; Run owns automatic
// scheduling with the configured protocol-specific lifetimes.
func (g *Gateway) ReapIdle(cutoff time.Time) []l3ingress.FlowSnapshot {
	return g.reapIdleCutoffs(cutoff, cutoff)
}

func (g *Gateway) reapFlowLifetimes(now time.Time) []l3ingress.FlowSnapshot {
	if g == nil || g.table == nil {
		return nil
	}
	reaped := g.reapIdleCutoffs(
		now.Add(-g.flowLifetime.UDPIdle),
		now.Add(-g.flowLifetime.TCPUnestablishedIdle),
	)
	g.table.ReapClosed(now.Add(-g.flowLifetime.ClosedRetention))
	return reaped
}

func (g *Gateway) reapIdleCutoffs(udpCutoff, tcpCutoff time.Time) []l3ingress.FlowSnapshot {
	if g == nil || g.table == nil {
		return nil
	}
	var reaped []l3ingress.FlowSnapshot
	for _, candidate := range g.table.Snapshots() {
		var cutoff time.Time
		switch candidate.Flow.L3Identity.Proto {
		case l3ingress.ProtocolUDP:
			cutoff = udpCutoff
		case l3ingress.ProtocolTCP:
			cutoff = tcpCutoff
		default:
			continue
		}
		if candidate.LastSeen.After(cutoff) || !g.claimIdleFlow(candidate.Ref) {
			continue
		}
		closed, ok := g.table.CloseIdleRef(candidate.Ref, cutoff)
		if ok {
			g.closeReapedSession(closed)
			reaped = append(reaped, closed)
		}
		g.finishIdleClaim(candidate.Ref, ok)
	}
	return reaped
}

func (g *Gateway) claimIdleFlow(ref l3ingress.FlowRef) bool {
	flowLock := g.tcpFlowLock(ref.Identity)
	flowLock.Lock()
	defer flowLock.Unlock()

	g.flowState.mu.Lock()
	defer g.flowState.mu.Unlock()
	if g.flowState.reaping[ref.Identity] != nil || g.flowState.inFlight[ref] != 0 {
		return false
	}
	if ref.Identity.Proto == l3ingress.ProtocolTCP {
		for establishedRef := range g.flowState.established {
			if establishedRef.Identity == ref.Identity && establishedRef != ref {
				delete(g.flowState.established, establishedRef)
			}
		}
		if _, established := g.flowState.established[ref]; established {
			return false
		}
	}
	if g.flowState.reaping == nil {
		g.flowState.reaping = make(map[l3ingress.L3Identity]*flowReapClaim)
	}
	g.flowState.reaping[ref.Identity] = &flowReapClaim{ref: ref, done: make(chan struct{})}
	return true
}

func (g *Gateway) finishIdleClaim(ref l3ingress.FlowRef, closed bool) {
	g.flowState.mu.Lock()
	claim := g.flowState.reaping[ref.Identity]
	if claim == nil || claim.ref != ref {
		g.flowState.mu.Unlock()
		return
	}
	if closed {
		delete(g.flowState.established, ref)
		delete(g.flowState.inFlight, ref)
	}
	delete(g.flowState.reaping, ref.Identity)
	close(claim.done)
	g.flowState.mu.Unlock()
}

func (g *Gateway) reapWaitLocked(id l3ingress.L3Identity) <-chan struct{} {
	g.flowState.mu.Lock()
	defer g.flowState.mu.Unlock()
	if claim := g.flowState.reaping[id]; claim != nil {
		return claim.done
	}
	return nil
}

// beginFlowOperationLocked requires ref's identity shard. The order is the
// identity shard, FlowTable validation, then flowState.
func (g *Gateway) beginFlowOperationLocked(ref l3ingress.FlowRef) bool {
	if ref == (l3ingress.FlowRef{}) {
		return false
	}
	if snapshot, ok := g.table.Snapshot(ref.Identity); !ok || snapshot.Ref != ref {
		return false
	}
	g.flowState.mu.Lock()
	defer g.flowState.mu.Unlock()
	if g.flowState.reaping[ref.Identity] != nil {
		return false
	}
	if g.flowState.inFlight == nil {
		g.flowState.inFlight = make(map[l3ingress.FlowRef]uint32)
	}
	g.flowState.inFlight[ref]++
	return true
}

func (g *Gateway) beginFlowOperation(ctx context.Context, ref l3ingress.FlowRef) (bool, error) {
	flowLock := g.tcpFlowLock(ref.Identity)
	for {
		flowLock.Lock()
		wait := g.reapWaitLocked(ref.Identity)
		if wait == nil {
			started := g.beginFlowOperationLocked(ref)
			flowLock.Unlock()
			return started, nil
		}
		flowLock.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

func (g *Gateway) endFlowOperation(ref l3ingress.FlowRef, deliveredReply bool) {
	if deliveredReply {
		g.table.TouchRef(ref)
	}
	g.flowState.mu.Lock()
	if count := g.flowState.inFlight[ref]; count > 1 {
		g.flowState.inFlight[ref] = count - 1
	} else {
		delete(g.flowState.inFlight, ref)
	}
	g.flowState.mu.Unlock()
}

func (g *Gateway) markTCPEstablishedLocked(ref l3ingress.FlowRef) bool {
	if snapshot, ok := g.table.Snapshot(ref.Identity); !ok || snapshot.Ref != ref {
		return false
	}
	g.flowState.mu.Lock()
	defer g.flowState.mu.Unlock()
	if claim := g.flowState.reaping[ref.Identity]; claim != nil {
		return false
	}
	if g.flowState.established == nil {
		g.flowState.established = make(map[l3ingress.FlowRef]struct{})
	}
	g.flowState.established[ref] = struct{}{}
	return true
}

func (g *Gateway) retireFlowState(ref l3ingress.FlowRef) {
	if ref == (l3ingress.FlowRef{}) {
		return
	}
	g.flowState.mu.Lock()
	delete(g.flowState.established, ref)
	if g.flowState.inFlight[ref] == 0 {
		delete(g.flowState.inFlight, ref)
	}
	g.flowState.mu.Unlock()
}

func (g *Gateway) beginUDPReply(ref l3ingress.FlowRef) bool {
	flowLock := g.tcpFlowLock(ref.Identity)
	flowLock.Lock()
	defer flowLock.Unlock()
	return g.beginFlowOperationLocked(ref)
}

type gatewayUDPReplyActivity struct {
	gateway *Gateway
}

func (a gatewayUDPReplyActivity) BeginUDPReply(ref l3ingress.FlowRef) bool {
	return a.gateway != nil && a.gateway.beginUDPReply(ref)
}

func (a gatewayUDPReplyActivity) EndUDPReply(ref l3ingress.FlowRef, delivered bool) {
	if a.gateway != nil {
		a.gateway.endFlowOperation(ref, delivered)
	}
}

func stopAndDrainTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}
