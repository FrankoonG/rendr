package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
)

var (
	ErrLeafMobilityNotNegotiated = errors.New("engine: leaf mobility was not negotiated")
	ErrStalePathRef              = errors.New("engine: stale path reference")
)

// PlanLeafMobilityCandidate builds one non-destructive local candidate for an
// exact attached path generation. Session capability only gates fresh endpoint
// preflight; the result is not executable until a peer-plan transaction agrees.
func (e *Engine) PlanLeafMobilityCandidate(
	ctx context.Context,
	ref PathRef,
	transactionID leafmobility.TransactionID,
	direction proto.SenderDirection,
) (leafmobility.Plan, error) {
	if e == nil {
		return leafmobility.Plan{}, ErrStalePathRef
	}
	return e.planLeafMobilityCandidateUntil(
		ctx, ref, transactionID, direction, time.Now().Add(e.limits.MigrationBudget),
	)
}

func (e *Engine) planLeafMobilityCandidateUntil(
	ctx context.Context,
	ref PathRef,
	transactionID leafmobility.TransactionID,
	direction proto.SenderDirection,
	deadline time.Time,
) (leafmobility.Plan, error) {
	if e == nil || ref.ID == 0 || ref.Owner == 0 {
		return leafmobility.Plan{}, ErrStalePathRef
	}
	e.graphMu.RLock()
	localNegotiation := e.localNegotiation
	localSet := e.localNegotiationSet
	peerNegotiation := e.peerNegotiation
	peerSet := e.peerNegotiationSet
	e.graphMu.RUnlock()
	if !localSet || !peerSet {
		return leafmobility.Plan{}, ErrLeafMobilityNotNegotiated
	}
	localSupport := leafmobility.KnownOperationSetFromProtocol(localNegotiation.MobilitySupported)
	peerSupport := leafmobility.KnownOperationSetFromProtocol(peerNegotiation.MobilitySupported)

	e.pathsMu.RLock()
	slot := e.paths[ref.ID]
	if slot == nil || slot.owner != ref.Owner {
		e.pathsMu.RUnlock()
		return leafmobility.Plan{}, ErrStalePathRef
	}
	claim := slot.mobilityClaim
	binding := leafmobility.Binding{
		FlowID:        e.FlowID(),
		LocalTargetID: [16]byte(slot.localTXTargetID),
		PeerTargetID:  [16]byte(slot.peerTXTargetID),
		PathID:        slot.id,
		Owner:         slot.owner,
	}
	e.pathsMu.RUnlock()

	session := leafmobility.SessionStream
	if e.Packetized() {
		session = leafmobility.SessionPacket
	}
	plan, err := leafmobility.PlanCandidate(ctx, claim, leafmobility.PlanRequest{
		TransactionID: transactionID,
		Binding:       binding,
		Direction:     direction,
		Session:       session,
		Deadline:      deadline,
		LocalSupport:  localSupport,
		PeerSupport:   peerSupport,
	})
	if err != nil {
		return leafmobility.Plan{}, err
	}

	e.pathsMu.RLock()
	current := e.paths[ref.ID]
	currentOK := current != nil && current.owner == ref.Owner && current.mobilityClaim == claim
	e.pathsMu.RUnlock()
	if !currentOK {
		return leafmobility.Plan{}, fmt.Errorf("%w: path changed during planning", ErrStalePathRef)
	}
	if plan.Operation != 0 {
		if _, err := e.leafMobilityControlRoutes(ref); err != nil {
			return leafmobility.Plan{}, err
		}
	}
	return plan, nil
}
