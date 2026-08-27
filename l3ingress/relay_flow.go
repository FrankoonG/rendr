package l3ingress

import "fmt"

// relayFlowKey keeps legacy tuple-only callers isolated from flow-table
// generations. Generation zero is reserved exclusively for that legacy path.
type relayFlowKey struct {
	identity   L3Identity
	generation uint64
}

func relayFlowKeyFromEvent(ev PacketEvent, id L3Identity) (relayFlowKey, error) {
	if ev.Flow.L3Identity != (L3Identity{}) && ev.Flow.L3Identity != id {
		return relayFlowKey{}, sessionErr(
			ReasonSessionIdentityMismatch,
			fmt.Sprintf("packet=%s flow=%s", id.String(), ev.Flow.L3Identity.String()),
		)
	}
	if ev.Ref == (FlowRef{}) {
		return legacyRelayFlowKey(id), nil
	}
	if ev.Ref.Identity != id || ev.Ref.Generation == 0 {
		return relayFlowKey{}, sessionErr(
			ReasonSessionFlowRefMismatch,
			fmt.Sprintf("packet=%s ref=%+v", id.String(), ev.Ref),
		)
	}
	return relayFlowKeyFromRef(ev.Ref), nil
}

func relayFlowKeyFromRef(ref FlowRef) relayFlowKey {
	return relayFlowKey{identity: ref.Identity, generation: ref.Generation}
}

func legacyRelayFlowKey(id L3Identity) relayFlowKey {
	return relayFlowKey{identity: id}
}
