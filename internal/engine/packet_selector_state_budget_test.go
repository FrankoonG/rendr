package engine

import (
	"testing"

	"github.com/FrankoonG/rendr/transport"
)

type selectorStateBudgetPath struct {
	transport.PathConn
	limit int
}

func (p *selectorStateBudgetPath) MaxFrameSize() int { return p.limit }

func TestPacketPathBudgetIncludesSelectorStateControl(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "budget-root", "budget-a", "budget-b", true)
	e, _ := newRootDeliveryTestEngine(t, manifest, ids["first"])
	e.SetPacketMode()
	required := e.selectorStateControlFrameSize()
	if required <= e.applicationPayloadOverhead() {
		t.Fatalf("selector-state frame=%d DATA overhead=%d", required, e.applicationPayloadOverhead())
	}
	path := &selectorStateBudgetPath{limit: required - 1}
	binding := PathBinding{LocalReceiveFrameCapacity: uint32(path.limit), PeerReceiveFrameCapacity: uint32(path.limit)}
	if _, set, err := e.validatePacketPathFrameLimit(path, binding, &externalPathCallbackOwner{}); err == nil || set {
		t.Fatalf("undersized selector-state path set/error=%t/%v", set, err)
	}
}
