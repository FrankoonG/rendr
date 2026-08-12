package engine

import "testing"

func TestReceiveAckPacingPreservesUrgentEvidence(t *testing.T) {
	e := &Engine{}

	e.expectedRecvSeq = 1
	e.noteRecvDataForAckLocked()
	if next, gap, _ := e.receiveAckStateLocked(false); next != 1 || gap {
		t.Fatalf("first burst DATA ACK=(%d,%t), want (1,false)", next, gap)
	}
	for nextSeq := uint64(2); nextSeq < 1+recvAckFrameThreshold; nextSeq++ {
		e.expectedRecvSeq = nextSeq
		e.noteRecvDataForAckLocked()
		if next, gap, _ := e.receiveAckStateLocked(false); next != 0 || gap {
			t.Fatalf("coalesced DATA frontier %d ACK=(%d,%t), want no ACK", nextSeq, next, gap)
		}
	}
	e.expectedRecvSeq = 1 + recvAckFrameThreshold
	e.noteRecvDataForAckLocked()
	if next, gap, _ := e.receiveAckStateLocked(false); next != e.expectedRecvSeq || gap {
		t.Fatalf("threshold DATA ACK=(%d,%t), want (%d,false)", next, gap, e.expectedRecvSeq)
	}

	// One pacing tick ends the old burst. The first DATA that can prove
	// post-migration payload must be acknowledged immediately for zombie
	// accounting, regardless of the ordinary frame threshold.
	e.recvAckBurstOpen = false
	e.expectedRecvSeq++
	e.noteRecvDataForAckLocked()
	if next, gap, _ := e.receiveAckStateLocked(false); next != e.expectedRecvSeq || gap {
		t.Fatalf("new burst DATA ACK=(%d,%t), want (%d,false)", next, gap, e.expectedRecvSeq)
	}

	e.expectedRecvSeq++
	e.recvControlAckPending = true
	if next, gap, _ := e.receiveAckStateLocked(false); next != e.expectedRecvSeq || gap {
		t.Fatalf("sequenced CTRL ACK=(%d,%t), want (%d,false)", next, gap, e.expectedRecvSeq)
	}
}

func TestReceiveSlotSnapshotReusesStableScratch(t *testing.T) {
	e := &Engine{
		paths:         map[uint32]*pathSlot{3: {id: 3}, 1: {id: 1}},
		stagedPaths:   map[uint32]*pathSlot{4: {id: 4}},
		retainedPaths: map[uint32]*pathSlot{2: {id: 2}},
	}
	scratch := make([]*pathSlot, 0, 4)
	scratch = e.recvSlotsSnapshotInto(scratch)
	for index, slot := range scratch {
		if want := uint32(index + 1); slot == nil || slot.id != want {
			t.Fatalf("slot[%d]=%v, want ID %d", index, slot, want)
		}
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		scratch = e.recvSlotsSnapshotInto(scratch[:0])
	}); allocations != 0 {
		t.Fatalf("stable receive-slot snapshot allocated %.2f objects", allocations)
	}
}
