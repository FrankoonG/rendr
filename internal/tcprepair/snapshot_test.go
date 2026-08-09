package tcprepair

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func TestSnapshotSealProducesStableDigest(t *testing.T) {
	snapshot := testValidSnapshot()
	wantTuple := snapshot.tuple

	if err := snapshot.seal(); err != nil {
		t.Fatalf("seal() error = %v", err)
	}
	if snapshot.digest == ([32]byte{}) {
		t.Fatal("seal() produced a zero digest")
	}
	if got := snapshot.computeDigest(); got != snapshot.digest {
		t.Fatalf("computeDigest() = %x, want %x", got, snapshot.digest)
	}
	if err := snapshot.valid(); err != nil {
		t.Fatalf("valid() after seal = %v", err)
	}
	if got := snapshot.Tuple(); got != wantTuple {
		t.Fatalf("Tuple() = %+v, want %+v", got, wantTuple)
	}
	if got := snapshot.Digest(); got != snapshot.digest {
		t.Fatalf("Digest() = %x, want %x", got, snapshot.digest)
	}
	if receive, send, unsent := snapshot.QueueBytes(); receive != 4 || send != 6 || unsent != 2 {
		t.Fatalf("QueueBytes() = (%d, %d, %d), want (4, 6, 2)", receive, send, unsent)
	}

	same := testValidSnapshot()
	if err := same.seal(); err != nil {
		t.Fatalf("second seal() error = %v", err)
	}
	if same.digest != snapshot.digest {
		t.Fatalf("equivalent snapshots have different digests: %x != %x", same.digest, snapshot.digest)
	}
}

func TestSnapshotSealAndCloneDeepCopyQueues(t *testing.T) {
	receive := []byte{0x10, 0x20, 0x30, 0x40}
	send := []byte{0x50, 0x60, 0x70, 0x80, 0x90, 0xa0}
	snapshot := testValidSnapshot()
	snapshot.receiveQueue = receive
	snapshot.sendQueue = send
	wantReceive := append([]byte(nil), receive...)
	wantSend := append([]byte(nil), send...)

	if err := snapshot.seal(); err != nil {
		t.Fatalf("seal() error = %v", err)
	}
	receive[0] ^= 0xff
	send[0] ^= 0xff
	if !bytes.Equal(snapshot.receiveQueue, wantReceive) {
		t.Fatalf("sealed receive queue changed through source slice: %x", snapshot.receiveQueue)
	}
	if !bytes.Equal(snapshot.sendQueue, wantSend) {
		t.Fatalf("sealed send queue changed through source slice: %x", snapshot.sendQueue)
	}
	if err := snapshot.valid(); err != nil {
		t.Fatalf("source-slice mutation invalidated sealed snapshot: %v", err)
	}

	clone, err := cloneSnapshot(snapshot)
	if err != nil {
		t.Fatalf("cloneSnapshot() error = %v", err)
	}
	clone.receiveQueue[0] ^= 0xff
	clone.sendQueue[0] ^= 0xff
	if !bytes.Equal(snapshot.receiveQueue, wantReceive) {
		t.Fatalf("clone receive queue aliases source: %x", snapshot.receiveQueue)
	}
	if !bytes.Equal(snapshot.sendQueue, wantSend) {
		t.Fatalf("clone send queue aliases source: %x", snapshot.sendQueue)
	}
	if err := snapshot.valid(); err != nil {
		t.Fatalf("clone mutation invalidated source snapshot: %v", err)
	}
	if err := clone.valid(); !errors.Is(err, ErrSnapshotInvalid) {
		t.Fatalf("mutated clone valid() error = %v, want ErrSnapshotInvalid", err)
	}
}

func TestSnapshotRejectsEveryDigestCoveredMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"local tuple", func(s *Snapshot) { s.tuple.Local = netip.MustParseAddrPort("192.0.2.9:12345") }},
		{"remote tuple", func(s *Snapshot) { s.tuple.Remote = netip.MustParseAddrPort("198.51.100.9:443") }},
		{"receive sequence", func(s *Snapshot) { s.receiveSequence++ }},
		{"send sequence", func(s *Snapshot) { s.sendSequence++ }},
		{"receive queue contents", func(s *Snapshot) { s.receiveQueue[0] ^= 0xff }},
		{"receive queue length", func(s *Snapshot) { s.receiveQueue = append(s.receiveQueue, 0x41) }},
		{"send queue contents", func(s *Snapshot) { s.sendQueue[0] ^= 0xff }},
		{"send queue length", func(s *Snapshot) { s.sendQueue = append(s.sendQueue, 0x42) }},
		{"unsent bytes", func(s *Snapshot) { s.unsentBytes++ }},
		{"option mask", func(s *Snapshot) { s.options.Mask ^= 1 }},
		{"send scale", func(s *Snapshot) { s.options.SendScale++ }},
		{"receive scale", func(s *Snapshot) { s.options.ReceiveScale++ }},
		{"MSS clamp", func(s *Snapshot) { s.options.MSSClamp++ }},
		{"timestamp", func(s *Snapshot) { s.options.Timestamp++ }},
		{"send buffer", func(s *Snapshot) { s.options.SendBuffer++ }},
		{"receive buffer", func(s *Snapshot) { s.options.ReceiveBuffer++ }},
		{"no delay", func(s *Snapshot) { s.options.NoDelay = !s.options.NoDelay }},
		{"send window last sequence", func(s *Snapshot) { s.window.SendWindowLastSequence++ }},
		{"send window", func(s *Snapshot) { s.window.SendWindow++ }},
		{"max window", func(s *Snapshot) { s.window.MaxWindow++ }},
		{"receive window", func(s *Snapshot) { s.window.ReceiveWindow++ }},
		{"receive window update", func(s *Snapshot) { s.window.ReceiveWindowUpdate++ }},
		{"digest", func(s *Snapshot) { s.digest[0] ^= 0xff }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testSealedSnapshot(t)
			test.mutate(snapshot)
			if err := snapshot.valid(); !errors.Is(err, ErrSnapshotInvalid) {
				t.Fatalf("valid() after mutation = %v, want ErrSnapshotInvalid", err)
			}
		})
	}
}

func TestSnapshotInvalidTuplesRejectWithoutPanic(t *testing.T) {
	validLocal := netip.MustParseAddrPort("192.0.2.1:12345")
	validRemote := netip.MustParseAddrPort("198.51.100.2:443")
	ipv4 := netip.MustParseAddr("192.0.2.1")
	ipv6 := netip.MustParseAddr("2001:db8::1")
	tests := []struct {
		name  string
		tuple Tuple
	}{
		{"zero tuple", Tuple{}},
		{"invalid local", Tuple{Remote: validRemote}},
		{"invalid remote", Tuple{Local: validLocal}},
		{"IPv6 local", Tuple{Local: netip.AddrPortFrom(ipv6, 12345), Remote: validRemote}},
		{"IPv6 remote", Tuple{Local: validLocal, Remote: netip.AddrPortFrom(ipv6, 443)}},
		{"zero local port", Tuple{Local: netip.AddrPortFrom(ipv4, 0), Remote: validRemote}},
		{"zero remote port", Tuple{Local: validLocal, Remote: netip.AddrPortFrom(ipv4, 0)}},
	}

	t.Run("nil snapshot", func(t *testing.T) {
		assertSnapshotRejectedWithoutPanic(t, nil)
	})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testValidSnapshot()
			snapshot.tuple = test.tuple
			assertSnapshotRejectedWithoutPanic(t, snapshot)
		})
	}
}

func TestSnapshotAllowsWrappedTCPSequences(t *testing.T) {
	snapshot := testValidSnapshot()
	snapshot.receiveSequence = 1
	snapshot.sendSequence = 0

	if receiveStart := snapshot.receiveSequence - uint32(len(snapshot.receiveQueue)); receiveStart != ^uint32(0)-2 {
		t.Fatalf("receive sequence did not wrap as expected: %d", receiveStart)
	}
	if sendStart := snapshot.sendSequence - uint32(len(snapshot.sendQueue)); sendStart != ^uint32(0)-5 {
		t.Fatalf("send sequence did not wrap as expected: %d", sendStart)
	}
	if err := snapshot.seal(); err != nil {
		t.Fatalf("seal() rejected valid wrapped sequences: %v", err)
	}
	if err := snapshot.valid(); err != nil {
		t.Fatalf("valid() rejected valid wrapped sequences: %v", err)
	}
}

func TestSnapshotQueueBudgetBoundaries(t *testing.T) {
	queue := make([]byte, MaxQueueBytes+1)
	tests := []struct {
		name      string
		configure func(*Snapshot)
		valid     bool
	}{
		{"receive at budget", func(s *Snapshot) { s.receiveQueue = queue[:MaxQueueBytes] }, true},
		{"receive over budget", func(s *Snapshot) { s.receiveQueue = queue[:MaxQueueBytes+1] }, false},
		{"send at budget", func(s *Snapshot) {
			s.sendQueue = queue[:MaxQueueBytes]
			s.unsentBytes = uint32(MaxQueueBytes)
		}, true},
		{"send over budget", func(s *Snapshot) {
			s.sendQueue = queue[:MaxQueueBytes+1]
			s.unsentBytes = 0
		}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testValidSnapshot()
			test.configure(snapshot)
			assertSnapshotStructuralValidity(t, snapshot, test.valid)
		})
	}
}

func TestSnapshotScalarBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		valid  bool
	}{
		{"unsent zero", func(s *Snapshot) { s.unsentBytes = 0 }, true},
		{"unsent equals send queue", func(s *Snapshot) { s.unsentBytes = uint32(len(s.sendQueue)) }, true},
		{"unsent exceeds send queue", func(s *Snapshot) { s.unsentBytes = uint32(len(s.sendQueue) + 1) }, false},
		{"zero MSS", func(s *Snapshot) { s.options.MSSClamp = 0 }, false},
		{"minimum MSS", func(s *Snapshot) { s.options.MSSClamp = 1 }, true},
		{"maximum MSS", func(s *Snapshot) { s.options.MSSClamp = ^uint32(0) }, true},
		{"zero send buffer", func(s *Snapshot) { s.options.SendBuffer = 0 }, false},
		{"minimum send buffer", func(s *Snapshot) { s.options.SendBuffer = 1 }, true},
		{"maximum send buffer", func(s *Snapshot) { s.options.SendBuffer = ^uint32(0) }, true},
		{"zero receive buffer", func(s *Snapshot) { s.options.ReceiveBuffer = 0 }, false},
		{"minimum receive buffer", func(s *Snapshot) { s.options.ReceiveBuffer = 1 }, true},
		{"maximum receive buffer", func(s *Snapshot) { s.options.ReceiveBuffer = ^uint32(0) }, true},
		{"send scale zero", func(s *Snapshot) { s.options.SendScale = 0 }, true},
		{"send scale fourteen", func(s *Snapshot) { s.options.SendScale = 14 }, true},
		{"send scale fifteen", func(s *Snapshot) { s.options.SendScale = 15 }, false},
		{"receive scale zero", func(s *Snapshot) { s.options.ReceiveScale = 0 }, true},
		{"receive scale fourteen", func(s *Snapshot) { s.options.ReceiveScale = 14 }, true},
		{"receive scale fifteen", func(s *Snapshot) { s.options.ReceiveScale = 15 }, false},
		{"unsupported option mask", func(s *Snapshot) { s.options.Mask |= 1 << 7 }, false},
		{"scales without window scale option", func(s *Snapshot) { s.options.Mask &^= optionWindowScale }, false},
		{"zero scales without window scale option", func(s *Snapshot) {
			s.options.Mask &^= optionWindowScale
			s.options.SendScale = 0
			s.options.ReceiveScale = 0
		}, true},
		{"timestamp without timestamp option", func(s *Snapshot) { s.options.Mask &^= optionTimestamps }, false},
		{"zero timestamp without timestamp option", func(s *Snapshot) {
			s.options.Mask &^= optionTimestamps
			s.options.Timestamp = 0
		}, true},
		{"zero windows", func(s *Snapshot) {
			s.window.SendWindowLastSequence = 0
			s.window.SendWindow = 0
			s.window.MaxWindow = 0
			s.window.ReceiveWindow = 0
			s.window.ReceiveWindowUpdate = 0
		}, true},
		{"maximum windows", func(s *Snapshot) {
			s.window.SendWindowLastSequence = ^uint32(0)
			s.window.SendWindow = ^uint32(0)
			s.window.MaxWindow = ^uint32(0)
			s.window.ReceiveWindow = ^uint32(0)
			s.window.ReceiveWindowUpdate = ^uint32(0)
		}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testValidSnapshot()
			test.mutate(snapshot)
			assertSnapshotStructuralValidity(t, snapshot, test.valid)
		})
	}
}

func testValidSnapshot() *Snapshot {
	return &Snapshot{
		tuple: Tuple{
			Local:  netip.MustParseAddrPort("192.0.2.1:12345"),
			Remote: netip.MustParseAddrPort("198.51.100.2:443"),
		},
		receiveSequence: 100,
		sendSequence:    200,
		receiveQueue:    []byte{0x10, 0x20, 0x30, 0x40},
		sendQueue:       []byte{0x50, 0x60, 0x70, 0x80, 0x90, 0xa0},
		unsentBytes:     2,
		options: streamOptions{
			Mask:          optionTimestamps | optionWindowScale,
			SendScale:     3,
			ReceiveScale:  4,
			MSSClamp:      1460,
			Timestamp:     0x11223344,
			SendBuffer:    1 << 20,
			ReceiveBuffer: 1 << 20,
		},
		window: repairWindow{
			SendWindowLastSequence: 300,
			SendWindow:             4096,
			MaxWindow:              8192,
			ReceiveWindow:          16384,
			ReceiveWindowUpdate:    400,
		},
	}
}

func testSealedSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	snapshot := testValidSnapshot()
	if err := snapshot.seal(); err != nil {
		t.Fatalf("seal() error = %v", err)
	}
	return snapshot
}

func assertSnapshotRejectedWithoutPanic(t *testing.T, snapshot *Snapshot) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("invalid snapshot panicked: %v", recovered)
		}
	}()
	_ = snapshot.computeDigest()
	if err := snapshot.seal(); !errors.Is(err, ErrSnapshotInvalid) {
		t.Fatalf("seal() error = %v, want ErrSnapshotInvalid", err)
	}
	if err := snapshot.valid(); !errors.Is(err, ErrSnapshotInvalid) {
		t.Fatalf("valid() error = %v, want ErrSnapshotInvalid", err)
	}
}

func assertSnapshotStructuralValidity(t *testing.T, snapshot *Snapshot, wantValid bool) {
	t.Helper()
	err := snapshot.structurallyValid()
	if wantValid {
		if err != nil {
			t.Fatalf("structurallyValid() error = %v", err)
		}
		return
	}
	if !errors.Is(err, ErrSnapshotInvalid) {
		t.Fatalf("structurallyValid() error = %v, want ErrSnapshotInvalid", err)
	}
}
