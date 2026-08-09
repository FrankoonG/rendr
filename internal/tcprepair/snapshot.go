package tcprepair

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

const MaxQueueBytes = 64 << 20

const (
	optionTimestamps uint8 = 1 << iota
	optionSACK
	optionWindowScale
	supportedOptionMask = optionTimestamps | optionSACK | optionWindowScale
)

var (
	ErrUnsupported        = errors.New("tcprepair: platform is unsupported")
	ErrIneligibleState    = errors.New("tcprepair: endpoint state is ineligible")
	ErrUnsupportedOption  = errors.New("tcprepair: endpoint uses an unsupported TCP option")
	ErrQueueBudget        = errors.New("tcprepair: queue exceeds snapshot budget")
	ErrSnapshotInvalid    = errors.New("tcprepair: snapshot is invalid")
	ErrSourceStateUnknown = errors.New("tcprepair: source state is unknown")
	ErrSourceClosed       = errors.New("tcprepair: source is closed")
	ErrSourceReleased     = errors.New("tcprepair: source ownership was released")
)

// SourceState reports the only socket ownership facts Capture can prove. An
// unknown state is deliberately not treated as normal: callers must retain
// tuple quarantine and explicitly Resume or close the source before release.
type SourceState uint8

const (
	SourceStateUnknown SourceState = iota
	SourceStateNormal
	SourceStateRepair
	SourceStateClosed
)

// SourceError preserves both the operation failure and the last factual state
// of the exact source lease.
type SourceError struct {
	Op    string
	State SourceState
	Err   error
}

func (err *SourceError) Error() string {
	if err == nil {
		return "tcprepair: source error"
	}
	return fmt.Sprintf("tcprepair: %s source state %d: %v", err.Op, err.State, err.Err)
}

func (err *SourceError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

// CaptureLease owns the destructive state of one exact TCPConn. Copies share
// one token, so Resume and Close remain serialized and idempotent.
type CaptureLease struct {
	token *captureToken
}

type captureToken struct {
	mu       sync.Mutex
	conn     *net.TCPConn
	snapshot *Snapshot
	state    SourceState
	released bool
}

func (lease *CaptureLease) State() SourceState {
	if lease == nil || lease.token == nil {
		return SourceStateUnknown
	}
	lease.token.mu.Lock()
	defer lease.token.mu.Unlock()
	return lease.token.state
}

func (lease *CaptureLease) Snapshot() *Snapshot {
	if lease == nil || lease.token == nil {
		return nil
	}
	lease.token.mu.Lock()
	defer lease.token.mu.Unlock()
	return lease.token.snapshot
}

type Tuple struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
}

func (t Tuple) ValidIPv4() bool {
	return t.Local.IsValid() && t.Remote.IsValid() && t.Local.Addr().Is4() && t.Remote.Addr().Is4() &&
		t.Local.Port() != 0 && t.Remote.Port() != 0
}

// Inspection is a non-destructive eligibility observation. Capture repeats
// every mutable check after entering repair mode; an Inspection is evidence,
// not permission to mutate a socket later.
type Inspection struct {
	Tuple             Tuple
	ReceiveQueueBytes uint32
	SendQueueBytes    uint32
	UnsentBytes       uint32
	OptionsMask       uint8
	SendScale         uint8
	ReceiveScale      uint8
}

type repairWindow struct {
	SendWindowLastSequence uint32
	SendWindow             uint32
	MaxWindow              uint32
	ReceiveWindow          uint32
	ReceiveWindowUpdate    uint32
}

type streamOptions struct {
	Mask          uint8
	SendScale     uint8
	ReceiveScale  uint8
	MSSClamp      uint32
	Timestamp     uint32
	SendBuffer    uint32
	ReceiveBuffer uint32
	NoDelay       bool
	ReuseAddress  bool
	Transparent   bool
}

// Snapshot is an immutable capsule for one established IPv4 TCP endpoint.
// Queue slices are never returned directly, so one capsule can be used by a
// cutover attempt and, if necessary, one rollback restore.
type Snapshot struct {
	tuple Tuple

	receiveSequence uint32
	sendSequence    uint32
	receiveQueue    []byte
	sendQueue       []byte
	unsentBytes     uint32
	options         streamOptions
	window          repairWindow
	digest          [32]byte
}

func (s *Snapshot) Tuple() Tuple {
	if s == nil {
		return Tuple{}
	}
	return s.tuple
}

func (s *Snapshot) Digest() [32]byte {
	if s == nil {
		return [32]byte{}
	}
	return s.digest
}

func (s *Snapshot) QueueBytes() (receive, send, unsent uint32) {
	if s == nil {
		return 0, 0, 0
	}
	return uint32(len(s.receiveQueue)), uint32(len(s.sendQueue)), s.unsentBytes
}

func (s *Snapshot) valid() error {
	if err := s.structurallyValid(); err != nil {
		return ErrSnapshotInvalid
	}
	want := s.computeDigest()
	if want == ([32]byte{}) || want != s.digest {
		return ErrSnapshotInvalid
	}
	return nil
}

func (s *Snapshot) seal() error {
	if err := s.structurallyValid(); err != nil {
		return err
	}
	s.receiveQueue = append([]byte(nil), s.receiveQueue...)
	s.sendQueue = append([]byte(nil), s.sendQueue...)
	s.digest = s.computeDigest()
	return s.valid()
}

func (s *Snapshot) structurallyValid() error {
	if s == nil || !s.tuple.ValidIPv4() {
		return ErrSnapshotInvalid
	}
	if len(s.receiveQueue) > MaxQueueBytes || len(s.sendQueue) > MaxQueueBytes ||
		int(s.unsentBytes) > len(s.sendQueue) || s.options.MSSClamp == 0 || s.options.SendBuffer == 0 ||
		s.options.ReceiveBuffer == 0 || s.options.SendScale > 14 ||
		s.options.ReceiveScale > 14 || s.options.Mask&^supportedOptionMask != 0 ||
		s.options.Mask&optionWindowScale == 0 && (s.options.SendScale != 0 || s.options.ReceiveScale != 0) ||
		s.options.Mask&optionTimestamps == 0 && s.options.Timestamp != 0 {
		return ErrSnapshotInvalid
	}
	return nil
}

func (s *Snapshot) computeDigest() [32]byte {
	if s == nil {
		return [32]byte{}
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("RTS2"))
	if !writeAddrPort(hash, s.tuple.Local) || !writeAddrPort(hash, s.tuple.Remote) {
		return [32]byte{}
	}
	var scalar [8]byte
	for _, value := range []uint32{
		s.receiveSequence, s.sendSequence, s.unsentBytes, s.options.MSSClamp, s.options.Timestamp,
		s.options.SendBuffer, s.options.ReceiveBuffer,
		s.window.SendWindowLastSequence, s.window.SendWindow, s.window.MaxWindow,
		s.window.ReceiveWindow, s.window.ReceiveWindowUpdate,
	} {
		binary.BigEndian.PutUint32(scalar[:4], value)
		_, _ = hash.Write(scalar[:4])
	}
	noDelay := byte(0)
	if s.options.NoDelay {
		noDelay = 1
	}
	reuseAddress := byte(0)
	if s.options.ReuseAddress {
		reuseAddress = 1
	}
	transparent := byte(0)
	if s.options.Transparent {
		transparent = 1
	}
	_, _ = hash.Write([]byte{
		s.options.Mask, s.options.SendScale, s.options.ReceiveScale,
		noDelay, reuseAddress, transparent,
	})
	for _, queue := range [][]byte{s.receiveQueue, s.sendQueue} {
		binary.BigEndian.PutUint64(scalar[:], uint64(len(queue)))
		_, _ = hash.Write(scalar[:])
		_, _ = hash.Write(queue)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeAddrPort(writer byteWriter, value netip.AddrPort) bool {
	if !value.IsValid() || !value.Addr().Is4() {
		return false
	}
	address := value.Addr().As4()
	_, _ = writer.Write(address[:])
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], value.Port())
	_, _ = writer.Write(port[:])
	return true
}

func cloneSnapshot(source *Snapshot) (*Snapshot, error) {
	if err := source.valid(); err != nil {
		return nil, errors.Join(ErrSnapshotInvalid, err)
	}
	clone := *source
	clone.receiveQueue = append([]byte(nil), source.receiveQueue...)
	clone.sendQueue = append([]byte(nil), source.sendQueue...)
	return &clone, nil
}
