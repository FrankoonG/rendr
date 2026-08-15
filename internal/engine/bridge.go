package engine

import (
	"context"
	"errors"
	"sync"
)

const DefaultBridgeTableCapacity = 4096

var (
	ErrBridgeDuplicate           = errors.New("engine: bridge flow is already reserved or active")
	ErrBridgeSessionConflict     = errors.New("engine: bridge session epoch is already active")
	ErrBridgeTableFull           = errors.New("engine: bridge table is full")
	ErrBridgeInvalidEngine       = errors.New("engine: bridge engine is nil")
	ErrBridgeStaleReservation    = errors.New("engine: bridge reservation is stale or invalid")
	ErrBridgeReservationReplaced = errors.New("engine: bridge reservation changed while waiting")
	ErrBridgeGenerationExhausted = errors.New("engine: bridge reservation generation exhausted")
)

// BridgeEntryState describes the publication state of a BridgeTable entry.
type BridgeEntryState uint8

const (
	BridgeEntryAbsent BridgeEntryState = iota
	BridgeEntryReserved
	BridgeEntryActive
)

// BridgeReservation is the opaque authority to activate, abort, or remove one
// generation of a flow. Its fields are deliberately private so callers cannot
// synthesize authority from a flow ID.
type BridgeReservation struct {
	table      *BridgeTable
	flowID     [16]byte
	generation uint64
}

type bridgeTableEntry struct {
	generation uint64
	sessionID  [16]byte
	state      BridgeEntryState
	engine     *Engine
	changed    chan struct{}
}

// BridgeTable owns the bounded server-side flow publication lifecycle. entries
// is keyed by the client HELLO proposal ID; sessions is keyed by the
// server-assigned final session epoch after activation.
type BridgeTable struct {
	mu             sync.Mutex
	entries        map[[16]byte]*bridgeTableEntry
	sessions       map[[16]byte]*bridgeTableEntry
	capacity       int
	nextGeneration uint64
}

// NewBridgeTable returns an empty table with the default capacity.
func NewBridgeTable() *BridgeTable {
	return NewBridgeTableWithCapacity(DefaultBridgeTableCapacity)
}

// NewBridgeTableWithCapacity returns an empty table with a hard entry limit.
// It panics when capacity is not positive because that is a configuration bug.
func NewBridgeTableWithCapacity(capacity int) *BridgeTable {
	if capacity <= 0 {
		panic("engine: bridge table capacity must be positive")
	}
	return &BridgeTable{
		entries:  make(map[[16]byte]*bridgeTableEntry),
		sessions: make(map[[16]byte]*bridgeTableEntry),
		capacity: capacity,
	}
}

// Reserve atomically claims an absent flow ID. Both reserved and active entries
// reject a duplicate HELLO. The returned token is unique for this table and
// entry generation.
func (b *BridgeTable) Reserve(id [16]byte) (BridgeReservation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.entries[id]; exists {
		return BridgeReservation{}, ErrBridgeDuplicate
	}
	if _, exists := b.sessions[id]; exists {
		return BridgeReservation{}, ErrBridgeSessionConflict
	}
	if len(b.entries) >= b.capacity {
		return BridgeReservation{}, ErrBridgeTableFull
	}
	if b.nextGeneration == ^uint64(0) {
		return BridgeReservation{}, ErrBridgeGenerationExhausted
	}
	b.nextGeneration++
	reservation := BridgeReservation{
		table:      b,
		flowID:     id,
		generation: b.nextGeneration,
	}
	b.entries[id] = &bridgeTableEntry{
		generation: reservation.generation,
		state:      BridgeEntryReserved,
		changed:    make(chan struct{}),
	}
	return reservation, nil
}

// Activate publishes e only when reservation still owns the reserved entry.
func (b *BridgeTable) Activate(reservation BridgeReservation, e *Engine) error {
	return b.ActivateSession(reservation, reservation.flowID, e)
}

// AssignSession reserves a final session epoch before it is published in
// HELLO_ACK. This prevents a random epoch collision from being discovered only
// after the peer has committed path admission.
func (b *BridgeTable) AssignSession(reservation BridgeReservation, sessionID [16]byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.matchLocked(reservation)
	if !ok || entry.state != BridgeEntryReserved {
		return ErrBridgeStaleReservation
	}
	return b.assignSessionLocked(entry, sessionID)
}

// ActivateSession publishes e under a server-assigned final session epoch
// while retaining the HELLO proposal ID as an active duplicate-handshake alias.
func (b *BridgeTable) ActivateSession(reservation BridgeReservation, sessionID [16]byte, e *Engine) error {
	if e == nil {
		return ErrBridgeInvalidEngine
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.matchLocked(reservation)
	if !ok || entry.state != BridgeEntryReserved {
		return ErrBridgeStaleReservation
	}
	if err := b.assignSessionLocked(entry, sessionID); err != nil {
		return err
	}
	entry.engine = e
	entry.state = BridgeEntryActive
	close(entry.changed)
	return nil
}

func (b *BridgeTable) assignSessionLocked(entry *bridgeTableEntry, sessionID [16]byte) error {
	if sessionID == ([16]byte{}) {
		return ErrBridgeSessionConflict
	}
	if entry.sessionID != ([16]byte{}) {
		if entry.sessionID == sessionID {
			return nil
		}
		return ErrBridgeSessionConflict
	}
	if other, exists := b.sessions[sessionID]; exists && other != entry {
		return ErrBridgeSessionConflict
	}
	if other, exists := b.entries[sessionID]; exists && other != entry {
		return ErrBridgeSessionConflict
	}
	entry.sessionID = sessionID
	b.sessions[sessionID] = entry
	return nil
}

// Lookup returns only active engines. A reservation is never externally usable.
func (b *BridgeTable) Lookup(id [16]byte) (*Engine, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.sessions[id]
	if !ok {
		entry, ok = b.entries[id]
	}
	if !ok || entry.state != BridgeEntryActive {
		return nil, false
	}
	return entry.engine, true
}

// WaitActive resolves the generation visible when the call starts. An absent
// flow returns BridgeEntryAbsent immediately. A reserved flow waits for
// activation, abort, removal, or context cancellation; cancellation returns
// BridgeEntryReserved with ctx.Err(). The wait never follows a replacement
// generation, which would attach a path to the wrong session after an ABA.
func (b *BridgeTable) WaitActive(ctx context.Context, id [16]byte) (*Engine, BridgeEntryState, error) {
	b.mu.Lock()
	entry, ok := b.sessions[id]
	if !ok {
		entry, ok = b.entries[id]
	}
	if !ok {
		b.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, BridgeEntryAbsent, err
		}
		return nil, BridgeEntryAbsent, nil
	}
	if err := ctx.Err(); err != nil {
		state := entry.state
		b.mu.Unlock()
		return nil, state, err
	}
	if entry.state == BridgeEntryActive {
		e := entry.engine
		b.mu.Unlock()
		return e, BridgeEntryActive, nil
	}
	generation := entry.generation
	changed := entry.changed
	b.mu.Unlock()

	select {
	case <-changed:
	case <-ctx.Done():
		return nil, BridgeEntryReserved, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, BridgeEntryReserved, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok = b.sessions[id]
	if !ok {
		entry, ok = b.entries[id]
	}
	if !ok {
		return nil, BridgeEntryAbsent, nil
	}
	if entry.generation != generation {
		return nil, entry.state, ErrBridgeReservationReplaced
	}
	if entry.state == BridgeEntryActive {
		return entry.engine, BridgeEntryActive, nil
	}
	return nil, BridgeEntryReserved, ctx.Err()
}

// Abort idempotently releases a matching reservation. Active entries and stale
// tokens are left untouched.
func (b *BridgeTable) Abort(reservation BridgeReservation) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.matchLocked(reservation)
	if !ok || entry.state != BridgeEntryReserved {
		return false
	}
	delete(b.entries, reservation.flowID)
	delete(b.sessions, entry.sessionID)
	close(entry.changed)
	return true
}

// RemoveActive removes an active entry only when both its reservation generation
// and Engine identity match. This comparison prevents stale cleanup from
// deleting a replacement generation.
func (b *BridgeTable) RemoveActive(reservation BridgeReservation, e *Engine) bool {
	if e == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.matchLocked(reservation)
	if !ok || entry.state != BridgeEntryActive || entry.engine != e {
		return false
	}
	delete(b.entries, reservation.flowID)
	delete(b.sessions, entry.sessionID)
	return true
}

func (b *BridgeTable) matchLocked(reservation BridgeReservation) (*bridgeTableEntry, bool) {
	if reservation.table != b || reservation.generation == 0 {
		return nil, false
	}
	entry, ok := b.entries[reservation.flowID]
	if !ok || entry.generation != reservation.generation {
		return nil, false
	}
	return entry, true
}

// Len returns the number of reserved and active entries charged to capacity.
func (b *BridgeTable) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}

// Snapshot returns a copy of active flow IDs. Reserved IDs are not published.
func (b *BridgeTable) Snapshot() [][16]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([][16]byte, 0, len(b.entries))
	for _, entry := range b.entries {
		if entry.state == BridgeEntryActive {
			out = append(out, entry.sessionID)
		}
	}
	return out
}
