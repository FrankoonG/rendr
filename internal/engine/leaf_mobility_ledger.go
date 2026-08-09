package engine

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/FrankoonG/rendr/proto"
)

const (
	leafMobilityPeerLedgerLimit       = 4096
	leafMobilityPeerLedgerGlobalLimit = 65536
)

var (
	ErrLeafMobilityPeerGenerationStale     = errors.New("engine: leaf mobility peer generation is stale")
	ErrLeafMobilityPeerTransactionBusy     = fmt.Errorf("%w: leaf mobility peer generation has another transaction", ErrLeafMobilityAuthorityBusy)
	ErrLeafMobilityPeerTransactionClosed   = errors.New("engine: leaf mobility peer generation transaction is closed")
	ErrLeafMobilityPeerTransactionRequired = errors.New("engine: leaf mobility peer generation transaction is required")
)

type leafMobilityPeerLedgerKey struct {
	peer     proto.InstanceID
	session  proto.SessionEpoch
	actor    proto.LeafMobilityActorSide
	resource proto.LeafMobilityResourceID
}

type leafMobilityPeerLedgerSession struct {
	peer    proto.InstanceID
	session proto.SessionEpoch
}

type leafMobilityPeerLedgerEntry struct {
	generation uint64

	activeTransaction [16]byte
	activeBase        uint64

	lastAdvancedTransaction [16]byte
	lastAdvancedBase        uint64
}

type leafMobilityPeerGenerationReservation struct {
	ledger        *LeafMobilityPeerLedger
	key           leafMobilityPeerLedgerKey
	transactionID [16]byte
	base          uint64
}

type leafMobilityPeerLedgerError struct {
	op        string
	cause     error
	base      uint64
	current   uint64
	currentOK bool
}

func (e *leafMobilityPeerLedgerError) Error() string {
	if e.currentOK {
		return fmt.Sprintf("leaf mobility peer ledger %s: base=%d current=%d: %v", e.op, e.base, e.current, e.cause)
	}
	return fmt.Sprintf("leaf mobility peer ledger %s: base=%d: %v", e.op, e.base, e.cause)
}

func (e *leafMobilityPeerLedgerError) Unwrap() error { return e.cause }

// LeafMobilityPeerLedger is owned by one public Runtime. It preserves the
// peer-visible generation of shared/process resources across Engine/session
// replacement without introducing process-global state. Entries live for the
// Runtime's entire lifetime; wall-clock time never makes an old generation
// acceptable again.
type LeafMobilityPeerLedger struct {
	mu          sync.Mutex
	entries     map[leafMobilityPeerLedgerKey]leafMobilityPeerLedgerEntry
	sessions    map[leafMobilityPeerLedgerSession]uint64
	entryCounts map[leafMobilityPeerLedgerSession]int
}

func NewLeafMobilityPeerLedger() *LeafMobilityPeerLedger {
	return &LeafMobilityPeerLedger{
		entries:     make(map[leafMobilityPeerLedgerKey]leafMobilityPeerLedgerEntry),
		sessions:    make(map[leafMobilityPeerLedgerSession]uint64),
		entryCounts: make(map[leafMobilityPeerLedgerSession]int),
	}
}

func (l *LeafMobilityPeerLedger) retainSession(peer proto.InstanceID, session proto.SessionEpoch) {
	if l == nil || peer == (proto.InstanceID{}) || session == (proto.SessionEpoch{}) {
		return
	}
	key := leafMobilityPeerLedgerSession{peer: peer, session: session}
	l.mu.Lock()
	l.sessions[key]++
	l.mu.Unlock()
}

func (l *LeafMobilityPeerLedger) releaseSession(peer proto.InstanceID, session proto.SessionEpoch) {
	if l == nil || peer == (proto.InstanceID{}) || session == (proto.SessionEpoch{}) {
		return
	}
	key := leafMobilityPeerLedgerSession{peer: peer, session: session}
	l.mu.Lock()
	refs := l.sessions[key]
	if refs > 1 {
		l.sessions[key] = refs - 1
		l.mu.Unlock()
		return
	}
	delete(l.sessions, key)
	for entryKey := range l.entries {
		if entryKey.peer == peer && entryKey.session == session {
			delete(l.entries, entryKey)
		}
	}
	delete(l.entryCounts, key)
	l.mu.Unlock()
}

// current is a non-mutating observation. In particular, an unvalidated peer
// request cannot consume ledger capacity merely by naming a resource.
func (l *LeafMobilityPeerLedger) current(key leafMobilityPeerLedgerKey) (uint64, bool) {
	if l == nil {
		return 0, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	return entry.generation, ok
}

// installValidated atomically observes or installs a generation and binds the
// right to advance it to transactionID. Callers must invoke this only after all
// immutable binding, factual-plan, and local resource checks have succeeded.
// A failed pre-commit transaction must release the returned reservation.
func (l *LeafMobilityPeerLedger) installValidated(
	key leafMobilityPeerLedgerKey,
	transactionID [16]byte,
	base uint64,
) (leafMobilityPeerGenerationReservation, error) {
	reservation := leafMobilityPeerGenerationReservation{
		ledger:        l,
		key:           key,
		transactionID: transactionID,
		base:          base,
	}
	if l == nil {
		return leafMobilityPeerGenerationReservation{}, fmt.Errorf("nil leaf mobility peer ledger")
	}
	if transactionID == ([16]byte{}) {
		return leafMobilityPeerGenerationReservation{}, &leafMobilityPeerLedgerError{
			op: "install", cause: ErrLeafMobilityPeerTransactionRequired, base: base,
		}
	}
	if key.peer == (proto.InstanceID{}) || key.session == (proto.SessionEpoch{}) {
		return leafMobilityPeerGenerationReservation{}, &leafMobilityPeerLedgerError{
			op: "install", cause: ErrLeafMobilityPeerTransactionRequired, base: base,
		}
	}
	if base == math.MaxUint64 {
		return leafMobilityPeerGenerationReservation{}, &leafMobilityPeerLedgerError{
			op: "install", cause: ErrLeafMobilityPeerGenerationStale, base: base,
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	if !ok {
		sessionKey := leafMobilityPeerLedgerSession{peer: key.peer, session: key.session}
		if l.entryCounts[sessionKey] >= leafMobilityPeerLedgerLimit ||
			len(l.entries) >= leafMobilityPeerLedgerGlobalLimit {
			return leafMobilityPeerGenerationReservation{}, &leafMobilityPeerLedgerError{
				op: "install", cause: ErrLeafMobilityAuthorityBusy, base: base,
			}
		}
		entry = leafMobilityPeerLedgerEntry{generation: base}
	}

	// Terminal evidence is replayed from the Engine cache. Once that cache is
	// gone, a transaction that already advanced the generation is closed.
	if entry.generation == base+1 &&
		entry.lastAdvancedTransaction == transactionID &&
		entry.lastAdvancedBase == base {
		return leafMobilityPeerGenerationReservation{}, &leafMobilityPeerLedgerError{
			op: "install", cause: ErrLeafMobilityPeerTransactionClosed, base: base,
			current: entry.generation, currentOK: true,
		}
	}
	if entry.activeTransaction != ([16]byte{}) {
		if entry.activeTransaction == transactionID && entry.activeBase == base {
			return reservation, nil
		}
		return leafMobilityPeerGenerationReservation{}, &leafMobilityPeerLedgerError{
			op: "install", cause: ErrLeafMobilityPeerTransactionBusy, base: base,
			current: entry.generation, currentOK: true,
		}
	}
	if entry.generation > base {
		return leafMobilityPeerGenerationReservation{}, &leafMobilityPeerLedgerError{
			op: "install", cause: ErrLeafMobilityPeerGenerationStale, base: base,
			current: entry.generation, currentOK: true,
		}
	}
	if entry.generation < base {
		// The actor owns this generation. It may conservatively consume a
		// proposal that never reached this peer, so an idle peer ledger must
		// catch up monotonically before reserving the next transaction. Older
		// frames remain stale after the fast-forward.
		entry.generation = base
		entry.lastAdvancedTransaction = [16]byte{}
		entry.lastAdvancedBase = 0
	}
	entry.activeTransaction = transactionID
	entry.activeBase = base
	if !ok {
		sessionKey := leafMobilityPeerLedgerSession{peer: key.peer, session: key.session}
		l.entryCounts[sessionKey]++
	}
	l.entries[key] = entry
	return reservation, nil
}

// compareAndAdvance changes base to base+1 exactly once. The resulting
// generation is idempotent only for the transaction that performed the
// advance; a different transaction presenting the old base is stale.
func (l *LeafMobilityPeerLedger) compareAndAdvance(reservation leafMobilityPeerGenerationReservation) error {
	if err := l.validateReservation(reservation, "advance"); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[reservation.key]
	if !ok {
		return &leafMobilityPeerLedgerError{
			op: "advance", cause: ErrLeafMobilityPeerGenerationStale, base: reservation.base,
		}
	}
	next := reservation.base + 1
	if entry.generation == next &&
		entry.lastAdvancedTransaction == reservation.transactionID &&
		entry.lastAdvancedBase == reservation.base {
		return nil
	}
	if entry.generation != reservation.base {
		return &leafMobilityPeerLedgerError{
			op: "advance", cause: ErrLeafMobilityPeerGenerationStale, base: reservation.base,
			current: entry.generation, currentOK: true,
		}
	}
	if entry.activeTransaction != reservation.transactionID || entry.activeBase != reservation.base {
		return &leafMobilityPeerLedgerError{
			op: "advance", cause: ErrLeafMobilityPeerTransactionBusy, base: reservation.base,
			current: entry.generation, currentOK: true,
		}
	}

	entry.generation = next
	entry.activeTransaction = [16]byte{}
	entry.activeBase = 0
	entry.lastAdvancedTransaction = reservation.transactionID
	entry.lastAdvancedBase = reservation.base
	l.entries[reservation.key] = entry
	return nil
}

// release abandons an installed transaction before generation advancement.
// It never rolls a generation back and cannot disturb a newer transaction.
func (l *LeafMobilityPeerLedger) release(reservation leafMobilityPeerGenerationReservation) error {
	if err := l.validateReservation(reservation, "release"); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[reservation.key]
	if !ok {
		return &leafMobilityPeerLedgerError{
			op: "release", cause: ErrLeafMobilityPeerGenerationStale, base: reservation.base,
		}
	}
	if entry.generation == reservation.base+1 &&
		entry.lastAdvancedTransaction == reservation.transactionID &&
		entry.lastAdvancedBase == reservation.base {
		return nil
	}
	if entry.generation != reservation.base {
		return &leafMobilityPeerLedgerError{
			op: "release", cause: ErrLeafMobilityPeerGenerationStale, base: reservation.base,
			current: entry.generation, currentOK: true,
		}
	}
	if entry.activeTransaction == ([16]byte{}) {
		return &leafMobilityPeerLedgerError{
			op: "release", cause: ErrLeafMobilityPeerTransactionClosed, base: reservation.base,
			current: entry.generation, currentOK: true,
		}
	}
	if entry.activeTransaction != reservation.transactionID || entry.activeBase != reservation.base {
		return &leafMobilityPeerLedgerError{
			op: "release", cause: ErrLeafMobilityPeerTransactionBusy, base: reservation.base,
			current: entry.generation, currentOK: true,
		}
	}

	entry.generation = reservation.base + 1
	entry.activeTransaction = [16]byte{}
	entry.activeBase = 0
	entry.lastAdvancedTransaction = reservation.transactionID
	entry.lastAdvancedBase = reservation.base
	l.entries[reservation.key] = entry
	return nil
}

func (l *LeafMobilityPeerLedger) validateReservation(
	reservation leafMobilityPeerGenerationReservation,
	op string,
) error {
	if l == nil || reservation.ledger != l || reservation.transactionID == ([16]byte{}) || reservation.base == math.MaxUint64 ||
		reservation.key.peer == (proto.InstanceID{}) || reservation.key.session == (proto.SessionEpoch{}) {
		return &leafMobilityPeerLedgerError{
			op: op, cause: ErrLeafMobilityPeerTransactionRequired, base: reservation.base,
		}
	}
	return nil
}

func (e *Engine) SetLeafMobilityPeerLedger(ledger *LeafMobilityPeerLedger) {
	if e == nil || ledger == nil || e.closing.Load() {
		return
	}
	e.leafTx.oobMu.Lock()
	e.leafTx.mu.Lock()
	if e.leafTx.peerLedger == ledger {
		e.leafTx.mu.Unlock()
		e.leafTx.oobMu.Unlock()
		return
	}
	if !e.closing.Load() && e.leafTx.sessionLedger == nil && e.leafTx.outgoing == nil &&
		len(e.leafTx.incoming) == 0 && len(e.leafTx.completed) == 0 &&
		len(e.leafTx.rejected) == 0 && len(e.leafTx.actorTerminal) == 0 &&
		len(e.leafTx.oobSeen) == 0 && e.leafTx.messageSeq.Load() == 0 {
		e.leafTx.peerLedger = ledger
	}
	e.leafTx.mu.Unlock()
	e.leafTx.oobMu.Unlock()
}

func (e *Engine) peerLeafLedgerKey(actor proto.LeafMobilityActorSide, resource proto.LeafMobilityResourceID) leafMobilityPeerLedgerKey {
	return leafMobilityPeerLedgerKey{
		peer: e.PeerInstanceID(), session: proto.SessionEpoch(e.FlowID()), actor: actor, resource: resource,
	}
}

func (e *Engine) releaseLeafMobilityPeerLedgerSession() {
	if e == nil {
		return
	}
	e.leafTx.mu.Lock()
	ledger := e.leafTx.sessionLedger
	peer, epoch := e.leafTx.sessionPeer, e.leafTx.sessionEpoch
	e.leafTx.sessionLedger = nil
	e.leafTx.sessionPeer = proto.InstanceID{}
	e.leafTx.sessionEpoch = proto.SessionEpoch{}
	e.leafTx.mu.Unlock()
	if ledger != nil {
		ledger.releaseSession(peer, epoch)
	}
}
