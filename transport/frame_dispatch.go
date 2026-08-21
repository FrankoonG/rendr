package transport

import (
	"time"

	"github.com/FrankoonG/rendr/proto"
)

// FrameDispatchKind identifies the ledger role of one DATA write attempt.
// InitialCohort may be observed more than once for race or bond fan-out; it
// does not assert that a particular physical write was globally first.
type FrameDispatchKind uint8

const (
	FrameDispatchKindUnknown FrameDispatchKind = iota
	FrameDispatchKindInitialCohort
	FrameDispatchKindReplay
)

// FrameDispatchAttemptState records what the adapter can prove about one
// authorized physical occurrence. In particular, a batch writer's incomplete
// suffix is Unknown: the completed-prefix contract cannot prove whether the
// transport touched those frames.
type FrameDispatchAttemptState uint8

const (
	FrameDispatchAttemptUnknown FrameDispatchAttemptState = iota
	FrameDispatchAttempted
	FrameDispatchNotAttempted
)

// FrameDispatchAuthorization is a diagnostic snapshot taken at the engine's
// final logical submission boundary. AttemptID identifies the logical
// submission. PhysicalOccurrence, EndpointGeneration, and FrameOffset bind a
// tracer span to one exact endpoint incarnation and contiguous frame suffix.
// A zero PhysicalOccurrence is the logical authorization passed to a
// FrameDispatchWriter; that writer must assign monotonically increasing,
// one-based occurrences before forwarding diagnostics to an endpoint tracer.
// For an ordinary single-route dispatch,
// that boundary is immediately before the physical writer. A race authorizes
// every child in one coherent fanout cohort before any child can produce an
// ACK; each child still receives its own AttemptID and completion.
//
// The snapshot proves that this exact immutable DATA frame still belonged to
// the replay ledger when the physical attempt was committed.
// AdmissionLedgerGeneration records the earlier recursive-dispatch admission;
// LedgerGeneration records the final writer-boundary snapshot.
//
// This contract is observational. Implementations must not use it to alter
// dispatch, ACK, replay, or migration decisions.
type FrameDispatchAuthorization struct {
	Sequence                  uint64
	PublishedNext             uint64
	AckNext                   uint64
	AdmissionLedgerGeneration uint64
	LedgerGeneration          uint64
	AdmissionID               uint64
	AttemptID                 uint64
	PhysicalOccurrence        uint64
	EndpointGeneration        uint64
	FrameOffset               int
	Kind                      FrameDispatchKind
	AuthorizedAt              time.Time
	FrameBytes                int
	FrameDigest               proto.FrameDigest
}

// FrameDispatchCompletion describes the result returned by the physical
// PathConn write associated with one authorization. BytesWrittenKnown is false
// when a batch writer reports only a completed prefix and cannot identify the
// partial suffix. WholeFrameAccepted records the adapter's factual result and
// is independent of Err: io.Writer permits a full byte count with an error.
type FrameDispatchCompletion struct {
	StartedAt         time.Time
	CompletedAt       time.Time
	FrameBytes        int
	BytesWritten      int
	BytesWrittenKnown bool
	WriteCalls        int
	AttemptState      FrameDispatchAttemptState
	// WriteAttempted is true only when AttemptState is
	// FrameDispatchAttempted. False is not proof that no write occurred; callers
	// must inspect AttemptState to distinguish Unknown from NotAttempted.
	WriteAttempted     bool
	WholeFrameAccepted bool
	BatchIndex         int
	BatchSize          int
	Err                error
}

// FrameDispatchSpan binds one physical occurrence to its aggregate contiguous
// write result. One occurrence may contain multiple short io.Writer calls;
// WriteCalls and BytesWritten expose that fact without storing every syscall.
// FinishFrameDispatch is called exactly once and must return promptly without
// calling back into the engine.
type FrameDispatchSpan interface {
	FinishFrameDispatch(FrameDispatchCompletion)
}

// FrameDispatchTracer is an optional diagnostic PathConn extension. The
// engine calls BeginFrameDispatch after its final replay-ledger check. It is
// immediately before Write or WriteFrameBatch for single-route dispatches; a
// race child may have queued after the coherent fanout check. A nil span
// disables completion observation for that occurrence.
//
// Adapters that wrap caller-provided net.Conn values may forward this hook to
// an underlying tracer. Implementations must return promptly and must not call
// back into the engine.
type FrameDispatchTracer interface {
	BeginFrameDispatch(FrameDispatchAuthorization) FrameDispatchSpan
}

// FrameDispatchWriter is an optional atomic DATA-write extension for adapters
// whose physical endpoint can change behind one stable PathConn. The engine
// calls this method instead of separately invoking FrameDispatchTracer and
// PathConn.Write, so authorization can be bound to the exact endpoint
// incarnation and write critical section that performs the I/O.
//
// An implementation that forwards diagnostics to an underlying
// FrameDispatchTracer owns the complete Begin/Finish lifecycle. It must emit
// one span per physical endpoint incarnation if in-place maintenance
// interrupts and resumes a logical write, assigning a distinct
// PhysicalOccurrence and the exact EndpointGeneration and FrameOffset. The
// input follows io.Writer's ownership rule: it must not be retained or
// modified. The engine additionally supplies a defensive copy so a violating
// external adapter cannot corrupt replay-owned bytes. Built-in adapters may use
// a sealed module-internal owned-frame extension. The method must not call back
// into the engine.
type FrameDispatchWriter interface {
	WriteFrameDispatch([]byte, FrameDispatchAuthorization) (int, error)
}
