// Package testhooks lets module tests build a Runtime with unclamped timing,
// changed internal constants, preset counters, a deterministic jitter source
// and named interleaving hooks (plan §4: "单元测试通过 internal/testhooks
// 设置不受钳制的值"). It is a standard-library-only leaf package; only this
// module can import it, and nothing in it is reachable through the public
// API.
//
// Production code never reads Overrides on a hot path: package rendr folds
// them into the effective parameter structs when the Runtime is built, and
// the Hooks pointer is nil unless a test installed it (one nil check at each
// rare call site).
package testhooks

import (
	"errors"
	"time"
)

// Overrides are applied after config normalization, bypassing every clamp
// and cross-parameter constraint, and are never listed in
// Status.ConfigAdjustments. A zero field keeps the normalized value.
type Overrides struct {
	// Timing (plan §4 parameters).
	NoPathGrace, RejoinBackoffMax, JoinStagger, RetireGrace   time.Duration
	PingBusy, PingIdle, DeadMin, DeadMax, WriteStall          time.Duration
	ProbeInterval, ProbeFresh, ProbeBackoffMax, ProbeDialWait time.Duration
	DialTimeout, Linger, IdleTimeout                          time.Duration
	HandshakeTimeout, AcceptTimeout, SessionlessIdle          time.Duration
	SelectorDwell, SelectorCooldown, SelectorFloor            time.Duration
	SelectorBand                                              float64
	ProbeIdleStop                                             time.Duration // health layer stops probing after this much non-use (5 min)
	RetainSlack                                               time.Duration // replaces the "+5 s" of PassiveRetain (design §7.7)
	AckDelay, RescueMin, AbandonWait, WindowReadvertise       time.Duration

	// Sizes and internal constants (plan §4 "内部常量").
	Window, Segment, BatchBudget, AckEvery, EventQueue, AbandonLimit int
	MaxCarriersPerSession, MaxSessions                               int
	CapFloor, LoadThreshold, MaxBufferedBytes                        int64

	// Aggregator knobs (G9 tuning, plan §4). Zero keeps the default.
	AggWindow, AggMinEarlier, AggShiftRun int
	AggSigmaK                             float64
	AggSigmaFloor                         time.Duration

	// Counter presets (L14). Both Runtimes of a test must use the same values.
	FirstFseq      uint32 // first fseq in each direction of every carrier
	FirstOffset    uint64 // first stream offset of every session
	FirstEpoch     uint32 // first SCHED epoch published by a dialer
	FirstPingID    uint32 // first PING id of every carrier
	FirstCarrierID uint32 // first CarrierID a dialer Runtime allocates
	OffsetLimit    uint64 // offset at which a session ends with RST(AbortExhausted) (2^62)

	// Rand replaces the U[0,1) jitter source (redial backoff, salts are not
	// affected). Nil keeps math/rand/v2.
	Rand func() float64

	// Hooks are deterministic interleaving points; nil = none.
	Hooks *Hooks
}

// Hooks are called at rare points, never with a lock held unless stated.
// A hook may block to hold the caller at that point (the test releases it).
type Hooks struct {
	// ReadDequeued runs in Conn.Read after the bytes were copied out and before
	// the commit that decides "Read won / Close won" (L07).
	ReadDequeued func()
	// DeathObserved runs in the session actor before it handles the death of
	// the carrier with this ID (L21, L27).
	DeathObserved func(carrier uint32)
	// DialResult runs in a dial-attempt goroutine before its result is
	// delivered to the actor (L21).
	DialResult func(carrier uint32)
	// DialStart runs before every factory call with the factory index (L20, L51).
	DialStart func(factory int)
	// BeforeWrite runs in a carrier writer before every physical write with
	// the batch's frame and byte counts (L41, L55).
	BeforeWrite func(carrier uint32, frames, bytes int)
	// EventEnqueued runs after an event was assigned its sequence number
	// (L53), under the event-queue lock: calls are in Seq order, and it runs
	// also for an event dropped because the queue is full (the drop keeps
	// its Seq). It never runs after the queue was closed (such an event gets
	// no Seq), nor in a Runtime without OnEvent (no event gets a Seq).
	// Unlike the other hooks it must not block, and it must not call into
	// rendr: every event producer waits for that lock meanwhile.
	EventEnqueued func(seq uint64)
	// DialBegin runs in Peer.Dial after its entry checks passed and its
	// MaxSessions placeholder was placed, right before beginDial, which
	// joins the Dial to the Runtime's group of in-flight Dials or, once
	// Runtime.Close began, fails it with net.ErrClosed (L52: a Dial racing
	// Runtime.Close).
	DialBegin func()
	// LeavePending runs on a passive session's actor goroutine at each of
	// that session's Registry.Opened and Registry.Ended calls, before its
	// Listener frees the session's backlog slot, if it still holds one, and
	// unlinks it from the Accept queue (L50). It runs once for a session
	// that ends while pending (rejected, refused, withdrawn or shut down)
	// and twice for a confirmed one: at Opened, which frees the slot, and at
	// Ended, when no slot is left.
	LeavePending func(session [16]byte)
}

// ErrNotInstalled is returned by NewRuntime when package rendr is not linked
// into the test binary.
var ErrNotInstalled = errors.New("rendr/testhooks: package rendr is not linked")

var newRuntime func(cfg any, ov *Overrides) (any, error)

// Install registers the constructor NewRuntime forwards to. Package rendr
// calls it exactly once from init; any other caller is a bug.
func Install(f func(cfg any, ov *Overrides) (any, error)) { newRuntime = f }

// NewRuntime builds a *rendr.Runtime from cfg (a rendr.Config) with ov
// applied after normalization. The result must be type-asserted by the
// caller. ov may be nil.
func NewRuntime(cfg any, ov *Overrides) (any, error) {
	if newRuntime == nil {
		return nil, ErrNotInstalled
	}
	return newRuntime(cfg, ov)
}
