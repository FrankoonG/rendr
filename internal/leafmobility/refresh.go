package leafmobility

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// RefreshReason identifies a factual endpoint-environment change. It is an
// input to fresh planning, never a mobility operation or execution authority.
type RefreshReason uint8

const (
	RefreshReasonInvalid                RefreshReason = 0
	RefreshReasonRouteSourceChanged     RefreshReason = 1
	RefreshReasonRouteSourceUnavailable RefreshReason = 2
	RefreshReasonRouteSourceRestored    RefreshReason = 3
	RefreshReasonLinkUnresponsive       RefreshReason = 4
	RefreshReasonLocalReadFailure       RefreshReason = 5
	RefreshReasonLocalWriteFailure      RefreshReason = 6
	RefreshReasonOuterMTUFailure        RefreshReason = 7
	RefreshReasonReplayStalled          RefreshReason = 8
	RefreshReasonReplayFailure          RefreshReason = 9
	RefreshReasonLivenessProbeFailure   RefreshReason = 10
)

var (
	ErrInvalidRefreshEvidence   = errors.New("leafmobility: invalid refresh evidence")
	ErrRefreshEvidenceStale     = errors.New("leafmobility: refresh evidence is stale")
	ErrRefreshSourceUnavailable = errors.New("leafmobility: refresh source is unavailable")
)

// RefreshSource is implemented by an owned leaf that can prove a factual
// environment change while its endpoint is still alive. Implementations must
// make callbacks non-blocking with respect to carrier I/O, abort setup when the
// context is canceled, and return a non-blocking idempotent cancel function.
type RefreshSource interface {
	SubscribeLeafMobilityRefresh(context.Context, func(RefreshEvidence)) (cancel func(), err error)
}

// RefreshCommitter advances an adapter's physical-incarnation comparison
// baseline only after the corresponding specialized transaction committed.
type RefreshCommitter interface {
	CommitLeafMobilityRefresh(RefreshEvidence) error
}

type refreshEvidenceToken struct {
	claim  *Claim
	source *RefreshSourceState
}

// RefreshSourceState is an adapter-owned monotonic factual state. A source
// advances it whenever its exact migration key changes and invalidates it when
// no usable replacement path can be proved. The digest never leaves this
// internal package through Engine or public status APIs.
type RefreshSourceState struct {
	mu         sync.RWMutex
	generation uint64
	digest     [32]byte
	valid      bool
	usable     bool
}

// RefreshSourceSnapshot is an opaque value bound to one source-state version.
type RefreshSourceSnapshot struct {
	state      *RefreshSourceState
	generation uint64
	digest     [32]byte
	usable     bool
}

// RefreshEmitter mints evidence bound to one exact Claim. It may be created
// before the Claim is bound, but Observe succeeds only for a live, bound Claim
// whose physical incarnation can be read.
type RefreshEmitter struct {
	token *refreshEvidenceToken
}

// RefreshEvidence is copy-safe opaque evidence. Callers can inspect stable
// metadata, but only ValidateFor can prove that it still describes the exact
// current Claim and physical endpoint incarnation.
type RefreshEvidence struct {
	token              *refreshEvidenceToken
	generation         uint64
	endpointGeneration uint64
	incarnation        uint64
	source             RefreshSourceSnapshot
	reason             RefreshReason
	observedAt         time.Time
}

var refreshEvidenceGeneration atomic.Uint64

var refreshSourceGeneration atomic.Uint64

func NewRefreshSourceState() *RefreshSourceState { return &RefreshSourceState{} }

// Update publishes a usable exact migration key and returns its current opaque
// snapshot. Repeating the same usable key is idempotent.
func (s *RefreshSourceState) Update(digest [32]byte) (RefreshSourceSnapshot, error) {
	if s == nil || digest == ([32]byte{}) {
		return RefreshSourceSnapshot{}, ErrInvalidRefreshEvidence
	}
	s.mu.Lock()
	if !s.valid || !s.usable || s.digest != digest {
		s.generation = nextRefreshSourceGeneration()
		s.digest = digest
		s.valid = true
		s.usable = true
	}
	snapshot := RefreshSourceSnapshot{state: s, generation: s.generation, digest: s.digest, usable: s.usable}
	s.mu.Unlock()
	return snapshot, nil
}

// MarkUnavailable publishes a current factual state without an executable
// replacement. The returned transition bit is false for repeated observations
// of the same unavailable episode.
func (s *RefreshSourceState) MarkUnavailable() (RefreshSourceSnapshot, bool, error) {
	if s == nil {
		return RefreshSourceSnapshot{}, false, ErrInvalidRefreshEvidence
	}
	s.mu.Lock()
	changed := !s.valid || s.usable
	if changed {
		s.generation = nextRefreshSourceGeneration()
		s.digest = [32]byte{}
		s.valid = true
		s.usable = false
	}
	snapshot := RefreshSourceSnapshot{state: s, generation: s.generation, digest: s.digest, usable: s.usable}
	s.mu.Unlock()
	return snapshot, changed, nil
}

// Invalidate revokes every previously minted snapshot without creating
// replacement evidence.
func (s *RefreshSourceState) Invalidate() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.valid {
		s.generation = nextRefreshSourceGeneration()
		s.digest = [32]byte{}
		s.valid = false
		s.usable = false
	}
	s.mu.Unlock()
}

// DigestForCommit returns the current source digest only when evidence still
// names this exact source generation. Claim generation is deliberately not
// revalidated: a successful commit has already advanced it.
func (s *RefreshSourceState) DigestForCommit(evidence RefreshEvidence) ([32]byte, error) {
	var digest [32]byte
	err := s.CommitCurrent(evidence, func(current [32]byte) { digest = current })
	return digest, err
}

// CommitCurrent runs commit while the evidence's source generation remains
// current. The callback must not call back into this source state or block on
// work that depends on a new source observation.
func (s *RefreshSourceState) CommitCurrent(evidence RefreshEvidence, commit func([32]byte)) error {
	if s == nil || commit == nil || evidence.token == nil || evidence.token.source != s {
		return ErrRefreshEvidenceStale
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	source := evidence.source
	if !s.valid || source.state != s || source.generation == 0 ||
		s.generation != source.generation || s.digest != source.digest || s.usable != source.usable {
		return ErrRefreshEvidenceStale
	}
	if !source.usable {
		return ErrRefreshSourceUnavailable
	}
	commit(source.digest)
	return nil
}

func NewRefreshEmitter(claim *Claim) (*RefreshEmitter, error) {
	state := NewRefreshSourceState()
	if _, err := state.Update([32]byte{1}); err != nil {
		return nil, err
	}
	return NewRefreshEmitterWithSourceState(claim, state)
}

func NewRefreshEmitterWithSourceState(claim *Claim, source *RefreshSourceState) (*RefreshEmitter, error) {
	if claim == nil {
		return nil, fmt.Errorf("%w: nil claim", ErrInvalidRefreshEvidence)
	}
	state := claim.State()
	if !state.HasDriver || state.Facts.Operations == 0 {
		return nil, fmt.Errorf("%w: claim has no specialized driver", ErrInvalidRefreshEvidence)
	}
	if _, ok := claim.endpointIncarnation(); !ok {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRefreshEvidence, ErrIncarnationUnproven)
	}
	if source == nil {
		return nil, fmt.Errorf("%w: nil source state", ErrInvalidRefreshEvidence)
	}
	return &RefreshEmitter{token: &refreshEvidenceToken{claim: claim, source: source}}, nil
}

// Observe records one factual change. Generation is process-wide monotonic so
// replacing a publisher object cannot make a newer event look like a replay.
func (e *RefreshEmitter) Observe(reason RefreshReason, snapshots ...RefreshSourceSnapshot) (RefreshEvidence, error) {
	if e == nil || e.token == nil || e.token.claim == nil || !reason.valid() {
		return RefreshEvidence{}, ErrInvalidRefreshEvidence
	}
	claim := e.token.claim
	var source RefreshSourceSnapshot
	if len(snapshots) > 1 {
		return RefreshEvidence{}, ErrInvalidRefreshEvidence
	}
	if len(snapshots) == 1 {
		source = snapshots[0]
	} else {
		source = e.token.source.current()
	}
	if !source.currentFor(e.token.source) {
		return RefreshEvidence{}, ErrRefreshEvidenceStale
	}
	if reason == RefreshReasonRouteSourceUnavailable && source.usable ||
		reason != RefreshReasonRouteSourceUnavailable && !source.usable {
		return RefreshEvidence{}, ErrInvalidRefreshEvidence
	}
	state := claim.State()
	incarnation, ok := claim.endpointIncarnation()
	if state.Retired || !state.Bound || !state.HasDriver || state.Facts.Operations == 0 || !ok {
		return RefreshEvidence{}, ErrRefreshEvidenceStale
	}
	generation := nextRefreshEvidenceGeneration()
	return RefreshEvidence{
		token:              e.token,
		generation:         generation,
		endpointGeneration: state.Facts.Generation,
		incarnation:        incarnation,
		source:             source,
		reason:             reason,
		observedAt:         time.Now(),
	}, nil
}

// ValidateFor returns immutable metadata only when the evidence is newer than
// afterGeneration and still names the exact current claim incarnation.
func (e RefreshEvidence) ValidateFor(claim *Claim, afterGeneration uint64) (RefreshSnapshot, error) {
	if claim == nil || e.token == nil || e.token.claim != claim || e.generation == 0 ||
		e.generation <= afterGeneration || e.endpointGeneration == 0 || e.incarnation == 0 ||
		!e.reason.valid() || e.observedAt.IsZero() || e.source.state == nil || e.source.generation == 0 {
		return RefreshSnapshot{}, ErrInvalidRefreshEvidence
	}
	state := claim.State()
	incarnation, ok := claim.endpointIncarnation()
	if state.Retired || !state.Bound || !state.HasDriver || state.Facts.Operations == 0 ||
		state.Facts.Generation != e.endpointGeneration || !ok || incarnation != e.incarnation ||
		!e.source.currentFor(e.token.source) {
		return RefreshSnapshot{}, ErrRefreshEvidenceStale
	}
	return RefreshSnapshot{
		Generation:         e.generation,
		EndpointGeneration: e.endpointGeneration,
		Incarnation:        e.incarnation,
		SourceGeneration:   e.source.generation,
		SourceUsable:       e.source.usable,
		Reason:             e.reason,
		ObservedAt:         e.observedAt,
	}, nil
}

// RefreshSnapshot contains only non-authorizing event metadata.
type RefreshSnapshot struct {
	Generation         uint64
	EndpointGeneration uint64
	Incarnation        uint64
	SourceGeneration   uint64
	SourceUsable       bool
	Reason             RefreshReason
	ObservedAt         time.Time
}

func nextRefreshEvidenceGeneration() uint64 {
	for {
		if generation := refreshEvidenceGeneration.Add(1); generation != 0 {
			return generation
		}
	}
}

func nextRefreshSourceGeneration() uint64 {
	for {
		if generation := refreshSourceGeneration.Add(1); generation != 0 {
			return generation
		}
	}
}

func (s *RefreshSourceState) current() RefreshSourceSnapshot {
	if s == nil {
		return RefreshSourceSnapshot{}
	}
	s.mu.RLock()
	snapshot := RefreshSourceSnapshot{state: s, generation: s.generation, digest: s.digest, usable: s.usable}
	valid := s.valid
	s.mu.RUnlock()
	if !valid {
		return RefreshSourceSnapshot{}
	}
	return snapshot
}

func (snapshot RefreshSourceSnapshot) currentFor(state *RefreshSourceState) bool {
	if state == nil || snapshot.state != state || snapshot.generation == 0 ||
		(snapshot.usable && snapshot.digest == ([32]byte{})) || (!snapshot.usable && snapshot.digest != ([32]byte{})) {
		return false
	}
	state.mu.RLock()
	current := state.valid && state.generation == snapshot.generation && state.digest == snapshot.digest &&
		state.usable == snapshot.usable
	state.mu.RUnlock()
	return current
}

func (r RefreshReason) valid() bool {
	switch r {
	case RefreshReasonRouteSourceChanged,
		RefreshReasonRouteSourceUnavailable,
		RefreshReasonRouteSourceRestored,
		RefreshReasonLinkUnresponsive,
		RefreshReasonLocalReadFailure,
		RefreshReasonLocalWriteFailure,
		RefreshReasonOuterMTUFailure,
		RefreshReasonReplayStalled,
		RefreshReasonReplayFailure,
		RefreshReasonLivenessProbeFailure:
		return true
	default:
		return false
	}
}
