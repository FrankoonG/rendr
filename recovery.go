package rendr

import (
	"context"
	"errors"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/transport"
)

const recoveryInitialBackoff = 100 * time.Millisecond
const recoveryMaximumBackoff = 5 * time.Second

const maxSessionRecoveryLeaves = 64

type pathRecoverySupervisor struct {
	e        *engine.Engine
	addPath  func(context.Context, PathSpec) (uint32, error)
	resolver *pathFactoryResolver
	tracker  *pathStatusTracker
	updates  chan recoveryUpdate
	done     chan struct{}
	minDelay time.Duration
	maxDelay time.Duration
}

type recoveryLeafState struct {
	spec              PathSpec
	index             int
	desired           bool
	owner             uint64
	generation        uint64
	runningGeneration uint64
	runningAttempt    uint64
	cancel            context.CancelFunc
}

type recoveryCompletion struct {
	key        string
	generation uint64
	attempt    uint64
	ref        engine.PathRef
}

type recoveryUpdateKind uint8

const (
	recoveryUpdateDeath recoveryUpdateKind = iota + 1
	recoveryUpdateAdd
	recoveryUpdateStatus
	recoveryUpdateStop
	recoveryUpdateBarrier
)

type recoveryUpdate struct {
	kind       recoveryUpdateKind
	death      engine.PathDeathEvent
	spec       PathSpec
	pathID     uint32
	ref        engine.PathRef
	generation uint64
	attempt    uint64
	state      PathState
	err        error
	reply      chan int
}

var errStaleRecoveryGeneration = errors.New("rendr: retire stale recovery generation")

func newPathRecoverySupervisor(
	e *engine.Engine,
	resolver *pathFactoryResolver,
	addPath func(context.Context, PathSpec) (uint32, error),
	desired []PathSpec,
	tracker *pathStatusTracker,
	retry retryPolicy,
) *pathRecoverySupervisor {
	if e == nil || addPath == nil {
		return nil
	}
	minDelay := retry.MinBackoff
	if minDelay <= 0 {
		minDelay = recoveryInitialBackoff
	}
	maxDelay := retry.MaxBackoff
	if maxDelay <= 0 {
		maxDelay = recoveryMaximumBackoff
	}
	if maxDelay < minDelay {
		maxDelay = minDelay
	}
	s := &pathRecoverySupervisor{
		e:        e,
		addPath:  addPath,
		resolver: resolver,
		tracker:  tracker,
		updates:  make(chan recoveryUpdate, 4*maxSessionRecoveryLeaves),
		done:     make(chan struct{}),
		minDelay: minDelay,
		maxDelay: maxDelay,
	}
	cancel := e.OnPathDeathSerial(func(event engine.PathDeathEvent) {
		event.Spec = event.Spec.Clone()
		if errors.Is(event.Err, errStaleRecoveryGeneration) {
			return
		}
		var reply chan int
		if event.Administrative {
			reply = make(chan int, 1)
		}
		if !s.enqueue(recoveryUpdate{kind: recoveryUpdateDeath, death: event, reply: reply}) {
			return
		}
		if reply != nil {
			select {
			case <-reply:
			case <-s.done:
			}
		}
	})
	snapshots := make([]PathSpec, len(desired))
	for i, spec := range desired {
		snapshots[i] = spec.Clone()
	}
	ready := make(chan struct{})
	go s.loop(cancel, snapshots, ready)
	// The session must not escape to its caller until recovery has reconciled
	// the initial path set. Otherwise an immediate clean RemovePath can race
	// startup: reconciliation observes the now-missing desired leaf and dials it
	// before consuming the already-queued clean-death event.
	select {
	case <-ready:
	case <-e.Closed():
	}
	return s
}

func (s *pathRecoverySupervisor) loop(cancel func(), desired []PathSpec, ready chan<- struct{}) {
	defer cancel()
	defer close(s.done)
	states := make(map[string]*recoveryLeafState, len(desired))
	completed := make(chan recoveryCompletion, maxSessionRecoveryLeaves)
	activeWorkers := 0
	nextAttempt := uint64(0)
	closing := false

	for index, spec := range desired {
		if planLeafMobility(s.resolver.carrierFamily(spec.Transport)).ID != MobilityRedialAttach {
			continue
		}
		key := recoveryLeafKey(spec)
		if key == "" {
			continue
		}
		state := &recoveryLeafState{spec: spec.Clone(), index: index, desired: true, generation: 1}
		if ref, ok := recoveryLeafPathRef(s.e, spec); ok {
			state.owner = ref.Owner
		}
		states[key] = state
	}

	start := func(key string, state *recoveryLeafState) {
		if closing || state == nil || !state.desired || state.runningAttempt != 0 || recoveryLeafAttached(s.e.Paths(), state.spec) {
			return
		}
		if state.generation == 0 {
			state.generation = 1
		}
		nextAttempt++
		attempt := nextAttempt
		generation := state.generation
		state.runningGeneration = generation
		state.runningAttempt = attempt
		spec := state.spec.Clone()
		ctx, cancelAttempt := context.WithCancel(context.Background())
		state.cancel = cancelAttempt
		activeWorkers++
		go func() {
			defer cancelAttempt()
			ref := s.recover(ctx, key, spec, generation, attempt)
			completed <- recoveryCompletion{key: key, generation: generation, attempt: attempt, ref: ref}
		}()
	}

	// Death can occur before the hook is registered, and an initial secondary
	// attach can fail without producing a death event. Reconcile the frozen
	// graph once after registration so neither startup case needs a wakeup.
	for key, state := range states {
		if recoveryLeafAttached(s.e.Paths(), state.spec) {
			continue
		}
		s.tracker.set(state.index, PathPending, nil)
		start(key, state)
	}
	close(ready)

	for {
		if closing && activeWorkers == 0 {
			return
		}
		select {
		case <-s.e.Closed():
			if !closing {
				closing = true
				for _, state := range states {
					if state.cancel != nil {
						state.cancel()
					}
				}
			}
		case result := <-completed:
			activeWorkers--
			state := states[result.key]
			if state == nil || state.runningGeneration != result.generation || state.runningAttempt != result.attempt {
				s.retireRecoveredPath(result.ref)
				continue
			}
			state.runningGeneration = 0
			state.runningAttempt = 0
			state.cancel = nil
			if state.generation != result.generation {
				s.retireRecoveredPath(result.ref)
				start(result.key, state)
				continue
			}
			if closing || !state.desired {
				s.retireRecoveredPath(result.ref)
				continue
			}
			if recoveryLeafAttached(s.e.Paths(), state.spec) {
				if result.ref.Owner != 0 {
					state.owner = result.ref.Owner
				}
				s.tracker.set(state.index, PathAttached, nil)
				continue
			}
			start(result.key, state)
		case update := <-s.updates:
			if update.kind == recoveryUpdateStop {
				if !closing {
					closing = true
					for _, state := range states {
						if state.cancel != nil {
							state.cancel()
						}
					}
				}
				if update.reply != nil {
					update.reply <- activeWorkers
				}
				continue
			}
			if update.kind == recoveryUpdateBarrier {
				if update.reply != nil {
					update.reply <- activeWorkers
				}
				continue
			}
			if update.kind == recoveryUpdateStatus {
				state := states[recoveryLeafKey(update.spec)]
				if !closing && state != nil && state.generation == update.generation &&
					state.runningGeneration == update.generation && state.runningAttempt == update.attempt {
					s.tracker.set(state.index, update.state, update.err)
				}
				continue
			}
			if update.kind == recoveryUpdateAdd {
				key := recoveryLeafKey(update.spec)
				if key != "" {
					state := states[key]
					if state == nil {
						state = &recoveryLeafState{index: -1}
						states[key] = state
					}
					if update.ref.Owner == 0 {
						if update.reply != nil {
							update.reply <- activeWorkers
						}
						continue
					}
					current, attached := s.e.PathRef(update.pathID)
					if !attached {
						if latest, ok := recoveryLeafPathRef(s.e, update.spec); ok && latest.Owner > update.ref.Owner {
							if update.reply != nil {
								update.reply <- activeWorkers
							}
							continue
						}
					}
					if !attached && state.owner >= update.ref.Owner {
						// The exact generation was already removed or failed. Its
						// ordered death event owns the desired-state decision.
						if update.reply != nil {
							update.reply <- activeWorkers
						}
						continue
					}
					if state.cancel != nil {
						state.cancel()
					}
					state.spec = update.spec.Clone()
					state.desired = true
					state.owner = update.ref.Owner
					state.generation++
					if state.generation == 0 {
						state.generation = 1
					}
					if attached && (update.ref.Owner == 0 || current == update.ref) {
						state.owner = current.Owner
						s.tracker.set(state.index, PathAttached, nil)
					} else {
						s.tracker.set(state.index, PathUnavailable, nil)
						start(key, state)
					}
				}
				if update.reply != nil {
					update.reply <- activeWorkers
				}
				continue
			}
			event := update.death
			key := recoveryLeafKey(event.Spec)
			if key == "" {
				if update.reply != nil {
					update.reply <- activeWorkers
				}
				continue
			}
			state := states[key]
			known := state != nil
			if state == nil {
				state = &recoveryLeafState{spec: event.Spec.Clone(), index: -1, generation: 1}
				states[key] = state
			} else {
				state.spec = event.Spec.Clone()
			}
			// Physical owners increase monotonically within one engine. A
			// delayed event from an older generation cannot change the desired
			// state established by a later manual add or recovery completion.
			if event.Owner != 0 && state.owner != 0 && event.Owner < state.owner {
				if update.reply != nil {
					update.reply <- activeWorkers
				}
				continue
			}
			if event.Cause == transport.CauseCleanClose {
				state.desired = false
				state.owner = event.Owner
				state.generation++
				if state.cancel != nil {
					state.cancel()
				}
				s.tracker.set(state.index, PathUnavailable, nil)
				if update.reply != nil {
					update.reply <- activeWorkers
				}
				continue
			}
			// A clean removal is a logical-leaf tombstone. Delayed transport
			// callbacks from an older physical generation must not resurrect it.
			if known && !state.desired && (event.Owner == 0 || event.Owner <= state.owner) {
				if update.reply != nil {
					update.reply <- activeWorkers
				}
				continue
			}
			if planLeafMobility(s.resolver.carrierFamily(event.Spec.Transport)).ID != MobilityRedialAttach {
				if update.reply != nil {
					update.reply <- activeWorkers
				}
				continue
			}
			state.desired = true
			state.owner = event.Owner
			s.tracker.set(state.index, PathUnavailable, event.Err)
			start(key, state)
			if update.reply != nil {
				update.reply <- activeWorkers
			}
		}
	}
}

func (s *pathRecoverySupervisor) recover(ctx context.Context, key string, spec PathSpec, generation, attempt uint64) engine.PathRef {
	backoff := s.minDelay
	for {
		if s.e.IsClosed() || ctx.Err() != nil {
			return engine.PathRef{}
		}
		if recoveryLeafAttached(s.e.Paths(), spec) {
			return engine.PathRef{}
		}
		s.reportStatus(key, spec, generation, attempt, PathDialing, nil)
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		pathID, err := s.addPath(attemptCtx, spec.Clone())
		cancel()
		if err == nil {
			ref, _ := s.e.PathRef(pathID)
			return ref
		}
		// An attached path observed after a failed dial may belong to a
		// concurrent manual AddPath or a newer recovery generation. Only a
		// successful addPath result transfers an exact PathRef to this worker.
		// The next loop iteration will observe that path without claiming it.
		s.reportStatus(key, spec, generation, attempt, PathPending, err)
		timer := time.NewTimer(backoff)
		select {
		case <-s.e.Closed():
			if !timer.Stop() {
				<-timer.C
			}
			return engine.PathRef{}
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return engine.PathRef{}
		case <-timer.C:
		}
		if backoff < s.maxDelay {
			backoff *= 2
			if backoff > s.maxDelay {
				backoff = s.maxDelay
			}
		}
	}
}

func (s *pathRecoverySupervisor) reportStatus(_ string, spec PathSpec, generation, attempt uint64, state PathState, err error) {
	if s == nil {
		return
	}
	_ = s.enqueue(recoveryUpdate{
		kind: recoveryUpdateStatus, spec: spec.Clone(), generation: generation,
		attempt: attempt, state: state, err: err,
	})
}

func (s *pathRecoverySupervisor) retireRecoveredPath(ref engine.PathRef) {
	if ref.ID == 0 || ref.Owner == 0 {
		return
	}
	_ = s.e.RetirePath(ref, errStaleRecoveryGeneration)
}

func (s *pathRecoverySupervisor) enqueue(update recoveryUpdate) bool {
	if s == nil {
		return false
	}
	select {
	case s.updates <- update:
		return true
	case <-s.done:
		return false
	}
}

func (s *pathRecoverySupervisor) pathAdded(spec PathSpec, pathID uint32) {
	if s == nil || pathID == 0 {
		return
	}
	ref, _ := s.e.PathRef(pathID)
	if ref.Owner == 0 {
		return
	}
	s.pathAddedRef(spec, pathID, ref)
}

func (s *pathRecoverySupervisor) pathAddedRef(spec PathSpec, pathID uint32, ref engine.PathRef) {
	if s == nil || pathID == 0 || ref.Owner == 0 {
		return
	}
	reply := make(chan int, 1)
	if !s.enqueue(recoveryUpdate{kind: recoveryUpdateAdd, spec: spec.Clone(), pathID: pathID, ref: ref, reply: reply}) {
		return
	}
	select {
	case <-reply:
	case <-s.done:
	}

}

func (s *pathRecoverySupervisor) stop() {
	if s == nil {
		return
	}
	reply := make(chan int, 1)
	if !s.enqueue(recoveryUpdate{kind: recoveryUpdateStop, reply: reply}) {
		return
	}
	select {
	case <-reply:
	case <-s.done:
	}
}

func recoveryLeafKey(spec PathSpec) string {
	if name := pathSpecName(spec); name != "" {
		return name
	}
	return spec.Transport + "\x00" + spec.Address
}

func recoveryLeafAttached(paths []PathInfo, spec PathSpec) bool {
	return len(recoveryLeafPathIDs(paths, spec)) != 0
}

func recoveryLeafPathIDs(paths []PathInfo, spec PathSpec) []uint32 {
	want := recoveryLeafKey(spec)
	ids := make([]uint32, 0, 1)
	for _, path := range paths {
		if recoveryLeafKey(path.Spec) == want {
			ids = append(ids, path.ID)
		}
	}
	return ids
}

func recoveryLeafPathRef(e *engine.Engine, spec PathSpec) (engine.PathRef, bool) {
	if e == nil {
		return engine.PathRef{}, false
	}
	ids := recoveryLeafPathIDs(e.Paths(), spec)
	var latest engine.PathRef
	for index := len(ids) - 1; index >= 0; index-- {
		if ref, ok := e.PathRef(ids[index]); ok {
			if ref.Owner > latest.Owner {
				latest = ref
			}
		}
	}
	return latest, latest.Owner != 0
}
