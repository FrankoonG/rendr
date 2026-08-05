package rendr

import (
	"context"
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
	events   chan engine.PathDeathEvent
	minDelay time.Duration
	maxDelay time.Duration
}

type recoveryLeafState struct {
	spec       PathSpec
	index      int
	desired    bool
	desiredGen uint64
	runningGen uint64
	cancel     context.CancelFunc
}

type recoveryCompletion struct {
	key        string
	generation uint64
}

func newPathRecoverySupervisor(
	e *engine.Engine,
	resolver *pathFactoryResolver,
	addPath func(context.Context, PathSpec) (uint32, error),
	desired []PathSpec,
	tracker *pathStatusTracker,
	retry RetryPolicy,
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
		events:   make(chan engine.PathDeathEvent, maxSessionRecoveryLeaves),
		minDelay: minDelay,
		maxDelay: maxDelay,
	}
	cancel := e.OnPathDeath(func(event engine.PathDeathEvent) {
		event.Spec = event.Spec.Clone()
		select {
		case s.events <- event:
		case <-e.Closed():
		}
	})
	snapshots := make([]PathSpec, len(desired))
	for i, spec := range desired {
		snapshots[i] = spec.Clone()
	}
	go s.loop(cancel, snapshots)
	return s
}

func (s *pathRecoverySupervisor) loop(cancel func(), desired []PathSpec) {
	defer cancel()
	states := make(map[string]*recoveryLeafState, len(desired))
	completed := make(chan recoveryCompletion, maxSessionRecoveryLeaves)

	for index, spec := range desired {
		if planLeafMobility(spec, s.resolver).ID != MobilityRedialAttach {
			continue
		}
		key := recoveryLeafKey(spec)
		if key == "" {
			continue
		}
		states[key] = &recoveryLeafState{spec: spec.Clone(), index: index, desired: true}
	}

	start := func(key string, state *recoveryLeafState) {
		if state == nil || !state.desired || state.runningGen != 0 || recoveryLeafAttached(s.e.Paths(), state.spec) {
			return
		}
		if state.desiredGen == 0 {
			state.desiredGen = 1
		}
		generation := state.desiredGen
		state.runningGen = generation
		spec := state.spec.Clone()
		index := state.index
		ctx, cancel := context.WithCancel(context.Background())
		state.cancel = cancel
		go func() {
			defer cancel()
			s.recover(ctx, spec, index)
			select {
			case completed <- recoveryCompletion{key: key, generation: generation}:
			case <-s.e.Closed():
			}
		}()
	}

	// Death can occur before the hook is registered, and an initial secondary
	// attach can fail without producing a death event. Reconcile the frozen
	// graph once after registration so neither startup case needs a wakeup.
	for key, state := range states {
		if recoveryLeafAttached(s.e.Paths(), state.spec) {
			continue
		}
		state.desiredGen++
		s.tracker.set(state.index, PathPending, nil)
		start(key, state)
	}

	for {
		select {
		case <-s.e.Closed():
			return
		case result := <-completed:
			state := states[result.key]
			if state == nil || state.runningGen != result.generation {
				continue
			}
			state.runningGen = 0
			state.cancel = nil
			if !state.desired {
				continue
			}
			if recoveryLeafAttached(s.e.Paths(), state.spec) {
				s.tracker.set(state.index, PathAttached, nil)
				continue
			}
			// A replacement may die after addPath succeeds but before this
			// completion is observed. Advance desired state even if its death
			// callback is still queued, then coalesce that callback below.
			if state.desiredGen <= result.generation {
				state.desiredGen = result.generation + 1
			}
			start(result.key, state)
		case event := <-s.events:
			key := recoveryLeafKey(event.Spec)
			if key == "" {
				continue
			}
			state := states[key]
			if state == nil {
				state = &recoveryLeafState{spec: event.Spec.Clone(), index: -1}
				states[key] = state
			} else {
				state.spec = event.Spec.Clone()
			}
			if event.Cause == transport.CauseCleanClose {
				state.desired = false
				state.desiredGen++
				if state.cancel != nil {
					state.cancel()
				}
				s.tracker.set(state.index, PathUnavailable, nil)
				continue
			}
			if planLeafMobility(event.Spec, s.resolver).ID != MobilityRedialAttach {
				continue
			}
			state.desired = true
			state.desiredGen++
			s.tracker.set(state.index, PathUnavailable, event.Err)
			start(key, state)
		}
	}
}

func (s *pathRecoverySupervisor) recover(ctx context.Context, spec PathSpec, index int) {
	backoff := s.minDelay
	for {
		if s.e.IsClosed() || ctx.Err() != nil {
			return
		}
		if recoveryLeafAttached(s.e.Paths(), spec) {
			s.tracker.set(index, PathAttached, nil)
			return
		}
		s.tracker.set(index, PathDialing, nil)
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := s.addPath(attemptCtx, spec.Clone())
		cancel()
		if err == nil || recoveryLeafAttached(s.e.Paths(), spec) {
			s.tracker.set(index, PathAttached, nil)
			return
		}
		s.tracker.set(index, PathPending, err)
		timer := time.NewTimer(backoff)
		select {
		case <-s.e.Closed():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
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

func recoveryLeafKey(spec PathSpec) string {
	if name := pathSpecName(spec); name != "" {
		return name
	}
	return spec.Transport + "\x00" + spec.Address
}

func recoveryLeafAttached(paths []PathInfo, spec PathSpec) bool {
	want := recoveryLeafKey(spec)
	for _, path := range paths {
		if recoveryLeafKey(path.Spec) == want {
			return true
		}
	}
	return false
}
