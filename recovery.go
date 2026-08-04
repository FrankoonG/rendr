package rendr

import (
	"context"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/transport"
)

const recoveryInitialBackoff = 100 * time.Millisecond
const recoveryMaximumBackoff = 5 * time.Second

type pathRecoverySupervisor struct {
	e        *engine.Engine
	addPath  func(context.Context, PathSpec) (uint32, error)
	resolver *pathFactoryResolver
	events   chan engine.PathDeathEvent
}

func newPathRecoverySupervisor(e *engine.Engine, resolver *pathFactoryResolver, addPath func(context.Context, PathSpec) (uint32, error)) *pathRecoverySupervisor {
	if e == nil || addPath == nil {
		return nil
	}
	s := &pathRecoverySupervisor{
		e:        e,
		addPath:  addPath,
		resolver: resolver,
		events:   make(chan engine.PathDeathEvent, maxSessionRecoveryLeaves),
	}
	cancel := e.OnPathDeath(func(event engine.PathDeathEvent) {
		if event.Cause == transport.CauseCleanClose {
			return
		}
		select {
		case s.events <- event:
		case <-e.Closed():
		}
	})
	go s.loop(cancel)
	return s
}

const maxSessionRecoveryLeaves = 64

func (s *pathRecoverySupervisor) loop(cancel func()) {
	defer cancel()
	recovering := make(map[string]bool)
	completed := make(chan string, maxSessionRecoveryLeaves)
	for {
		select {
		case <-s.e.Closed():
			return
		case key := <-completed:
			delete(recovering, key)
		case event := <-s.events:
			if planLeafMobility(event.Spec, s.resolver).ID != MobilityRedialAttach {
				continue
			}
			key := recoveryLeafKey(event.Spec)
			if key == "" || recovering[key] {
				continue
			}
			recovering[key] = true
			go func(spec PathSpec, leafKey string) {
				s.recover(spec)
				select {
				case completed <- leafKey:
				case <-s.e.Closed():
				}
			}(event.Spec, key)
		}
	}
}

func (s *pathRecoverySupervisor) recover(spec PathSpec) {
	backoff := recoveryInitialBackoff
	for {
		if s.e.IsClosed() || recoveryLeafAttached(s.e.Paths(), spec) {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := s.addPath(ctx, spec)
		cancel()
		if err == nil || recoveryLeafAttached(s.e.Paths(), spec) {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-s.e.Closed():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
		if backoff < recoveryMaximumBackoff {
			backoff *= 2
			if backoff > recoveryMaximumBackoff {
				backoff = recoveryMaximumBackoff
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
