package engine

import (
	"fmt"
	"os"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

// nowFn is overridable in tests; production calls time.Now.
var nowFn = time.Now

// debugPathDeath gates a diagnostic stderr line inside onPathDeath.
// Enabled via RENDR_DEBUG_PATH_DEATH=1; used to bisect chaos-induced
// TCP failures (currently REG-T4 G1-T4-tcp at ~10 MiB under 50 Mbps
// tbf shaping where both paths die near-simultaneously and the
// migration budget exhausts).
var debugPathDeath = os.Getenv("RENDR_DEBUG_PATH_DEATH") != ""

// onPathDeath is the OnDeath callback installed on every attached
// PathConn. It runs on the transport adapter's goroutine, so it
// keeps work brief and never blocks on locks held by the send path.
func (e *Engine) onPathDeath(id uint32, gen uint64, cause transport.DeathCause, err error) {
	if debugPathDeath {
		fmt.Fprintf(os.Stderr, "[rendr-engine] path %d died: cause=%v err=%v\n", id, cause, err)
	}
	e.pathsMu.Lock()
	slot, ok := e.paths[id]
	if !ok {
		e.pathsMu.Unlock()
		return
	}
	if slot.gen != gen || slot.maintenance.Load() {
		e.pathsMu.Unlock()
		return
	}
	var redistribute [][]byte
	if e.mode.Load() == dispatchBond && cause != transport.CauseCleanClose {
		redistribute = slot.bondSendHistorySnapshot()
	}
	slot.closeQuit()
	delete(e.paths, id)
	wasActive := e.activeID == id
	migratedOk := false
	var newActive uint32
	if wasActive {
		e.activeID = e.pickAnyActive()
		newActive = e.activeID
		if e.activeID == 0 {
			e.setState(BridgeMigrating)
		} else {
			migratedOk = true
			e.migrationCount++
		}
	}
	hasPaths := len(e.paths) > 0
	e.pathsMu.Unlock()

	if migratedOk {
		e.fireMigrateHooks(id, newActive, "death")
	}

	switch cause {
	case transport.CauseCleanClose:
		// Hard rule #2: only a clean close ends the engine. And only
		// if this was the last path; partial cleanCloses on a
		// non-final path are a no-op (the engine continues on
		// remaining paths).
		if !hasPaths {
			e.setCloseErr(nil)
			_ = e.Close()
		}
	case transport.CauseTransportError, transport.CauseUnknown:
		if hasPaths && len(redistribute) > 0 {
			go e.redistributeBondFrames(redistribute)
		}
		// Successful death-driven migration counts for zombie
		// accounting. Without a fresh path, fall through to budget.
		if migratedOk {
			e.recordMigration()
		}
		if !hasPaths {
			go e.startMigrationBudget(err)
		}
	}
}

// recordMigration decrements the zombie counter and triggers
// zombie protection when it hits zero. Cooldown semantics: if the
// gap since the last migration exceeds ZombieCooldown, the counter
// is refreshed to ZombieMaxMigrations before being decremented;
// this prevents long-lived connections with infrequent but legit
// migrations from accumulating into zombie territory.
//
// Must NOT be called with pathsMu held: the zombie close path
// goes through Engine.Close which itself takes pathsMu.
func (e *Engine) recordMigration() {
	e.zombieMu.Lock()
	if !e.zombieLastMig.IsZero() && nowFn().Sub(e.zombieLastMig) > e.limits.ZombieCooldown {
		e.zombieLeft = e.limits.ZombieMaxMigrations
	}
	e.zombieLeft--
	e.zombieLastMig = nowFn()
	trip := e.zombieLeft <= 0
	e.zombieMu.Unlock()

	if trip {
		go func() {
			e.setCloseErr(ErrZombie)
			_ = e.Close()
		}()
	}
}

// pickAnyActive returns any remaining path id, or 0 if none.
// Caller must hold pathsMu.
func (e *Engine) pickAnyActive() uint32 {
	for id := range e.paths {
		return id
	}
	return 0
}

// startMigrationBudget runs as a goroutine after the last path died.
// It either signals close (budget exceeded) or returns once a fresh
// path attaches.
func (e *Engine) startMigrationBudget(reason error) {
	deadline := nowFn().Add(e.limits.MigrationBudget)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-e.closed:
			return
		case <-tick.C:
			e.pathsMu.RLock()
			has := len(e.paths) > 0
			e.pathsMu.RUnlock()
			if has {
				return
			}
			if nowFn().After(deadline) {
				e.setCloseErr(ErrMigrationBudgetExceeded)
				_ = e.Close()
				return
			}
		}
	}
}

// waitForPath blocks until a path attaches or the budget elapses.
// Called from the send loop when there is no active path.
func (e *Engine) waitForPath() error {
	deadline := nowFn().Add(e.limits.MigrationBudget)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-e.closed:
			if err := e.CloseErr(); err != nil {
				return err
			}
			return nil
		case <-tick.C:
			e.pathsMu.RLock()
			id := e.activeID
			e.pathsMu.RUnlock()
			if id != 0 {
				return nil
			}
			if nowFn().After(deadline) {
				e.setCloseErr(ErrMigrationBudgetExceeded)
				_ = e.Close()
				return ErrMigrationBudgetExceeded
			}
		}
	}
}
