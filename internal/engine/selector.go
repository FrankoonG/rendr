package engine

import (
	"sync"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

// PathScore: lower is better.
//
//	score = rtt + JitterCoef*jitter + LossCoef*loss_per_1000
//
// Default coefficients: rtt + jitter + 10ms per loss percent.
type ScoreFn func(transport.PathQuality) float64

// DefaultScoreFn implements the selector scoring with α=1.0 and
// β=10ms per percent loss. β was picked so 5% loss adds 50 ms of
// "effective RTT" - i.e. a 5% loss path is treated about as bad as
// 50 ms of extra latency. Embedders that want a different curve can
// supply their own ScoreFn.
func DefaultScoreFn(q transport.PathQuality) float64 {
	rtt := float64(q.RTT.Milliseconds())
	jit := float64(q.Jitter.Milliseconds())
	loss := float64(q.LossPP) / 10.0 // parts-per-thousand -> percent
	return rtt + jit + 10.0*loss
}

// selector is the per-Engine selector-mode scheduler state. It is created
// only when StartSelector is called; otherwise nil (and the engine
// behaves like fixed-path: only death-driven migration fires).
type selector struct {
	mu sync.Mutex

	score      ScoreFn
	hysteresis float64
	dwell      time.Duration
	cooldown   time.Duration

	// bestID is the candidate path that has been "best by margin"
	// since bestSince. When bestSince + dwell elapses, the engine
	// migrates to it.
	bestID    uint32
	bestSince time.Time
	lastMig   time.Time

	stop chan struct{}
	done chan struct{}
}

// StartSelector arms the selector-mode quality scheduler. tickEvery sets
// the cadence at which the engine re-scores paths; pass 0 for a
// 200ms default. The scheduler runs until Engine.Close.
//
// Per CLAUDE.md hard rule #3 ("默认不安装主动迁移触发器"), selector
// scoring is OFF until this method is called. The Dialer wires it
// up when Mode == ModeSelector.
func (e *Engine) StartSelector(score ScoreFn, tickEvery time.Duration) {
	if score == nil {
		score = DefaultScoreFn
	}
	if tickEvery <= 0 {
		tickEvery = 200 * time.Millisecond
	}
	p := &selector{
		score:      score,
		hysteresis: e.limits.SelectorHysteresis,
		dwell:      e.limits.SelectorDwell,
		cooldown:   e.limits.SelectorCooldown,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	e.selectorMu.Lock()
	if e.selector != nil {
		e.selectorMu.Unlock()
		return
	}
	e.selector = p
	e.selectorMu.Unlock()

	go p.loop(e, tickEvery)
}

func (p *selector) loop(e *Engine, tick time.Duration) {
	defer close(p.done)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-e.closed:
			return
		case <-t.C:
			p.evaluate(e)
		}
	}
}

// evaluate runs one tick of the scheduler.
func (p *selector) evaluate(e *Engine) {
	if e.mode.Load() != dispatchSelector {
		return
	}
	now := nowFn()

	e.pathsMu.RLock()
	current := e.activeID
	candidates := make(map[uint32]transport.PathQuality, len(e.paths))
	for id, s := range e.paths {
		if !e.dispatchScopeAllowsLocked(id) {
			continue
		}
		candidates[id] = s.conn.Quality()
	}
	e.pathsMu.RUnlock()

	if current == 0 || len(candidates) < 2 {
		return
	}

	curQ, ok := candidates[current]
	if !ok {
		return
	}
	curScore := p.score(curQ)

	// Pick the best non-current candidate.
	var bestID uint32
	bestScore := curScore
	for id, q := range candidates {
		if id == current {
			continue
		}
		s := p.score(q)
		if s < bestScore {
			bestScore = s
			bestID = id
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if bestID == 0 {
		// Current is still best or tied.
		p.bestID = 0
		p.bestSince = time.Time{}
		return
	}
	// Hysteresis test: bestScore must beat curScore by 1+hysteresis.
	if !(curScore > 0 && bestScore < curScore/(1+p.hysteresis)) {
		// Margin not met. Reset candidate tracking.
		if p.bestID != bestID {
			p.bestID = bestID
			p.bestSince = now
		}
		return
	}
	// Margin met. Track dwell.
	if p.bestID != bestID {
		p.bestID = bestID
		p.bestSince = now
		return
	}
	if now.Sub(p.bestSince) < p.dwell {
		return
	}
	// Cooldown check.
	if !p.lastMig.IsZero() && now.Sub(p.lastMig) < p.cooldown {
		return
	}
	// Fire migration.
	if err := e.migrate(bestID, false, "quality"); err == nil {
		p.lastMig = now
	}
	// Reset candidate tracking after a migration.
	p.bestID = 0
	p.bestSince = time.Time{}
}

// SetPathQualityForTest pokes a quality reading into a specific
// path. Used by unit tests to drive selector-mode scoring without
// having to wait for real RTT measurements (M6(2/n) wires up the
// HEARTBEAT-based probe; until then the engine reads only what
// tests / external callers inject).
func (e *Engine) SetPathQualityForTest(id uint32, q transport.PathQuality) {
	e.pathsMu.RLock()
	slot, ok := e.paths[id]
	e.pathsMu.RUnlock()
	if !ok {
		return
	}
	if setter, ok := slot.conn.(interface {
		SetQuality(transport.PathQuality)
	}); ok {
		setter.SetQuality(q)
	}
}
