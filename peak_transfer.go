package rendr

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
)

const (
	defaultPeakWindow        = 200 * time.Millisecond
	defaultPeakSaturationFor = 600 * time.Millisecond
	defaultPeakReturnFor     = 800 * time.Millisecond
	defaultPeakVerifyFor     = 800 * time.Millisecond
	defaultPeakSuppressFor   = 5 * time.Second
	defaultPeakSaturation    = 0.95
	defaultPeakReturn        = 0.50
	defaultPeakMinGain       = 0.90
	defaultPeakMinBytes      = 256 << 10
)

type peakTransferController struct {
	e       *engine.Engine
	setMode func(Mode)

	normalIDs   []uint32
	peakIDs     []uint32
	normalNames []string
	peakNames   []string
	peakMode    Mode
	opts        PeakTransfer

	writeBytes atomic.Uint64
	readBytes  atomic.Uint64

	mu sync.Mutex
	tx peakTransferDirection
	rx peakTransferDirection

	stop chan struct{}
}

type peakTransferDirection struct {
	onPeak         bool
	normalPeakBps  float64
	normalBytes    uint64
	peakStarted    time.Time
	peakBytes      uint64
	suppressUntil  time.Time
	saturatedSince time.Time
	returnSince    time.Time
}

func newPeakTransferController(e *engine.Engine, setMode func(Mode), plan compiledTarget, pathIDs []uint32) *peakTransferController {
	c := &peakTransferController{
		e:        e,
		setMode:  setMode,
		peakMode: plan.peakMode,
		opts:     plan.peakOptions,
		stop:     make(chan struct{}),
	}
	if !c.peakMode.Valid() {
		c.peakMode = ModePrime
	}
	for i, id := range pathIDs {
		name := ""
		if i < len(plan.paths) {
			name = pathSpecName(plan.paths[i])
		}
		if i < len(plan.pathPeak) && plan.pathPeak[i] {
			c.peakIDs = append(c.peakIDs, id)
			c.peakNames = append(c.peakNames, name)
		} else {
			c.normalIDs = append(c.normalIDs, id)
			c.normalNames = append(c.normalNames, name)
		}
	}
	if len(c.normalIDs) == 0 && len(pathIDs) > 0 {
		c.normalIDs = append(c.normalIDs, pathIDs[0])
		if len(plan.paths) > 0 {
			c.normalNames = append(c.normalNames, pathSpecName(plan.paths[0]))
		}
	}
	if len(c.peakIDs) == 0 && len(pathIDs) > 1 {
		c.peakIDs = append(c.peakIDs, pathIDs[1:]...)
		for _, ps := range plan.paths[1:] {
			c.peakNames = append(c.peakNames, pathSpecName(ps))
		}
	}
	return c
}

func (c *peakTransferController) start() {
	if c == nil || len(c.normalIDs) == 0 || len(c.peakIDs) == 0 {
		return
	}
	_ = c.e.SetDispatchPolicy(uint32(ModePrime), c.normalIDs[0], c.normalIDs, "selector")
	_ = c.e.SendPolicyRequest(uint32(ModePrime), firstNonEmpty(c.normalNames), nonEmptyNames(c.normalNames), "selector-rx")
	c.e.StartPrime(nil, 0)
	go c.loop()
}

func (c *peakTransferController) stopLoop() {
	if c == nil {
		return
	}
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
}

func (c *peakTransferController) observeWrite(n int) {
	if c == nil || n <= 0 {
		return
	}
	c.writeBytes.Add(uint64(n))
}

func (c *peakTransferController) observeRead(n int) {
	if c == nil || n <= 0 {
		return
	}
	c.readBytes.Add(uint64(n))
}

func (c *peakTransferController) loop() {
	t := time.NewTicker(defaultPeakWindow)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-c.stop:
			return
		case <-c.e.Closed():
			return
		case now := <-t.C:
			elapsed := now.Sub(last)
			last = now
			if elapsed <= 0 {
				elapsed = defaultPeakWindow
			}
			writeBytes := c.writeBytes.Swap(0)
			writeBps := float64(writeBytes*8) / elapsed.Seconds()
			c.evaluate(now, writeBytes, writeBps, false)
			readBytes := c.readBytes.Swap(0)
			readBps := float64(readBytes*8) / elapsed.Seconds()
			c.evaluate(now, readBytes, readBps, true)
		}
	}
}

func (c *peakTransferController) evaluate(now time.Time, bytes uint64, bps float64, rx bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := &c.tx
	if rx {
		st = &c.rx
	}

	if !st.onPeak {
		st.normalBytes += bytes
		if bps > st.normalPeakBps {
			st.normalPeakBps = bps
		}
		if st.normalBytes < defaultPeakMinBytes || st.normalPeakBps <= 0 {
			return
		}
		ratio := c.opts.SaturationRatio
		if ratio <= 0 {
			ratio = defaultPeakSaturation
		}
		needFor := c.opts.SaturationFor
		if needFor <= 0 {
			needFor = defaultPeakSaturationFor
		}
		saturated := bps > 0 && bps >= st.normalPeakBps*ratio
		if !saturated {
			st.saturatedSince = time.Time{}
			return
		}
		if st.saturatedSince.IsZero() {
			st.saturatedSince = now
			return
		}
		if now.Sub(st.saturatedSince) < needFor {
			return
		}
		if now.Before(st.suppressUntil) {
			st.saturatedSince = time.Time{}
			return
		}
		if !c.peakHealthy() {
			st.saturatedSince = time.Time{}
			return
		}
		st.onPeak = true
		st.peakStarted = now
		st.peakBytes = 0
		st.saturatedSince = time.Time{}
		st.returnSince = time.Time{}
		c.mu.Unlock()
		c.applyPolicy(rx, uint32(c.peakMode), c.peakIDs[0], c.peakIDs, firstNonEmpty(c.peakNames), nonEmptyNames(c.peakNames), "peak-transfer")
		c.mu.Lock()
		return
	}

	st.peakBytes += bytes
	if st.peakStarted.IsZero() {
		st.peakStarted = now
	}
	verifyFor := defaultPeakVerifyFor
	if elapsed := now.Sub(st.peakStarted); elapsed >= verifyFor && st.normalPeakBps > 0 {
		peakBps := float64(st.peakBytes*8) / elapsed.Seconds()
		if peakBps < st.normalPeakBps*defaultPeakMinGain {
			st.onPeak = false
			st.peakStarted = time.Time{}
			st.peakBytes = 0
			st.returnSince = time.Time{}
			st.suppressUntil = now.Add(defaultPeakSuppressFor)
			c.mu.Unlock()
			c.applyPolicy(rx, uint32(ModePrime), c.normalIDs[0], c.normalIDs, firstNonEmpty(c.normalNames), nonEmptyNames(c.normalNames), "peak-verify-failed")
			c.mu.Lock()
			return
		}
		st.peakStarted = time.Time{}
		st.peakBytes = 0
	}

	ratio := c.opts.ReturnRatio
	if ratio <= 0 {
		ratio = defaultPeakReturn
	}
	needFor := c.opts.ReturnFor
	if needFor <= 0 {
		needFor = defaultPeakReturnFor
	}
	low := st.normalPeakBps > 0 && bps < st.normalPeakBps*ratio
	if !low {
		st.returnSince = time.Time{}
		return
	}
	if st.returnSince.IsZero() {
		st.returnSince = now
		return
	}
	if now.Sub(st.returnSince) < needFor {
		return
	}
	st.onPeak = false
	st.peakStarted = time.Time{}
	st.peakBytes = 0
	st.returnSince = time.Time{}
	c.mu.Unlock()
	c.applyPolicy(rx, uint32(ModePrime), c.normalIDs[0], c.normalIDs, firstNonEmpty(c.normalNames), nonEmptyNames(c.normalNames), "peak-return")
	c.mu.Lock()
}

func (c *peakTransferController) applyPolicy(rx bool, mode uint32, activeID uint32, scopeIDs []uint32, activeName string, scopeNames []string, cause string) {
	if rx {
		if activeName == "" || len(scopeNames) == 0 {
			return
		}
		_ = c.e.SendPolicyRequest(mode, activeName, scopeNames, cause+"-rx")
		return
	}
	_ = c.e.SetDispatchPolicy(mode, activeID, scopeIDs, cause)
	c.setMode(Mode(mode))
}

func (c *peakTransferController) peakHealthy() bool {
	const (
		maxLossPP = 50 // 5%
		maxJitter = 200 * time.Millisecond
		maxAge    = 5 * time.Second
	)
	now := time.Now()
	stats := c.e.Paths()
	peak := make(map[uint32]bool, len(c.peakIDs))
	for _, id := range c.peakIDs {
		peak[id] = true
	}
	seenMeasured := false
	for _, p := range stats {
		if !peak[p.ID] {
			continue
		}
		q := p.Quality
		if q.At.IsZero() && q.RTT == 0 && q.Jitter == 0 && q.LossPP == 0 {
			return true
		}
		seenMeasured = true
		if !q.At.IsZero() && now.Sub(q.At) > maxAge {
			continue
		}
		if q.LossPP <= maxLossPP && q.Jitter <= maxJitter {
			return true
		}
	}
	return !seenMeasured
}

func nonEmptyNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func firstNonEmpty(names []string) string {
	for _, name := range names {
		if name != "" {
			return name
		}
	}
	return ""
}
