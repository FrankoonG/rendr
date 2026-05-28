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

	normalIDs []uint32
	peakIDs   []uint32
	peakMode  Mode
	opts      PeakTransfer

	bytes atomic.Uint64

	mu             sync.Mutex
	onPeak         bool
	normalPeakBps  float64
	normalBytes    uint64
	peakStarted    time.Time
	peakBytes      uint64
	suppressUntil  time.Time
	saturatedSince time.Time
	returnSince    time.Time

	stop chan struct{}
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
		if i < len(plan.pathPeak) && plan.pathPeak[i] {
			c.peakIDs = append(c.peakIDs, id)
		} else {
			c.normalIDs = append(c.normalIDs, id)
		}
	}
	if len(c.normalIDs) == 0 && len(pathIDs) > 0 {
		c.normalIDs = append(c.normalIDs, pathIDs[0])
	}
	if len(c.peakIDs) == 0 && len(pathIDs) > 1 {
		c.peakIDs = append(c.peakIDs, pathIDs[1:]...)
	}
	return c
}

func (c *peakTransferController) start() {
	if c == nil || len(c.normalIDs) == 0 || len(c.peakIDs) == 0 {
		return
	}
	_ = c.e.SetDispatchPolicy(uint32(ModePrime), c.normalIDs[0], c.normalIDs, "selector")
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
	c.bytes.Add(uint64(n))
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
			bytes := c.bytes.Swap(0)
			bps := float64(bytes*8) / elapsed.Seconds()
			c.evaluate(now, bytes, bps)
		}
	}
}

func (c *peakTransferController) evaluate(now time.Time, bytes uint64, bps float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.onPeak {
		c.normalBytes += bytes
		if bps > c.normalPeakBps {
			c.normalPeakBps = bps
		}
		if c.normalBytes < defaultPeakMinBytes || c.normalPeakBps <= 0 {
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
		saturated := bps > 0 && bps >= c.normalPeakBps*ratio
		if !saturated {
			c.saturatedSince = time.Time{}
			return
		}
		if c.saturatedSince.IsZero() {
			c.saturatedSince = now
			return
		}
		if now.Sub(c.saturatedSince) < needFor {
			return
		}
		if now.Before(c.suppressUntil) {
			c.saturatedSince = time.Time{}
			return
		}
		if !c.peakHealthy() {
			c.saturatedSince = time.Time{}
			return
		}
		c.onPeak = true
		c.peakStarted = now
		c.peakBytes = 0
		c.saturatedSince = time.Time{}
		c.returnSince = time.Time{}
		c.mu.Unlock()
		_ = c.e.SetDispatchPolicy(uint32(c.peakMode), c.peakIDs[0], c.peakIDs, "peak-transfer")
		c.setMode(c.peakMode)
		c.mu.Lock()
		return
	}

	c.peakBytes += bytes
	if c.peakStarted.IsZero() {
		c.peakStarted = now
	}
	verifyFor := defaultPeakVerifyFor
	if elapsed := now.Sub(c.peakStarted); elapsed >= verifyFor && c.normalPeakBps > 0 {
		peakBps := float64(c.peakBytes*8) / elapsed.Seconds()
		if peakBps < c.normalPeakBps*defaultPeakMinGain {
			c.onPeak = false
			c.peakStarted = time.Time{}
			c.peakBytes = 0
			c.returnSince = time.Time{}
			c.suppressUntil = now.Add(defaultPeakSuppressFor)
			c.mu.Unlock()
			_ = c.e.SetDispatchPolicy(uint32(ModePrime), c.normalIDs[0], c.normalIDs, "peak-verify-failed")
			c.setMode(ModePrime)
			c.mu.Lock()
			return
		}
		c.peakStarted = time.Time{}
		c.peakBytes = 0
	}

	ratio := c.opts.ReturnRatio
	if ratio <= 0 {
		ratio = defaultPeakReturn
	}
	needFor := c.opts.ReturnFor
	if needFor <= 0 {
		needFor = defaultPeakReturnFor
	}
	low := c.normalPeakBps > 0 && bps < c.normalPeakBps*ratio
	if !low {
		c.returnSince = time.Time{}
		return
	}
	if c.returnSince.IsZero() {
		c.returnSince = now
		return
	}
	if now.Sub(c.returnSince) < needFor {
		return
	}
	c.onPeak = false
	c.peakStarted = time.Time{}
	c.peakBytes = 0
	c.returnSince = time.Time{}
	c.mu.Unlock()
	_ = c.e.SetDispatchPolicy(uint32(ModePrime), c.normalIDs[0], c.normalIDs, "peak-return")
	c.setMode(ModePrime)
	c.mu.Lock()
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
