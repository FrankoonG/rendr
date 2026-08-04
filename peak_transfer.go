package rendr

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
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

	normalIDs      []uint32
	peakIDs        []uint32
	peakMode       Mode
	opts           PeakTransfer
	selectorID     proto.TargetID
	normalTargetID proto.TargetID
	peakTargetID   proto.TargetID

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
		c.peakMode = ModeSelector
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
	if root, ok := plan.graph.manifest.Node(plan.graph.manifest.RootID); ok && root.Kind == proto.GraphNodeKindSelector {
		c.selectorID = root.ID
		peaks := make(map[proto.TargetID]struct{}, len(root.PeakCandidates))
		for _, id := range root.PeakCandidates {
			peaks[id] = struct{}{}
		}
		for _, id := range root.Children {
			if _, peak := peaks[id]; peak {
				if c.peakTargetID == (proto.TargetID{}) {
					c.peakTargetID = id
				}
				continue
			}
			if c.normalTargetID == (proto.TargetID{}) {
				c.normalTargetID = id
			}
		}
	}
	return c
}

func (c *peakTransferController) start() {
	if c == nil || len(c.normalIDs) == 0 || len(c.peakIDs) == 0 {
		return
	}
	if c.selectorID != (proto.TargetID{}) && c.normalTargetID != (proto.TargetID{}) {
		_ = c.e.InitializePolicySelection(c.selectorID, c.normalTargetID, "selector")
		_ = c.e.RequestPeerSelection(context.Background(), c.selectorID, c.normalTargetID, "selector-rx")
	}
	c.e.StartSelector(nil, 0)
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
		c.applyPolicy(rx, c.peakMode, c.peakTargetID, "peak-transfer")
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
			c.applyPolicy(rx, ModeSelector, c.normalTargetID, "peak-verify-failed")
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
	c.applyPolicy(rx, ModeSelector, c.normalTargetID, "peak-return")
	c.mu.Lock()
}

func (c *peakTransferController) applyPolicy(rx bool, mode Mode, peerTargetID proto.TargetID, cause string) {
	if rx {
		if c.selectorID == (proto.TargetID{}) || peerTargetID == (proto.TargetID{}) {
			return
		}
		_ = c.e.RequestPeerSelection(context.Background(), c.selectorID, peerTargetID, cause+"-rx")
		return
	}
	if err := c.e.SelectLocalTarget(c.selectorID, peerTargetID, cause); err == nil {
		c.setMode(mode)
	}
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
