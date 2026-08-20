package rendr

import (
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	tadapter "github.com/FrankoonG/rendr/transport/tcp"
)

func TestRuntimeControlledTCPProbeDelayFIFOArrivalSchedule(t *testing.T) {
	clock := newRuntimeControlledTCPManualProbeClock(time.Unix(0, 0))
	base := newRuntimeControlledTCPProbeScriptPath()
	path := &runtimeControlledTCPPath{
		base:             base,
		dataPath:         newRuntimeControlledTCPDataPath(),
		probeDelayClosed: make(chan struct{}),
		probeClock:       clock,
	}
	path.probeDelayNanos.Store(int64(250 * time.Millisecond))
	t.Cleanup(func() { _ = path.Close() })

	type delivery struct {
		id uint64
		at time.Time
	}
	deliveries := make(chan delivery, 3)
	go func() {
		for range 3 {
			buf := make([]byte, tadapter.MaxFrameSize)
			n, err := path.Read(buf)
			if err != nil {
				deliveries <- delivery{}
				return
			}
			probe, err := proto.DecodeProbe(buf[proto.HeaderSize:n])
			if err != nil {
				deliveries <- delivery{}
				return
			}
			deliveries <- delivery{id: probe.ID, at: clock.Now()}
		}
	}()

	base.deliver(runtimeControlledTCPProbeFixtureFrame(t, proto.ProbePayload{TS: 1, ID: 1}.Encode()))
	runtimeControlledTCPWaitForProbeQueue(t, path, 1)
	clock.Advance(100 * time.Millisecond)
	base.deliver(runtimeControlledTCPProbeFixtureFrame(t, proto.ProbePayload{TS: 2, ID: 2}.Encode()))
	runtimeControlledTCPWaitForProbeQueue(t, path, 2)
	clock.Advance(100 * time.Millisecond)
	base.deliver(runtimeControlledTCPProbeFixtureFrame(t, proto.ProbePayload{TS: 3, ID: 3}.Encode()))
	runtimeControlledTCPWaitForProbeQueue(t, path, 3)

	select {
	case got := <-deliveries:
		t.Fatalf("delivered before first arrival+delay: %+v", got)
	default:
	}

	wantTimes := []time.Time{
		time.Unix(0, 0).Add(250 * time.Millisecond),
		time.Unix(0, 0).Add(350 * time.Millisecond),
		time.Unix(0, 0).Add(450 * time.Millisecond),
	}
	clock.Advance(50 * time.Millisecond)
	for i := range 3 {
		got := runtimeControlledTCPAwaitProbeDelivery(t, deliveries)
		if got.id != uint64(i+1) || !got.at.Equal(wantTimes[i]) {
			t.Fatalf("delivery %d = {id:%d at:%s}, want {id:%d at:%s}", i, got.id, got.at, i+1, wantTimes[i])
		}
		if i < 2 {
			clock.Advance(100 * time.Millisecond)
		}
	}
}

func TestRuntimeControlledTCPProbeDelayFIFOPreservesMixedFrameOrder(t *testing.T) {
	clock := newRuntimeControlledTCPManualProbeClock(time.Unix(0, 0))
	closed := make(chan struct{})
	defer close(closed)
	var delay atomic.Int64
	delay.Store(int64(250 * time.Millisecond))
	fifo := newRuntimeControlledTCPProbeDelayFIFO(
		nil,
		&delay,
		clock,
		runtimeControlledTCPProbeQueueLimits{frames: 16, bytes: 1 << 20},
		closed,
	)

	probe1 := runtimeControlledTCPProbeFixtureFrame(t, proto.ProbePayload{TS: 1, ID: 1}.Encode())
	probe2 := runtimeControlledTCPProbeFixtureFrame(t, proto.ProbePayload{TS: 2, ID: 2}.Encode())
	ackPayload := (proto.AckPayload{
		Direction:     proto.SenderDirectionClientToServer,
		GraphRevision: 1,
		NextSeq:       2,
	}).Encode()
	if _, ok := proto.DecodeAck(ackPayload); !ok {
		t.Fatal("fixture AckPayload is not valid")
	}
	ack := runtimeControlledTCPProbeFixtureFrame(t, ackPayload)
	if !isExactPathProbeReply(probe1) {
		t.Fatal("exact ProbePayload was not classified as delayed")
	}
	if isExactPathProbeReply(ack) {
		t.Fatal("valid AckPayload was classified as a delayed probe")
	}
	if isExactPathProbeReply(runtimeControlledTCPProbeFixtureFrame(t, []byte{1, 2, 3})) {
		t.Fatal("malformed probe payload was classified as delayed")
	}

	if err := fifo.enqueue(probe1, clock.Now()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(100 * time.Millisecond)
	for range 3 {
		if err := fifo.enqueue(ack, clock.Now()); err != nil {
			t.Fatal(err)
		}
	}
	clock.Advance(100 * time.Millisecond)
	if err := fifo.enqueue(probe2, clock.Now()); err != nil {
		t.Fatal(err)
	}

	type delivery struct {
		frame []byte
		at    time.Time
		err   error
	}
	deliveries := make(chan delivery, 5)
	go func() {
		for range 5 {
			buf := make([]byte, tadapter.MaxFrameSize)
			n, err := fifo.Read(buf)
			deliveries <- delivery{frame: append([]byte(nil), buf[:n]...), at: clock.Now(), err: err}
		}
	}()

	clock.Advance(50 * time.Millisecond)
	first := runtimeControlledTCPAwaitMixedDelivery(t, deliveries)
	if first.err != nil || !reflect.DeepEqual(first.frame, probe1) || !first.at.Equal(time.Unix(0, 0).Add(250*time.Millisecond)) {
		t.Fatalf("first delivery = {%d bytes, %s, %v}, want probe1 at 250ms", len(first.frame), first.at, first.err)
	}
	for i := range 3 {
		got := runtimeControlledTCPAwaitMixedDelivery(t, deliveries)
		if got.err != nil || !reflect.DeepEqual(got.frame, ack) || !got.at.Equal(first.at) {
			t.Fatalf("ACK delivery %d = {%d bytes, %s, %v}, want FIFO release at %s", i, len(got.frame), got.at, got.err, first.at)
		}
	}
	select {
	case got := <-deliveries:
		t.Fatalf("second probe delivered before its own arrival+delay: %+v", got)
	default:
	}
	clock.Advance(200 * time.Millisecond)
	last := runtimeControlledTCPAwaitMixedDelivery(t, deliveries)
	if last.err != nil || !reflect.DeepEqual(last.frame, probe2) || !last.at.Equal(time.Unix(0, 0).Add(450*time.Millisecond)) {
		t.Fatalf("last delivery = {%d bytes, %s, %v}, want probe2 at 450ms", len(last.frame), last.at, last.err)
	}
}

func TestRuntimeControlledTCPProbeDelayFIFOOverflowIsExplicit(t *testing.T) {
	frame := runtimeControlledTCPProbeFixtureFrame(t, proto.ProbePayload{TS: 1, ID: 1}.Encode())
	newFIFO := func(limits runtimeControlledTCPProbeQueueLimits) *runtimeControlledTCPProbeDelayFIFO {
		var delay atomic.Int64
		return newRuntimeControlledTCPProbeDelayFIFO(
			nil,
			&delay,
			newRuntimeControlledTCPManualProbeClock(time.Unix(0, 0)),
			limits,
			make(chan struct{}),
		)
	}

	t.Run("frame bound", func(t *testing.T) {
		fifo := newFIFO(runtimeControlledTCPProbeQueueLimits{frames: 2, bytes: len(frame) * 3})
		if err := fifo.enqueue(frame, time.Unix(0, 0)); err != nil {
			t.Fatal(err)
		}
		if err := fifo.enqueue(frame, time.Unix(0, 0)); err != nil {
			t.Fatal(err)
		}
		if err := fifo.enqueue(frame, time.Unix(0, 0)); !errors.Is(err, errRuntimeControlledTCPProbeQueueOverflow) {
			t.Fatalf("third enqueue error=%v, want explicit overflow", err)
		}
		if _, err := fifo.Read(make([]byte, tadapter.MaxFrameSize)); !errors.Is(err, errRuntimeControlledTCPProbeQueueOverflow) {
			t.Fatalf("read after overflow error=%v, want explicit overflow", err)
		}
	})

	t.Run("byte bound", func(t *testing.T) {
		fifo := newFIFO(runtimeControlledTCPProbeQueueLimits{frames: 3, bytes: len(frame)*2 - 1})
		if err := fifo.enqueue(frame, time.Unix(0, 0)); err != nil {
			t.Fatal(err)
		}
		if err := fifo.enqueue(frame, time.Unix(0, 0)); !errors.Is(err, errRuntimeControlledTCPProbeQueueOverflow) {
			t.Fatalf("second enqueue error=%v, want explicit byte overflow", err)
		}
	})
}

func TestRuntimeControlledTCPProbeDelayFIFOStorageRemainsBounded(t *testing.T) {
	frame := runtimeControlledTCPProbeFixtureFrame(t, (proto.AckPayload{
		Direction:     proto.SenderDirectionClientToServer,
		GraphRevision: 1,
		NextSeq:       1,
	}).Encode())
	var delay atomic.Int64
	fifo := newRuntimeControlledTCPProbeDelayFIFO(
		nil,
		&delay,
		newRuntimeControlledTCPManualProbeClock(time.Unix(0, 0)),
		runtimeControlledTCPProbeQueueLimits{frames: 4, bytes: len(frame) * 4},
		make(chan struct{}),
	)
	for range 3 {
		if err := fifo.enqueue(frame, time.Unix(0, 0)); err != nil {
			t.Fatal(err)
		}
	}
	for range 1000 {
		buf := make([]byte, len(frame))
		if n, err := fifo.Read(buf); err != nil || n != len(frame) {
			t.Fatalf("steady-state read=(%d,%v), want (%d,nil)", n, err, len(frame))
		}
		if err := fifo.enqueue(frame, time.Unix(0, 0)); err != nil {
			t.Fatal(err)
		}
	}
	fifo.mu.Lock()
	queued := len(fifo.frames) - fifo.head
	storage := cap(fifo.frames)
	queuedBytes := fifo.bytes
	fifo.mu.Unlock()
	if queued != 3 || queuedBytes != 3*len(frame) {
		t.Fatalf("steady-state queue=(%d frames,%d bytes), want (3,%d)", queued, queuedBytes, 3*len(frame))
	}
	if storage > fifo.limits.frames {
		t.Fatalf("FIFO backing storage=%d frames exceeds configured bound=%d", storage, fifo.limits.frames)
	}
}

func TestRuntimeControlledTCPProbeDelayFIFOBackpressuresPhysicalPump(t *testing.T) {
	base := newRuntimeControlledTCPProbeScriptPath()
	closed := make(chan struct{})
	var delay atomic.Int64
	fifo := newRuntimeControlledTCPProbeDelayFIFO(
		base,
		&delay,
		runtimeControlledTCPRealProbeClock{},
		runtimeControlledTCPProbeQueueLimits{frames: 2, bytes: 2 * tadapter.MaxFrameSize},
		closed,
	)
	fifo.start()
	t.Cleanup(func() {
		close(closed)
		_ = base.Close()
		fifo.wait()
	})

	frame := runtimeControlledTCPProbeFixtureFrame(t, (proto.AckPayload{
		Direction:     proto.SenderDirectionClientToServer,
		GraphRevision: 1,
		NextSeq:       1,
	}).Encode())
	for i := 0; i < 2; i++ {
		base.deliver(frame)
	}
	runtimeControlledTCPWaitForFIFOQueue(t, fifo, 2)

	thirdDelivered := make(chan struct{})
	go func() {
		base.deliver(frame)
		close(thirdDelivered)
	}()
	select {
	case <-thirdDelivered:
		t.Fatal("physical pump read a third frame while its two-frame queue was full")
	case <-time.After(25 * time.Millisecond):
	}

	buf := make([]byte, tadapter.MaxFrameSize)
	if n, err := fifo.Read(buf); err != nil || n != len(frame) {
		t.Fatalf("release read=(%d,%v) want (%d,nil)", n, err, len(frame))
	}
	select {
	case <-thirdDelivered:
	case <-time.After(time.Second):
		t.Fatal("physical pump did not resume after one queue slot was released")
	}
	runtimeControlledTCPWaitForFIFOQueue(t, fifo, 2)
	fifo.mu.Lock()
	fatalErr := fifo.fatalErr
	fifo.mu.Unlock()
	if fatalErr != nil {
		t.Fatalf("bounded physical backpressure became a path failure: %v", fatalErr)
	}
}

func TestRuntimeControlledTCPProbeDelayCloseJoinsPump(t *testing.T) {
	base := newRuntimeControlledTCPProbeBlockingPath()
	closed := make(chan struct{})
	path := &runtimeControlledTCPPath{
		base:             base,
		dataPath:         newRuntimeControlledTCPDataPath(),
		probeDelayClosed: closed,
	}
	var delay atomic.Int64
	delay.Store(int64(time.Second))
	fifo := newRuntimeControlledTCPProbeDelayFIFO(
		base,
		&delay,
		runtimeControlledTCPRealProbeClock{},
		runtimeControlledTCPProbeQueueLimits{frames: 4, bytes: 1 << 20},
		closed,
	)
	path.probeDelayNanos.Store(delay.Load())
	path.probeDelayFIFO = fifo
	fifo.start()

	select {
	case <-base.readStarted:
	case <-time.After(time.Second):
		t.Fatal("probe-delay pump did not enter the physical read")
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := path.Read(make([]byte, tadapter.MaxFrameSize))
		readDone <- err
	}()
	if err := path.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-base.readExited:
	default:
		t.Fatal("Close returned before the physical reader exited")
	}
	select {
	case <-fifo.done:
	default:
		t.Fatal("Close returned before the probe-delay pump joined")
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("cancelled delayed read error=%v, want %v", err, net.ErrClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the delayed reader")
	}
}

func runtimeControlledTCPProbeFixtureFrame(t testing.TB, payload []byte) []byte {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Last:    true,
		Flags:   proto.FlagsForCtrl(proto.CtrlPathProbeReply),
		Seq:     1,
	}).Encode(frame); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	return frame
}

func runtimeControlledTCPWaitForProbeQueue(t testing.TB, path *runtimeControlledTCPPath, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		fifo := path.loadProbeDelayFIFO()
		if fifo != nil {
			fifo.mu.Lock()
			queued := len(fifo.frames) - fifo.head
			fatalErr := fifo.fatalErr
			fifo.mu.Unlock()
			if fatalErr != nil {
				t.Fatal(fatalErr)
			}
			if queued >= want {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("probe-delay FIFO did not reach %d queued frames", want)
}

func runtimeControlledTCPWaitForFIFOQueue(
	t testing.TB,
	fifo *runtimeControlledTCPProbeDelayFIFO,
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		fifo.mu.Lock()
		queued := len(fifo.frames) - fifo.head
		fatalErr := fifo.fatalErr
		fifo.mu.Unlock()
		if fatalErr != nil {
			t.Fatal(fatalErr)
		}
		if queued == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	fifo.mu.Lock()
	queued := len(fifo.frames) - fifo.head
	fifo.mu.Unlock()
	t.Fatalf("probe-delay FIFO queue=%d want %d", queued, want)
}

func runtimeControlledTCPAwaitProbeDelivery[T any](t testing.TB, deliveries <-chan T) T {
	t.Helper()
	select {
	case got := <-deliveries:
		return got
	case <-time.After(time.Second):
		var zero T
		t.Fatal("timed out waiting for probe-delay delivery")
		return zero
	}
}

func runtimeControlledTCPAwaitMixedDelivery[T any](t testing.TB, deliveries <-chan T) T {
	t.Helper()
	return runtimeControlledTCPAwaitProbeDelivery(t, deliveries)
}

type runtimeControlledTCPManualProbeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[*runtimeControlledTCPManualProbeTimer]struct{}
}

func newRuntimeControlledTCPManualProbeClock(now time.Time) *runtimeControlledTCPManualProbeClock {
	return &runtimeControlledTCPManualProbeClock{
		now:    now,
		timers: make(map[*runtimeControlledTCPManualProbeTimer]struct{}),
	}
}

func (c *runtimeControlledTCPManualProbeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *runtimeControlledTCPManualProbeClock) NewTimerAt(deadline time.Time) runtimeControlledTCPProbeTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &runtimeControlledTCPManualProbeTimer{
		clock:    c,
		deadline: deadline,
		ch:       make(chan time.Time, 1),
		active:   true,
	}
	if timer.deadline.After(c.now) {
		c.timers[timer] = struct{}{}
	} else {
		timer.active = false
		timer.ch <- c.now
	}
	return timer
}

func (c *runtimeControlledTCPManualProbeClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	now := c.now
	var ready []*runtimeControlledTCPManualProbeTimer
	for timer := range c.timers {
		if !timer.deadline.After(now) {
			delete(c.timers, timer)
			timer.active = false
			ready = append(ready, timer)
		}
	}
	c.mu.Unlock()
	for _, timer := range ready {
		timer.ch <- now
	}
}

type runtimeControlledTCPManualProbeTimer struct {
	clock    *runtimeControlledTCPManualProbeClock
	deadline time.Time
	ch       chan time.Time
	active   bool
}

func (t *runtimeControlledTCPManualProbeTimer) C() <-chan time.Time { return t.ch }

func (t *runtimeControlledTCPManualProbeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if !t.active {
		return false
	}
	delete(t.clock.timers, t)
	t.active = false
	return true
}

type runtimeControlledTCPProbeScriptPath struct {
	incoming chan []byte
	closed   chan struct{}
	once     sync.Once
}

func newRuntimeControlledTCPProbeScriptPath() *runtimeControlledTCPProbeScriptPath {
	return &runtimeControlledTCPProbeScriptPath{
		incoming: make(chan []byte),
		closed:   make(chan struct{}),
	}
}

func (p *runtimeControlledTCPProbeScriptPath) deliver(frame []byte) {
	p.incoming <- append([]byte(nil), frame...)
}

func (p *runtimeControlledTCPProbeScriptPath) Read(buf []byte) (int, error) {
	select {
	case frame := <-p.incoming:
		if len(buf) < len(frame) {
			copy(buf, frame)
			return len(buf), io.ErrShortBuffer
		}
		return copy(buf, frame), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *runtimeControlledTCPProbeScriptPath) Write(frame []byte) (int, error) {
	return len(frame), nil
}

func (p *runtimeControlledTCPProbeScriptPath) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (*runtimeControlledTCPProbeScriptPath) Quality() transport.PathQuality {
	return transport.PathQuality{}
}
func (*runtimeControlledTCPProbeScriptPath) OnDeath(func(transport.DeathCause, error)) {}
func (*runtimeControlledTCPProbeScriptPath) LocalAddr() string                         { return "script-local" }
func (*runtimeControlledTCPProbeScriptPath) RemoteAddr() string                        { return "script-remote" }

type runtimeControlledTCPProbeBlockingPath struct {
	readStarted chan struct{}
	readExited  chan struct{}
	closed      chan struct{}
	startOnce   sync.Once
	exitOnce    sync.Once
	closeOnce   sync.Once
}

func newRuntimeControlledTCPProbeBlockingPath() *runtimeControlledTCPProbeBlockingPath {
	return &runtimeControlledTCPProbeBlockingPath{
		readStarted: make(chan struct{}),
		readExited:  make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (p *runtimeControlledTCPProbeBlockingPath) Read([]byte) (int, error) {
	p.startOnce.Do(func() { close(p.readStarted) })
	<-p.closed
	p.exitOnce.Do(func() { close(p.readExited) })
	return 0, net.ErrClosed
}

func (p *runtimeControlledTCPProbeBlockingPath) Write(frame []byte) (int, error) {
	return len(frame), nil
}

func (p *runtimeControlledTCPProbeBlockingPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (*runtimeControlledTCPProbeBlockingPath) Quality() transport.PathQuality {
	return transport.PathQuality{}
}
func (*runtimeControlledTCPProbeBlockingPath) OnDeath(func(transport.DeathCause, error)) {}
func (*runtimeControlledTCPProbeBlockingPath) LocalAddr() string                         { return "blocking-local" }
func (*runtimeControlledTCPProbeBlockingPath) RemoteAddr() string                        { return "blocking-remote" }
