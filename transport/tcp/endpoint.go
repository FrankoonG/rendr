package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

var (
	errEndpointClosed      = errors.New("tcp: endpoint is closed")
	errEndpointMaintenance = errors.New("tcp: endpoint maintenance is already active")
	errEndpointStaleLease  = errors.New("tcp: endpoint maintenance lease is stale")
	errEndpointQuiesce     = errors.New("tcp: endpoint I/O did not quiesce after deadline interrupt")
)

const endpointInterruptGrace = 250 * time.Millisecond

// endpointOwner serializes destructive endpoint maintenance with framed I/O.
// A reader may be interrupted between arbitrary TCP bytes; the framing layer
// keeps those bytes in its current call and resumes on the replacement socket.
type endpointOwner struct {
	mu sync.Mutex

	conn           net.Conn
	generation     uint64
	closed         bool
	failed         bool
	maintenance    bool
	maintenanceErr error

	readActive  bool
	writeActive bool
	io          sync.WaitGroup
	state       chan struct{}
}

func (o *endpointOwner) LeafMobilityIncarnation() uint64 {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	generation := o.generation
	o.mu.Unlock()
	return generation
}

func newEndpointOwner(conn net.Conn) *endpointOwner {
	return &endpointOwner{
		conn:       conn,
		generation: 1,
		state:      make(chan struct{}),
	}
}

func (o *endpointOwner) currentTCPConn() (*net.TCPConn, bool) {
	if o == nil {
		return nil, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	conn, ok := o.conn.(*net.TCPConn)
	return conn, ok && conn != nil && !o.closed && !o.failed
}

type endpointRead struct {
	owner      *endpointOwner
	conn       net.Conn
	generation uint64
}

func (o *endpointOwner) acquireRead() (endpointRead, error) {
	if o == nil {
		return endpointRead{}, errEndpointClosed
	}
	for {
		o.mu.Lock()
		if o.closed || o.failed || o.conn == nil {
			o.mu.Unlock()
			return endpointRead{}, errEndpointClosed
		}
		if !o.maintenance {
			if o.readActive {
				o.mu.Unlock()
				return endpointRead{}, fmt.Errorf("tcp: concurrent endpoint read")
			}
			o.readActive = true
			o.io.Add(1)
			read := endpointRead{owner: o, conn: o.conn, generation: o.generation}
			o.mu.Unlock()
			return read, nil
		}
		changed := o.state
		o.mu.Unlock()
		<-changed
	}
}

// finish releases one kernel read. It reports whether a maintenance deadline
// interrupted this exact endpoint generation and the framing read should wait
// and continue instead of declaring path death.
func (r endpointRead) finish(err error, complete bool) bool {
	if r.owner == nil {
		return false
	}
	o := r.owner
	o.mu.Lock()
	released := false
	if o.readActive {
		o.readActive = false
		released = true
	}
	interrupted := o.maintenance && !o.closed && o.generation == r.generation &&
		(err == nil || errors.Is(err, os.ErrDeadlineExceeded) || isTimeout(err))
	if o.maintenance && !o.closed && o.generation == r.generation && err != nil && !interrupted && !complete && o.maintenanceErr == nil {
		o.maintenanceErr = err
	}
	o.mu.Unlock()
	if released {
		o.io.Done()
	}
	return interrupted
}

type endpointWrite struct {
	owner      *endpointOwner
	conn       net.Conn
	generation uint64
}

func (o *endpointOwner) acquireWrite() (endpointWrite, error) {
	if o == nil {
		return endpointWrite{}, errEndpointClosed
	}
	for {
		o.mu.Lock()
		if o.closed || o.failed || o.conn == nil {
			o.mu.Unlock()
			return endpointWrite{}, errEndpointClosed
		}
		if !o.maintenance {
			if o.writeActive {
				o.mu.Unlock()
				return endpointWrite{}, fmt.Errorf("tcp: concurrent endpoint write")
			}
			o.writeActive = true
			o.io.Add(1)
			write := endpointWrite{owner: o, conn: o.conn, generation: o.generation}
			o.mu.Unlock()
			return write, nil
		}
		changed := o.state
		o.mu.Unlock()
		<-changed
	}
}

func (w endpointWrite) finish(err error, complete bool) bool {
	if w.owner == nil {
		return false
	}
	o := w.owner
	o.mu.Lock()
	released := false
	if o.writeActive {
		o.writeActive = false
		released = true
	}
	interrupted := o.maintenance && !o.closed && o.generation == w.generation &&
		(err == nil || errors.Is(err, os.ErrDeadlineExceeded) || isTimeout(err))
	if o.maintenance && !o.closed && o.generation == w.generation && err != nil && !interrupted && !complete && o.maintenanceErr == nil {
		o.maintenanceErr = err
	}
	o.mu.Unlock()
	if released {
		o.io.Done()
	}
	return interrupted
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

type endpointMaintenance struct {
	owner      *endpointOwner
	conn       net.Conn
	generation uint64
	done       bool
}

// beginMaintenance prevents new reads, interrupts an in-kernel read, and waits
// until no goroutine is using the socket. The caller must eventually call
// Resume or leave the endpoint closed.
func (o *endpointOwner) beginMaintenance(ctx context.Context) (*endpointMaintenance, error) {
	if o == nil {
		return nil, errEndpointClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o.mu.Lock()
	if o.closed || o.failed || o.conn == nil {
		o.mu.Unlock()
		return nil, errEndpointClosed
	}
	if o.maintenance {
		o.mu.Unlock()
		return nil, errEndpointMaintenance
	}
	o.maintenance = true
	o.maintenanceErr = nil
	o.signalLocked()
	conn := o.conn
	generation := o.generation
	readActive, writeActive := o.readActive, o.writeActive
	o.mu.Unlock()

	interruptAt := time.Now()
	if err := conn.SetReadDeadline(interruptAt); err != nil {
		return nil, errors.Join(fmt.Errorf("tcp: interrupt endpoint read: %w", err), o.cancelMaintenance(conn, generation))
	}
	if err := conn.SetWriteDeadline(interruptAt); err != nil {
		idle := waitGroupDone(&o.io, readActive || writeActive)
		if !o.abortInterruptedMaintenance(conn, generation, idle, readActive || writeActive) {
			_ = o.close()
			return nil, errors.Join(fmt.Errorf("tcp: interrupt endpoint write: %w", err), errEndpointQuiesce)
		}
		return nil, fmt.Errorf("tcp: interrupt endpoint write: %w", err)
	}
	idle := waitGroupDone(&o.io, readActive || writeActive)
	if readActive || writeActive {
		select {
		case <-idle:
		case <-ctx.Done():
			if o.abortInterruptedMaintenance(conn, generation, idle, true) {
				return nil, ctx.Err()
			}
			_ = o.close()
			return nil, errors.Join(ctx.Err(), errEndpointQuiesce)
		}
	}
	o.mu.Lock()
	maintenanceErr := o.maintenanceErr
	currentBeforeClear := !o.closed && !o.failed && o.maintenance && o.conn == conn && o.generation == generation &&
		!o.readActive && !o.writeActive
	o.mu.Unlock()
	if maintenanceErr != nil {
		return nil, errors.Join(fmt.Errorf("tcp: endpoint failed while quiescing: %w", maintenanceErr), o.cancelMaintenance(conn, generation))
	}
	if !currentBeforeClear {
		return nil, errors.Join(errEndpointStaleLease, o.cancelMaintenance(conn, generation))
	}
	if err := ctx.Err(); err != nil {
		if cancelErr := o.cancelMaintenance(conn, generation); cancelErr != nil {
			return nil, errors.Join(err, cancelErr)
		}
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, errors.Join(fmt.Errorf("tcp: clear endpoint read deadline: %w", err), o.cancelMaintenance(conn, generation))
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, errors.Join(fmt.Errorf("tcp: clear endpoint write deadline: %w", err), o.cancelMaintenance(conn, generation))
	}
	if err := ctx.Err(); err != nil {
		if cancelErr := o.cancelMaintenance(conn, generation); cancelErr != nil {
			return nil, errors.Join(err, cancelErr)
		}
		return nil, err
	}

	o.mu.Lock()
	current := !o.closed && !o.failed && o.maintenance && o.conn == conn && o.generation == generation &&
		!o.readActive && !o.writeActive
	o.mu.Unlock()
	if !current {
		return nil, errors.Join(errEndpointStaleLease, o.cancelMaintenance(conn, generation))
	}
	return &endpointMaintenance{owner: o, conn: conn, generation: generation}, nil
}

// abortInterruptedMaintenance keeps the artificial deadlines armed until the
// in-kernel calls have actually returned. Clearing maintenance first would let
// their delayed timeout masquerade as a real path death.
func (o *endpointOwner) abortInterruptedMaintenance(
	conn net.Conn,
	generation uint64,
	idle <-chan struct{},
	active bool,
) bool {
	if !active {
		return o.cancelMaintenance(conn, generation) == nil
	}
	timer := time.NewTimer(endpointInterruptGrace)
	defer timer.Stop()
	select {
	case <-idle:
	case <-timer.C:
		return false
	}
	return o.cancelMaintenance(conn, generation) == nil
}

func waitGroupDone(group *sync.WaitGroup, active bool) <-chan struct{} {
	if !active {
		return nil
	}
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	return done
}

func (o *endpointOwner) cancelMaintenance(conn net.Conn, generation uint64) error {
	if o == nil {
		return errEndpointClosed
	}
	clearErr := errors.Join(conn.SetReadDeadline(time.Time{}), conn.SetWriteDeadline(time.Time{}))
	if clearErr != nil {
		_ = o.close()
		return fmt.Errorf("tcp: restore endpoint deadlines: %w", clearErr)
	}
	o.mu.Lock()
	if o.closed || o.failed || !o.maintenance || o.conn != conn || o.generation != generation {
		o.mu.Unlock()
		return errEndpointStaleLease
	}
	o.maintenance = false
	o.maintenanceErr = nil
	o.signalLocked()
	o.mu.Unlock()
	return nil
}

func (m *endpointMaintenance) Conn() net.Conn {
	if m == nil {
		return nil
	}
	return m.conn
}

// Replace atomically publishes a replacement while readers remain paused.
// Closing the predecessor is deliberately left to the destructive driver.
func (m *endpointMaintenance) Replace(replacement net.Conn) error {
	return m.ReplaceContext(context.Background(), replacement)
}

// ReplaceContext checks cancellation while holding the endpoint owner lock,
// immediately before the owner-swap linearization point.
func (m *endpointMaintenance) ReplaceContext(ctx context.Context, replacement net.Conn) error {
	if m == nil || m.owner == nil || replacement == nil || m.done {
		return errEndpointStaleLease
	}
	if ctx == nil {
		ctx = context.Background()
	}
	o := m.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.failed || !o.maintenance || o.conn != m.conn || o.generation != m.generation || o.readActive || o.writeActive {
		return errEndpointStaleLease
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	o.conn = replacement
	o.generation++
	if o.generation == 0 {
		o.generation++
	}
	m.conn = replacement
	m.generation = o.generation
	return nil
}

// Resume makes the current endpoint visible to framed reads again. The caller
// is responsible for releasing its framed-write exclusion after this returns.
func (m *endpointMaintenance) Resume() error {
	if m == nil || m.owner == nil || m.done {
		return errEndpointStaleLease
	}
	o := m.owner
	o.mu.Lock()
	if o.closed || o.failed || !o.maintenance || o.conn != m.conn || o.generation != m.generation || o.readActive || o.writeActive {
		o.mu.Unlock()
		return errEndpointStaleLease
	}
	o.maintenance = false
	o.maintenanceErr = nil
	m.done = true
	o.signalLocked()
	o.mu.Unlock()
	return nil
}

// FailClosed permanently retires the endpoint held by this maintenance lease.
// Destructive drivers call it only after closing every physical incarnation
// while any required packet quarantine is still active.
func (m *endpointMaintenance) FailClosed() error {
	if m == nil || m.owner == nil {
		return errEndpointStaleLease
	}
	if m.done {
		return nil
	}
	o := m.owner
	o.mu.Lock()
	if o.closed {
		m.done = true
		o.mu.Unlock()
		return nil
	}
	if o.failed || !o.maintenance || o.conn != m.conn || o.generation != m.generation || o.readActive || o.writeActive {
		o.mu.Unlock()
		return errEndpointStaleLease
	}
	o.closed = true
	o.maintenance = false
	o.maintenanceErr = nil
	o.conn = nil
	m.done = true
	o.signalLocked()
	o.mu.Unlock()
	return nil
}

func (o *endpointOwner) failClosedCurrent(conn net.Conn) error {
	if o == nil || conn == nil {
		return errEndpointStaleLease
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	if o.conn != conn || o.readActive || o.writeActive || o.maintenance {
		return errEndpointStaleLease
	}
	o.closed = true
	o.conn = nil
	o.signalLocked()
	return nil
}

func (o *endpointOwner) current() (net.Conn, uint64, bool) {
	if o == nil {
		return nil, 0, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.failed || o.conn == nil || o.maintenance {
		return nil, o.generation, false
	}
	return o.conn, o.generation, true
}

// markFailure atomically prevents a replacement from being published over a
// transport error from the same endpoint generation. False means the error
// belongs to a predecessor that has already been replaced and must be ignored.
func (o *endpointOwner) markFailure(generation uint64) bool {
	if o == nil {
		return true
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.generation != generation {
		return false
	}
	if o.closed || o.failed {
		return true
	}
	o.failed = true
	o.signalLocked()
	return true
}

func (o *endpointOwner) addresses() (net.Addr, net.Addr) {
	if o == nil {
		return nil, nil
	}
	o.mu.Lock()
	conn := o.conn
	o.mu.Unlock()
	if conn == nil {
		return nil, nil
	}
	return conn.LocalAddr(), conn.RemoteAddr()
}

func (o *endpointOwner) close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	conn := o.conn
	o.signalLocked()
	o.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

func (o *endpointOwner) signalLocked() {
	close(o.state)
	o.state = make(chan struct{})
}
