package tcp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

type uninterruptibleReadConn struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newUninterruptibleReadConn() *uninterruptibleReadConn {
	return &uninterruptibleReadConn{started: make(chan struct{}), closed: make(chan struct{})}
}

func (c *uninterruptibleReadConn) Read([]byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	<-c.closed
	return 0, net.ErrClosed
}

func (*uninterruptibleReadConn) Write(buf []byte) (int, error) { return len(buf), nil }
func (c *uninterruptibleReadConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (*uninterruptibleReadConn) LocalAddr() net.Addr              { return nil }
func (*uninterruptibleReadConn) RemoteAddr() net.Addr             { return nil }
func (*uninterruptibleReadConn) SetDeadline(time.Time) error      { return nil }
func (*uninterruptibleReadConn) SetReadDeadline(time.Time) error  { return nil }
func (*uninterruptibleReadConn) SetWriteDeadline(time.Time) error { return nil }

type dataAndEOFConn struct{ data []byte }

func (c *dataAndEOFConn) Read(buf []byte) (int, error) {
	n := copy(buf, c.data)
	c.data = c.data[n:]
	if len(c.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}
func (*dataAndEOFConn) Write(buf []byte) (int, error)    { return len(buf), nil }
func (*dataAndEOFConn) Close() error                     { return nil }
func (*dataAndEOFConn) LocalAddr() net.Addr              { return nil }
func (*dataAndEOFConn) RemoteAddr() net.Addr             { return nil }
func (*dataAndEOFConn) SetDeadline(time.Time) error      { return nil }
func (*dataAndEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (*dataAndEOFConn) SetWriteDeadline(time.Time) error { return nil }

type nonTimeoutInterruptConn struct {
	started       chan struct{}
	interrupted   chan struct{}
	closed        chan struct{}
	startedOnce   sync.Once
	interruptOnce sync.Once
	closeOnce     sync.Once
	failure       error
}

func newNonTimeoutInterruptConn(failure error) *nonTimeoutInterruptConn {
	return &nonTimeoutInterruptConn{
		started: make(chan struct{}), interrupted: make(chan struct{}), closed: make(chan struct{}), failure: failure,
	}
}

func (c *nonTimeoutInterruptConn) Read([]byte) (int, error) {
	c.startedOnce.Do(func() { close(c.started) })
	select {
	case <-c.interrupted:
		return 0, c.failure
	case <-c.closed:
		return 0, net.ErrClosed
	}
}
func (*nonTimeoutInterruptConn) Write(buf []byte) (int, error) { return len(buf), nil }
func (c *nonTimeoutInterruptConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (*nonTimeoutInterruptConn) LocalAddr() net.Addr         { return nil }
func (*nonTimeoutInterruptConn) RemoteAddr() net.Addr        { return nil }
func (*nonTimeoutInterruptConn) SetDeadline(time.Time) error { return nil }
func (c *nonTimeoutInterruptConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.interruptOnce.Do(func() { close(c.interrupted) })
	}
	return nil
}
func (*nonTimeoutInterruptConn) SetWriteDeadline(time.Time) error { return nil }

type rejectingDeadlineConn struct {
	*uninterruptibleReadConn
	failure error
}

func (c *rejectingDeadlineConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		return c.failure
	}
	return nil
}

func TestEndpointMaintenancePreservesPartialFrameAcrossReplacement(t *testing.T) {
	oldLocal, oldPeer := net.Pipe()
	path := Wrap(oldLocal)
	t.Cleanup(func() {
		_ = path.Close()
		_ = oldPeer.Close()
	})

	death := make(chan error, 1)
	path.OnDeath(func(_ transport.DeathCause, err error) { death <- err })
	payload := []byte("frame-spans-the-endpoint-cutover")
	result := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		buf := make([]byte, len(payload))
		n, err := path.Read(buf)
		result <- struct {
			data []byte
			err  error
		}{data: append([]byte(nil), buf[:max(n, 0)]...), err: err}
	}()

	var prefix [LengthPrefixSize]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(payload)))
	if _, err := oldPeer.Write(prefix[:1]); err != nil {
		t.Fatalf("write partial prefix: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	lease, err := path.endpoint.beginMaintenance(ctx)
	cancel()
	if err != nil {
		t.Fatalf("begin maintenance: %v", err)
	}

	newLocal, newPeer := net.Pipe()
	t.Cleanup(func() { _ = newPeer.Close() })
	if err := lease.Conn().Close(); err != nil {
		t.Fatalf("close predecessor: %v", err)
	}
	if err := lease.Replace(newLocal); err != nil {
		t.Fatalf("replace endpoint: %v", err)
	}
	if err := lease.Resume(); err != nil {
		t.Fatalf("resume endpoint: %v", err)
	}

	wire := append(append([]byte(nil), prefix[1:]...), payload...)
	if _, err := newPeer.Write(wire); err != nil {
		t.Fatalf("write replacement remainder: %v", err)
	}
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("Read after replacement: %v", got.err)
		}
		if string(got.data) != string(payload) {
			t.Fatalf("payload=%q want %q", got.data, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("partial frame did not resume on replacement endpoint")
	}
	select {
	case err := <-death:
		t.Fatalf("maintenance leaked as path death: %v", err)
	default:
	}
}

func TestEndpointMaintenanceFencesWriteUntilReplacementIsPublished(t *testing.T) {
	oldLocal, oldPeer := net.Pipe()
	path := Wrap(oldLocal)
	t.Cleanup(func() {
		_ = path.Close()
		_ = oldPeer.Close()
	})

	payload := []byte("write-only-on-successor")
	wrote := make(chan error, 1)
	go func() {
		_, err := path.Write(payload)
		wrote <- err
	}()

	var predecessorByte [1]byte
	if _, err := io.ReadFull(oldPeer, predecessorByte[:]); err != nil {
		t.Fatalf("read predecessor partial frame: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	lease, err := path.endpoint.beginMaintenance(ctx)
	cancel()
	if err != nil {
		t.Fatalf("begin maintenance: %v", err)
	}

	newLocal, newPeer := net.Pipe()
	t.Cleanup(func() { _ = newPeer.Close() })
	_ = lease.Conn().Close()
	if err := lease.Replace(newLocal); err != nil {
		t.Fatalf("replace endpoint: %v", err)
	}
	if err := lease.Resume(); err != nil {
		t.Fatalf("resume endpoint: %v", err)
	}

	wire := make([]byte, LengthPrefixSize+len(payload))
	wire[0] = predecessorByte[0]
	if _, err := io.ReadFull(newPeer, wire[1:]); err != nil {
		t.Fatalf("read replacement write: %v", err)
	}
	if size := int(binary.BigEndian.Uint16(wire[:LengthPrefixSize])); size != len(payload) {
		t.Fatalf("frame size=%d want %d", size, len(payload))
	}
	if string(wire[LengthPrefixSize:]) != string(payload) {
		t.Fatalf("payload=%q want %q", wire[LengthPrefixSize:], payload)
	}
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatalf("Write after replacement: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fenced Write did not resume")
	}

	_ = oldPeer.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	var stale [1]byte
	if _, err := oldPeer.Read(stale[:]); err == nil {
		t.Fatal("predecessor unexpectedly received replacement payload")
	}
}

func TestEndpointClosePermanentlyRevokesMaintenanceLease(t *testing.T) {
	local, peer := net.Pipe()
	path := Wrap(local)
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	lease, err := path.endpoint.beginMaintenance(ctx)
	cancel()
	if err != nil {
		t.Fatalf("begin maintenance: %v", err)
	}
	if err := path.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	replacement, replacementPeer := net.Pipe()
	defer replacement.Close()
	defer replacementPeer.Close()
	if err := lease.Replace(replacement); !errors.Is(err, errEndpointStaleLease) {
		t.Fatalf("Replace after Close=%v, want stale lease", err)
	}
	if err := lease.Resume(); !errors.Is(err, errEndpointStaleLease) {
		t.Fatalf("Resume after Close=%v, want stale lease", err)
	}
	if _, err := path.Write([]byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close=%v, want net.ErrClosed", err)
	}
}

func TestEndpointMaintenanceCancellationFailsClosedWhenSyscallIgnoresDeadline(t *testing.T) {
	conn := newUninterruptibleReadConn()
	path := Wrap(conn)
	readDone := make(chan error, 1)
	go func() {
		_, err := path.Read(make([]byte, 32))
		readDone <- err
	}()
	<-conn.started

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := path.endpoint.beginMaintenance(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, errEndpointQuiesce) {
		t.Fatalf("begin maintenance=%v, want deadline plus fail-closed quiesce error", err)
	}
	if elapsed := time.Since(started); elapsed < endpointInterruptGrace {
		t.Fatalf("maintenance failed closed before interrupt grace: %v", elapsed)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read after fail-close=%v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fail-closed maintenance did not release blocked Read")
	}
}

func TestEndpointReadAcceptsCompleteBufferWithTerminalError(t *testing.T) {
	want := []byte("complete-with-eof")
	path := Wrap(&dataAndEOFConn{data: append([]byte(nil), want...)})
	got := make([]byte, len(want))
	if err := path.readFull(got); err != nil {
		t.Fatalf("readFull discarded complete data: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("readFull=%q want %q", got, want)
	}
}

func TestEndpointMaintenanceRejectsOldGenerationTransportErrorBeforeLease(t *testing.T) {
	failure := errors.New("old generation failed while quiescing")
	conn := newNonTimeoutInterruptConn(failure)
	path := Wrap(conn)
	readDone := make(chan error, 1)
	go func() {
		_, err := path.Read(make([]byte, 32))
		readDone <- err
	}()
	<-conn.started

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := path.endpoint.beginMaintenance(ctx)
	if lease != nil || !errors.Is(err, failure) {
		t.Fatalf("begin maintenance=(%v,%v), want old-generation failure and no lease", lease, err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read=%v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("old-generation failure did not finish Read")
	}
}

func TestEndpointDeadlineSetupFailureDoesNotLeaveWaitEpoch(t *testing.T) {
	failure := errors.New("deadline setup rejected")
	base := newUninterruptibleReadConn()
	path := Wrap(&rejectingDeadlineConn{uninterruptibleReadConn: base, failure: failure})
	readDone := make(chan error, 1)
	go func() {
		_, err := path.Read(make([]byte, 32))
		readDone <- err
	}()
	<-base.started

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := path.endpoint.beginMaintenance(ctx); !errors.Is(err, failure) {
		t.Fatalf("begin maintenance=%v, want deadline setup failure", err)
	}
	if _, _, available := path.endpoint.current(); !available {
		t.Fatal("deadline setup failure did not restore live endpoint")
	}
	_ = path.Close()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not release read after deadline setup failure")
	}
}

func TestEndpointStaleFailureCannotPoisonReplacement(t *testing.T) {
	oldLocal, oldPeer := net.Pipe()
	owner := newEndpointOwner(oldLocal)
	read, err := owner.acquireRead()
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("delayed predecessor failure")
	_ = read.finish(failure, false)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	lease, err := owner.beginMaintenance(ctx)
	cancel()
	if err != nil {
		t.Fatalf("begin maintenance: %v", err)
	}
	newLocal, newPeer := net.Pipe()
	defer oldPeer.Close()
	defer newPeer.Close()
	_ = lease.Conn().Close()
	if err := lease.Replace(newLocal); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if owner.markFailure(read.generation) {
		t.Fatal("delayed predecessor failure claimed the replacement generation")
	}
	if err := lease.Resume(); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	conn, generation, available := owner.current()
	if !available || conn != newLocal || generation == read.generation {
		t.Fatalf("replacement=(%T,%d,%t), predecessor generation=%d", conn, generation, available, read.generation)
	}
	_ = owner.close()
}
