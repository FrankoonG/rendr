package tcp

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

type blockingCloseConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingCloseConn) Close() error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return c.Conn.Close()
}

func TestOnDeathCannotObserveHalfPublishedLocalClose(t *testing.T) {
	local, peer := net.Pipe()
	conn := &blockingCloseConn{Conn: local, started: make(chan struct{}), release: make(chan struct{})}
	path := Wrap(conn)
	closed := make(chan error, 1)
	go func() { closed <- path.Close() }()
	<-conn.started

	called := make(chan error, 1)
	path.OnDeath(func(_ transport.DeathCause, err error) { called <- err })
	close(conn.release)
	if err := <-closed; err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-called:
		t.Fatalf("local Close leaked through OnDeath: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	_ = peer.Close()
}

type failingReadConn struct {
	*blockingCloseConn
	readErr error
}

func (c *failingReadConn) Read([]byte) (int, error) { return 0, c.readErr }

func TestOnDeathWaitsForCompleteTransportFailureRecord(t *testing.T) {
	local, peer := net.Pipe()
	failure := errors.New("deterministic transport failure")
	base := &blockingCloseConn{Conn: local, started: make(chan struct{}), release: make(chan struct{})}
	path := Wrap(&failingReadConn{blockingCloseConn: base, readErr: failure})
	readDone := make(chan error, 1)
	go func() {
		_, err := path.Read(make([]byte, 32))
		readDone <- err
	}()
	<-base.started

	type observed struct {
		cause transport.DeathCause
		err   error
	}
	callback := make(chan observed, 1)
	path.OnDeath(func(cause transport.DeathCause, err error) {
		_ = path.Close()
		_ = path.LocalAddr()
		_ = path.Quality()
		callback <- observed{cause: cause, err: err}
	})
	close(base.release)
	select {
	case got := <-callback:
		if got.cause != transport.CauseTransportError || !errors.Is(got.err, failure) {
			t.Fatalf("OnDeath=(%v,%v), want transport failure", got.cause, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("OnDeath did not observe completed failure record")
	}
	if err := <-readDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read error=%v, want net.ErrClosed", err)
	}

	late := make(chan observed, 1)
	path.OnDeath(func(cause transport.DeathCause, err error) { late <- observed{cause: cause, err: err} })
	select {
	case got := <-late:
		t.Fatalf("terminal callback delivered twice: %+v", got)
	case <-time.After(20 * time.Millisecond):
	}
	_ = peer.Close()
}
