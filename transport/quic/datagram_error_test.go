package quic

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"

	qg "github.com/FrankoonG/quic-go"

	"github.com/FrankoonG/rendr/transport"
)

func TestDatagramTooLargeDoesNotKillHealthyPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &scriptedDatagramQUICConn{
		ctx: ctx,
		sendErrors: []error{
			&qg.DatagramTooLargeError{MaxDatagramPayloadSize: 900},
			nil,
		},
	}
	path := &datagramPathConn{conn: conn, recvQ: make(chan []byte)}
	deaths := make(chan error, 1)
	path.OnDeath(func(_ transport.DeathCause, err error) { deaths <- err })

	if n, err := path.Write(make([]byte, MaxDatagramFrame)); n != 0 {
		t.Fatalf("oversized negotiated datagram wrote %d bytes", n)
	} else {
		var tooLarge *qg.DatagramTooLargeError
		if !errors.As(err, &tooLarge) || tooLarge.MaxDatagramPayloadSize != 900 {
			t.Fatalf("write error=%T %v, want DatagramTooLargeError(max=900)", err, err)
		}
	}
	if path.dead.Load() {
		t.Fatal("per-datagram size error marked the QUIC path dead")
	}
	select {
	case err := <-deaths:
		t.Fatalf("per-datagram size error invoked OnDeath: %v", err)
	default:
	}

	payload := []byte("small-datagram")
	if n, err := path.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("subsequent datagram write=%d/%d err=%v", n, len(payload), err)
	}
	if path.writes.Load() != 1 || conn.successfulSends() != 1 {
		t.Fatalf("successful writes path/conn=%d/%d want 1/1", path.writes.Load(), conn.successfulSends())
	}
}

func TestDatagramFrameBatchIsAtomicAndCountsWholeFrames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &scriptedDatagramQUICConn{ctx: ctx}
	path := &datagramPathConn{conn: conn, recvQ: make(chan []byte)}
	frames := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	if completed, err := path.WriteFrameBatch(frames); err != nil || completed != len(frames) {
		t.Fatalf("batch completed=%d/%d err=%v", completed, len(frames), err)
	}
	conn.mu.Lock()
	batches := append([]int(nil), conn.batches...)
	conn.mu.Unlock()
	if path.writes.Load() != uint64(len(frames)) || !reflect.DeepEqual(batches, []int{len(frames)}) {
		t.Fatalf("path writes=%d batches=%v", path.writes.Load(), batches)
	}
}

func TestDatagramSingleFrameBatchUsesSingleSendPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &scriptedDatagramQUICConn{ctx: ctx}
	path := &datagramPathConn{conn: conn, recvQ: make(chan []byte)}
	frame := []byte("one")
	if completed, err := path.WriteFrameBatch([][]byte{frame}); err != nil || completed != 1 {
		t.Fatalf("single batch completed=%d err=%v", completed, err)
	}
	conn.mu.Lock()
	batches, sends := len(conn.batches), conn.sends
	conn.mu.Unlock()
	if batches != 0 || sends != 1 || path.writes.Load() != 1 {
		t.Fatalf("single batch used batches=%d sends=%d path_writes=%d", batches, sends, path.writes.Load())
	}
}

func TestDatagramFrameBatchPrevalidationPreventsPartialSubmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &scriptedDatagramQUICConn{ctx: ctx}
	path := &datagramPathConn{conn: conn, recvQ: make(chan []byte)}
	frames := [][]byte{[]byte("valid"), make([]byte, MaxDatagramFrame+1), []byte("suffix")}
	if completed, err := path.WriteFrameBatch(frames); err == nil || completed != 0 {
		t.Fatalf("oversize batch completed=%d err=%v", completed, err)
	}
	conn.mu.Lock()
	batches := len(conn.batches)
	conn.mu.Unlock()
	if batches != 0 || path.writes.Load() != 0 || path.dead.Load() {
		t.Fatalf("oversize batch submitted=%d writes=%d dead=%t", batches, path.writes.Load(), path.dead.Load())
	}
}

func TestDatagramFrameBatchNegotiatedSizeErrorDoesNotKillPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &scriptedDatagramQUICConn{ctx: ctx, sendErrors: []error{
		&qg.DatagramTooLargeError{MaxDatagramPayloadSize: 900}, nil,
	}}
	path := &datagramPathConn{conn: conn, recvQ: make(chan []byte)}
	frames := [][]byte{make([]byte, 800), make([]byte, 800)}
	if completed, err := path.WriteFrameBatch(frames); err == nil || completed != 0 {
		t.Fatalf("negotiated oversize completed=%d err=%v", completed, err)
	}
	if path.dead.Load() {
		t.Fatal("negotiated batch size error killed the path")
	}
	if completed, err := path.WriteFrameBatch(frames); err != nil || completed != len(frames) {
		t.Fatalf("second batch completed=%d/%d err=%v", completed, len(frames), err)
	}
}

type scriptedDatagramQUICConn struct {
	ctx context.Context

	mu         sync.Mutex
	sendErrors []error
	sends      int
	batches    []int
}

func (c *scriptedDatagramQUICConn) SendDatagram([]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sendErrors) == 0 {
		c.sends++
		return nil
	}
	err := c.sendErrors[0]
	c.sendErrors = c.sendErrors[1:]
	if err == nil {
		c.sends++
	}
	return err
}

func (c *scriptedDatagramQUICConn) SendDatagrams(frames [][]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batches = append(c.batches, len(frames))
	if len(c.sendErrors) == 0 {
		c.sends += len(frames)
		return nil
	}
	err := c.sendErrors[0]
	c.sendErrors = c.sendErrors[1:]
	if err == nil {
		c.sends += len(frames)
	}
	return err
}

func (c *scriptedDatagramQUICConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, context.Cause(ctx)
}

func (*scriptedDatagramQUICConn) CloseWithError(qg.ApplicationErrorCode, string) error { return nil }
func (c *scriptedDatagramQUICConn) Context() context.Context                           { return c.ctx }
func (*scriptedDatagramQUICConn) LocalAddr() net.Addr                                  { return datagramTestAddr("local") }
func (*scriptedDatagramQUICConn) RemoteAddr() net.Addr                                 { return datagramTestAddr("remote") }

func (c *scriptedDatagramQUICConn) successfulSends() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sends
}

type datagramTestAddr string

func (a datagramTestAddr) Network() string { return "test" }
func (a datagramTestAddr) String() string  { return string(a) }
