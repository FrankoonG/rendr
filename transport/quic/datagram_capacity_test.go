package quic

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	qg "github.com/FrankoonG/quic-go"
)

type capacityDatagramConn struct {
	capacity atomic.Int64
	closed   atomic.Bool

	mu      sync.Mutex
	singles [][]byte
	batches [][][]byte
}

func newCapacityDatagramConn(capacity int64) *capacityDatagramConn {
	conn := &capacityDatagramConn{}
	conn.capacity.Store(capacity)
	return conn
}

func (c *capacityDatagramConn) SendDatagram(payload []byte) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	capacity := c.capacity.Load()
	if int64(len(payload)) > capacity {
		return &qg.DatagramTooLargeError{MaxDatagramPayloadSize: capacity}
	}
	c.mu.Lock()
	c.singles = append(c.singles, append([]byte(nil), payload...))
	c.mu.Unlock()
	return nil
}

func (c *capacityDatagramConn) SendDatagrams(payloads [][]byte) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	capacity := c.capacity.Load()
	for _, payload := range payloads {
		if int64(len(payload)) > capacity {
			return &qg.DatagramTooLargeError{MaxDatagramPayloadSize: capacity}
		}
	}
	batch := make([][]byte, len(payloads))
	for index, payload := range payloads {
		batch[index] = append([]byte(nil), payload...)
	}
	c.mu.Lock()
	c.batches = append(c.batches, batch)
	c.mu.Unlock()
	return nil
}

func (c *capacityDatagramConn) MaxDatagramPayloadSize() int64 { return c.capacity.Load() }

func (*capacityDatagramConn) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, net.ErrClosed
}

func (*capacityDatagramConn) Context() context.Context { return context.Background() }

func (c *capacityDatagramConn) CloseWithError(qg.ApplicationErrorCode, string) error {
	c.closed.Store(true)
	c.capacity.Store(0)
	return nil
}

func (*capacityDatagramConn) LocalAddr() net.Addr  { return nil }
func (*capacityDatagramConn) RemoteAddr() net.Addr { return nil }

func TestDatagramMaxFrameSizeRequiresStableNegotiatedCapacity(t *testing.T) {
	conn := newCapacityDatagramConn(MaxDatagramFrame)
	path := &datagramPathConn{conn: conn}
	for _, test := range []struct {
		capacity int64
		want     int
	}{
		{capacity: 0, want: 0},
		{capacity: MaxDatagramFrame - 1, want: 0},
		{capacity: MaxDatagramFrame, want: MaxDatagramFrame},
		{capacity: MaxDatagramFrame + 256, want: MaxDatagramFrame},
	} {
		conn.capacity.Store(test.capacity)
		if got := path.MaxFrameSize(); got != test.want {
			t.Fatalf("capacity=%d MaxFrameSize=%d want %d", test.capacity, got, test.want)
		}
	}
	path.dead.Store(true)
	if got := path.MaxFrameSize(); got != 0 {
		t.Fatalf("dead path MaxFrameSize=%d want 0", got)
	}
}

func TestDatagramWriteRevalidatesPointInTimeCapacity(t *testing.T) {
	conn := newCapacityDatagramConn(MaxDatagramFrame)
	path := &datagramPathConn{conn: conn}
	frame := make([]byte, MaxDatagramFrame)
	if n, err := path.Write(frame); err != nil || n != len(frame) {
		t.Fatalf("initial Write=(%d,%v)", n, err)
	}

	conn.capacity.Store(MaxDatagramFrame - 1)
	n, err := path.Write(frame)
	var tooLarge *qg.DatagramTooLargeError
	if n != 0 || !errors.As(err, &tooLarge) || tooLarge.MaxDatagramPayloadSize != MaxDatagramFrame-1 {
		t.Fatalf("capacity-reduced Write=(%d,%v), want typed limit %d", n, err, MaxDatagramFrame-1)
	}
	if path.dead.Load() {
		t.Fatal("point-in-time capacity rejection declared transport death inside adapter")
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.singles) != 1 {
		t.Fatalf("physical single sends=%d want 1", len(conn.singles))
	}
}

func TestDatagramBatchCapacityRejectionIsAtomic(t *testing.T) {
	conn := newCapacityDatagramConn(MaxDatagramFrame - 1)
	path := &datagramPathConn{conn: conn}
	frames := [][]byte{make([]byte, 512), make([]byte, MaxDatagramFrame)}
	completed, err := path.WriteFrameBatch(frames)
	var tooLarge *qg.DatagramTooLargeError
	if completed != 0 || !errors.As(err, &tooLarge) || tooLarge.MaxDatagramPayloadSize != MaxDatagramFrame-1 {
		t.Fatalf("WriteFrameBatch=(%d,%v), want atomic typed rejection", completed, err)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.batches) != 0 || len(conn.singles) != 0 {
		t.Fatalf("rejected batch reached physical sender: batches=%d singles=%d", len(conn.batches), len(conn.singles))
	}
}
