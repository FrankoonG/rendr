//go:build linux

package tun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/virtualif"
)

const injectedWriteFD = 73

func TestDeviceImplementsContextWriter(t *testing.T) {
	var device any = (*Device)(nil)
	if _, ok := device.(virtualif.ContextWriter); !ok {
		t.Fatal("*tun.Device does not implement virtualif.ContextWriter")
	}
}

func TestWriteContextAlreadyCanceledDoesNotWrite(t *testing.T) {
	var calls atomic.Int32
	device := newInjectedWriteDevice(func(int, []byte) (int, error) {
		calls.Add(1)
		return 0, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	n, err := device.WriteContext(ctx, []byte("packet"))
	if n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("WriteContext=%d, %v want 0, context.Canceled", n, err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("write syscall calls=%d want 0", got)
	}
	if got := device.writeCursor.Load(); got != 0 {
		t.Fatalf("write cursor=%d want 0", got)
	}
}

func TestWriteContextSuccess(t *testing.T) {
	packet := []byte("complete-packet")
	var calls int
	var gotFD int
	var gotPacket []byte
	device := newInjectedWriteDevice(func(fd int, p []byte) (int, error) {
		calls++
		gotFD = fd
		gotPacket = append(gotPacket[:0], p...)
		return len(p), nil
	})

	n, err := device.WriteContext(context.Background(), packet)
	if err != nil || n != len(packet) {
		t.Fatalf("WriteContext=%d, %v want %d, nil", n, err, len(packet))
	}
	if calls != 1 || gotFD != injectedWriteFD || !bytes.Equal(gotPacket, packet) {
		t.Fatalf("write calls/fd/packet=%d/%d/%q want 1/%d/%q", calls, gotFD, gotPacket, injectedWriteFD, packet)
	}
}

func TestWriteContextShortWriteRemainsAtomicError(t *testing.T) {
	packet := []byte("packet")
	var calls int
	device := newInjectedWriteDevice(func(int, []byte) (int, error) {
		calls++
		return len(packet) - 1, nil
	})

	n, err := device.WriteContext(context.Background(), packet)
	if n != len(packet)-1 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteContext=%d, %v want %d, io.ErrShortWrite", n, err, len(packet)-1)
	}
	if calls != 1 {
		t.Fatalf("write syscall calls=%d want 1", calls)
	}
}

func TestWriteContextCancellationStopsRetryLoop(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "eagain", err: syscall.EAGAIN},
		{name: "eintr", err: syscall.EINTR},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempted := make(chan struct{})
			release := make(chan struct{})
			var first sync.Once
			var releaseOnce sync.Once
			releaseWrite := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(releaseWrite)
			var calls atomic.Int32
			device := newInjectedWriteDevice(func(int, []byte) (int, error) {
				calls.Add(1)
				first.Do(func() {
					close(attempted)
					<-release
				})
				return 0, test.err
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan writeContextResult, 1)
			go func() {
				n, err := device.WriteContext(ctx, []byte("packet"))
				result <- writeContextResult{n: n, err: err}
			}()

			select {
			case <-attempted:
			case <-time.After(time.Second):
				t.Fatal("write syscall was not attempted")
			}
			cancel()
			releaseWrite()
			select {
			case got := <-result:
				if got.n != 0 || !errors.Is(got.err, context.Canceled) {
					t.Fatalf("WriteContext=%d, %v want 0, context.Canceled", got.n, got.err)
				}
			case <-time.After(time.Second):
				t.Fatal("WriteContext did not stop after cancellation")
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("write syscall calls=%d want 1", got)
			}
		})
	}
}

type writeContextResult struct {
	n   int
	err error
}

func newInjectedWriteDevice(write func(int, []byte) (int, error)) *Device {
	return &Device{
		files: []*os.File{nil},
		fds:   []int{injectedWriteFD},
		mtu:   1500,
		write: write,
	}
}
