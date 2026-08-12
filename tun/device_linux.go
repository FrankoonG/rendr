//go:build linux

package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/FrankoonG/rendr/virtualif"
	"golang.org/x/sys/unix"
)

const (
	linuxTunSetIFF     = 0x400454ca
	linuxIFFTun        = 0x0001
	linuxIFFMultiQueue = 0x0100
	linuxIFFNoPI       = 0x1000
	linuxIFFTunExcl    = 0x8000
	linuxPollInterval  = 10 * time.Millisecond
)

// Device is a Linux TUN file descriptor implementing virtualif.Device.
type Device struct {
	files       []*os.File
	fds         []int
	name        string
	mtu         int
	readGate    chan struct{}
	readBuffer  []byte
	pendingRead []byte
	readCursor  atomic.Uint32
	writeCursor atomic.Uint32
	poll        func([]unix.PollFd, int) (int, error)
	write       func(int, []byte) (int, error)
	beforePoll  func()
	mu          sync.RWMutex
	closed      bool
}

var (
	_ virtualif.Device        = (*Device)(nil)
	_ virtualif.ContextReader = (*Device)(nil)
	_ virtualif.ContextWriter = (*Device)(nil)
)

// Open exclusively creates a Linux TUN device. It does not configure routes
// or addresses; embedders retain that policy.
func Open(cfg Config) (*Device, error) {
	if !cfg.Enabled {
		return nil, &virtualif.Error{
			Op:     "tun open",
			Reason: virtualif.ReasonTUNUnavailable,
			Err:    errors.New("disabled"),
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.Normalize()
	files := make([]*os.File, 0, cfg.Queues)
	fds := make([]int, 0, cfg.Queues)
	flags := uint16(linuxIFFTun | linuxIFFNoPI | linuxIFFTunExcl)
	if cfg.Queues > 1 {
		flags |= linuxIFFMultiQueue
	}
	first, firstFD, name, err := openLinuxTUNQueue(cfg.Name, flags)
	if err != nil {
		return nil, err
	}
	files = append(files, first)
	fds = append(fds, firstFD)
	for queue := 1; queue < cfg.Queues; queue++ {
		file, fd, actualName, queueErr := openLinuxTUNQueue(name, linuxIFFTun|linuxIFFNoPI|linuxIFFMultiQueue)
		if queueErr != nil {
			return nil, errors.Join(queueErr, closeTUNFiles(files))
		}
		if actualName != name {
			attachErr := &virtualif.Error{
				Op: "tun setiff", Reason: virtualif.ReasonTUNUnavailable,
				Err: fmt.Errorf("queue %d attached to %q want %q", queue, actualName, name),
			}
			return nil, errors.Join(attachErr, file.Close(), closeTUNFiles(files))
		}
		files = append(files, file)
		fds = append(fds, fd)
	}
	mtu, err := setAndReadInterfaceMTU(name, cfg.MTU)
	if err != nil {
		return nil, errors.Join(classifyMTUError(err), closeTUNFiles(files))
	}
	readGate := make(chan struct{}, 1)
	readGate <- struct{}{}
	return &Device{
		files:      files,
		fds:        fds,
		name:       name,
		mtu:        mtu,
		readGate:   readGate,
		readBuffer: make([]byte, MaxMTU),
		poll:       unix.Poll,
		write:      unix.Write,
	}, nil
}

func (d *Device) Read(p []byte) (int, error) {
	return d.ReadContext(context.Background(), p)
}

// ReadContext reads one complete raw IP packet and lets cancellation interrupt
// an otherwise idle TUN without destroying the interface.
func (d *Device) ReadContext(ctx context.Context, p []byte) (int, error) {
	if ctx == nil {
		return 0, errors.New("tun: nil read context")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := d.acquireRead(ctx); err != nil {
		return 0, err
	}
	defer d.releaseRead()
	var pollFDs []unix.PollFd
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		d.mu.RLock()
		if d.closed || len(d.files) == 0 {
			d.mu.RUnlock()
			return 0, os.ErrClosed
		}
		if len(d.pendingRead) != 0 {
			if len(p) < len(d.pendingRead) {
				d.mu.RUnlock()
				return 0, io.ErrShortBuffer
			}
			n := copy(p, d.pendingRead)
			d.pendingRead = d.pendingRead[:0]
			d.mu.RUnlock()
			return n, nil
		}
		if len(p) < d.mtu {
			d.mu.RUnlock()
			return 0, io.ErrShortBuffer
		}
		start := int(d.readCursor.Add(1)-1) % len(d.files)
		if cap(pollFDs) < len(d.files) {
			pollFDs = make([]unix.PollFd, len(d.files))
		} else {
			pollFDs = pollFDs[:len(d.files)]
		}
		for offset := 0; offset < len(d.files); offset++ {
			pollFDs[offset] = unix.PollFd{
				Fd:     int32(d.fds[(start+offset)%len(d.fds)]),
				Events: unix.POLLIN,
			}
		}
		if d.beforePoll != nil {
			d.beforePoll()
		}
		poll := d.poll
		if poll == nil {
			poll = unix.Poll
		}
		ready, err := poll(pollFDs, pollTimeout(ctx, linuxPollInterval))
		if errors.Is(err, syscall.EINTR) {
			d.mu.RUnlock()
			continue
		}
		if err != nil {
			d.mu.RUnlock()
			return 0, err
		}
		if ready > 0 {
			for _, descriptor := range pollFDs {
				if descriptor.Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) == 0 {
					continue
				}
				if len(d.readBuffer) < MaxMTU {
					d.readBuffer = make([]byte, MaxMTU)
				}
				n, readErr := unix.Read(int(descriptor.Fd), d.readBuffer)
				if readErr == nil {
					if n > len(p) {
						d.pendingRead = append(d.pendingRead[:0], d.readBuffer[:n]...)
						d.mu.RUnlock()
						return 0, io.ErrShortBuffer
					}
					copy(p, d.readBuffer[:n])
					d.mu.RUnlock()
					return n, nil
				}
				if errors.Is(readErr, syscall.EINTR) || errors.Is(readErr, syscall.EAGAIN) || errors.Is(readErr, syscall.EWOULDBLOCK) {
					continue
				}
				d.mu.RUnlock()
				return n, readErr
			}
		}
		d.mu.RUnlock()
	}
}

func (d *Device) acquireRead(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.readGate:
	}
	if err := ctx.Err(); err != nil {
		d.releaseRead()
		return err
	}
	return nil
}

func (d *Device) releaseRead() {
	d.readGate <- struct{}{}
}

func (d *Device) Write(p []byte) (int, error) {
	return d.WriteContext(context.Background(), p)
}

// WriteContext writes one complete raw IP packet and lets cancellation stop
// retries on a temporarily unavailable nonblocking TUN queue.
func (d *Device) WriteContext(ctx context.Context, p []byte) (int, error) {
	if ctx == nil {
		return 0, errors.New("tun: nil write context")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	d.mu.RLock()
	if err := ctx.Err(); err != nil {
		d.mu.RUnlock()
		return 0, err
	}
	if d.closed || len(d.files) == 0 {
		d.mu.RUnlock()
		return 0, os.ErrClosed
	}
	if len(p) > d.mtu {
		d.mu.RUnlock()
		return 0, os.NewSyscallError("tun write", syscall.EMSGSIZE)
	}
	queue := int(d.writeCursor.Add(1)-1) % len(d.files)
	d.mu.RUnlock()
	return d.writeQueueContext(ctx, queue, p)
}

func pollTimeout(ctx context.Context, limit time.Duration) int {
	timeout := limit
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	milliseconds := timeout.Milliseconds()
	if milliseconds == 0 {
		return 1
	}
	return int(milliseconds)
}

func (d *Device) readQueue(queue int, p []byte) (int, error) {
	return d.retryQueueIO(queue, func(fd int) (int, error) { return unix.Read(fd, p) })
}

func (d *Device) writeQueue(queue int, p []byte) (int, error) {
	return d.writeQueueContext(context.Background(), queue, p)
}

func (d *Device) writeQueueContext(ctx context.Context, queue int, p []byte) (int, error) {
	return d.retryQueueIOContext(ctx, queue, func(fd int) (int, error) {
		write := d.write
		if write == nil {
			write = unix.Write
		}
		n, err := write(fd, p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		return n, err
	})
}

func (d *Device) retryQueueIO(queue int, operation func(int) (int, error)) (int, error) {
	return d.retryQueueIOContext(context.Background(), queue, operation)
}

func (d *Device) retryQueueIOContext(
	ctx context.Context,
	queue int,
	operation func(int) (int, error),
) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		d.mu.RLock()
		if err := ctx.Err(); err != nil {
			d.mu.RUnlock()
			return 0, err
		}
		if d.closed || queue < 0 || queue >= len(d.files) {
			d.mu.RUnlock()
			return 0, os.ErrClosed
		}
		n, err := operation(d.fds[queue])
		d.mu.RUnlock()
		if err == nil {
			return n, nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			// Go's epoll integration can reject a TUN fd as "not pollable"
			// on some kernels after the interface moves network namespaces.
			// Keep the fd nonblocking so Close remains prompt, and retry with
			// a cancellable bounded wait instead of routing through os.File's
			// poller.
			if err := waitQueueRetry(ctx); err != nil {
				return 0, err
			}
			continue
		}
		return n, err
	}
}

func waitQueueRetry(ctx context.Context) error {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return os.ErrClosed
	}
	d.closed = true
	return closeTUNFiles(d.files)
}

func (d *Device) Name() string { return d.name }
func (d *Device) MTU() int     { return d.mtu }
func (d *Device) QueueCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.files)
}

func openLinuxTUNQueue(name string, flags uint16) (*os.File, int, string, error) {
	file, err := os.OpenFile(devNetTun, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, -1, "", probeOpenError("tun open", err)
	}
	req, err := newIfReqFlags(name, flags)
	if err != nil {
		return nil, -1, "", errors.Join(err, file.Close())
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, -1, "", errors.Join(err, file.Close())
	}
	fd := -1
	var ioctlErr error
	if err := raw.Control(func(rawFD uintptr) {
		fd = int(rawFD)
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, rawFD, uintptr(linuxTunSetIFF), uintptr(unsafe.Pointer(req))); errno != 0 {
			ioctlErr = probeOpenError("tun setiff", errno)
		}
	}); err != nil {
		return nil, -1, "", errors.Join(err, file.Close())
	}
	if ioctlErr != nil {
		return nil, -1, "", errors.Join(ioctlErr, file.Close())
	}
	return file, fd, ifReqName(req), nil
}

func setAndReadInterfaceMTU(name string, mtu int) (actual int, err error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	request, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	request.SetUint32(uint32(mtu))
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFMTU, request); err != nil {
		return 0, err
	}
	readback, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFMTU, readback); err != nil {
		return 0, err
	}
	actual = int(readback.Uint32())
	if actual != mtu {
		return 0, fmt.Errorf("MTU readback=%d want %d", actual, mtu)
	}
	return actual, nil
}

func classifyMTUError(err error) error {
	if errors.Is(err, syscall.EINVAL) {
		return &virtualif.Error{Op: "tun mtu", Reason: virtualif.ReasonInvalidMTU, Err: err}
	}
	return probeOpenError("tun mtu", err)
}

func closeTUNFiles(files []*os.File) error {
	errs := make([]error, 0, len(files))
	for _, file := range files {
		if file != nil {
			if err := file.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

type ifReq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

func newIfReq(name string) (*ifReq, error) {
	return newIfReqFlags(name, linuxIFFTun|linuxIFFNoPI)
}

func newIfReqFlags(name string, flags uint16) (*ifReq, error) {
	if len(name) >= unix.IFNAMSIZ {
		return nil, &virtualif.Error{
			Op:     "tun config",
			Reason: virtualif.ReasonTUNUnavailable,
			Err:    fmt.Errorf("name %q exceeds IFNAMSIZ-1", name),
		}
	}
	var req ifReq
	copy(req.Name[:], name)
	req.Flags = flags
	return &req, nil
}

func ifReqName(req *ifReq) string {
	raw := string(req.Name[:])
	if i := strings.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

func probeOpenError(op string, err error) error {
	reason := virtualif.ReasonTUNUnavailable
	if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		reason = virtualif.ReasonTUNPermissionDenied
	}
	return &virtualif.Error{Op: op, Reason: reason, Err: err}
}
