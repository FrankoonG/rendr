//go:build linux

package tun

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/FrankoonG/rendr/virtualif"
	"golang.org/x/sys/unix"
)

const (
	linuxTunSetIFF = 0x400454ca
	linuxIFFTun    = 0x0001
	linuxIFFNoPI   = 0x1000
)

// Device is a Linux TUN file descriptor implementing virtualif.Device.
type Device struct {
	file   *os.File
	name   string
	mtu    int
	mu     sync.RWMutex
	closed bool
}

// Open creates or attaches a Linux TUN device. It does not configure
// routes or addresses; embedders retain that policy.
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
	f, err := os.OpenFile(devNetTun, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, probeOpenError("tun open", err)
	}
	req, err := newIfReq(cfg.Name)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(linuxTunSetIFF), uintptr(unsafe.Pointer(req))); errno != 0 {
		_ = f.Close()
		return nil, probeOpenError("tun setiff", errno)
	}
	return &Device{file: f, name: ifReqName(req), mtu: cfg.MTU}, nil
}

func (d *Device) Read(p []byte) (int, error) {
	return d.retryIO(func(fd int) (int, error) { return unix.Read(fd, p) })
}

func (d *Device) Write(p []byte) (int, error) {
	return d.retryIO(func(fd int) (int, error) { return unix.Write(fd, p) })
}

func (d *Device) retryIO(operation func(int) (int, error)) (int, error) {
	for {
		d.mu.RLock()
		if d.closed {
			d.mu.RUnlock()
			return 0, os.ErrClosed
		}
		n, err := operation(int(d.file.Fd()))
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
			// a bounded sleep instead of routing through os.File's poller.
			time.Sleep(time.Millisecond)
			continue
		}
		return n, err
	}
}

func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return os.ErrClosed
	}
	d.closed = true
	return d.file.Close()
}

func (d *Device) Name() string { return d.name }
func (d *Device) MTU() int     { return d.mtu }

type ifReq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

func newIfReq(name string) (*ifReq, error) {
	if len(name) >= unix.IFNAMSIZ {
		return nil, &virtualif.Error{
			Op:     "tun config",
			Reason: virtualif.ReasonTUNUnavailable,
			Err:    fmt.Errorf("name %q exceeds IFNAMSIZ-1", name),
		}
	}
	var req ifReq
	copy(req.Name[:], name)
	req.Flags = linuxIFFTun | linuxIFFNoPI
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
