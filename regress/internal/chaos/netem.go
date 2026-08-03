//go:build linux

// Package chaos owns Linux tc/netem fixtures used by the regression suite.
package chaos

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const loopbackLockPath = "/run/lock/rendr-regress-tc-lo.lock"

// ApplyChecked installs a tc fixture that continuously exposes qdisc change
// notifications and supports synchronous ownership verification.
func ApplyChecked(p Profile) (Fixture, error) {
	return applyWithDeps(p, fixtureDeps{
		run:         runTCCommand,
		acquireLock: acquireLoopbackLock,
		handles:     randomHandles,
		watch:       watchLoopbackQdisc,
	})
}

func runTCCommand(args ...string) ([]byte, error) {
	return exec.Command("tc", args...).CombinedOutput()
}

type fileFixtureLock struct {
	file *os.File
	once sync.Once
	err  error
}

func acquireLoopbackLock() (fixtureLock, error) {
	file, err := os.OpenFile(loopbackLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		owner, _ := os.ReadFile(loopbackLockPath)
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("%w: another regress process owns loopback shaping (%s)", ErrStimulusInvalid, strings.TrimSpace(string(owner)))
		}
		return nil, err
	}
	marker := fmt.Sprintf("pid=%d acquired=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
	if err := file.Truncate(0); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, err
	}
	if _, err := file.WriteString(marker); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, err
	}
	return &fileFixtureLock{file: file}, nil
}

func (l *fileFixtureLock) Release() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.file == nil {
			return
		}
		unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
		closeErr := l.file.Close()
		l.err = errors.Join(unlockErr, closeErr)
	})
	return l.err
}

func randomHandles() (string, string, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	major := func(v uint16) uint16 { return 0x1000 + v%0xdfff }
	root := major(binary.BigEndian.Uint16(raw[0:2]))
	child := major(binary.BigEndian.Uint16(raw[2:4]))
	if child == root {
		child++
		if child >= 0xefff {
			child = 0x1000
		}
	}
	return fmt.Sprintf("%x:", root), fmt.Sprintf("%x:", child), nil
}

type netlinkQdiscWatcher struct {
	fd      int
	ifindex int
	changes chan error
	done    chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func watchLoopbackQdisc() (qdiscWatcher, error) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_TC}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	w := &netlinkQdiscWatcher{
		fd:      fd,
		ifindex: iface.Index,
		changes: make(chan error, 1),
		done:    make(chan struct{}),
		closed:  make(chan struct{}),
	}
	go w.run()
	return w, nil
}

func (w *netlinkQdiscWatcher) Changes() <-chan error { return w.changes }

func (w *netlinkQdiscWatcher) Close() error {
	if w == nil {
		return nil
	}
	w.once.Do(func() { close(w.done) })
	<-w.closed
	return nil
}

func (w *netlinkQdiscWatcher) run() {
	defer close(w.closed)
	defer close(w.changes)
	defer unix.Close(w.fd)
	buffer := make([]byte, 64<<10)
	for {
		select {
		case <-w.done:
			return
		default:
		}
		poll := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 250)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			w.report(fmt.Errorf("%w: qdisc event watcher poll failed: %v", ErrStimulusInvalid, err))
			return
		}
		if n == 0 || poll[0].Revents&unix.POLLIN == 0 {
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				w.report(fmt.Errorf("%w: qdisc event watcher poll revents=%#x", ErrStimulusInvalid, poll[0].Revents))
				return
			}
			continue
		}
		n, _, err = unix.Recvfrom(w.fd, buffer, unix.MSG_DONTWAIT)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			w.report(fmt.Errorf("%w: qdisc event watcher receive failed: %v", ErrStimulusInvalid, err))
			return
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			w.report(fmt.Errorf("%w: parse qdisc event: %v", ErrStimulusInvalid, err))
			return
		}
		for _, message := range messages {
			if qdiscEventForInterface(message, w.ifindex) {
				w.report(fmt.Errorf("%w: kernel reported a loopback qdisc replacement event", ErrStimulusInvalid))
				return
			}
		}
	}
}

func (w *netlinkQdiscWatcher) report(err error) {
	select {
	case w.changes <- err:
	default:
	}
}

func qdiscEventForInterface(message syscall.NetlinkMessage, ifindex int) bool {
	if message.Header.Type != unix.RTM_NEWQDISC && message.Header.Type != unix.RTM_DELQDISC {
		return false
	}
	// struct tcmsg stores tcm_ifindex at byte offset 4.
	return len(message.Data) >= 8 && int(binary.NativeEndian.Uint32(message.Data[4:8])) == ifindex
}
