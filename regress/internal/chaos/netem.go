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
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	loopbackLockPath       = "/run/lock/rendr-regress-tc-lo.lock"
	qdiscWatcherPollMillis = 250
	qdiscWatcherCloseLimit = time.Second
)

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
	return runExternalCommand(tcCommandTimeout, "tc", args...)
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

func randomBarrierSequence() (uint32, error) {
	var raw [4]byte
	for {
		if _, err := rand.Read(raw[:]); err != nil {
			return 0, err
		}
		if sequence := binary.BigEndian.Uint32(raw[:]); sequence != 0 {
			return sequence, nil
		}
	}
}

type netlinkQdiscWatcher struct {
	fd            int
	ifindex       int
	changes       chan error
	done          chan struct{}
	closed        chan struct{}
	barrier       func(uint32) error
	barrierSeq    uint32
	barrierPortID uint32
	kernelUnicast func(unix.Sockaddr) bool
	closeLimit    time.Duration
	closeErr      error
	once          sync.Once
}

func watchLoopbackQdisc() (qdiscWatcher, error) {
	barrierSeq, err := randomBarrierSequence()
	if err != nil {
		return nil, fmt.Errorf("allocate qdisc watcher barrier sequence: %w", err)
	}
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
	bound, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inspect qdisc watcher netlink port: %w", err)
	}
	netlink, ok := bound.(*unix.SockaddrNetlink)
	if !ok || netlink.Pid == 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inspect qdisc watcher netlink port: unexpected address %T", bound)
	}
	w := &netlinkQdiscWatcher{
		fd:            fd,
		ifindex:       iface.Index,
		changes:       make(chan error, 1),
		done:          make(chan struct{}),
		closed:        make(chan struct{}),
		barrierSeq:    barrierSeq,
		barrierPortID: netlink.Pid,
		kernelUnicast: kernelUnicastNetlinkSender,
		closeLimit:    qdiscWatcherCloseLimit,
	}
	w.barrier = func(sequence uint32) error { return sendQdiscDrainBarrier(fd, sequence) }
	go w.run()
	return w, nil
}

func (w *netlinkQdiscWatcher) Changes() <-chan error { return w.changes }

func (w *netlinkQdiscWatcher) Close() error {
	if w == nil {
		return nil
	}
	w.once.Do(func() {
		select {
		case <-w.closed:
			close(w.done)
			return
		default:
		}

		barrierResult := make(chan error, 1)
		if w.barrier == nil {
			barrierResult <- errors.New("qdisc watcher has no shutdown barrier")
		} else {
			go func() { barrierResult <- w.barrier(w.barrierSeq) }()
		}
		timer := time.NewTimer(w.shutdownLimit())
		select {
		case err := <-barrierResult:
			if err != nil {
				w.closeErr = fmt.Errorf("%w: qdisc watcher shutdown barrier send failed: %v", ErrStimulusInvalid, err)
			}
		case <-timer.C:
			w.closeErr = fmt.Errorf("%w: qdisc watcher shutdown barrier send exceeded %s", ErrStimulusInvalid, w.shutdownLimit())
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		close(w.done)
	})
	<-w.closed
	return w.closeErr
}

func (w *netlinkQdiscWatcher) shutdownLimit() time.Duration {
	if w.closeLimit > 0 {
		return w.closeLimit
	}
	return qdiscWatcherCloseLimit
}

func (w *netlinkQdiscWatcher) run() {
	defer close(w.closed)
	defer close(w.changes)
	defer unix.Close(w.fd)
	buffer := make([]byte, 64<<10)
	shuttingDown := false
	var shutdownDeadline time.Time
	beginShutdown := func() {
		if !shuttingDown {
			shuttingDown = true
			shutdownDeadline = time.Now().Add(w.shutdownLimit())
		}
	}
	for {
		if !shuttingDown {
			select {
			case <-w.done:
				beginShutdown()
			default:
			}
		}
		if shuttingDown && w.closeErr != nil {
			w.report(w.closeErr)
			return
		}
		if shuttingDown && !time.Now().Before(shutdownDeadline) {
			err := fmt.Errorf("%w: qdisc watcher shutdown barrier response exceeded %s", ErrStimulusInvalid, w.shutdownLimit())
			w.closeErr = errors.Join(w.closeErr, err)
			w.report(err)
			return
		}
		poll := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
		pollMillis := qdiscWatcherPollMillis
		if shuttingDown {
			remaining := time.Until(shutdownDeadline)
			remainingMillis := int((remaining + time.Millisecond - 1) / time.Millisecond)
			if remainingMillis < 1 {
				remainingMillis = 1
			}
			if remainingMillis < pollMillis {
				pollMillis = remainingMillis
			}
		}
		n, err := unix.Poll(poll, pollMillis)
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
		n, sender, err := unix.Recvfrom(w.fd, buffer, unix.MSG_DONTWAIT)
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
			kernelUnicast := w.kernelUnicast != nil && w.kernelUnicast(sender)
			barrierKind, barrierErr := classifyQdiscBarrierMessage(message, w.barrierSeq, w.barrierPortID, kernelUnicast)
			if barrierKind != qdiscBarrierNone {
				if !shuttingDown {
					<-w.done
					beginShutdown()
					if w.closeErr != nil {
						w.report(w.closeErr)
						return
					}
				}
				if barrierErr != nil {
					err := fmt.Errorf("%w: qdisc watcher shutdown barrier response: %v", ErrStimulusInvalid, barrierErr)
					w.closeErr = errors.Join(w.closeErr, err)
					w.report(err)
					return
				}
				if barrierKind == qdiscBarrierTerminal {
					return
				}
				continue
			}
			if qdiscEventForInterface(message, w.ifindex) {
				w.report(fmt.Errorf("%w: kernel reported a loopback qdisc replacement event (seq=%d pid=%d flags=%#x kernel_unicast=%t barrier_seq=%d)",
					ErrStimulusInvalid, message.Header.Seq, message.Header.Pid, message.Header.Flags, kernelUnicast, w.barrierSeq))
				return
			}
		}
	}
}

type qdiscBarrierMessageKind uint8

const (
	qdiscBarrierNone qdiscBarrierMessageKind = iota
	qdiscBarrierData
	qdiscBarrierTerminal
)

func classifyQdiscBarrierMessage(message syscall.NetlinkMessage, sequence, portID uint32, kernelUnicast bool) (qdiscBarrierMessageKind, error) {
	if sequence == 0 || portID == 0 || message.Header.Seq != sequence || message.Header.Pid != portID || !kernelUnicast {
		return qdiscBarrierNone, nil
	}
	switch message.Header.Type {
	case unix.NLMSG_DONE:
		return qdiscBarrierTerminal, nil
	case unix.NLMSG_ERROR:
		return qdiscBarrierTerminal, netlinkMessageError(message)
	case unix.RTM_NEWQDISC:
		if message.Header.Flags&unix.NLM_F_MULTI != 0 {
			return qdiscBarrierData, nil
		}
	}
	return qdiscBarrierNone, nil
}

func kernelUnicastNetlinkSender(sender unix.Sockaddr) bool {
	netlink, ok := sender.(*unix.SockaddrNetlink)
	return ok && netlink.Pid == 0 && netlink.Groups == 0
}

func sendQdiscDrainBarrier(fd int, sequence uint32) error {
	const tcmsgSize = 20
	request := make([]byte, unix.NLMSG_HDRLEN+tcmsgSize)
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], unix.RTM_GETQDISC)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], sequence)
	request[unix.NLMSG_HDRLEN] = unix.AF_UNSPEC
	return unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func netlinkMessageError(message syscall.NetlinkMessage) error {
	if len(message.Data) < 4 {
		return errors.New("short NLMSG_ERROR payload")
	}
	errno := int32(binary.NativeEndian.Uint32(message.Data[:4]))
	if errno == 0 {
		return nil
	}
	if errno > 0 {
		errno = -errno
	}
	return syscall.Errno(-errno)
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
