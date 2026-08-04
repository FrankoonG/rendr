//go:build linux

package chaos

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	testQdiscBarrierSeq    uint32 = 0xa5c39e17
	testQdiscBarrierPortID uint32 = 0x17c3
)

func testCanManageTC() bool {
	_, err := exec.LookPath("tc")
	return os.Geteuid() == 0 && err == nil
}

func testProcessGone(pid int) bool {
	err := syscall.Kill(pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

func testWatcherShutdownBarrier(t *testing.T) {
	t.Helper()
	t.Run("barrier sequences are nonzero", func(t *testing.T) {
		for i := 0; i < 32; i++ {
			sequence, err := randomBarrierSequence()
			if err != nil {
				t.Fatal(err)
			}
			if sequence == 0 {
				t.Fatal("randomBarrierSequence returned the reserved zero sequence")
			}
		}
	})

	t.Run("barrier message classification requires type and pid semantics", func(t *testing.T) {
		message := func(messageType, flags uint16, sequence, pid uint32) syscall.NetlinkMessage {
			return syscall.NetlinkMessage{Header: syscall.NlMsghdr{
				Type: messageType, Flags: flags, Seq: sequence, Pid: pid,
			}}
		}
		for _, testCase := range []struct {
			name          string
			message       syscall.NetlinkMessage
			kernelUnicast bool
			want          qdiscBarrierMessageKind
		}{
			{name: "colliding notification", message: message(unix.RTM_NEWQDISC, 0, testQdiscBarrierSeq, testQdiscBarrierPortID), kernelUnicast: true, want: qdiscBarrierNone},
			{name: "multicast dump-shaped notification", message: message(unix.RTM_NEWQDISC, unix.NLM_F_MULTI, testQdiscBarrierSeq, testQdiscBarrierPortID), want: qdiscBarrierNone},
			{name: "kernel unicast multipart data", message: message(unix.RTM_NEWQDISC, unix.NLM_F_MULTI, testQdiscBarrierSeq, testQdiscBarrierPortID), kernelUnicast: true, want: qdiscBarrierData},
			{name: "kernel terminal", message: message(unix.NLMSG_DONE, 0, testQdiscBarrierSeq, testQdiscBarrierPortID), kernelUnicast: true, want: qdiscBarrierTerminal},
			{name: "userspace terminal pid", message: message(unix.NLMSG_DONE, 0, testQdiscBarrierSeq, 42), kernelUnicast: true, want: qdiscBarrierNone},
			{name: "wrong sequence", message: message(unix.NLMSG_DONE, 0, testQdiscBarrierSeq+1, testQdiscBarrierPortID), kernelUnicast: true, want: qdiscBarrierNone},
			{name: "wrong response type", message: message(unix.RTM_DELQDISC, unix.NLM_F_MULTI, testQdiscBarrierSeq, testQdiscBarrierPortID), kernelUnicast: true, want: qdiscBarrierNone},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				got, err := classifyQdiscBarrierMessage(testCase.message, testQdiscBarrierSeq, testQdiscBarrierPortID, testCase.kernelUnicast)
				if err != nil {
					t.Fatalf("classifyQdiscBarrierMessage: %v", err)
				}
				if got != testCase.want {
					t.Fatalf("kind=%d, want %d", got, testCase.want)
				}
			})
		}
	})

	t.Run("qdisc notification with barrier sequence is still reported", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[1])

		const ifindex = 7
		event := make([]byte, unix.NLMSG_HDRLEN+20)
		binary.NativeEndian.PutUint32(event[0:4], uint32(len(event)))
		binary.NativeEndian.PutUint16(event[4:6], unix.RTM_NEWQDISC)
		binary.NativeEndian.PutUint32(event[8:12], testQdiscBarrierSeq)
		binary.NativeEndian.PutUint32(event[12:16], testQdiscBarrierPortID)
		binary.NativeEndian.PutUint32(event[unix.NLMSG_HDRLEN+4:unix.NLMSG_HDRLEN+8], ifindex)
		barrierDone := make([]byte, unix.NLMSG_HDRLEN)
		binary.NativeEndian.PutUint32(barrierDone[0:4], uint32(len(barrierDone)))
		binary.NativeEndian.PutUint16(barrierDone[4:6], unix.NLMSG_DONE)
		binary.NativeEndian.PutUint32(barrierDone[8:12], testQdiscBarrierSeq)
		binary.NativeEndian.PutUint32(barrierDone[12:16], testQdiscBarrierPortID)

		watcher := &netlinkQdiscWatcher{
			fd:            fds[0],
			ifindex:       ifindex,
			changes:       make(chan error, 1),
			done:          make(chan struct{}),
			closed:        make(chan struct{}),
			barrierSeq:    testQdiscBarrierSeq,
			barrierPortID: testQdiscBarrierPortID,
			kernelUnicast: func(unix.Sockaddr) bool { return true },
		}
		go watcher.run()
		if _, err := unix.Write(fds[1], event); err != nil {
			t.Fatal(err)
		}

		select {
		case change := <-watcher.changes:
			if !errors.Is(change, ErrStimulusInvalid) {
				t.Fatalf("change=%v, want ErrStimulusInvalid", change)
			}
		case <-time.After(100 * time.Millisecond):
			close(watcher.done)
			_, _ = unix.Write(fds[1], barrierDone)
			<-watcher.closed
			t.Fatal("qdisc notification was mistaken for a barrier response")
		}
	})

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])

	const ifindex = 7
	event := make([]byte, unix.NLMSG_HDRLEN+20)
	binary.NativeEndian.PutUint32(event[0:4], uint32(len(event)))
	binary.NativeEndian.PutUint16(event[4:6], unix.RTM_NEWQDISC)
	binary.NativeEndian.PutUint32(event[unix.NLMSG_HDRLEN+4:unix.NLMSG_HDRLEN+8], ifindex)
	barrierDone := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(barrierDone[0:4], uint32(len(barrierDone)))
	binary.NativeEndian.PutUint16(barrierDone[4:6], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint32(barrierDone[8:12], testQdiscBarrierSeq)
	binary.NativeEndian.PutUint32(barrierDone[12:16], testQdiscBarrierPortID)

	watcher := &netlinkQdiscWatcher{
		fd:            fds[0],
		ifindex:       ifindex,
		changes:       make(chan error, 1),
		done:          make(chan struct{}),
		closed:        make(chan struct{}),
		barrierSeq:    testQdiscBarrierSeq,
		barrierPortID: testQdiscBarrierPortID,
		kernelUnicast: func(unix.Sockaddr) bool { return true },
		barrier: func(uint32) error {
			if _, err := unix.Write(fds[1], event); err != nil {
				return err
			}
			_, err := unix.Write(fds[1], barrierDone)
			return err
		},
	}
	go watcher.run()
	closeDone := make(chan error, 1)
	go func() { closeDone <- watcher.Close() }()

	select {
	case change, ok := <-watcher.changes:
		if !ok || !errors.Is(change, ErrStimulusInvalid) {
			t.Fatalf("shutdown discarded queued notification: change=%v ok=%v", change, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("watcher shutdown did not deliver the event ordered before its barrier")
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}

	t.Run("barrier response can beat shutdown publication", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[1])

		barrierWritten := make(chan struct{})
		releaseBarrier := make(chan struct{})
		watcher := &netlinkQdiscWatcher{
			fd:            fds[0],
			ifindex:       ifindex,
			changes:       make(chan error, 1),
			done:          make(chan struct{}),
			closed:        make(chan struct{}),
			barrierSeq:    testQdiscBarrierSeq,
			barrierPortID: testQdiscBarrierPortID,
			kernelUnicast: func(unix.Sockaddr) bool { return true },
			barrier: func(uint32) error {
				if _, err := unix.Write(fds[1], barrierDone); err != nil {
					return err
				}
				close(barrierWritten)
				<-releaseBarrier
				return nil
			},
		}
		go watcher.run()
		closeDone := make(chan error, 1)
		go func() { closeDone <- watcher.Close() }()
		<-barrierWritten
		close(releaseBarrier)

		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Close: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("watcher discarded an early barrier response and could not finish shutdown")
		}
	})

	t.Run("blocked barrier send has a shutdown deadline", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[1])

		barrierStarted := make(chan struct{})
		releaseBarrier := make(chan struct{})
		watcher := &netlinkQdiscWatcher{
			fd:            fds[0],
			ifindex:       ifindex,
			changes:       make(chan error, 1),
			done:          make(chan struct{}),
			closed:        make(chan struct{}),
			barrierSeq:    testQdiscBarrierSeq,
			barrierPortID: testQdiscBarrierPortID,
			kernelUnicast: func(unix.Sockaddr) bool { return true },
			closeLimit:    25 * time.Millisecond,
			barrier: func(uint32) error {
				close(barrierStarted)
				<-releaseBarrier
				return nil
			},
		}
		go watcher.run()
		started := time.Now()
		closeDone := make(chan error, 1)
		go func() { closeDone <- watcher.Close() }()
		<-barrierStarted
		select {
		case err := <-closeDone:
			close(releaseBarrier)
			if !errors.Is(err, ErrStimulusInvalid) || !strings.Contains(err.Error(), "send exceeded") {
				t.Fatalf("Close error=%v, want bounded barrier-send failure", err)
			}
			if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
				t.Fatalf("Close took %s despite barrier deadline", elapsed)
			}
		case <-time.After(500 * time.Millisecond):
			close(releaseBarrier)
			t.Fatal("Close hung behind a blocked barrier sender")
		}
	})

	t.Run("missing barrier response has a shutdown deadline", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[1])

		watcher := &netlinkQdiscWatcher{
			fd:            fds[0],
			ifindex:       ifindex,
			changes:       make(chan error, 1),
			done:          make(chan struct{}),
			closed:        make(chan struct{}),
			barrierSeq:    testQdiscBarrierSeq,
			barrierPortID: testQdiscBarrierPortID,
			kernelUnicast: func(unix.Sockaddr) bool { return true },
			closeLimit:    25 * time.Millisecond,
			barrier:       func(uint32) error { return nil },
		}
		go watcher.run()
		started := time.Now()
		err = watcher.Close()
		if !errors.Is(err, ErrStimulusInvalid) || !strings.Contains(err.Error(), "response exceeded") {
			t.Fatalf("Close error=%v, want bounded missing-response failure", err)
		}
		if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
			t.Fatalf("Close took %s despite response deadline", elapsed)
		}
		for range watcher.changes {
		}
	})
}
