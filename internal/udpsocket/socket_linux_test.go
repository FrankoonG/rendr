//go:build linux

package udpsocket

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/FrankoonG/rendr/internal/platform"
	"github.com/FrankoonG/rendr/transport"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	realGSOTestModeEnvironment = "RENDR_UDP_GSO_REAL_TEST"
	realGSOTestNetNSID         = "RENDR_UDP_GSO_REAL_NETNS_ID"
	realGSOTraceReady          = "RENDR_UDP_GSO_TRACE_READY"
	realGSOSegmentSize         = 1200
	realGSOSegmentCount        = 16
)

func TestPrivilegedUDPGSOActive(t *testing.T) {
	requireRealGSOTest(t, "active")
	if err := platform.Invalidate(platform.FeatureUDPGSO); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snapshot, err := platform.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	evidence, ok := snapshot.Feature(platform.FeatureUDPGSO)
	if !ok || evidence.State != platform.FeatureAvailable {
		t.Fatalf("UDP GSO evidence=%+v present=%t", evidence, ok)
	}

	receiver := listenOwnedRealGSO(t, ctx)
	sender := listenOwnedRealGSO(t, ctx)
	datagrams := realGSODatagrams()
	completed, err := sender.WriteBatch(datagrams, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil || completed != len(datagrams) {
		t.Fatalf("active WriteBatch=%d/%d err=%v", completed, len(datagrams), err)
	}
	assertRealGSODatagrams(t, receiver, datagrams)
	status := sender.DatagramAccelerationStatus()
	if status.Mode != transport.DatagramAccelerationGSO || status.GSOAttempts != 1 ||
		status.GSOSuperPackets != 1 || status.GSOSegments != realGSOSegmentCount ||
		status.OrdinaryDatagrams != 0 || status.FallbackTransitions != 0 {
		t.Fatalf("active status=%+v", status)
	}
	logRealGSOEvidence(t, "active", evidence.State, status, len(datagrams)*realGSOSegmentSize, len(datagrams))
}

func TestPrivilegedUDPGSOFallback(t *testing.T) {
	requireRealGSOTest(t, "fallback")
	if err := platform.Invalidate(platform.FeatureUDPGSO); err != nil {
		t.Fatal(err)
	}
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), 10*time.Second)
	snapshot, err := platform.Detect(probeCtx)
	cancelProbe()
	if err != nil {
		t.Fatalf("fallback pre-probe did not produce cacheable evidence: %v", err)
	}
	evidence, ok := snapshot.Feature(platform.FeatureUDPGSO)
	if !ok || evidence.State != platform.FeatureUnsupported {
		t.Fatalf("fallback pre-probe evidence=%+v present=%t; require injected UDP_SEGMENT unsupported", evidence, ok)
	}
	awaitRealGSOProductionTrace(t)

	dataCtx, cancelData := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelData()
	receiver := listenOwnedRealGSO(t, dataCtx)
	sender := listenOwnedRealGSO(t, dataCtx)
	datagrams := realGSODatagrams()
	completed, err := sender.WriteBatch(datagrams, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil || completed != len(datagrams) {
		t.Fatalf("fallback WriteBatch=%d/%d err=%v", completed, len(datagrams), err)
	}
	assertRealGSODatagrams(t, receiver, datagrams)
	status := sender.DatagramAccelerationStatus()
	if status.Mode != transport.DatagramAccelerationOrdinary || status.GSOAttempts != 0 ||
		status.GSOSuperPackets != 0 || status.GSOSegments != 0 ||
		status.OrdinaryDatagrams != realGSOSegmentCount || status.FallbackTransitions != 0 {
		t.Fatalf("fallback status=%+v", status)
	}
	logRealGSOEvidence(t, "fallback", evidence.State, status, len(datagrams)*realGSOSegmentSize, len(datagrams))
}

func TestPacketConnFallbackStripsOnlyUDPSegment(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test_fallback"}, 0)
	expectedOOB := append(ipv4TOSControl(2), ipv4PacketInfoControl(7)...)
	var calls int
	socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
		calls++
		if !bytes.Equal(oob, expectedOOB) {
			t.Fatalf("ordinary call %d OOB=%x want=%x", calls, oob, expectedOOB)
		}
		if _, _, found, err := stripUDPSegment(oob); err != nil || found {
			t.Fatalf("ordinary call %d retained UDP_SEGMENT: found=%t err=%v", calls, found, err)
		}
		messages, err := unix.ParseSocketControlMessage(oob)
		if err != nil || len(messages) != 2 ||
			messages[0].Header.Level != unix.IPPROTO_IP || messages[0].Header.Type != unix.IP_TOS ||
			messages[1].Header.Level != unix.IPPROTO_IP || messages[1].Header.Type != unix.IP_PKTINFO {
			t.Fatalf("ordinary call %d changed ECN cmsg: messages=%+v err=%v", calls, messages, err)
		}
		return len(payload), len(oob), nil
	}
	oob := append(ipv4TOSControl(2), udpSegmentControl(4)...)
	oob = append(oob, ipv4PacketInfoControl(7)...)
	view := socket.PacketConn().(*packetConnView)
	n, oobN, err := view.WriteMsgUDP([]byte("aaaabbbbcc"), oob, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil || n != 10 || oobN != len(oob) || calls != 3 {
		t.Fatalf("WriteMsgUDP=%d/%d calls=%d err=%v", n, oobN, calls, err)
	}
	status := socket.DatagramAccelerationStatus()
	if status.OrdinaryDatagrams != 3 || status.GSOAttempts != 0 {
		t.Fatalf("status=%+v", status)
	}
}

func TestPacketConnViewAlsoSatisfiesXNetConnRequirement(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test_fallback"}, 0)
	if _, ok := socket.PacketConn().(net.Conn); !ok {
		t.Fatalf("packet view %T does not implement net.Conn", socket.PacketConn())
	}
}

func TestPacketConnActivePassesGSOAndAccounts(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
	wantOOB := append(ipv4TOSControl(1), udpSegmentControl(4)...)
	var calls int
	socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
		calls++
		if !bytes.Equal(oob, wantOOB) {
			t.Fatalf("kernel OOB=%x want=%x", oob, wantOOB)
		}
		return len(payload), len(oob), nil
	}
	view := socket.PacketConn().(*packetConnView)
	n, oobN, err := view.WriteMsgUDP([]byte("aaaabbbbcc"), wantOOB,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil || n != 10 || oobN != len(wantOOB) || calls != 1 {
		t.Fatalf("WriteMsgUDP=%d/%d calls=%d err=%v", n, oobN, calls, err)
	}
	status := socket.Status()
	if status.Mode != transport.DatagramAccelerationGSO || status.GSOAttempts != 1 ||
		status.GSOSuperPackets != 1 || status.GSOSegments != 3 || status.OrdinaryDatagrams != 0 {
		t.Fatalf("status=%+v", status)
	}
}

func TestPacketConnSingleSegmentGSORequestUsesOrdinarySend(t *testing.T) {
	for _, payload := range [][]byte{[]byte("aaa"), []byte("aaaa")} {
		t.Run(fmt.Sprintf("payload-%d", len(payload)), func(t *testing.T) {
			socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
			nonGSO := ipv4TOSControl(1)
			var calls int
			socket.writeMsg = func(gotPayload, oob []byte, _ *net.UDPAddr) (int, int, error) {
				calls++
				if !bytes.Equal(gotPayload, payload) || !bytes.Equal(oob, nonGSO) {
					t.Fatalf("payload=%q oob=%x want payload=%q oob=%x", gotPayload, oob, payload, nonGSO)
				}
				return len(gotPayload), len(oob), nil
			}
			oob := append(append([]byte(nil), nonGSO...), udpSegmentControl(4)...)
			view := socket.PacketConn().(*packetConnView)
			n, oobN, err := view.WriteMsgUDP(payload, oob,
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
			if err != nil || n != len(payload) || oobN != len(oob) || calls != 1 {
				t.Fatalf("WriteMsgUDP=%d/%d calls=%d err=%v", n, oobN, calls, err)
			}
			status := socket.Status()
			if status.Mode != transport.DatagramAccelerationGSO || status.GSOAttempts != 0 ||
				status.GSOSuperPackets != 0 || status.GSOSegments != 0 || status.OrdinaryDatagrams != 1 {
				t.Fatalf("status=%+v", status)
			}
		})
	}
}

func TestWriteBatchActiveUsesOneSuperPacket(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
	var calls int
	socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
		calls++
		segmentSize, _, found, err := stripUDPSegment(oob)
		if err != nil || !found || segmentSize != 4 || string(payload) != "aaaabbbbcc" {
			t.Fatalf("payload=%q segment=%d found=%t err=%v", payload, segmentSize, found, err)
		}
		return len(payload), len(oob), nil
	}
	completed, err := socket.WriteBatch([][]byte{[]byte("aaaa"), []byte("bbbb"), []byte("cc")},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil || completed != 3 || calls != 1 {
		t.Fatalf("WriteBatch=%d calls=%d err=%v", completed, calls, err)
	}
	status := socket.Status()
	if status.GSOAttempts != 1 || status.GSOSuperPackets != 1 || status.GSOSegments != 3 || status.OrdinaryDatagrams != 0 {
		t.Fatalf("status=%+v", status)
	}
}

func TestPacketConnContradictionReplaysOrdinaryWithoutQuicGoFallback(t *testing.T) {
	for _, test := range []struct {
		name          string
		err           error
		cause         string
		invalidations int32
	}{
		{name: "global", err: unix.ENOPROTOOPT, cause: causeRuntimeUnsupported, invalidations: 1},
		{name: "path", err: unix.EIO, cause: causePathUnsupported},
		{name: "path EPERM", err: unix.EPERM, cause: causePathUnsupported},
		{name: "path EACCES", err: unix.EACCES, cause: causePathUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
			var invalidations atomic.Int32
			socket.invalidateGSO = func() error { invalidations.Add(1); return nil }
			var gsoCalls, ordinaryCalls int
			socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
				_, _, found, stripErr := stripUDPSegment(oob)
				if stripErr != nil {
					return 0, 0, stripErr
				}
				if found {
					gsoCalls++
					return 0, 0, test.err
				}
				ordinaryCalls++
				return len(payload), len(oob), nil
			}
			view := socket.PacketConn().(*packetConnView)
			control := udpSegmentControl(4)
			n, oobN, err := view.WriteMsgUDP([]byte("aaaabbbb"), control,
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
			if err != nil || n != 8 || oobN != len(control) || gsoCalls != 1 || ordinaryCalls != 2 {
				t.Fatalf("WriteMsgUDP=%d/%d GSO=%d ordinary=%d err=%v", n, oobN, gsoCalls, ordinaryCalls, err)
			}
			status := socket.DatagramAccelerationStatus()
			if status.Mode != transport.DatagramAccelerationOrdinary || status.Cause != test.cause ||
				status.GSOAttempts != 1 || status.FallbackTransitions != 1 || status.GSOSuperPackets != 0 ||
				status.OrdinaryDatagrams != 2 {
				t.Fatalf("status=%+v", status)
			}
			if got := invalidations.Load(); got != test.invalidations {
				t.Fatalf("invalidations=%d want=%d", got, test.invalidations)
			}
		})
	}
}

func TestPacketConnDoesNotDowngradeAmbiguousOrOperationalErrors(t *testing.T) {
	for _, result := range []struct {
		name string
		n    int
		oobN int
		err  error
	}{
		{name: "buffer pressure", err: unix.ENOBUFS},
		{name: "mtu", err: unix.EMSGSIZE},
		{name: "invalid batch", err: unix.EINVAL},
		{name: "ambiguous contradiction", n: 1, err: unix.ENOPROTOOPT},
		{name: "ambiguous path EIO", n: 1, err: os.NewSyscallError("sendmsg", unix.EIO)},
		{name: "ambiguous OOB", oobN: 1, err: unix.EOPNOTSUPP},
	} {
		t.Run(result.name, func(t *testing.T) {
			socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
			var calls int
			socket.writeMsg = func([]byte, []byte, *net.UDPAddr) (int, int, error) {
				calls++
				return result.n, result.oobN, result.err
			}
			view := socket.PacketConn().(*packetConnView)
			_, _, writeErr := view.WriteMsgUDP([]byte("aaaabbbb"), udpSegmentControl(4),
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
			status := socket.DatagramAccelerationStatus()
			if status.Mode != transport.DatagramAccelerationGSO || status.FallbackTransitions != 0 {
				t.Fatalf("status=%+v", status)
			}
			if calls != 1 {
				t.Fatalf("write calls=%d want=1", calls)
			}
			if result.n != 0 || result.oobN != 0 {
				if !errors.Is(writeErr, ErrAmbiguousWrite) {
					t.Fatalf("partial error=%v want ErrAmbiguousWrite", writeErr)
				}
				var syscallErr *os.SyscallError
				if errors.As(writeErr, &syscallErr) {
					t.Fatalf("partial error leaked quic-go-recognizable EIO: %v", writeErr)
				}
			}
		})
	}
}

func TestPacketConnOrdinaryAmbiguityCannotTriggerQuicGoRetry(t *testing.T) {
	for _, result := range []struct {
		name      string
		n         int
		oobN      int
		err       error
		ambiguous bool
	}{
		{name: "partial EPERM", n: 1, err: os.NewSyscallError("sendmsg", unix.EPERM), ambiguous: true},
		{name: "reported full EPERM", n: 8, err: os.NewSyscallError("sendmsg", unix.EPERM), ambiguous: true},
		{name: "partial EIO", n: 1, err: os.NewSyscallError("sendmsg", unix.EIO), ambiguous: true},
		{name: "zero EIO", err: os.NewSyscallError("sendmsg", unix.EIO)},
	} {
		t.Run(result.name, func(t *testing.T) {
			socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
			var calls int
			socket.writeMsg = func([]byte, []byte, *net.UDPAddr) (int, int, error) {
				calls++
				return result.n, result.oobN, result.err
			}
			view := socket.PacketConn().(*packetConnView)
			_, _, writeErr := view.WriteMsgUDP([]byte("12345678"), nil,
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
			if calls != 1 {
				t.Fatalf("write calls=%d want=1", calls)
			}
			if result.ambiguous && !errors.Is(writeErr, ErrAmbiguousWrite) {
				t.Fatalf("error=%v want ErrAmbiguousWrite", writeErr)
			}
			if errors.Is(writeErr, unix.EIO) {
				t.Fatalf("ordinary error leaked quic-go-recognizable EIO: %v", writeErr)
			}
			var syscallErr *os.SyscallError
			if errors.As(writeErr, &syscallErr) {
				t.Fatalf("ordinary error leaked retryable syscall error: %v", writeErr)
			}
			status := socket.Status()
			if status.Mode != transport.DatagramAccelerationGSO || status.OrdinaryDatagrams != 0 ||
				status.FallbackTransitions != 0 {
				t.Fatalf("status=%+v", status)
			}
		})
	}
}

func TestPacketConnSingleSegmentEIODoesNotFabricateGSOFallback(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
	var calls int
	socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
		calls++
		if calls == 1 {
			return 0, 0, os.NewSyscallError("sendmsg", unix.EIO)
		}
		return len(payload), len(oob), nil
	}
	view := socket.PacketConn().(*packetConnView)
	payload := []byte("aaa")
	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	if n, oobN, err := view.WriteMsgUDP(payload, udpSegmentControl(4), destination); n != 0 || oobN != 0 || err == nil || errors.Is(err, unix.EIO) {
		t.Fatalf("single-segment GSO request=%d/%d err=%v want non-GSO ordinary error", n, oobN, err)
	}
	status := socket.Status()
	if status.Mode != transport.DatagramAccelerationGSO || status.Cause != causeProbeConfirmed ||
		status.FallbackTransitions != 0 || status.GSOAttempts != 0 || status.OrdinaryDatagrams != 0 {
		t.Fatalf("post-EIO status=%+v", status)
	}
	if n, oobN, err := view.WriteMsgUDP(payload, nil, destination); err != nil || n != len(payload) || oobN != 0 {
		t.Fatalf("ordinary retry=%d/%d err=%v", n, oobN, err)
	}
	if status = socket.Status(); status.Mode != transport.DatagramAccelerationGSO || status.OrdinaryDatagrams != 1 || calls != 2 {
		t.Fatalf("post-retry calls=%d status=%+v", calls, status)
	}
}

func TestConcurrentContradictionSerializesOneWayFallback(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
	var gsoCalls atomic.Int32
	var invalidations atomic.Int32
	socket.invalidateGSO = func() error { invalidations.Add(1); return nil }
	socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
		_, _, found, err := stripUDPSegment(oob)
		if err != nil {
			return 0, 0, err
		}
		if found {
			if got := gsoCalls.Add(1); got != 1 {
				t.Errorf("GSO write continued after contradiction: call %d", got)
			}
			return 0, 0, unix.EOPNOTSUPP
		}
		return len(payload), len(oob), nil
	}

	const writers = 64
	start := make(chan struct{})
	var wait sync.WaitGroup
	errCh := make(chan error, writers)
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			completed, err := socket.WriteBatch([][]byte{[]byte("aaaa"), []byte("bbbb")},
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
			if err != nil || completed != 2 {
				errCh <- fmt.Errorf("completed=%d err=%w", completed, err)
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	status := socket.Status()
	if got := gsoCalls.Load(); got != 1 || status.GSOAttempts != 1 || status.FallbackTransitions != 1 ||
		status.OrdinaryDatagrams != writers*2 || invalidations.Load() != 1 {
		t.Fatalf("GSO calls=%d invalidations=%d status=%+v", got, invalidations.Load(), status)
	}
}

func TestWriteBatchContradictionReplaysOrdinaryExactlyOnce(t *testing.T) {
	receiver := listenUDP4(t)
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
	original := socket.writeMsg
	var gsoCalls int
	socket.writeMsg = func(payload, oob []byte, address *net.UDPAddr) (int, int, error) {
		if _, _, found, err := stripUDPSegment(oob); err != nil {
			return 0, 0, err
		} else if found {
			gsoCalls++
			return 0, 0, unix.EOPNOTSUPP
		}
		return original(payload, oob, address)
	}
	datagrams := [][]byte{[]byte("aaaaaaaa"), []byte("bbbbbbbb"), []byte("ccc")}
	completed, err := socket.WriteBatch(datagrams, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil || completed != len(datagrams) || gsoCalls != 1 {
		t.Fatalf("WriteBatch=%d calls=%d err=%v", completed, gsoCalls, err)
	}
	for index, want := range datagrams {
		buffer := make([]byte, 16)
		n, _, err := receiver.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:n], want) {
			t.Fatalf("datagram %d=%q want=%q", index, buffer[:n], want)
		}
	}
	status := socket.DatagramAccelerationStatus()
	if status.GSOAttempts != 1 || status.GSOSuperPackets != 0 || status.OrdinaryDatagrams != 3 || status.FallbackTransitions != 1 {
		t.Fatalf("status=%+v", status)
	}
}

func TestWriteBatchPathEIOFallsBackWithoutGlobalInvalidation(t *testing.T) {
	for _, contradiction := range []error{unix.EIO, unix.EPERM, unix.EACCES} {
		t.Run(contradiction.Error(), func(t *testing.T) {
			socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
			var gsoCalls, ordinaryCalls, invalidations atomic.Int32
			socket.invalidateGSO = func() error { invalidations.Add(1); return nil }
			socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
				_, _, found, err := stripUDPSegment(oob)
				if err != nil {
					return 0, 0, err
				}
				if found {
					gsoCalls.Add(1)
					return 0, 0, contradiction
				}
				ordinaryCalls.Add(1)
				return len(payload), len(oob), nil
			}
			completed, err := socket.WriteBatch([][]byte{[]byte("aaaa"), []byte("bbbb")},
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
			if err != nil || completed != 2 {
				t.Fatalf("WriteBatch=%d err=%v", completed, err)
			}
			status := socket.Status()
			if gsoCalls.Load() != 1 || ordinaryCalls.Load() != 2 || invalidations.Load() != 0 ||
				status.Mode != transport.DatagramAccelerationOrdinary || status.Cause != causePathUnsupported ||
				status.FallbackTransitions != 1 || status.OrdinaryDatagrams != 2 {
				t.Fatalf("GSO=%d ordinary=%d invalidations=%d status=%+v",
					gsoCalls.Load(), ordinaryCalls.Load(), invalidations.Load(), status)
			}
		})
	}
}

func TestWriteBatchDoesNotRetryOperationalOrAmbiguousErrors(t *testing.T) {
	for _, result := range []struct {
		name      string
		n         int
		oobN      int
		err       error
		ambiguous bool
	}{
		{name: "buffer pressure", err: unix.ENOBUFS},
		{name: "mtu", err: unix.EMSGSIZE},
		{name: "invalid", err: unix.EINVAL},
		{name: "partial contradiction", n: 1, err: unix.ENOPROTOOPT, ambiguous: true},
		{name: "partial OOB", oobN: 1, err: unix.EOPNOTSUPP, ambiguous: true},
	} {
		t.Run(result.name, func(t *testing.T) {
			socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
			var calls int
			socket.writeMsg = func([]byte, []byte, *net.UDPAddr) (int, int, error) {
				calls++
				return result.n, result.oobN, result.err
			}
			completed, err := socket.WriteBatch([][]byte{[]byte("aaaa"), []byte("bbbb")},
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
			if completed != 0 || calls != 1 {
				t.Fatalf("completed=%d calls=%d err=%v", completed, calls, err)
			}
			if result.ambiguous {
				if !errors.Is(err, ErrAmbiguousWrite) {
					t.Fatalf("error=%v want ErrAmbiguousWrite", err)
				}
			} else if !errors.Is(err, result.err) {
				t.Fatalf("error=%v want %v", err, result.err)
			}
			status := socket.Status()
			if status.Mode != transport.DatagramAccelerationGSO || status.FallbackTransitions != 0 || status.OrdinaryDatagrams != 0 {
				t.Fatalf("status=%+v", status)
			}
		})
	}
}

func TestSuccessfulGSOAccountingRequiresCompleteWrite(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
	socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
		return len(payload) - 1, len(oob), nil
	}
	view := socket.PacketConn().(*packetConnView)
	_, _, err := view.WriteMsgUDP([]byte("aaaabbbb"), udpSegmentControl(4),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if !errors.Is(err, ErrAmbiguousWrite) {
		t.Fatalf("error=%v want ErrAmbiguousWrite", err)
	}
	status := socket.DatagramAccelerationStatus()
	if status.GSOAttempts != 1 || status.GSOSuperPackets != 0 || status.GSOSegments != 0 || status.FallbackTransitions != 0 {
		t.Fatalf("status=%+v", status)
	}
}

func TestOrdinaryBatchPartialSuccessIsAmbiguous(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test_fallback"}, 0)
	socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
		return len(payload) - 1, len(oob), nil
	}
	completed, err := socket.WriteBatch([][]byte{[]byte("aaaa"), []byte("bbbb")},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if completed != 0 || !errors.Is(err, ErrAmbiguousWrite) {
		t.Fatalf("WriteBatch=%d err=%v want ambiguous zero-prefix result", completed, err)
	}
}

func ipv4TOSControl(value byte) []byte {
	oob := make([]byte, unix.CmsgSpace(1))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_IP
	header.Type = unix.IP_TOS
	header.SetLen(unix.CmsgLen(1))
	oob[unix.CmsgSpace(0)] = value
	return oob
}

func ipv4PacketInfoControl(ifIndex uint32) []byte {
	oob := make([]byte, unix.CmsgSpace(12))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_IP
	header.Type = unix.IP_PKTINFO
	header.SetLen(unix.CmsgLen(12))
	binary.NativeEndian.PutUint32(oob[unix.CmsgSpace(0):], ifIndex)
	return oob
}

func TestUDPSegmentControlUsesNativeUint16(t *testing.T) {
	oob := udpSegmentControl(1232)
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil || len(messages) != 1 {
		t.Fatalf("messages=%+v err=%v", messages, err)
	}
	if messages[0].Header.Level != syscall.IPPROTO_UDP || messages[0].Header.Type != unix.UDP_SEGMENT ||
		len(messages[0].Data) != 2 || binary.NativeEndian.Uint16(messages[0].Data) != 1232 {
		t.Fatalf("UDP_SEGMENT message=%+v", messages[0])
	}
}

func TestPacketConnWriteMsgUDPPreservesIPv4AndIPv6Destination(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ip := net.IPv4(127, 0, 0, 1)
			if network == "udp6" {
				ip = net.IPv6loopback
			}
			receiver, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
			if err != nil {
				if network == "udp6" {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = receiver.Close() })
			senderConn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
			if err != nil {
				t.Fatal(err)
			}
			socket := newSocket(senderConn, policy{treatment: treatmentOrdinary, cause: "test"}, 0)
			t.Cleanup(func() { _ = socket.Close() })
			view := socket.PacketConn().(*packetConnView)
			want := []byte("cached-address")
			for range 2 {
				if n, oobN, err := view.WriteMsgUDP(want, nil, receiver.LocalAddr().(*net.UDPAddr)); err != nil || n != len(want) || oobN != 0 {
					t.Fatalf("WriteMsgUDP=%d/%d err=%v", n, oobN, err)
				}
				buffer := make([]byte, len(want))
				if n, source, err := receiver.ReadFromUDP(buffer); err != nil || n != len(want) || !bytes.Equal(buffer, want) || source.Port != senderConn.LocalAddr().(*net.UDPAddr).Port {
					t.Fatalf("ReadFromUDP=%d source=%v payload=%q err=%v", n, source, buffer, err)
				}
			}
		})
	}
}

func TestPacketConnWriteBatchUsesOneSendmmsgAndPreservesPerMessageControl(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
	view := socket.PacketConn().(*packetConnView)
	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	wantOOB := [][]byte{ipv4TOSControl(1), ipv4TOSControl(2), ipv4TOSControl(3)}
	messages := make([]ipv4.Message, len(wantOOB))
	for i := range messages {
		messages[i] = ipv4.Message{
			Buffers: [][]byte{[]byte{byte('a' + i)}},
			OOB:     append(append([]byte(nil), wantOOB[i]...), udpSegmentControl(1200)...),
			Addr:    destination,
		}
	}
	var calls int
	socket.platform.send.batch = func(got []ipv4.Message, flags int) (int, error) {
		calls++
		if flags != 0 || len(got) != len(messages) {
			t.Fatalf("batch flags=%d messages=%d", flags, len(got))
		}
		for i := range got {
			if !bytes.Equal(got[i].Buffers[0], messages[i].Buffers[0]) || !bytes.Equal(got[i].OOB, wantOOB[i]) || got[i].Addr.String() != destination.String() {
				t.Fatalf("message %d=%+v oob=%x", i, got[i], got[i].OOB)
			}
			got[i].N = len(got[i].Buffers[0])
		}
		return len(got), nil
	}
	completed, err := view.WriteBatch(messages, 0)
	if err != nil || completed != len(messages) || calls != 1 {
		t.Fatalf("WriteBatch=%d/%d calls=%d err=%v", completed, len(messages), calls, err)
	}
	status := socket.Status()
	if status.BatchCalls != 1 || status.BatchDatagrams != uint64(len(messages)) ||
		status.OrdinaryDatagrams != uint64(len(messages)) || status.GSOAttempts != 0 {
		t.Fatalf("status=%+v", status)
	}
}

func TestPacketConnWriteBatchPreservesPinnedSourceAndCompletedPrefix(t *testing.T) {
	sender := listenUDP4(t)
	source := sender.LocalAddr().(*net.UDPAddr)
	socket := newSocketConfigured(sender, policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0, source, true)
	view := socket.PacketConn().(*packetConnView)
	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	messages := []ipv4.Message{
		{Buffers: [][]byte{[]byte("first")}, Addr: destination},
		{Buffers: [][]byte{[]byte("second")}, Addr: destination},
		{Buffers: [][]byte{[]byte("third")}, Addr: destination},
	}
	injected := errors.New("injected sendmmsg suffix failure")
	socket.platform.send.batch = func(got []ipv4.Message, _ int) (int, error) {
		for i := range got {
			parsed, err := unix.ParseSocketControlMessage(got[i].OOB)
			if err != nil || len(parsed) != 1 || parsed[0].Header.Type != unix.IP_PKTINFO {
				t.Fatalf("message %d pinned OOB=%x parsed=%+v err=%v", i, got[i].OOB, parsed, err)
			}
		}
		got[0].N = len(got[0].Buffers[0])
		got[1].N = len(got[1].Buffers[0])
		return 2, injected
	}
	completed, err := view.WriteBatch(messages, 0)
	if completed != 2 || !errors.Is(err, injected) {
		t.Fatalf("WriteBatch=%d err=%v", completed, err)
	}
	status := socket.Status()
	if status.BatchCalls != 1 || status.BatchDatagrams != 2 || status.OrdinaryDatagrams != 2 || status.FallbackTransitions != 0 {
		t.Fatalf("status=%+v", status)
	}
}

func TestPacketConnWriteBatchGSOContradictionFallsBackExactlyOnce(t *testing.T) {
	socket := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
	view := socket.PacketConn().(*packetConnView)
	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	messages := []ipv4.Message{
		{Buffers: [][]byte{[]byte("aaaabbbb")}, OOB: udpSegmentControl(4), Addr: destination},
		{Buffers: [][]byte{[]byte("ccccdddd")}, OOB: udpSegmentControl(4), Addr: destination},
	}
	var batchCalls, ordinaryCalls int
	socket.platform.send.batch = func([]ipv4.Message, int) (int, error) {
		batchCalls++
		return 0, unix.EIO
	}
	socket.writeMsg = func(payload, oob []byte, _ *net.UDPAddr) (int, int, error) {
		ordinaryCalls++
		if _, _, found, err := stripUDPSegment(oob); err != nil || found {
			t.Fatalf("fallback retained UDP_SEGMENT: %x err=%v", oob, err)
		}
		return len(payload), len(oob), nil
	}
	completed, err := view.WriteBatch(messages, 0)
	if err != nil || completed != len(messages) || batchCalls != 1 || ordinaryCalls != 4 {
		t.Fatalf("WriteBatch=%d batch=%d ordinary=%d err=%v", completed, batchCalls, ordinaryCalls, err)
	}
	status := socket.Status()
	if status.Mode != transport.DatagramAccelerationOrdinary || status.FallbackTransitions != 1 ||
		status.BatchCalls != 0 || status.OrdinaryDatagrams != 4 {
		t.Fatalf("status=%+v", status)
	}
}

func TestPinnedSourceAddsPacketInfoWithoutChangingReportedOOBBytes(t *testing.T) {
	senderConn := listenUDP4(t)
	source := senderConn.LocalAddr().(*net.UDPAddr)
	pinned := pinnedSourceControl(source)
	decorated := appendPinnedSourceControl(nil, pinned)
	observed, err := unix.ParseSocketControlMessage(decorated)
	if len(observed) != 1 || observed[0].Header.Level != unix.IPPROTO_IP ||
		observed[0].Header.Type != unix.IP_PKTINFO || len(observed[0].Data) != 12 {
		t.Fatalf("packet info=%+v err=%v", observed, err)
	}
	if got := net.IP(observed[0].Data[4:8]); !got.Equal(source.IP) {
		t.Fatalf("pinned source=%s want %s", got, source.IP)
	}
}

func TestPinnedSourcePreservesQuicReplyPacketInfo(t *testing.T) {
	senderConn := listenUDP4(t)
	source := senderConn.LocalAddr().(*net.UDPAddr)
	existing := ipv4PacketInfoControl(7)
	decorated := appendPinnedSourceControl(existing, pinnedSourceControl(source))
	if !bytes.Equal(decorated, existing) {
		t.Fatalf("caller packet info changed: %x want %x", decorated, existing)
	}
}

func TestReadBatchPreservesBoundariesSourceAndTruncation(t *testing.T) {
	receiver := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test"}, 0)
	t.Cleanup(func() { _ = receiver.Close() })
	sender := listenUDP4(t)
	payloads := [][]byte{[]byte("first"), bytes.Repeat([]byte("x"), 64), []byte("third")}
	for _, payload := range payloads {
		if _, err := sender.WriteToUDP(payload, receiver.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
	}
	messages := make([]ipv4.Message, len(payloads))
	for index := range messages {
		size := 128
		if index == 1 {
			size = 8
		}
		messages[index].Buffers = [][]byte{make([]byte, size)}
		messages[index].OOB = make([]byte, 128)
	}
	n, err := receiver.PacketConn().(*packetConnView).ReadBatch(messages, 0)
	if err != nil || n != len(messages) {
		t.Fatalf("ReadBatch=%d err=%v", n, err)
	}
	for index, message := range messages {
		source, ok := message.Addr.(*net.UDPAddr)
		if !ok || source.Port != sender.LocalAddr().(*net.UDPAddr).Port {
			t.Fatalf("message %d source=%T %v", index, message.Addr, message.Addr)
		}
		want := payloads[index]
		if len(want) > len(message.Buffers[0]) {
			want = want[:len(message.Buffers[0])]
			if message.Flags&unix.MSG_TRUNC == 0 {
				t.Fatalf("message %d missing MSG_TRUNC flags=%#x", index, message.Flags)
			}
		}
		if message.N != len(want) || !bytes.Equal(message.Buffers[0][:message.N], want) {
			t.Fatalf("message %d bytes=%d payload=%q want=%q", index, message.N, message.Buffers[0][:message.N], want)
		}
	}
}

func TestReadBatchSupportsScatterBuffers(t *testing.T) {
	receiver := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test"}, 0)
	t.Cleanup(func() { _ = receiver.Close() })
	sender := listenUDP4(t)
	if _, err := sender.WriteToUDP([]byte("abcdefgh"), receiver.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	messages := []ipv4.Message{{Buffers: [][]byte{make([]byte, 3), make([]byte, 5)}, OOB: make([]byte, 32)}}
	n, err := receiver.PacketConn().(*packetConnView).ReadBatch(messages, 0)
	if err != nil || n != 1 || messages[0].N != 8 || string(messages[0].Buffers[0]) != "abc" || string(messages[0].Buffers[1]) != "defgh" {
		t.Fatalf("ReadBatch=%d message=%+v buffers=%q/%q err=%v", n, messages[0], messages[0].Buffers[0], messages[0].Buffers[1], err)
	}
}

func TestGROSplitterMixedSizesAndTruncation(t *testing.T) {
	state := &linuxReceiveState{
		gro:        true,
		groPayload: make([]byte, MaxGSOSuperPacket),
	}
	state.queued = groQueue{
		valid: true, payload: []byte("aaaabbbbcc"), segmentSize: 4,
		address: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
	}
	messages := []ipv4.Message{
		{Buffers: [][]byte{make([]byte, 4)}, OOB: make([]byte, 8)},
		{Buffers: [][]byte{make([]byte, 2)}, OOB: make([]byte, 8)},
	}
	n, err := state.readBatch(messages, 0)
	if err != nil || n != 2 || string(messages[0].Buffers[0][:messages[0].N]) != "aaaa" ||
		string(messages[1].Buffers[0][:messages[1].N]) != "bb" || messages[1].Flags&unix.MSG_TRUNC == 0 {
		t.Fatalf("first batch n=%d messages=%+v err=%v", n, messages, err)
	}
	messages = []ipv4.Message{{Buffers: [][]byte{make([]byte, 8)}, OOB: make([]byte, 8)}}
	n, err = state.readBatch(messages, 0)
	if err != nil || n != 1 || string(messages[0].Buffers[0][:messages[0].N]) != "cc" || state.queued.payload != nil {
		t.Fatalf("tail batch n=%d message=%+v queued=%+v err=%v", n, messages[0], state.queued, err)
	}
	state.queued = groQueue{valid: true, payload: []byte("xxxxxzz"), segmentSize: 5, address: &net.UDPAddr{Port: 9}}
	messages = []ipv4.Message{{Buffers: [][]byte{make([]byte, 8)}}, {Buffers: [][]byte{make([]byte, 8)}}}
	n, err = state.readBatch(messages, 0)
	if err != nil || n != 2 || string(messages[0].Buffers[0][:messages[0].N]) != "xxxxx" || string(messages[1].Buffers[0][:messages[1].N]) != "zz" {
		t.Fatalf("mixed batch n=%d messages=%+v err=%v", n, messages, err)
	}
}

func TestGROSplitterPreservesZeroLengthDatagram(t *testing.T) {
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	state := &linuxReceiveState{gro: true, groPayload: make([]byte, MaxGSOSuperPacket)}
	state.queued = groQueue{valid: true, payload: state.groPayload[:0], address: address}
	messages := []ipv4.Message{{Buffers: [][]byte{make([]byte, 1)}, OOB: make([]byte, 8)}}
	n, err := state.readBatch(messages, 0)
	if err != nil || n != 1 || messages[0].N != 0 || messages[0].Addr != address || state.queued.valid {
		t.Fatalf("ReadBatch=%d message=%+v queue=%+v err=%v", n, messages[0], state.queued, err)
	}
}

func TestGROSplitterPreservesECNAndGROMetadata(t *testing.T) {
	control := append(ipv4TOSControl(3), fakeGROControl(4)...)
	state := &linuxReceiveState{gro: true, groPayload: make([]byte, MaxGSOSuperPacket)}
	copy(state.groOOB[:], control)
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	state.queued = groQueue{valid: true, payload: []byte("aaaabbbb"), oobN: len(control), address: address, segmentSize: 4}
	messages := []ipv4.Message{
		{Buffers: [][]byte{make([]byte, 8)}, OOB: make([]byte, len(control))},
		{Buffers: [][]byte{make([]byte, 8)}, OOB: make([]byte, len(control))},
	}
	n, err := state.readBatch(messages, 0)
	if err != nil || n != 2 {
		t.Fatalf("ReadBatch=%d err=%v", n, err)
	}
	for index := range messages {
		if !bytes.Equal(messages[index].OOB[:messages[index].NN], control) || messages[index].Addr != address {
			t.Fatalf("message %d OOB=%x address=%p want=%x %p", index, messages[index].OOB[:messages[index].NN], messages[index].Addr, control, address)
		}
	}
}

func TestRealGROReceivePreservesDatagramBoundaries(t *testing.T) {
	receiver := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed, gro: true}, 0)
	t.Cleanup(func() { _ = receiver.Close() })
	if !receiver.platform.recv.gro {
		t.Skip("UDP_GRO unavailable on this kernel")
	}
	sender := newSocket(listenUDP4(t), policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, 0)
	t.Cleanup(func() { _ = sender.Close() })
	datagrams := [][]byte{
		bytes.Repeat([]byte{1}, 1200), bytes.Repeat([]byte{2}, 1200), bytes.Repeat([]byte{3}, 137),
	}
	if completed, err := sender.WriteBatch(datagrams, receiver.LocalAddr().(*net.UDPAddr)); err != nil || completed != len(datagrams) {
		t.Fatalf("WriteBatch=%d err=%v", completed, err)
	}
	messages := make([]ipv4.Message, len(datagrams))
	for index := range messages {
		messages[index].Buffers = [][]byte{make([]byte, 1200)}
		messages[index].OOB = make([]byte, 128)
	}
	received := 0
	for received < len(messages) {
		n, err := receiver.PacketConn().(*packetConnView).ReadBatch(messages[received:], 0)
		if err != nil {
			t.Fatal(err)
		}
		received += n
	}
	for index, want := range datagrams {
		message := messages[index]
		if message.N != len(want) || !bytes.Equal(message.Buffers[0][:message.N], want) {
			t.Fatalf("datagram %d bytes=%d want=%d", index, message.N, len(want))
		}
		if source, ok := message.Addr.(*net.UDPAddr); !ok || source.Port != sender.LocalAddr().(*net.UDPAddr).Port {
			t.Fatalf("datagram %d source=%T %v", index, message.Addr, message.Addr)
		}
	}
}

func TestConcurrentCloseReadAndWrite(t *testing.T) {
	for iteration := range 50 {
		receiver := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test"}, 0)
		sender := newSocket(listenUDP4(t), policy{treatment: treatmentOrdinary, cause: "test"}, 0)
		view := receiver.PacketConn().(*packetConnView)
		messages := []ipv4.Message{{Buffers: [][]byte{make([]byte, 64)}, OOB: make([]byte, 128)}}
		readDone := make(chan error, 1)
		go func() { _, err := view.ReadBatch(messages, 0); readDone <- err }()
		writeDone := make(chan error, 1)
		go func() {
			_, _, err := sender.PacketConn().(*packetConnView).WriteMsgUDP([]byte("payload"), nil, receiver.LocalAddr().(*net.UDPAddr))
			writeDone <- err
		}()
		_ = receiver.Close()
		_ = sender.Close()
		select {
		case <-readDone:
		case <-time.After(time.Second):
			t.Fatalf("iteration %d read did not unblock", iteration)
		}
		select {
		case <-writeDone:
		case <-time.After(time.Second):
			t.Fatalf("iteration %d write did not unblock", iteration)
		}
	}
}

func fakeGROControl(segmentSize int) []byte {
	oob := make([]byte, unix.CmsgSpace(udpGRODataSize))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_UDP
	header.Type = unix.UDP_GRO
	header.SetLen(unix.CmsgLen(udpGRODataSize))
	binary.NativeEndian.PutUint32(oob[unix.CmsgSpace(0):], uint32(segmentSize))
	return oob
}

type realGSOEvidence struct {
	Mode                string `json:"mode"`
	ProbeState          string `json:"probe_state"`
	SelectedTreatment   string `json:"selected_treatment"`
	OfferedBytes        int    `json:"offered_bytes"`
	OfferedPackets      int    `json:"offered_packets"`
	ReceivedBytes       int    `json:"received_bytes"`
	ReceivedPackets     int    `json:"received_packets"`
	GSOAttempts         uint64 `json:"gso_attempts"`
	GSOSuperPackets     uint64 `json:"gso_super_packets"`
	GSOSegments         uint64 `json:"gso_segments"`
	OrdinaryDatagrams   uint64 `json:"ordinary_datagrams"`
	FallbackTransitions uint64 `json:"fallback_transitions"`
}

func requireRealGSOTest(t testing.TB, mode string) {
	t.Helper()
	selected := os.Getenv(realGSOTestModeEnvironment)
	if selected != mode {
		t.Skipf("set %s=%s to exercise real UDP GSO %s", realGSOTestModeEnvironment, mode, mode)
	}
	if os.Geteuid() != 0 {
		t.Fatal("real UDP GSO qualification requires root in the test namespace")
	}
	self := networkNamespaceIdentity(t, "/proc/self/ns/net")
	init := networkNamespaceIdentity(t, "/proc/1/ns/net")
	expected := os.Getenv(realGSOTestNetNSID)
	if self == init || expected == "" || self != expected {
		t.Fatalf("network namespace self=%q init=%q expected=%q", self, init, expected)
	}
	t.Logf("isolated network namespace=%s (init=%s)", self, init)
}

func awaitRealGSOProductionTrace(t testing.TB) {
	t.Helper()
	path := os.Getenv(realGSOTraceReady)
	if path == "" {
		t.Fatalf("%s is required for fallback production tracing", realGSOTraceReady)
	}
	if err := publishRealGSOTraceReady(path, os.Getpid()); err != nil {
		t.Fatalf("publish production trace readiness: %v", err)
	}
	if err := unix.Kill(os.Getpid(), unix.SIGSTOP); err != nil {
		t.Fatalf("stop for production trace attachment: %v", err)
	}
}

func publishRealGSOTraceReady(path string, pid int) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.WriteString(strconv.Itoa(pid) + "\n"); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Link(temporaryPath, path)
}

func listenOwnedRealGSO(t testing.TB, ctx context.Context) *Socket {
	t.Helper()
	socket, err := Listen(ctx, Config{
		Network:   "udp4",
		LocalAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	if err := socket.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return socket
}

func realGSODatagrams() [][]byte {
	datagrams := make([][]byte, realGSOSegmentCount)
	for segment := range datagrams {
		datagrams[segment] = make([]byte, realGSOSegmentSize)
		binary.BigEndian.PutUint32(datagrams[segment][:4], uint32(segment))
		for offset := 4; offset < len(datagrams[segment]); offset++ {
			datagrams[segment][offset] = byte(segment*37 + offset*11)
		}
	}
	return datagrams
}

func assertRealGSODatagrams(t testing.TB, receiver *Socket, datagrams [][]byte) {
	t.Helper()
	buffer := make([]byte, realGSOSegmentSize+1)
	for index, want := range datagrams {
		n, _, err := receiver.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("receive segment %d: %v", index, err)
		}
		if n != len(want) || !bytes.Equal(buffer[:n], want) {
			t.Fatalf("segment %d bytes=%d want=%d", index, n, len(want))
		}
	}
	if err := receiver.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, _, err := receiver.ReadFrom(buffer)
	var netErr net.Error
	if n != 0 || !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("unexpected trailing datagram bytes=%d err=%v", n, err)
	}
}

func logRealGSOEvidence(
	t testing.TB,
	mode string,
	probeState platform.FeatureState,
	status transport.DatagramAccelerationStatus,
	bytes, packets int,
) {
	t.Helper()
	evidence := realGSOEvidence{
		Mode: mode, ProbeState: string(probeState), SelectedTreatment: string(status.Mode),
		OfferedBytes: bytes, OfferedPackets: packets, ReceivedBytes: bytes, ReceivedPackets: packets,
		GSOAttempts: status.GSOAttempts, GSOSuperPackets: status.GSOSuperPackets,
		GSOSegments: status.GSOSegments, OrdinaryDatagrams: status.OrdinaryDatagrams,
		FallbackTransitions: status.FallbackTransitions,
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RENDR_UDP_GSO_EVIDENCE %s", encoded)
}

func networkNamespaceIdentity(t testing.TB, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		t.Fatalf("%s has no network namespace identity", path)
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
}
