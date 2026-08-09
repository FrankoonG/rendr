//go:build linux

package platform

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fakeTransparentBindSocket struct {
	fd        int
	domain    int
	optionSet bool
	bound     unix.Sockaddr
	closed    bool
}

type fakeTransparentBindKernel struct {
	nextFD            int
	open              map[int]*fakeTransparentBindSocket
	history           []*fakeTransparentBindSocket
	setErr            map[int]error
	bindErr           map[int]error
	optionValue       map[int]int
	optionValueSet    map[int]bool
	socknameAddress   map[int]netip.Addr
	assigned          map[netip.Addr]bool
	assignedAfterBind map[int]bool
	closeErr          map[int]error
	socketCalls       int
	setCalls          int
	getOptionCalls    int
	bindCalls         int
	getSocknameCalls  int
	addressChecks     int
	closeCalls        int
}

func newFakeTransparentBindKernel() *fakeTransparentBindKernel {
	return &fakeTransparentBindKernel{
		nextFD:            10,
		open:              make(map[int]*fakeTransparentBindSocket),
		setErr:            make(map[int]error),
		bindErr:           make(map[int]error),
		optionValue:       make(map[int]int),
		optionValueSet:    make(map[int]bool),
		socknameAddress:   make(map[int]netip.Addr),
		assigned:          make(map[netip.Addr]bool),
		assignedAfterBind: make(map[int]bool),
		closeErr:          make(map[int]error),
	}
}

func (kernel *fakeTransparentBindKernel) ops() transparentBindProbeOps {
	return transparentBindProbeOps{
		socket: func(domain, typ, protocol int) (int, error) {
			kernel.socketCalls++
			if typ != unix.SOCK_STREAM|unix.SOCK_CLOEXEC || protocol != unix.IPPROTO_TCP {
				return -1, syscall.EINVAL
			}
			fd := kernel.nextFD
			kernel.nextFD++
			socket := &fakeTransparentBindSocket{fd: fd, domain: domain}
			kernel.open[fd] = socket
			kernel.history = append(kernel.history, socket)
			return fd, nil
		},
		setSockoptInt: func(fd, level, option, value int) error {
			kernel.setCalls++
			socket := kernel.requireOpen(fd)
			wantLevel, wantOption := transparentBindOption(socket.domain)
			if level != wantLevel || option != wantOption || value != 1 {
				return syscall.EINVAL
			}
			if err := kernel.setErr[socket.domain]; err != nil {
				return err
			}
			socket.optionSet = true
			return nil
		},
		getSockoptInt: func(fd, level, option int) (int, error) {
			kernel.getOptionCalls++
			socket := kernel.requireOpen(fd)
			wantLevel, wantOption := transparentBindOption(socket.domain)
			if level != wantLevel || option != wantOption {
				return 0, syscall.EINVAL
			}
			if kernel.optionValueSet[socket.domain] {
				return kernel.optionValue[socket.domain], nil
			}
			if socket.optionSet {
				return 1, nil
			}
			return 0, nil
		},
		bind: func(fd int, address unix.Sockaddr) error {
			kernel.bindCalls++
			socket := kernel.requireOpen(fd)
			if err := kernel.bindErr[socket.domain]; err != nil {
				return err
			}
			if !socket.optionSet {
				return syscall.EADDRNOTAVAIL
			}
			switch value := address.(type) {
			case *unix.SockaddrInet4:
				copy := *value
				copy.Port = 40000 + fd
				socket.bound = &copy
			case *unix.SockaddrInet6:
				copy := *value
				copy.Port = 40000 + fd
				socket.bound = &copy
			default:
				return syscall.EAFNOSUPPORT
			}
			return nil
		},
		getSockname: func(fd int) (unix.Sockaddr, error) {
			kernel.getSocknameCalls++
			socket := kernel.requireOpen(fd)
			if socket.bound == nil {
				return nil, syscall.EINVAL
			}
			if replacement, ok := kernel.socknameAddress[socket.domain]; ok {
				return fakeTransparentSockaddr(replacement, 40000+fd), nil
			}
			return socket.bound, nil
		},
		addressAssigned: func(address netip.Addr) (bool, error) {
			kernel.addressChecks++
			if kernel.assigned[address] {
				return true, nil
			}
			domain := unix.AF_INET6
			if address.Is4() {
				domain = unix.AF_INET
			}
			if kernel.assignedAfterBind[domain] && kernel.hasBoundSocket(domain) {
				return true, nil
			}
			return false, nil
		},
		close: func(fd int) error {
			kernel.closeCalls++
			socket := kernel.requireOpen(fd)
			socket.closed = true
			delete(kernel.open, fd)
			return kernel.closeErr[socket.domain]
		},
	}
}

func (kernel *fakeTransparentBindKernel) requireOpen(fd int) *fakeTransparentBindSocket {
	socket := kernel.open[fd]
	if socket == nil || socket.closed {
		panic("fake transparent bind kernel used a closed fd")
	}
	return socket
}

func (kernel *fakeTransparentBindKernel) hasBoundSocket(domain int) bool {
	for _, socket := range kernel.open {
		if socket.domain == domain && socket.bound != nil {
			return true
		}
	}
	return false
}

func transparentBindOption(domain int) (int, int) {
	if domain == unix.AF_INET {
		return unix.SOL_IP, unix.IP_TRANSPARENT
	}
	return unix.SOL_IPV6, unix.IPV6_TRANSPARENT
}

func fakeTransparentSockaddr(address netip.Addr, port int) unix.Sockaddr {
	if address.Is4() {
		return &unix.SockaddrInet4{Port: port, Addr: address.As4()}
	}
	return &unix.SockaddrInet6{Port: port, Addr: address.As16()}
}

func TestProbeTransparentBindConfirmsIPv4AndIPv6Semantics(t *testing.T) {
	kernel := newFakeTransparentBindKernel()
	evidence, err := probeTransparentBind(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTransparentEvidence(t, evidence, FeatureTransparentBindV4, FeatureAvailable, ReasonConfirmed, 0)
	assertTransparentEvidence(t, evidence, FeatureTransparentBindV6, FeatureAvailable, ReasonConfirmed, 0)
	if kernel.setCalls != 2 || kernel.getOptionCalls != 2 || kernel.bindCalls != 2 || kernel.getSocknameCalls != 2 {
		t.Fatalf("semantic calls set=%d get-option=%d bind=%d get-name=%d", kernel.setCalls, kernel.getOptionCalls, kernel.bindCalls, kernel.getSocknameCalls)
	}
	if kernel.addressChecks != 4 {
		t.Fatalf("nonlocal address checks=%d want 4", kernel.addressChecks)
	}
	assertFakeTransparentBindClean(t, kernel)
}

func TestProbeTransparentBindClassifiesDeniedAndUnsupportedErrnos(t *testing.T) {
	tests := []struct {
		name   string
		v4Err  error
		v6Err  error
		state  FeatureState
		reason FeatureReason
	}{
		{name: "denied", v4Err: syscall.EPERM, v6Err: syscall.EACCES, state: FeaturePermissionDenied, reason: ReasonPermissionDenied},
		{name: "unsupported", v4Err: syscall.ENOPROTOOPT, v6Err: syscall.EOPNOTSUPP, state: FeatureUnsupported, reason: ReasonPrimitiveUnsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kernel := newFakeTransparentBindKernel()
			kernel.setErr[unix.AF_INET] = test.v4Err
			kernel.setErr[unix.AF_INET6] = test.v6Err
			evidence, err := probeTransparentBind(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
			if err != nil {
				t.Fatal(err)
			}
			assertTransparentEvidence(t, evidence, FeatureTransparentBindV4, test.state, test.reason, errnoOf(test.v4Err))
			assertTransparentEvidence(t, evidence, FeatureTransparentBindV6, test.state, test.reason, errnoOf(test.v6Err))
			if kernel.bindCalls != 0 || kernel.getOptionCalls != 0 {
				t.Fatalf("probe continued after setsockopt failures: get=%d bind=%d", kernel.getOptionCalls, kernel.bindCalls)
			}
			assertFakeTransparentBindClean(t, kernel)
		})
	}
}

func TestProbeTransparentBindDoesNotAcceptSockoptWithoutBindSemantics(t *testing.T) {
	kernel := newFakeTransparentBindKernel()
	kernel.bindErr[unix.AF_INET] = syscall.EADDRNOTAVAIL
	evidence, err := probeTransparentBind(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTransparentEvidence(t, evidence, FeatureTransparentBindV4, FeatureProbeFailed, ReasonSemanticMismatch, syscall.EADDRNOTAVAIL)
	assertTransparentEvidence(t, evidence, FeatureTransparentBindV6, FeatureAvailable, ReasonConfirmed, 0)
	assertFakeTransparentBindClean(t, kernel)
}

func TestProbeTransparentBindRejectsSemanticMismatches(t *testing.T) {
	t.Run("option readback", func(t *testing.T) {
		kernel := newFakeTransparentBindKernel()
		kernel.optionValueSet[unix.AF_INET] = true
		kernel.optionValue[unix.AF_INET] = 0
		evidence, err := probeTransparentBind(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
		if err != nil {
			t.Fatal(err)
		}
		assertTransparentEvidence(t, evidence, FeatureTransparentBindV4, FeatureProbeFailed, ReasonSemanticMismatch, 0)
		if kernel.bindCalls != 1 {
			t.Fatalf("bind calls=%d want only IPv6 bind", kernel.bindCalls)
		}
		assertFakeTransparentBindClean(t, kernel)
	})

	t.Run("socket name", func(t *testing.T) {
		kernel := newFakeTransparentBindKernel()
		kernel.socknameAddress[unix.AF_INET6] = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99})
		evidence, err := probeTransparentBind(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
		if err != nil {
			t.Fatal(err)
		}
		assertTransparentEvidence(t, evidence, FeatureTransparentBindV6, FeatureProbeFailed, ReasonSemanticMismatch, 0)
		assertFakeTransparentBindClean(t, kernel)
	})

	t.Run("address became local", func(t *testing.T) {
		kernel := newFakeTransparentBindKernel()
		kernel.assignedAfterBind[unix.AF_INET] = true
		evidence, err := probeTransparentBind(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
		if err != nil {
			t.Fatal(err)
		}
		assertTransparentEvidence(t, evidence, FeatureTransparentBindV4, FeatureProbeFailed, ReasonSemanticMismatch, 0)
		assertFakeTransparentBindClean(t, kernel)
	})
}

func TestProbeTransparentBindSkipsAssignedCandidate(t *testing.T) {
	kernel := newFakeTransparentBindKernel()
	families := transparentBindProbeFamilies()
	kernel.assigned[families[0].candidates[0]] = true
	evidence, err := probeTransparentBind(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTransparentEvidence(t, evidence, FeatureTransparentBindV4, FeatureAvailable, ReasonConfirmed, 0)
	bound := kernel.history[0].bound.(*unix.SockaddrInet4)
	if got := netip.AddrFrom4(bound.Addr); got != families[0].candidates[1] {
		t.Fatalf("bound address=%s want second nonlocal candidate %s", got, families[0].candidates[1])
	}
	assertFakeTransparentBindClean(t, kernel)
}

func TestProbeTransparentBindCancellationStopsMutationButCleansFD(t *testing.T) {
	kernel := newFakeTransparentBindKernel()
	ops := kernel.ops()
	ctx, cancel := context.WithCancel(context.Background())
	originalSet := ops.setSockoptInt
	ops.setSockoptInt = func(fd, level, option, value int) error {
		err := originalSet(fd, level, option, value)
		cancel()
		return err
	}
	evidence, err := probeTransparentBind(ctx, time.Unix(100, 0).UTC(), ops)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("probe error=%v want context cancellation", err)
	}
	if len(evidence) != 0 {
		t.Fatalf("canceled probe published evidence: %+v", evidence)
	}
	if kernel.socketCalls != 1 || kernel.setCalls != 1 || kernel.getOptionCalls != 0 || kernel.bindCalls != 0 {
		t.Fatalf("calls after cancellation socket=%d set=%d get=%d bind=%d", kernel.socketCalls, kernel.setCalls, kernel.getOptionCalls, kernel.bindCalls)
	}
	assertFakeTransparentBindClean(t, kernel)
}

func TestProbeTransparentBindCloseFailureInvalidatesAvailabilityAndStops(t *testing.T) {
	kernel := newFakeTransparentBindKernel()
	kernel.closeErr[unix.AF_INET] = syscall.EIO
	evidence, err := probeTransparentBind(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTransparentEvidence(t, evidence, FeatureTransparentBindV4, FeatureProbeFailed, ReasonSyscallFailed, syscall.EIO)
	result := mustTransparentEvidence(t, evidence, FeatureTransparentBindV4)
	if !result.Retryable {
		t.Fatal("cleanup failure was not retryable")
	}
	if kernel.socketCalls != 1 {
		t.Fatalf("probe opened IPv6 after cleanup failure: socket calls=%d", kernel.socketCalls)
	}
	assertFakeTransparentBindClean(t, kernel)
}

func assertTransparentEvidence(t *testing.T, evidence []FeatureEvidence, id FeatureID, state FeatureState, reason FeatureReason, errno syscall.Errno) {
	t.Helper()
	result := mustTransparentEvidence(t, evidence, id)
	if result.State != state || result.Reason != reason || result.RawErrno() != errno {
		t.Fatalf("%s=%s/%s errno=%v, want %s/%s errno=%v", id, result.State, result.Reason, result.RawErrno(), state, reason, errno)
	}
	if state == FeatureAvailable && result.Source != SourceRuntimeRoundTrip {
		t.Fatalf("%s source=%s want runtime round trip", id, result.Source)
	}
}

func mustTransparentEvidence(t *testing.T, evidence []FeatureEvidence, id FeatureID) FeatureEvidence {
	t.Helper()
	for _, result := range evidence {
		if result.ID == id {
			return result
		}
	}
	t.Fatalf("missing %s evidence: %+v", id, evidence)
	return FeatureEvidence{}
}

func assertFakeTransparentBindClean(t *testing.T, kernel *fakeTransparentBindKernel) {
	t.Helper()
	if len(kernel.open) != 0 {
		t.Fatalf("fake kernel leaked descriptors: %+v", kernel.open)
	}
	for _, socket := range kernel.history {
		if !socket.closed {
			t.Fatalf("fd %d was not closed", socket.fd)
		}
	}
	if kernel.closeCalls != len(kernel.history) {
		t.Fatalf("close calls=%d opened=%d", kernel.closeCalls, len(kernel.history))
	}
}

func errnoOf(err error) syscall.Errno {
	var errno syscall.Errno
	_ = errors.As(err, &errno)
	return errno
}
