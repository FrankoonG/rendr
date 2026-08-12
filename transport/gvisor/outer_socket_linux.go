//go:build linux

package gvisor

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

type outerSocketContext struct {
	mu       *sync.Mutex
	netnsFD  int
	identity outerNetNSIdentity
}

func platformOuterPacketAvailable() error { return nil }

func platformConfigureOuterUDPPMTU(conn *net.UDPConn, mode outerUDPMode) error {
	if conn == nil {
		return fmt.Errorf("nil outer UDP socket")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("obtain raw UDP socket: %w", err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		optionErr = configureOuterUDPPMTUFD(int(fd), mode)
	}); err != nil {
		return fmt.Errorf("control outer UDP socket: %w", err)
	}
	runtime.KeepAlive(conn)
	return optionErr
}

func configureOuterUDPPMTUFD(fd int, mode outerUDPMode) error {
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return fmt.Errorf("read SO_DOMAIN: %w", err)
	}
	switch mode {
	case outerUDPIPv4:
		if domain != unix.AF_INET {
			return fmt.Errorf("SO_DOMAIN=%d want AF_INET", domain)
		}
		return setAndReadOuterPMTU(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO, "IP_MTU_DISCOVER")
	case outerUDPIPv6, outerUDPDualStack:
		if domain != unix.AF_INET6 {
			return fmt.Errorf("SO_DOMAIN=%d want AF_INET6", domain)
		}
		wantV6Only := 1
		if mode == outerUDPDualStack {
			wantV6Only = 0
		}
		v6Only, err := unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
		if err != nil {
			return fmt.Errorf("read IPV6_V6ONLY: %w", err)
		}
		if v6Only != wantV6Only {
			return fmt.Errorf("IPV6_V6ONLY=%d want %d for %s", v6Only, wantV6Only, mode)
		}
		if mode == outerUDPDualStack {
			if err := setAndReadOuterPMTU(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO, "IP_MTU_DISCOVER"); err != nil {
				return err
			}
		}
		return setAndReadOuterPMTU(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO, "IPV6_MTU_DISCOVER")
	default:
		return fmt.Errorf("invalid outer UDP mode %d", mode)
	}
}

func setAndReadOuterPMTU(fd, level, option, want int, name string) error {
	if err := unix.SetsockoptInt(fd, level, option, want); err != nil {
		return fmt.Errorf("set %s=%d: %w", name, want, err)
	}
	got, err := unix.GetsockoptInt(fd, level, option)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if got != want {
		return fmt.Errorf("%s readback=%d want %d", name, got, want)
	}
	return nil
}

func platformCaptureOuterSocketContext(conn net.PacketConn) (outerSocketContext, error) {
	udp, ok := conn.(*net.UDPConn)
	if !ok || udp == nil {
		return outerSocketContext{netnsFD: -1}, fmt.Errorf("gvisor: outer packet socket is %T, want *net.UDPConn", conn)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	netnsFD, err := unix.Open(
		fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()),
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return outerSocketContext{netnsFD: -1}, fmt.Errorf("gvisor: capture outer socket network namespace: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = unix.Close(netnsFD)
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(netnsFD, &stat); err != nil {
		return outerSocketContext{netnsFD: -1}, fmt.Errorf("gvisor: stat outer socket network namespace: %w", err)
	}
	identity := outerNetNSIdentity{device: uint64(stat.Dev), inode: stat.Ino}
	var socketCookie uint64
	var socketCookieKnown bool
	raw, err := udp.SyscallConn()
	if err != nil {
		return outerSocketContext{netnsFD: -1}, fmt.Errorf("gvisor: obtain outer UDP socket fd: %w", err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		socketCookie, socketCookieKnown, optionErr = getOuterNetNSCookie(int(fd))
	}); err != nil {
		return outerSocketContext{netnsFD: -1}, fmt.Errorf("gvisor: control outer UDP socket: %w", err)
	}
	runtime.KeepAlive(udp)
	if optionErr != nil {
		return outerSocketContext{netnsFD: -1}, optionErr
	}
	if socketCookieKnown {
		probeFD, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
		if err != nil {
			return outerSocketContext{netnsFD: -1}, fmt.Errorf("gvisor: verify outer socket network namespace: %w", err)
		}
		probeCookie, probeKnown, probeErr := getOuterNetNSCookie(probeFD)
		_ = unix.Close(probeFD)
		if probeErr != nil {
			return outerSocketContext{netnsFD: -1}, probeErr
		}
		if !probeKnown || probeCookie != socketCookie {
			return outerSocketContext{netnsFD: -1}, errors.New("gvisor: outer UDP socket does not belong to the captured network namespace")
		}
		identity.cookie = socketCookie
		identity.cookieKnown = true
	}
	closeOnError = false
	return outerSocketContext{mu: &sync.Mutex{}, netnsFD: netnsFD, identity: identity}, nil
}

func platformReleaseOuterSocketContext(context *outerSocketContext) {
	if context == nil {
		return
	}
	if context.mu == nil {
		return
	}
	context.mu.Lock()
	defer context.mu.Unlock()
	if context.netnsFD < 0 {
		return
	}
	_ = unix.Close(context.netnsFD)
	context.netnsFD = -1
	context.identity = outerNetNSIdentity{}
}

func getOuterNetNSCookie(fd int) (uint64, bool, error) {
	var cookie uint64
	length := uint32(unsafe.Sizeof(cookie))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_SOCKET),
		uintptr(unix.SO_NETNS_COOKIE),
		uintptr(unsafe.Pointer(&cookie)),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	if errno != 0 {
		if errors.Is(errno, unix.ENOPROTOOPT) || errors.Is(errno, unix.EINVAL) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("gvisor: read SO_NETNS_COOKIE: %w", errno)
	}
	if length != uint32(unsafe.Sizeof(cookie)) {
		return 0, false, fmt.Errorf("gvisor: SO_NETNS_COOKIE length=%d", length)
	}
	return cookie, true, nil
}
