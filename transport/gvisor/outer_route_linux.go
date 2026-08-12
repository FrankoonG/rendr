//go:build linux

package gvisor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

var outerRouteSequence atomic.Uint32

type outerSocketFacts struct {
	local          *net.UDPAddr
	peer           *net.UDPAddr
	connected      bool
	mark           uint32
	boundDevice    string
	socketMTU      int
	socketMTUKnown bool
}

type outerRouteResult struct {
	outputInterface uint32
	selectedSource  net.IP
	pathMTU         int
	pathMTUKnown    bool
}

func platformObserveOuterUDPRoute(
	ctx context.Context,
	wire *packetWire,
	mode outerUDPMode,
	declaredLocal *net.UDPAddr,
	remote *net.UDPAddr,
) (outerRoutePlatformEvidence, error) {
	if wire == nil || wire.conn == nil || declaredLocal == nil || remote == nil {
		return outerRoutePlatformEvidence{}, errors.New("gvisor: incomplete Linux outer UDP route observation")
	}
	if wire.socketErr != nil {
		return outerRoutePlatformEvidence{}, wire.socketErr
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var evidence outerRoutePlatformEvidence
	err := withOuterSocketNetworkNamespace(ctx, wire, func(identity outerNetNSIdentity) error {
		facts, err := readOuterUDPSocketFacts(wire, mode, declaredLocal, remote, identity)
		if err != nil {
			return err
		}
		zoneInterface, err := resolveOuterRouteZones(facts.local.Zone, remote.Zone)
		if err != nil {
			return err
		}
		boundInterface := uint32(0)
		if facts.boundDevice != "" {
			device, err := net.InterfaceByName(facts.boundDevice)
			if err != nil {
				return fmt.Errorf("gvisor: resolve SO_BINDTODEVICE %q: %w", facts.boundDevice, err)
			}
			boundInterface = uint32(device.Index)
		}
		if zoneInterface != 0 && boundInterface != 0 && zoneInterface != boundInterface {
			return errors.New("gvisor: scoped UDP peer conflicts with SO_BINDTODEVICE")
		}
		expectedInterface := zoneInterface
		if expectedInterface == 0 {
			expectedInterface = boundInterface
		}
		result, err := queryOuterUDPRoute(
			ctx, mode, facts.local, remote, facts.mark, expectedInterface, identity,
		)
		if err != nil {
			return err
		}
		if expectedInterface != 0 && result.outputInterface != expectedInterface {
			return fmt.Errorf(
				"gvisor: route OIF=%d does not match socket selector OIF=%d",
				result.outputInterface, expectedInterface,
			)
		}
		selectedLocal := cloneOuterUDPAddress(facts.local)
		if len(selectedLocal.IP) == 0 || selectedLocal.IP.IsUnspecified() {
			if len(result.selectedSource) == 0 || result.selectedSource.IsUnspecified() {
				return errors.New("gvisor: exact outer UDP route has no selected source")
			}
			selectedLocal.IP = append(net.IP(nil), result.selectedSource...)
		} else if len(result.selectedSource) != 0 && !selectedLocal.IP.Equal(result.selectedSource) {
			return fmt.Errorf(
				"gvisor: route selected source %s differs from socket source %s",
				result.selectedSource, selectedLocal.IP,
			)
		}
		if mode == outerUDPIPv6 && zoneInterface != 0 {
			selectedLocal.Zone = strconv.FormatUint(uint64(zoneInterface), 10)
		}
		pathMTU, pathMTUKnown := facts.socketMTU, facts.socketMTUKnown
		if result.pathMTUKnown && (!pathMTUKnown || result.pathMTU < pathMTU) {
			pathMTU, pathMTUKnown = result.pathMTU, true
		}
		evidence = outerRoutePlatformEvidence{
			local: selectedLocal, outputInterface: result.outputInterface,
			pathMTU: pathMTU, pathMTUKnown: pathMTUKnown,
			socketMark: facts.mark, boundInterface: boundInterface,
			connected: facts.connected, networkNamespace: identity,
		}
		return nil
	})
	if err != nil {
		return outerRoutePlatformEvidence{}, err
	}
	return evidence, nil
}

func withOuterSocketNetworkNamespace(
	ctx context.Context,
	wire *packetWire,
	fn func(outerNetNSIdentity) error,
) error {
	if wire == nil || fn == nil {
		return errors.New("gvisor: invalid outer socket execution context")
	}
	context := &wire.socket
	if context.mu == nil {
		return errors.New("gvisor: outer socket network namespace lock is unavailable")
	}
	context.mu.Lock()
	defer context.mu.Unlock()
	if context.netnsFD < 0 || !context.identity.valid() {
		return errors.New("gvisor: outer socket network namespace is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return contextCause(ctx)
	}
	runtime.LockOSThread()
	currentFD, currentIdentity, err := openCurrentOuterNetworkNamespace()
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	sameNamespace := currentIdentity.device == context.identity.device && currentIdentity.inode == context.identity.inode
	_ = unix.Close(currentFD)
	if sameNamespace {
		defer runtime.UnlockOSThread()
		return fn(context.identity)
	}
	runtime.UnlockOSThread()

	var workerFD = -1
	var workerIdentity outerNetNSIdentity
	switched := false
	return runOuterNamespaceWorker(
		func() (bool, error) {
			workerFD, workerIdentity, err = openCurrentOuterNetworkNamespace()
			if err != nil {
				return false, err
			}
			if workerIdentity.device == context.identity.device && workerIdentity.inode == context.identity.inode {
				return false, nil
			}
			if err := unix.Setns(context.netnsFD, unix.CLONE_NEWNET); err != nil {
				return false, fmt.Errorf("gvisor: enter outer socket network namespace: %w", err)
			}
			switched = true
			enteredFD, enteredIdentity, verifyErr := openCurrentOuterNetworkNamespace()
			if enteredFD >= 0 {
				_ = unix.Close(enteredFD)
			}
			if verifyErr != nil {
				return true, fmt.Errorf("gvisor: verify entered network namespace: %w", verifyErr)
			}
			if enteredIdentity.device != context.identity.device || enteredIdentity.inode != context.identity.inode {
				return true, errors.New("gvisor: failed to enter captured outer socket network namespace")
			}
			return true, nil
		},
		func() error { return fn(context.identity) },
		func() error {
			if workerFD >= 0 {
				defer unix.Close(workerFD)
			}
			if !switched {
				return nil
			}
			if err := unix.Setns(workerFD, unix.CLONE_NEWNET); err != nil {
				return err
			}
			restoredFD, restoredIdentity, err := openCurrentOuterNetworkNamespace()
			if restoredFD >= 0 {
				_ = unix.Close(restoredFD)
			}
			if err != nil {
				return fmt.Errorf("verify restored network namespace: %w", err)
			}
			if restoredIdentity.device != workerIdentity.device || restoredIdentity.inode != workerIdentity.inode {
				return errors.New("restored network namespace differs from worker origin")
			}
			return nil
		},
		outerNamespaceRuntimeHooks(),
	)
}

type outerNamespaceThreadHooks struct {
	lock    func()
	unlock  func()
	abandon func()
}

func outerNamespaceRuntimeHooks() outerNamespaceThreadHooks {
	return outerNamespaceThreadHooks{
		lock: runtime.LockOSThread, unlock: runtime.UnlockOSThread, abandon: runtime.Goexit,
	}
}

func runOuterNamespaceWorker(
	enter func() (bool, error),
	operation func() error,
	restore func() error,
	hooks outerNamespaceThreadHooks,
) error {
	if enter == nil || operation == nil || restore == nil || hooks.lock == nil || hooks.unlock == nil || hooks.abandon == nil {
		return errors.New("gvisor: invalid outer namespace worker")
	}
	result := make(chan error, 1)
	go func() {
		var resultErr error
		defer func() { result <- resultErr }()
		hooks.lock()
		entered, enterErr := enter()
		var operationErr error
		if enterErr == nil {
			operationErr = callOuterNamespaceOperation(operation)
		}
		restoreErr := restore()
		resultErr = errors.Join(enterErr, operationErr)
		if restoreErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("gvisor: restore caller network namespace: %w", restoreErr))
			if entered {
				// Goexit runs the result defer; retaining the thread lock makes the
				// runtime discard this OS thread instead of scheduling Go work on it.
				hooks.abandon()
				return
			}
		}
		hooks.unlock()
	}()
	return <-result
}

func callOuterNamespaceOperation(operation func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("gvisor: outer namespace operation panicked: %v", recovered)
		}
	}()
	return operation()
}

func openCurrentOuterNetworkNamespace() (int, outerNetNSIdentity, error) {
	fd, err := unix.Open(
		fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()),
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, outerNetNSIdentity{}, fmt.Errorf("gvisor: capture current network namespace: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, outerNetNSIdentity{}, fmt.Errorf("gvisor: stat current network namespace: %w", err)
	}
	return fd, outerNetNSIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func readOuterUDPSocketFacts(
	wire *packetWire,
	mode outerUDPMode,
	declaredLocal *net.UDPAddr,
	remote *net.UDPAddr,
	identity outerNetNSIdentity,
) (outerSocketFacts, error) {
	udp, ok := wire.conn.(*net.UDPConn)
	if !ok || udp == nil {
		return outerSocketFacts{}, fmt.Errorf("gvisor: active outer socket is %T, want *net.UDPConn", wire.conn)
	}
	raw, err := udp.SyscallConn()
	if err != nil {
		return outerSocketFacts{}, fmt.Errorf("gvisor: obtain active outer UDP socket: %w", err)
	}
	var facts outerSocketFacts
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		facts, optionErr = readOuterUDPSocketFactsFD(int(fd), mode, identity)
	}); err != nil {
		return outerSocketFacts{}, fmt.Errorf("gvisor: control active outer UDP socket: %w", err)
	}
	runtime.KeepAlive(udp)
	if optionErr != nil {
		return outerSocketFacts{}, optionErr
	}
	if facts.local == nil || declaredLocal == nil || facts.local.Port != declaredLocal.Port {
		return outerSocketFacts{}, errors.New("gvisor: active socket local tuple changed")
	}
	if len(declaredLocal.IP) != 0 && !declaredLocal.IP.IsUnspecified() && !facts.local.IP.Equal(declaredLocal.IP) {
		return outerSocketFacts{}, errors.New("gvisor: active socket local address differs from net.PacketConn")
	}
	if facts.connected && !udpAddrEqualScoped(facts.peer, remote) {
		return outerSocketFacts{}, fmt.Errorf("gvisor: connected outer UDP peer=%v want %v", facts.peer, remote)
	}
	return facts, nil
}

func readOuterUDPSocketFactsFD(
	fd int,
	mode outerUDPMode,
	identity outerNetNSIdentity,
) (outerSocketFacts, error) {
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return outerSocketFacts{}, fmt.Errorf("gvisor: read active socket SO_DOMAIN: %w", err)
	}
	wantDomain := unix.AF_INET
	if mode == outerUDPIPv6 {
		wantDomain = unix.AF_INET6
	}
	dualStackIPv4 := false
	if mode == outerUDPIPv4 && domain == unix.AF_INET6 {
		v6Only, optionErr := unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
		if optionErr != nil || v6Only != 0 {
			return outerSocketFacts{}, fmt.Errorf(
				"gvisor: active dual-stack socket IPV6_V6ONLY=%d: %w", v6Only, optionErr,
			)
		}
		dualStackIPv4 = true
	} else if domain != wantDomain {
		return outerSocketFacts{}, fmt.Errorf("gvisor: active socket SO_DOMAIN=%d want %d", domain, wantDomain)
	}
	socketType, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || socketType != unix.SOCK_DGRAM {
		return outerSocketFacts{}, fmt.Errorf("gvisor: active socket SO_TYPE=%d: %w", socketType, err)
	}
	protocol, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil || protocol != unix.IPPROTO_UDP {
		return outerSocketFacts{}, fmt.Errorf("gvisor: active socket SO_PROTOCOL=%d: %w", protocol, err)
	}
	if cookie, known, err := getOuterNetNSCookie(fd); err != nil {
		return outerSocketFacts{}, err
	} else if identity.cookieKnown && (!known || cookie != identity.cookie) {
		return outerSocketFacts{}, errors.New("gvisor: active socket network namespace changed")
	}
	localSockaddr, err := unix.Getsockname(fd)
	if err != nil {
		return outerSocketFacts{}, fmt.Errorf("gvisor: read active socket local tuple: %w", err)
	}
	local, err := outerUDPAddrFromSockaddr(localSockaddr)
	if err != nil {
		return outerSocketFacts{}, err
	}
	if dualStackIPv4 && local.IP.IsUnspecified() {
		local.IP = append(net.IP(nil), net.IPv4zero...)
		local.Zone = ""
	}
	mark, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
	if err != nil {
		return outerSocketFacts{}, fmt.Errorf("gvisor: read active socket SO_MARK: %w", err)
	}
	boundDevice, err := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	if err != nil {
		return outerSocketFacts{}, fmt.Errorf("gvisor: read active socket SO_BINDTODEVICE: %w", err)
	}
	facts := outerSocketFacts{local: local, mark: uint32(mark), boundDevice: strings.TrimRight(boundDevice, "\x00")}
	peerSockaddr, err := unix.Getpeername(fd)
	switch {
	case err == nil:
		facts.peer, err = outerUDPAddrFromSockaddr(peerSockaddr)
		if err != nil {
			return outerSocketFacts{}, err
		}
		facts.connected = true
		facts.socketMTU, err = readConnectedOuterUDPMTUFD(fd, mode)
		if err != nil {
			return outerSocketFacts{}, err
		}
		facts.socketMTUKnown = true
	case errors.Is(err, unix.ENOTCONN):
	case err != nil:
		return outerSocketFacts{}, fmt.Errorf("gvisor: read active socket peer tuple: %w", err)
	}
	return facts, nil
}

func readConnectedOuterUDPMTUFD(fd int, mode outerUDPMode) (int, error) {
	var (
		mtu int
		err error
	)
	switch mode {
	case outerUDPIPv4:
		mtu, err = unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU)
	case outerUDPIPv6:
		mtu, err = unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU)
	default:
		err = fmt.Errorf("invalid outer UDP mode %d", mode)
	}
	if err != nil {
		return 0, fmt.Errorf("gvisor: read active connected outer UDP PMTU: %w", err)
	}
	if mtu <= 0 {
		return 0, fmt.Errorf("gvisor: active connected outer UDP PMTU=%d", mtu)
	}
	return mtu, nil
}

func outerUDPAddrFromSockaddr(address unix.Sockaddr) (*net.UDPAddr, error) {
	switch value := address.(type) {
	case *unix.SockaddrInet4:
		return &net.UDPAddr{IP: append(net.IP(nil), value.Addr[:]...), Port: value.Port}, nil
	case *unix.SockaddrInet6:
		zone := ""
		if value.ZoneId != 0 {
			zone = strconv.FormatUint(uint64(value.ZoneId), 10)
		}
		return &net.UDPAddr{IP: append(net.IP(nil), value.Addr[:]...), Port: value.Port, Zone: zone}, nil
	default:
		return nil, fmt.Errorf("gvisor: active socket has non-INET tuple %T", address)
	}
}

func udpAddrEqualScoped(left, right *net.UDPAddr) bool {
	if left == nil || right == nil || left.Port != right.Port || !left.IP.Equal(right.IP) {
		return false
	}
	leftZone, leftErr := resolveOuterRouteZone(left.Zone)
	rightZone, rightErr := resolveOuterRouteZone(right.Zone)
	return leftErr == nil && rightErr == nil && leftZone == rightZone
}

func resolveOuterRouteZones(local, remote string) (uint32, error) {
	localIndex, err := resolveOuterRouteZone(local)
	if err != nil {
		return 0, fmt.Errorf("gvisor: resolve local IPv6 zone %q: %w", local, err)
	}
	remoteIndex, err := resolveOuterRouteZone(remote)
	if err != nil {
		return 0, fmt.Errorf("gvisor: resolve remote IPv6 zone %q: %w", remote, err)
	}
	if localIndex != 0 && remoteIndex != 0 && localIndex != remoteIndex {
		return 0, fmt.Errorf("gvisor: conflicting local/remote IPv6 zones %d/%d", localIndex, remoteIndex)
	}
	if remoteIndex != 0 {
		return remoteIndex, nil
	}
	return localIndex, nil
}

func resolveOuterRouteZone(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if numeric, err := strconv.ParseUint(zone, 10, 32); err == nil {
		if numeric == 0 {
			return 0, errors.New("zero numeric zone")
		}
		device, err := net.InterfaceByIndex(int(numeric))
		if err != nil {
			return 0, err
		}
		return uint32(device.Index), nil
	}
	device, err := net.InterfaceByName(zone)
	if err != nil {
		return 0, err
	}
	return uint32(device.Index), nil
}

func platformOuterUDPZonesEqual(wire *packetWire, left, right string) bool {
	if left == right {
		return true
	}
	if wire == nil {
		return false
	}
	equal := false
	err := withOuterSocketNetworkNamespace(context.Background(), wire, func(outerNetNSIdentity) error {
		leftIndex, leftErr := resolveOuterRouteZone(left)
		rightIndex, rightErr := resolveOuterRouteZone(right)
		if leftErr != nil || rightErr != nil {
			return errors.Join(leftErr, rightErr)
		}
		equal = leftIndex == rightIndex
		return nil
	})
	return err == nil && equal
}

func queryOuterUDPRoute(
	ctx context.Context,
	mode outerUDPMode,
	local *net.UDPAddr,
	remote *net.UDPAddr,
	mark uint32,
	expectedInterface uint32,
	identity outerNetNSIdentity,
) (outerRouteResult, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return outerRouteResult{}, fmt.Errorf("gvisor: open route netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if identity.cookieKnown {
		cookie, known, err := getOuterNetNSCookie(fd)
		if err != nil || !known || cookie != identity.cookie {
			return outerRouteResult{}, errors.Join(errors.New("gvisor: route socket is in the wrong network namespace"), err)
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return outerRouteResult{}, fmt.Errorf("gvisor: bind route netlink socket: %w", err)
	}
	sequence := outerRouteSequence.Add(1)
	if sequence == 0 {
		sequence = outerRouteSequence.Add(1)
	}
	request, err := outerUDPRouteRequest(mode, local, remote, mark, expectedInterface, sequence)
	if err != nil {
		return outerRouteResult{}, err
	}
	if err := sendOuterRouteRequest(ctx, fd, request); err != nil {
		return outerRouteResult{}, fmt.Errorf("gvisor: send route lookup: %w", err)
	}
	for {
		messages, err := receiveOuterRouteMessages(ctx, fd)
		if err != nil {
			return outerRouteResult{}, err
		}
		for _, message := range messages {
			if message.Header.Seq != sequence {
				continue
			}
			switch message.Header.Type {
			case unix.NLMSG_ERROR:
				if len(message.Data) < 4 {
					return outerRouteResult{}, errors.New("gvisor: short route netlink error")
				}
				code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
				if code == 0 {
					continue
				}
				return outerRouteResult{}, syscall.Errno(-code)
			case unix.RTM_NEWROUTE:
				return parseOuterUDPRoute(message, mode, expectedInterface)
			case unix.NLMSG_DONE:
				return outerRouteResult{}, errors.New("gvisor: route lookup returned no route")
			}
		}
	}
}

func outerUDPRouteRequest(
	mode outerUDPMode,
	local *net.UDPAddr,
	remote *net.UDPAddr,
	mark uint32,
	expectedInterface uint32,
	sequence uint32,
) ([]byte, error) {
	family, bits := byte(unix.AF_INET6), byte(128)
	localIP, remoteIP := local.IP.To16(), remote.IP.To16()
	if mode == outerUDPIPv4 {
		family, bits = unix.AF_INET, 32
		localIP, remoteIP = local.IP.To4(), remote.IP.To4()
	}
	if remoteIP == nil || localIP == nil {
		return nil, errors.New("gvisor: route lookup address family mismatch")
	}
	concreteLocal := !local.IP.IsUnspecified()
	body := make([]byte, unix.SizeofRtMsg)
	body[0], body[1], body[4] = family, bits, unix.RT_TABLE_UNSPEC
	if concreteLocal {
		body[2] = bits
	}
	var uid, routeMark, oif [4]byte
	var sourcePort, destinationPort [2]byte
	binary.NativeEndian.PutUint32(uid[:], uint32(os.Geteuid()))
	binary.NativeEndian.PutUint32(routeMark[:], mark)
	binary.BigEndian.PutUint16(sourcePort[:], uint16(local.Port))
	binary.BigEndian.PutUint16(destinationPort[:], uint16(remote.Port))
	attributes := [][]byte{
		outerNetlinkAttribute(unix.RTA_DST, remoteIP),
		outerNetlinkAttribute(unix.RTA_UID, uid[:]),
		outerNetlinkAttribute(unix.RTA_MARK, routeMark[:]),
		outerNetlinkAttribute(unix.RTA_IP_PROTO, []byte{unix.IPPROTO_UDP}),
		outerNetlinkAttribute(unix.RTA_SPORT, sourcePort[:]),
		outerNetlinkAttribute(unix.RTA_DPORT, destinationPort[:]),
	}
	if concreteLocal {
		attributes = append(attributes, outerNetlinkAttribute(unix.RTA_SRC, localIP))
	}
	if expectedInterface != 0 {
		binary.NativeEndian.PutUint32(oif[:], expectedInterface)
		attributes = append(attributes, outerNetlinkAttribute(unix.RTA_OIF, oif[:]))
	}
	length := unix.SizeofNlMsghdr + len(body)
	for _, attribute := range attributes {
		length += len(attribute)
	}
	request := make([]byte, length)
	binary.NativeEndian.PutUint32(request[0:4], uint32(length))
	binary.NativeEndian.PutUint16(request[4:6], unix.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:12], sequence)
	copy(request[unix.SizeofNlMsghdr:], body)
	offset := unix.SizeofNlMsghdr + len(body)
	for _, attribute := range attributes {
		copy(request[offset:], attribute)
		offset += len(attribute)
	}
	return request, nil
}

func outerNetlinkAttribute(attributeType uint16, value []byte) []byte {
	length := 4 + len(value)
	aligned := (length + 3) &^ 3
	attribute := make([]byte, aligned)
	binary.NativeEndian.PutUint16(attribute[0:2], uint16(length))
	binary.NativeEndian.PutUint16(attribute[2:4], attributeType)
	copy(attribute[4:], value)
	return attribute
}

func sendOuterRouteRequest(ctx context.Context, fd int, request []byte) error {
	for {
		err := unix.Sendto(fd, request, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EINTR) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		if err := waitOuterRoutePoll(ctx, fd, unix.POLLOUT); err != nil {
			return err
		}
	}
}

func receiveOuterRouteMessages(ctx context.Context, fd int) ([]syscall.NetlinkMessage, error) {
	for {
		if err := waitOuterRoutePoll(ctx, fd, unix.POLLIN); err != nil {
			return nil, err
		}
		buffer := make([]byte, 1<<16)
		n, _, flags, sender, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("gvisor: receive route lookup: %w", err)
		}
		netlinkSender, ok := sender.(*unix.SockaddrNetlink)
		if !ok || netlinkSender.Pid != 0 {
			return nil, errors.New("gvisor: route lookup did not originate from the kernel")
		}
		if flags&unix.MSG_TRUNC != 0 {
			return nil, errors.New("gvisor: truncated route lookup response")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return nil, fmt.Errorf("gvisor: parse route lookup: %w", err)
		}
		return messages, nil
	}
}

func waitOuterRoutePoll(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return contextCause(ctx)
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: events | unix.POLLERR | unix.POLLHUP}}
		ready, err := unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 0 {
			continue
		}
		if poll[0].Revents&unix.POLLNVAL != 0 {
			return unix.EBADF
		}
		return nil
	}
}

func parseOuterUDPRoute(
	message syscall.NetlinkMessage,
	mode outerUDPMode,
	expectedInterface uint32,
) (outerRouteResult, error) {
	if len(message.Data) < unix.SizeofRtMsg {
		return outerRouteResult{}, errors.New("gvisor: short UDP route response")
	}
	wantFamily := byte(unix.AF_INET6)
	wantAddressSize := net.IPv6len
	if mode == outerUDPIPv4 {
		wantFamily = unix.AF_INET
		wantAddressSize = net.IPv4len
	}
	if message.Data[0] != wantFamily {
		return outerRouteResult{}, fmt.Errorf("gvisor: UDP route family=%d want %d", message.Data[0], wantFamily)
	}
	attributes, err := syscall.ParseNetlinkRouteAttr(&message)
	if err != nil {
		return outerRouteResult{}, fmt.Errorf("gvisor: parse UDP route attributes: %w", err)
	}
	result := outerRouteResult{}
	metricsSeen := false
	for _, attribute := range attributes {
		switch attribute.Attr.Type & 0x3fff {
		case unix.RTA_OIF:
			if len(attribute.Value) != 4 || result.outputInterface != 0 {
				return outerRouteResult{}, errors.New("gvisor: malformed or duplicate UDP route OIF")
			}
			result.outputInterface = binary.NativeEndian.Uint32(attribute.Value)
		case unix.RTA_PREFSRC:
			if len(attribute.Value) != wantAddressSize || len(result.selectedSource) != 0 {
				return outerRouteResult{}, errors.New("gvisor: malformed or duplicate UDP route preferred source")
			}
			result.selectedSource = append(net.IP(nil), attribute.Value...)
		case unix.RTA_METRICS:
			if metricsSeen {
				return outerRouteResult{}, errors.New("gvisor: duplicate UDP route metrics")
			}
			metricsSeen = true
			result.pathMTU, result.pathMTUKnown, err = parseOuterRouteMTU(attribute.Value)
			if err != nil {
				return outerRouteResult{}, err
			}
		}
	}
	if result.outputInterface == 0 {
		return outerRouteResult{}, errors.New("gvisor: UDP route response has no OIF")
	}
	if expectedInterface != 0 && result.outputInterface != expectedInterface {
		return outerRouteResult{}, fmt.Errorf(
			"gvisor: UDP route response OIF=%d want %d", result.outputInterface, expectedInterface,
		)
	}
	return result, nil
}

func parseOuterRouteMTU(attributes []byte) (int, bool, error) {
	found := false
	mtu := 0
	for len(attributes) != 0 {
		if len(attributes) < 4 {
			if allZero(attributes) {
				break
			}
			return 0, false, errors.New("gvisor: truncated RTA_METRICS attribute")
		}
		length := int(binary.NativeEndian.Uint16(attributes[0:2]))
		typ := binary.NativeEndian.Uint16(attributes[2:4]) & 0x3fff
		if length < 4 || length > len(attributes) {
			return 0, false, errors.New("gvisor: malformed RTA_METRICS attribute length")
		}
		aligned := (length + 3) &^ 3
		if aligned > len(attributes) {
			return 0, false, errors.New("gvisor: truncated RTA_METRICS alignment")
		}
		if typ == unix.RTAX_MTU {
			if found || length != 8 {
				return 0, false, errors.New("gvisor: malformed or duplicate RTAX_MTU")
			}
			mtu = int(binary.NativeEndian.Uint32(attributes[4:8]))
			if mtu <= 0 {
				return 0, false, errors.New("gvisor: invalid RTAX_MTU")
			}
			found = true
		}
		if !allZero(attributes[length:aligned]) {
			return 0, false, errors.New("gvisor: non-zero RTA_METRICS padding")
		}
		attributes = attributes[aligned:]
	}
	return mtu, found, nil
}
