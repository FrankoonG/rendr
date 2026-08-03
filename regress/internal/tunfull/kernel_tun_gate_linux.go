//go:build linux

package tunfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/FrankoonG/rendr/tun"
	"github.com/FrankoonG/rendr/virtualif"
	"golang.org/x/sys/unix"
)

const (
	kernelTUNHelperOutputLimit = 16 << 10
	kernelTUNPacketIOLimit     = 2 * time.Second
	kernelTUNCleanupLimit      = time.Second
)

func executeKernelTUNProbePlatform(ctx context.Context, mode string) kernelTUNProbeResult {
	result := kernelTUNProbeResult{Mode: mode}
	_, result.Bounded = ctx.Deadline()

	nonce, err := newKernelTUNProbeNonce()
	if err != nil {
		result.ProcessError = "generate probe nonce: " + boundedKernelTUNDetail(err.Error())
		return result
	}
	result.Nonce = nonce
	executable, err := os.Executable()
	if err != nil {
		result.ProcessError = "resolve probe executable: " + boundedKernelTUNDetail(err.Error())
		return result
	}

	cmd := exec.CommandContext(ctx, executable, kernelTUNHelperArgPrefix+nonce)
	cmd.Env = append(os.Environ(),
		kernelTUNHelperModeEnv+"="+mode,
		kernelTUNHelperNonceEnv+"="+nonce,
	)
	cmd.WaitDelay = 500 * time.Millisecond
	var stdout, stderr boundedKernelTUNBuffer
	stdout.limit = kernelTUNHelperOutputLimit
	stderr.limit = kernelTUNHelperOutputLimit
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true
	}
	if stdout.truncated || stderr.truncated {
		result.ProcessError = "probe helper output exceeded bounded capture"
		return result
	}
	parsed, parseErr := parseKernelTUNHelperOutput(stdout.Bytes(), mode, nonce)
	if parseErr != nil {
		result.ProcessError = boundedKernelTUNDetail(parseErr.Error())
		if runErr != nil {
			result.ProcessError += ": " + boundedKernelTUNDetail(runErr.Error())
		}
		if detail := boundedKernelTUNDetail(stderr.String()); detail != "" {
			result.ProcessError += ": stderr: " + detail
		}
		return result
	}
	parsed.Bounded = result.Bounded
	parsed.TimedOut = result.TimedOut
	if runErr != nil {
		parsed.ProcessError = boundedKernelTUNDetail(runErr.Error())
		if detail := boundedKernelTUNDetail(stderr.String()); detail != "" {
			parsed.ProcessError += ": stderr: " + detail
		}
	}
	if parsed.InterfaceName != "" && runErr == nil {
		parsed.CleanupVerified, err = waitKernelTUNInterfaceAbsent(ctx, parsed.InterfaceName, kernelTUNCleanupLimit)
		if err != nil {
			parsed.Detail = appendKernelTUNDetail(parsed.Detail, "verify cleanup: "+err.Error())
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		parsed.TimedOut = true
	}
	return parsed
}

func runKernelTUNProbeHelper(mode, nonce string) kernelTUNProbeResult {
	switch mode {
	case kernelTUNProbePositive:
		return runPositiveKernelTUNProbe(nonce)
	case kernelTUNProbeNegative:
		return runNegativeKernelTUNProbe()
	default:
		return kernelTUNProbeResult{
			Completed: true,
			Reason:    string(virtualif.ReasonTUNUnavailable),
			Stage:     "helper-mode",
			Detail:    "unknown probe mode",
		}
	}
}

func runPositiveKernelTUNProbe(nonce string) (result kernelTUNProbeResult) {
	result.Stage = "open"
	device, err := tun.Open(tun.Config{Enabled: true, Name: "rendrg%d", MTU: tun.DefaultMTU})
	if err != nil {
		setKernelTUNProbeError(&result, err)
		result.Completed = true
		return result
	}
	result.DeviceOpened = true
	result.InterfaceCreated = device.Name() != ""
	result.InterfaceName = device.Name()

	deviceClosed := false
	closeDevice := func() error {
		if deviceClosed {
			return nil
		}
		deviceClosed = true
		result.CleanupAttempted = true
		err := device.Close()
		result.CleanupCloseOK = err == nil || errors.Is(err, os.ErrClosed)
		return err
	}
	defer func() {
		_ = closeDevice()
		result.Completed = true
	}()

	localIP, peerIP := kernelTUNProbeIPv4Pair(nonce)
	result.Stage = "configure-interface"
	if err := configureKernelTUNIPv4(device.Name(), localIP); err != nil {
		setKernelTUNProbeError(&result, err)
		return result
	}

	result.Stage = "kernel-to-tun-read"
	readBytes, err := observeKernelPacketOnTUN(device, localIP, peerIP, nonce)
	if err != nil {
		setKernelTUNProbeError(&result, err)
		if errors.Is(err, context.DeadlineExceeded) {
			_ = closeDevice()
		}
		return result
	}
	result.KernelPacketRead = true
	result.ReadBytes = readBytes

	result.Stage = "tun-to-kernel-write"
	writeBytes, err := observeTUNPacketAtKernelSocket(device, localIP, peerIP, nonce)
	if err != nil {
		setKernelTUNProbeError(&result, err)
		if errors.Is(err, context.DeadlineExceeded) {
			_ = closeDevice()
		}
		return result
	}
	result.KernelPacketWrite = true
	result.WriteBytes = writeBytes
	result.PacketIntegrity = true
	result.Available = true
	result.Stage = "complete"
	return result
}

func runNegativeKernelTUNProbe() kernelTUNProbeResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	result := kernelTUNProbeResult{Stage: "drop-capabilities"}
	dropped, capNetAdmin, err := dropKernelTUNCapabilities()
	result.CapabilitiesDropped = dropped
	result.CAPNetAdminPresent = capNetAdmin
	if err != nil {
		setKernelTUNProbeError(&result, err)
		result.Completed = true
		return result
	}

	result.Stage = "probe-without-cap-net-admin"
	device, err := tun.Open(tun.Config{Enabled: true, Name: "rendrn%d", MTU: tun.DefaultMTU})
	if err != nil {
		setKernelTUNProbeError(&result, err)
		result.Completed = true
		return result
	}
	result.Available = true
	result.DeviceOpened = true
	result.InterfaceCreated = device.Name() != ""
	result.InterfaceName = device.Name()
	result.CleanupAttempted = true
	closeErr := device.Close()
	result.CleanupCloseOK = closeErr == nil || errors.Is(closeErr, os.ErrClosed)
	if closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
		result.Detail = appendKernelTUNDetail(result.Detail, "close false-green TUN: "+closeErr.Error())
	}
	result.Completed = true
	return result
}

func configureKernelTUNIPv4(name string, localIP net.IP) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open interface control socket: %w", err)
	}
	defer unix.Close(fd)

	setAddress := func(request uint, address net.IP) error {
		ifreq, err := unix.NewIfreq(name)
		if err != nil {
			return err
		}
		if err := ifreq.SetInet4Addr(address.To4()); err != nil {
			return err
		}
		return unix.IoctlIfreq(fd, request, ifreq)
	}
	if err := setAddress(unix.SIOCSIFADDR, localIP); err != nil {
		return fmt.Errorf("set TUN IPv4 address: %w", err)
	}
	if err := setAddress(unix.SIOCSIFNETMASK, net.IPv4(255, 255, 255, 252)); err != nil {
		return fmt.Errorf("set TUN IPv4 netmask: %w", err)
	}

	ifreq, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifreq); err != nil {
		return fmt.Errorf("get TUN flags: %w", err)
	}
	ifreq.SetUint16(ifreq.Uint16() | uint16(unix.IFF_UP))
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifreq); err != nil {
		return fmt.Errorf("set TUN up: %w", err)
	}
	return nil
}

func observeKernelPacketOnTUN(device *tun.Device, localIP, peerIP net.IP, nonce string) (int, error) {
	marker := []byte("rendr-tun-read:" + nonce)
	const destinationPort = 39071

	type readResult struct {
		bytes int
		err   error
	}
	readDone := make(chan readResult, 1)
	go func() {
		buffer := make([]byte, tun.DefaultMTU)
		for {
			n, err := device.Read(buffer)
			if err != nil {
				readDone <- readResult{err: err}
				return
			}
			if matchKernelTUNUDP(buffer[:n], localIP, peerIP, 0, destinationPort, marker) {
				readDone <- readResult{bytes: n}
				return
			}
		}
	}()

	remote := &net.UDPAddr{IP: peerIP, Port: destinationPort}
	conn, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		return 0, fmt.Errorf("dial routed UDP probe: %w", err)
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(kernelTUNPacketIOLimit)); err != nil {
		return 0, fmt.Errorf("set routed UDP deadline: %w", err)
	}
	if n, err := conn.Write(marker); err != nil {
		return 0, fmt.Errorf("emit kernel UDP packet: %w", err)
	} else if n != len(marker) {
		return 0, fmt.Errorf("emit kernel UDP packet: short write %d/%d", n, len(marker))
	}

	timer := time.NewTimer(kernelTUNPacketIOLimit)
	defer timer.Stop()
	select {
	case outcome := <-readDone:
		if outcome.err != nil {
			return 0, fmt.Errorf("read TUN packet: %w", outcome.err)
		}
		return outcome.bytes, nil
	case <-timer.C:
		return 0, fmt.Errorf("kernel-emitted packet stimulus: %w", context.DeadlineExceeded)
	}
}

func observeTUNPacketAtKernelSocket(device *tun.Device, localIP, peerIP net.IP, nonce string) (int, error) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		return 0, fmt.Errorf("listen for injected TUN packet: %w", err)
	}
	defer listener.Close()
	if err := listener.SetReadDeadline(time.Now().Add(kernelTUNPacketIOLimit)); err != nil {
		return 0, fmt.Errorf("set injected packet deadline: %w", err)
	}

	marker := []byte("rendr-tun-write:" + nonce)
	const sourcePort = 39072
	destinationPort := listener.LocalAddr().(*net.UDPAddr).Port
	packet := buildKernelTUNIPv4UDP(peerIP, localIP, sourcePort, destinationPort, marker)

	type writeResult struct {
		bytes int
		err   error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		n, err := device.Write(packet)
		writeDone <- writeResult{bytes: n, err: err}
	}()
	timer := time.NewTimer(kernelTUNPacketIOLimit)
	defer timer.Stop()
	select {
	case outcome := <-writeDone:
		if outcome.err != nil {
			return 0, fmt.Errorf("inject TUN packet: %w", outcome.err)
		}
		if outcome.bytes != len(packet) {
			return 0, fmt.Errorf("inject TUN packet: short write %d/%d", outcome.bytes, len(packet))
		}
	case <-timer.C:
		return 0, fmt.Errorf("TUN write stimulus: %w", context.DeadlineExceeded)
	}

	buffer := make([]byte, len(marker)+1)
	n, source, err := listener.ReadFromUDP(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return 0, fmt.Errorf("kernel UDP receive stimulus: %w", context.DeadlineExceeded)
		}
		return 0, fmt.Errorf("receive injected TUN packet: %w", err)
	}
	if !source.IP.Equal(peerIP) || source.Port != sourcePort {
		return 0, fmt.Errorf("injected TUN packet source=%s, want %s:%d", source, peerIP, sourcePort)
	}
	if !bytes.Equal(buffer[:n], marker) {
		return 0, fmt.Errorf("injected TUN packet payload mismatch")
	}
	return len(packet), nil
}

func matchKernelTUNUDP(packet []byte, sourceIP, destinationIP net.IP, sourcePort, destinationPort int, payload []byte) bool {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return false
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || len(packet) < headerLength+8 || packet[9] != unix.IPPROTO_UDP {
		return false
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength < headerLength+8 || totalLength > len(packet) {
		return false
	}
	if !net.IP(packet[12:16]).Equal(sourceIP) || !net.IP(packet[16:20]).Equal(destinationIP) {
		return false
	}
	udp := packet[headerLength:totalLength]
	if sourcePort != 0 && int(binary.BigEndian.Uint16(udp[0:2])) != sourcePort {
		return false
	}
	if int(binary.BigEndian.Uint16(udp[2:4])) != destinationPort {
		return false
	}
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength < 8 || udpLength > len(udp) {
		return false
	}
	return bytes.Equal(udp[8:udpLength], payload)
}

func buildKernelTUNIPv4UDP(sourceIP, destinationIP net.IP, sourcePort, destinationPort int, payload []byte) []byte {
	const ipv4HeaderLength = 20
	const udpHeaderLength = 8
	packet := make([]byte, ipv4HeaderLength+udpHeaderLength+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 0x5244)
	packet[8] = 64
	packet[9] = unix.IPPROTO_UDP
	copy(packet[12:16], sourceIP.To4())
	copy(packet[16:20], destinationIP.To4())
	binary.BigEndian.PutUint16(packet[10:12], kernelTUNIPv4Checksum(packet[:ipv4HeaderLength]))

	udp := packet[ipv4HeaderLength:]
	binary.BigEndian.PutUint16(udp[0:2], uint16(sourcePort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(destinationPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[udpHeaderLength:], payload)
	return packet
}

func kernelTUNIPv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func kernelTUNProbeIPv4Pair(nonce string) (net.IP, net.IP) {
	digest := sha256.Sum256([]byte(nonce))
	secondOctet := byte(18 + digest[0]&1)
	base := digest[2] & 0xfc
	return net.IPv4(198, secondOctet, digest[1], base+1).To4(),
		net.IPv4(198, secondOctet, digest[1], base+2).To4()
}

func dropKernelTUNCapabilities() (dropped, capNetAdmin bool, err error) {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return false, true, fmt.Errorf("set no_new_privs: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return false, true, fmt.Errorf("clear ambient capabilities: %w", err)
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return false, true, fmt.Errorf("drop capabilities: %w", err)
	}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return false, true, fmt.Errorf("read dropped capabilities: %w", err)
	}
	capNetAdmin = capabilitySet(data, unix.CAP_NET_ADMIN)
	allZero := true
	for _, word := range data {
		if word.Effective != 0 || word.Permitted != 0 || word.Inheritable != 0 {
			allZero = false
			break
		}
	}
	return allZero && !capNetAdmin, capNetAdmin, nil
}

func capabilitySet(data [2]unix.CapUserData, capability int) bool {
	word := capability / 32
	bit := uint(capability % 32)
	if word >= len(data) {
		return false
	}
	mask := uint32(1) << bit
	return data[word].Effective&mask != 0 || data[word].Permitted&mask != 0 || data[word].Inheritable&mask != 0
}

func waitKernelTUNInterfaceAbsent(ctx context.Context, name string, limit time.Duration) (bool, error) {
	cleanupCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	for {
		interfaces, err := net.Interfaces()
		if err != nil {
			return false, err
		}
		found := false
		for _, iface := range interfaces {
			if iface.Name == name {
				found = true
				break
			}
		}
		if !found {
			return true, nil
		}
		select {
		case <-cleanupCtx.Done():
			return false, cleanupCtx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func setKernelTUNProbeError(result *kernelTUNProbeResult, err error) {
	if result == nil || err == nil {
		return
	}
	result.Detail = boundedKernelTUNDetail(err.Error())
	var virtualError *virtualif.Error
	if errors.As(err, &virtualError) {
		result.Reason = string(virtualError.Reason)
		if virtualError.Op != "" {
			result.Stage = virtualError.Op
		}
		return
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrPermission) {
		result.Reason = string(virtualif.ReasonTUNPermissionDenied)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		result.Reason = "packet_stimulus_missing"
		return
	}
	result.Reason = string(virtualif.ReasonTUNUnavailable)
}

func appendKernelTUNDetail(existing, detail string) string {
	if existing != "" {
		detail = existing + "; " + detail
	}
	return boundedKernelTUNDetail(detail)
}

type boundedKernelTUNBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedKernelTUNBuffer) Write(payload []byte) (int, error) {
	originalLength := len(payload)
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.truncated = b.truncated || originalLength > 0
		return originalLength, nil
	}
	if len(payload) > remaining {
		payload = payload[:remaining]
		b.truncated = true
	}
	_, _ = b.Buffer.Write(payload)
	return originalLength, nil
}
