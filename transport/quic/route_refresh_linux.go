//go:build linux

package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const cidRouteQueryTimeout = time.Second

type linuxCIDRouteChangeWatcher struct {
	fd     int
	events chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func openRouteChangeWatcherPlatform(parent context.Context) (routeChangeWatcher, error) {
	if parent == nil {
		return nil, errors.New("quic: nil route change watcher context")
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	closeOnError := func(cause error) (routeChangeWatcher, error) {
		_ = unix.Close(fd)
		return nil, cause
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return closeOnError(err)
	}
	if err := joinCIDRouteNetlinkGroups(fd, unix.SetsockoptInt); err != nil {
		return closeOnError(err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	ctx, cancel := context.WithCancel(parent)
	watcher := &linuxCIDRouteChangeWatcher{
		fd: fd, events: make(chan struct{}, 1), cancel: cancel, done: make(chan struct{}),
	}
	go watcher.loop(ctx)
	return watcher, nil
}

func joinCIDRouteNetlinkGroups(fd int, setMembership func(int, int, int, int) error) error {
	for _, group := range []int{
		unix.RTNLGRP_LINK,
		unix.RTNLGRP_IPV4_IFADDR, unix.RTNLGRP_IPV6_IFADDR,
		unix.RTNLGRP_IPV4_ROUTE, unix.RTNLGRP_IPV6_ROUTE,
		unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE,
	} {
		if err := setMembership(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, group); err != nil {
			return err
		}
	}
	if err := setMembership(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, unix.RTNLGRP_NEXTHOP); err != nil &&
		!errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOPROTOOPT) {
		return err
	}
	return nil
}

func (w *linuxCIDRouteChangeWatcher) Events() <-chan struct{} {
	if w == nil {
		return nil
	}
	return w.events
}

func (w *linuxCIDRouteChangeWatcher) Close() {
	if w == nil {
		return
	}
	w.once.Do(func() {
		w.cancel()
		_ = unix.Close(w.fd)
		<-w.done
	})
}

func (w *linuxCIDRouteChangeWatcher) loop(ctx context.Context) {
	defer close(w.done)
	defer close(w.events)
	buffer := make([]byte, 1<<16)
	for {
		if ctx.Err() != nil {
			return
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP}}, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		if ready == 0 {
			continue
		}
		for {
			n, _, flags, sender, recvErr := unix.Recvmsg(w.fd, buffer, nil, unix.MSG_DONTWAIT)
			if recvErr != nil {
				if errors.Is(recvErr, unix.EAGAIN) || errors.Is(recvErr, unix.EWOULDBLOCK) {
					break
				}
				if errors.Is(recvErr, unix.ENOBUFS) {
					w.signal()
					break
				}
				return
			}
			if n == 0 {
				break
			}
			netlinkSender, ok := sender.(*unix.SockaddrNetlink)
			if !ok || netlinkSender.Pid != 0 {
				return
			}
			if flags&unix.MSG_TRUNC != 0 {
				w.signal()
				continue
			}
			messages, parseErr := syscall.ParseNetlinkMessage(buffer[:n])
			if parseErr != nil {
				w.signal()
				continue
			}
			if containsCIDRouteChange(messages) {
				w.signal()
			}
		}
	}
}

func (w *linuxCIDRouteChangeWatcher) signal() {
	select {
	case w.events <- struct{}{}:
	default:
	}
}

func containsCIDRouteChange(messages []syscall.NetlinkMessage) bool {
	for _, message := range messages {
		if isCIDRouteChangeType(message.Header.Type) {
			return true
		}
	}
	return false
}

func isCIDRouteChangeType(messageType uint16) bool {
	switch messageType {
	case unix.RTM_NEWLINK, unix.RTM_DELLINK,
		unix.RTM_NEWADDR, unix.RTM_DELADDR,
		unix.RTM_NEWROUTE, unix.RTM_DELROUTE,
		unix.RTM_NEWRULE, unix.RTM_DELRULE,
		unix.RTM_NEWNEXTHOP, unix.RTM_DELNEXTHOP:
		return true
	default:
		return false
	}
}

func observeRouteSourcePlatform(ctx context.Context, remote *net.UDPAddr) (routeObservation, error) {
	local, err := dialRouteSource(ctx, remote)
	if err != nil {
		return routeObservation{}, err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return routeObservation{}, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return routeObservation{}, err
	}

	sequence := uint32(time.Now().UnixNano())
	if sequence == 0 {
		sequence = 1
	}
	request, err := cidRouteRequest(sequence, local, remote)
	if err != nil {
		return routeObservation{}, err
	}
	if err := unix.Sendto(fd, request, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return routeObservation{}, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, cidRouteQueryTimeout)
	defer cancel()
	message, err := receiveCIDRoute(queryCtx, fd, sequence)
	if err != nil {
		return routeObservation{}, err
	}
	canonical, outputIf, err := canonicalCIDRoute(message)
	if err != nil {
		return routeObservation{}, err
	}
	iface, err := selectedCIDInterface(outputIf, local.IP)
	if err != nil {
		return routeObservation{}, err
	}
	if iface.Flags&net.FlagUp == 0 {
		return routeObservation{}, errors.New("quic: selected route interface is down")
	}

	source := cloneUDPAddr(local)
	source.Port = 0
	hash := sha256.New()
	_, _ = hash.Write([]byte("QRL1"))
	writeRouteBytes(hash, canonicalIP(remote.IP))
	writeRouteString(hash, remote.Zone)
	writeRouteBytes(hash, canonicalIP(source.IP))
	writeRouteString(hash, source.Zone)
	writeRouteBytes(hash, canonical)
	var scalar [8]byte
	binary.BigEndian.PutUint32(scalar[:4], uint32(iface.Index))
	_, _ = hash.Write(scalar[:4])
	binary.BigEndian.PutUint32(scalar[:4], uint32(iface.MTU))
	_, _ = hash.Write(scalar[:4])
	binary.BigEndian.PutUint64(scalar[:], uint64(iface.Flags))
	_, _ = hash.Write(scalar[:])
	writeRouteString(hash, iface.Name)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return routeObservation{source: source, digest: digest}, nil
}

func cidRouteRequest(sequence uint32, local, remote *net.UDPAddr) ([]byte, error) {
	family, bits := byte(unix.AF_INET6), byte(128)
	remoteIP, localIP := remote.IP.To16(), local.IP.To16()
	if remote.IP.To4() != nil {
		family, bits = unix.AF_INET, 32
		remoteIP, localIP = remote.IP.To4(), local.IP.To4()
	}
	if remoteIP == nil || localIP == nil || (family == unix.AF_INET) != (local.IP.To4() != nil) {
		return nil, errors.New("quic: incompatible route/source address families")
	}
	body := make([]byte, unix.SizeofRtMsg)
	body[0], body[1], body[2] = family, bits, bits
	body[4] = unix.RT_TABLE_UNSPEC
	var protocol [1]byte
	protocol[0] = unix.IPPROTO_UDP
	var uid [4]byte
	binary.NativeEndian.PutUint32(uid[:], uint32(unix.Geteuid()))
	var sourcePort, destinationPort [2]byte
	binary.BigEndian.PutUint16(sourcePort[:], uint16(local.Port))
	binary.BigEndian.PutUint16(destinationPort[:], uint16(remote.Port))
	attributes := [][]byte{
		cidNetlinkAttribute(unix.RTA_DST, remoteIP),
		cidNetlinkAttribute(unix.RTA_SRC, localIP),
		cidNetlinkAttribute(unix.RTA_UID, uid[:]),
		cidNetlinkAttribute(unix.RTA_IP_PROTO, protocol[:]),
		cidNetlinkAttribute(unix.RTA_SPORT, sourcePort[:]),
		cidNetlinkAttribute(unix.RTA_DPORT, destinationPort[:]),
	}
	if remote.Zone != "" {
		iface, err := net.InterfaceByName(remote.Zone)
		if err != nil {
			return nil, err
		}
		var outputIf [4]byte
		binary.NativeEndian.PutUint32(outputIf[:], uint32(iface.Index))
		attributes = append(attributes, cidNetlinkAttribute(unix.RTA_OIF, outputIf[:]))
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

func cidNetlinkAttribute(attributeType uint16, value []byte) []byte {
	length := 4 + len(value)
	aligned := (length + 3) &^ 3
	attribute := make([]byte, aligned)
	binary.NativeEndian.PutUint16(attribute[0:2], uint16(length))
	binary.NativeEndian.PutUint16(attribute[2:4], attributeType)
	copy(attribute[4:], value)
	return attribute
}

func receiveCIDRoute(ctx context.Context, fd int, sequence uint32) (syscall.NetlinkMessage, error) {
	buffer := make([]byte, 1<<16)
	for {
		if err := ctx.Err(); err != nil {
			return syscall.NetlinkMessage{}, context.Cause(ctx)
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP}}, 10)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return syscall.NetlinkMessage{}, err
		}
		if ready == 0 {
			continue
		}
		n, _, flags, sender, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return syscall.NetlinkMessage{}, err
		}
		netlinkSender, ok := sender.(*unix.SockaddrNetlink)
		if !ok || netlinkSender.Pid != 0 || flags&unix.MSG_TRUNC != 0 {
			return syscall.NetlinkMessage{}, errors.New("quic: invalid kernel route response")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return syscall.NetlinkMessage{}, err
		}
		for _, message := range messages {
			if message.Header.Seq != sequence {
				continue
			}
			switch message.Header.Type {
			case unix.NLMSG_ERROR:
				if len(message.Data) < 4 {
					return syscall.NetlinkMessage{}, errors.New("quic: short route lookup error")
				}
				code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
				if code != 0 {
					return syscall.NetlinkMessage{}, syscall.Errno(-code)
				}
			case unix.RTM_NEWROUTE:
				message.Data = append([]byte(nil), message.Data...)
				return message, nil
			}
		}
	}
}

func canonicalCIDRoute(message syscall.NetlinkMessage) ([]byte, uint32, error) {
	if len(message.Data) < unix.SizeofRtMsg {
		return nil, 0, errors.New("quic: short route lookup response")
	}
	attributes, err := syscall.ParseNetlinkRouteAttr(&message)
	if err != nil {
		return nil, 0, err
	}
	stable := make([]syscall.NetlinkRouteAttr, 0, len(attributes))
	var outputIf uint32
	for _, attribute := range attributes {
		if attribute.Attr.Type == unix.RTA_CACHEINFO || attribute.Attr.Type == unix.RTA_EXPIRES {
			continue
		}
		if attribute.Attr.Type == unix.RTA_OIF && len(attribute.Value) == 4 {
			outputIf = binary.NativeEndian.Uint32(attribute.Value)
		}
		stable = append(stable, syscall.NetlinkRouteAttr{
			Attr: attribute.Attr, Value: append([]byte(nil), attribute.Value...),
		})
	}
	sort.Slice(stable, func(i, j int) bool {
		if stable[i].Attr.Type != stable[j].Attr.Type {
			return stable[i].Attr.Type < stable[j].Attr.Type
		}
		return bytes.Compare(stable[i].Value, stable[j].Value) < 0
	})
	var canonical bytes.Buffer
	canonical.Write(message.Data[:unix.SizeofRtMsg])
	for _, attribute := range stable {
		var header [6]byte
		binary.NativeEndian.PutUint16(header[0:2], attribute.Attr.Type)
		binary.NativeEndian.PutUint32(header[2:6], uint32(len(attribute.Value)))
		canonical.Write(header[:])
		canonical.Write(attribute.Value)
	}
	return canonical.Bytes(), outputIf, nil
}

func selectedCIDInterface(outputIf uint32, source net.IP) (*net.Interface, error) {
	if outputIf != 0 {
		iface, err := net.InterfaceByIndex(int(outputIf))
		if err != nil {
			return nil, err
		}
		assigned, err := cidInterfaceHasAddress(iface, source)
		if err != nil || !assigned {
			return nil, errors.Join(errors.New("quic: selected source is not assigned to the route interface"), err)
		}
		return iface, nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for index := range interfaces {
		assigned, addressErr := cidInterfaceHasAddress(&interfaces[index], source)
		if addressErr != nil {
			return nil, addressErr
		}
		if assigned {
			return &interfaces[index], nil
		}
	}
	return nil, fmt.Errorf("quic: selected source %s is not assigned", source)
}

func cidInterfaceHasAddress(iface *net.Interface, source net.IP) (bool, error) {
	addresses, err := iface.Addrs()
	if err != nil {
		return false, err
	}
	for _, address := range addresses {
		ip, _, parseErr := net.ParseCIDR(address.String())
		if parseErr == nil && ip.Equal(source) {
			return true, nil
		}
	}
	return false, nil
}
