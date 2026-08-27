//go:build linux && amd64 && rendr_experimental_tcprepair

package tcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"golang.org/x/sys/unix"
)

const (
	pathRefreshDebounce     = 25 * time.Millisecond
	pathRefreshPollInterval = 100 * time.Millisecond
	pathRefreshQueryTimeout = time.Second
	pathRefreshOpenTimeout  = 2 * time.Second
)

var (
	errRouteSnapshotUnstable       = errors.New("tcp: route/source snapshot changed while observed")
	errReplacementRouteUnavailable = errors.New("tcp: replacement route is not currently usable")
)

type linuxPathRefreshMonitor struct {
	fd   int
	flow tcpRouteFlowKey
	path *PathConn

	ctx         context.Context
	cancel      context.CancelFunc
	stopOnce    sync.Once
	done        chan struct{}
	seq         uint32
	baselineMu  sync.RWMutex
	baseline    routeObservation
	published   [sha256.Size]byte
	unavailable bool
}

type tcpRouteFlowKey struct {
	local       netip.AddrPort
	remote      netip.AddrPort
	uid         uint32
	tos         uint8
	mark        uint32
	boundDevice string
}

type routeObservation struct {
	migration [sha256.Size]byte
	factual   [sha256.Size]byte
	usable    bool
}

type routeSelection struct {
	migration []byte
	factual   []byte
	outputIf  uint32
	usable    bool
}

func newPathRefreshMonitor(parent context.Context, path *PathConn) (pathRefreshMonitor, error) {
	if path == nil || path.endpoint == nil || path.refreshEmitter == nil || path.refreshState == nil {
		return nil, errors.New("tcp: route/source refresh monitor has no owned endpoint")
	}
	conn, ok := path.endpoint.currentTCPConn()
	if !ok {
		return nil, errors.New("tcp: route/source refresh monitor requires an active TCP socket")
	}
	flow, err := tcpRouteFlowKeyForConn(conn)
	if err != nil {
		return nil, err
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	openCtx, openCancel := context.WithTimeout(ctx, pathRefreshOpenTimeout)
	fd, err := openTCPRouteNetlink(openCtx, conn)
	openCancel()
	if err != nil {
		cancel()
		return nil, err
	}
	monitor := &linuxPathRefreshMonitor{
		fd: fd, flow: flow, path: path,
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
	}
	queryCtx, queryCancel := context.WithTimeout(ctx, pathRefreshQueryTimeout)
	monitor.baseline, err = monitor.stableObservation(queryCtx)
	queryCancel()
	if err == nil && !monitor.baseline.usable {
		err = errors.New("tcp: replacement route is not currently usable")
	}
	if err != nil {
		cancel()
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tcp: establish route/source refresh baseline: %w", err)
	}
	if _, err := path.refreshState.Update(monitor.baseline.migration); err != nil {
		cancel()
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tcp: publish route/source refresh baseline: %w", err)
	}
	go monitor.loop()
	return monitor, nil
}

func (m *linuxPathRefreshMonitor) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(m.cancel)
}

func (m *linuxPathRefreshMonitor) Done() <-chan struct{} {
	if m == nil || m.done == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return m.done
}

func (m *linuxPathRefreshMonitor) Commit(digest [32]byte) {
	if m == nil || digest == ([32]byte{}) {
		return
	}
	m.baselineMu.Lock()
	m.baseline.migration = digest
	m.baseline.usable = true
	m.published = [sha256.Size]byte{}
	m.unavailable = false
	m.baselineMu.Unlock()
}

func (m *linuxPathRefreshMonitor) loop() {
	defer close(m.done)
	defer unix.Close(m.fd)
	pending := false
	var due time.Time
	for {
		if err := m.ctx.Err(); err != nil {
			return
		}
		timeout := pathRefreshPollInterval
		if pending {
			remaining := time.Until(due)
			if remaining <= 0 {
				queryCtx, cancel := context.WithTimeout(m.ctx, pathRefreshQueryTimeout)
				observation, err := m.stableObservation(queryCtx)
				cancel()
				if err == nil {
					pending = false
					if !observation.usable {
						source, changed, updateErr := m.path.refreshState.MarkUnavailable()
						if updateErr == nil {
							m.baselineMu.Lock()
							m.unavailable = true
							if changed {
								m.published = [sha256.Size]byte{}
							}
							m.baselineMu.Unlock()
							if changed {
								m.path.publishRefresh(leafmobility.RefreshReasonRouteSourceUnavailable, source)
							}
						}
					} else if source, updateErr := m.path.refreshState.Update(observation.migration); updateErr == nil {
						m.baselineMu.Lock()
						changed := observation.migration != m.baseline.migration
						wasUnavailable := m.unavailable
						hadPublishedChange := m.published != ([sha256.Size]byte{})
						m.unavailable = false
						reason := leafmobility.RefreshReasonInvalid
						if changed && (observation.migration != m.published || wasUnavailable) {
							m.published = observation.migration
							reason = leafmobility.RefreshReasonRouteSourceChanged
						} else if !changed && (wasUnavailable || hadPublishedChange) {
							m.published = [sha256.Size]byte{}
							reason = leafmobility.RefreshReasonRouteSourceRestored
						} else if !changed {
							m.published = [sha256.Size]byte{}
						}
						m.baselineMu.Unlock()
						if reason != leafmobility.RefreshReasonInvalid {
							m.path.publishRefresh(reason, source)
						}
					}
				} else if errors.Is(err, errRouteSnapshotUnstable) {
					due = time.Now().Add(pathRefreshDebounce)
				} else if m.ctx.Err() != nil {
					return
				} else {
					// A failed query is not factual evidence. Keep the pending bit so
					// a transient netlink error cannot silently discard a real event.
					due = time.Now().Add(pathRefreshPollInterval)
				}
				continue
			}
			if remaining < timeout {
				timeout = remaining
			}
		}
		messages, truncated, err := pollNetlinkMessages(m.ctx, m.fd, timeout)
		if err != nil {
			if m.ctx.Err() != nil {
				return
			}
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			armPathRefresh(&pending, &due, time.Now())
			continue
		}
		if truncated || containsRouteRefreshNotification(messages, 0) {
			armPathRefresh(&pending, &due, time.Now())
		}
	}
}

func armPathRefresh(pending *bool, due *time.Time, now time.Time) {
	if pending == nil || due == nil || *pending {
		return
	}
	*pending = true
	*due = now.Add(pathRefreshDebounce)
}

func (m *linuxPathRefreshMonitor) stableObservation(ctx context.Context) (routeObservation, error) {
	var previous routeObservation
	havePrevious := false
	for attempt := 0; attempt < 4; attempt++ {
		observation, unstable, err := m.observe(ctx)
		if err != nil {
			return routeObservation{}, err
		}
		if !unstable || havePrevious && observation == previous {
			return observation, nil
		}
		previous = observation
		havePrevious = true
		if err := waitContext(ctx, pathRefreshDebounce); err != nil {
			return routeObservation{}, err
		}
	}
	return routeObservation{}, errRouteSnapshotUnstable
}

func (m *linuxPathRefreshMonitor) observe(ctx context.Context) (routeObservation, bool, error) {
	addressState, present, addressNotifications, err := querySourceAddressState(ctx, m.fd, m.nextSequence(), m.flow.local.Addr())
	if err != nil {
		return routeObservation{}, addressNotifications, err
	}
	selection, routeNotifications, routeErr := queryRouteState(ctx, m.fd, m.nextSequence(), m.flow)
	if routeErr != nil {
		if !routeUnavailableError(routeErr, present) {
			return routeObservation{}, addressNotifications || routeNotifications, routeErr
		}
		selection = routeSelection{migration: []byte("unavailable"), factual: []byte(routeErr.Error())}
	}
	var linkState []byte
	linkUsable := true
	linkNotifications := false
	if selection.outputIf != 0 {
		linkState, linkUsable, linkNotifications, err = querySelectedLinkState(ctx, m.fd, m.nextSequence(), selection.outputIf)
		if err != nil {
			return routeObservation{}, addressNotifications || routeNotifications || linkNotifications, err
		}
	}
	drained, truncated, drainErr := drainNetlinkMessages(m.fd)
	if drainErr != nil && !errors.Is(drainErr, unix.EAGAIN) {
		return routeObservation{}, true, drainErr
	}
	unstable := addressNotifications || routeNotifications || linkNotifications || truncated || containsRouteRefreshNotification(drained, 0)
	migrationHash := sha256.New()
	migrationHash.Write([]byte("rendr-tcp-route-source-migration-v2\x00"))
	migrationHash.Write(m.flow.local.Addr().AsSlice())
	migrationHash.Write(m.flow.remote.Addr().AsSlice())
	if present {
		migrationHash.Write([]byte{1})
	} else {
		migrationHash.Write([]byte{0})
	}
	writeLengthPrefixed(migrationHash, addressState)
	writeLengthPrefixed(migrationHash, selection.migration)
	writeLengthPrefixed(migrationHash, linkState)
	factualHash := sha256.New()
	factualHash.Write([]byte("rendr-tcp-route-source-factual-v2\x00"))
	writeLengthPrefixed(factualHash, selection.factual)
	writeLengthPrefixed(factualHash, addressState)
	writeLengthPrefixed(factualHash, linkState)
	observation := routeObservation{usable: selection.usable && linkUsable}
	copy(observation.migration[:], migrationHash.Sum(nil))
	copy(observation.factual[:], factualHash.Sum(nil))
	return observation, unstable, nil
}

func (m *linuxPathRefreshMonitor) nextSequence() uint32 {
	m.seq++
	if m.seq == 0 {
		m.seq++
	}
	return m.seq
}

func tcpRouteFlowKeyForConn(conn *net.TCPConn) (tcpRouteFlowKey, error) {
	var key tcpRouteFlowKey
	local, localOK := conn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := conn.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK || local == nil || remote == nil || local.Zone != "" || remote.Zone != "" {
		return key, errors.New("tcp: route/source refresh requires unzoned TCP addresses")
	}
	localIP, localOK := netip.AddrFromSlice(local.IP)
	remoteIP, remoteOK := netip.AddrFromSlice(remote.IP)
	if !localOK || !remoteOK {
		return key, errors.New("tcp: route/source refresh has invalid TCP addresses")
	}
	localIP = localIP.Unmap()
	remoteIP = remoteIP.Unmap()
	if localIP.Is4() != remoteIP.Is4() || localIP.IsUnspecified() || remoteIP.IsUnspecified() {
		return key, errors.New("tcp: route/source refresh has incompatible TCP addresses")
	}
	key.local = netip.AddrPortFrom(localIP, uint16(local.Port))
	key.remote = netip.AddrPortFrom(remoteIP, uint16(remote.Port))
	raw, err := conn.SyscallConn()
	if err != nil {
		return tcpRouteFlowKey{}, fmt.Errorf("tcp: access route/source socket: %w", err)
	}
	var metadataErr error
	controlErr := raw.Control(func(fd uintptr) {
		var state unix.Stat_t
		if metadataErr = unix.Fstat(int(fd), &state); metadataErr != nil {
			return
		}
		key.uid = state.Uid
		level, option := unix.IPPROTO_IPV6, unix.IPV6_TCLASS
		if localIP.Is4() {
			level, option = unix.IPPROTO_IP, unix.IP_TOS
		}
		tos, optionErr := unix.GetsockoptInt(int(fd), level, option)
		if optionErr != nil {
			metadataErr = optionErr
			return
		}
		mark, optionErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
		if optionErr != nil {
			metadataErr = optionErr
			return
		}
		device, optionErr := unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		if optionErr != nil {
			metadataErr = optionErr
			return
		}
		key.tos = uint8(tos)
		key.mark = uint32(mark)
		key.boundDevice = device
	})
	if err := errors.Join(controlErr, metadataErr); err != nil {
		return tcpRouteFlowKey{}, fmt.Errorf("tcp: read route/source socket policy: %w", err)
	}
	if key.tos != 0 || key.mark != 0 || key.boundDevice != "" {
		return tcpRouteFlowKey{}, fmt.Errorf("tcp: route/source socket policy is not restorable: tos=%d mark=%d device=%q",
			key.tos, key.mark, key.boundDevice)
	}
	return key, nil
}

func captureTCPRouteObservation(
	ctx context.Context,
	conn *net.TCPConn,
) (tcpRouteFlowKey, routeObservation, error) {
	flow, err := tcpRouteFlowKeyForConn(conn)
	if err != nil {
		return tcpRouteFlowKey{}, routeObservation{}, err
	}
	observation, err := observeTCPRouteFlow(ctx, conn, flow)
	return flow, observation, err
}

func observeTCPRouteFlow(
	ctx context.Context,
	conn *net.TCPConn,
	flow tcpRouteFlowKey,
) (routeObservation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	fd, err := openTCPRouteNetlink(ctx, conn)
	if err != nil {
		return routeObservation{}, err
	}
	defer unix.Close(fd)
	observer := &linuxPathRefreshMonitor{fd: fd, flow: flow, ctx: ctx}
	observation, err := observer.stableObservation(ctx)
	if err != nil {
		return routeObservation{}, err
	}
	if !observation.usable {
		return routeObservation{}, errReplacementRouteUnavailable
	}
	return observation, nil
}

type routeNetlinkOpenResult struct {
	fd  int
	err error
}

func openTCPRouteNetlink(ctx context.Context, conn *net.TCPConn) (int, error) {
	ops := systemRepairNamespaceOps{}
	targetFD, err := ops.socketNamespaceFD(conn)
	if err != nil {
		return -1, err
	}
	result := make(chan routeNetlinkOpenResult)
	go openTCPRouteNetlinkWorker(ctx, targetFD, ops, result)
	select {
	case opened := <-result:
		return opened.fd, opened.err
	case <-ctx.Done():
		return -1, context.Cause(ctx)
	}
}

func openTCPRouteNetlinkWorker(
	ctx context.Context,
	targetFD int,
	ops systemRepairNamespaceOps,
	result chan<- routeNetlinkOpenResult,
) {
	runtime.LockOSThread()
	restoreRequired := false
	restoreSucceeded := false
	originalFD := -1
	defer func() {
		_ = ops.closeFD(targetFD)
		_ = ops.closeFD(originalFD)
		if !restoreRequired || restoreSucceeded {
			runtime.UnlockOSThread()
		}
	}()
	send := func(opened routeNetlinkOpenResult) {
		select {
		case result <- opened:
		case <-ctx.Done():
			if opened.fd >= 0 {
				_ = unix.Close(opened.fd)
			}
		}
	}

	originalFD, err := ops.openCurrentNamespace()
	if err != nil {
		send(routeNetlinkOpenResult{fd: -1, err: err})
		return
	}
	same, err := ops.sameNamespace(targetFD, originalFD)
	if err == nil && !same {
		err = ops.setNamespace(targetFD)
		if err == nil {
			restoreRequired = true
		}
	}
	if err != nil {
		send(routeNetlinkOpenResult{fd: -1, err: err})
		return
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err == nil {
		err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
	}
	if err == nil {
		err = joinTCPRouteNetlinkGroups(fd, unix.SetsockoptInt)
	}
	if err == nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	}
	if restoreRequired {
		restoreErr := ops.setNamespace(originalFD)
		restoreSucceeded = restoreErr == nil
		if restoreErr != nil {
			err = errors.Join(err, restoreErr)
		}
	}
	if err != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		send(routeNetlinkOpenResult{fd: -1, err: err})
		return
	}
	send(routeNetlinkOpenResult{fd: fd})
}

func joinTCPRouteNetlinkGroups(fd int, setMembership func(int, int, int, int) error) error {
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

func queryRouteState(
	ctx context.Context,
	fd int,
	sequence uint32,
	flow tcpRouteFlowKey,
) (routeSelection, bool, error) {
	family, bits := byte(unix.AF_INET6), byte(128)
	if flow.remote.Addr().Is4() {
		family, bits = unix.AF_INET, 32
	}
	body := make([]byte, unix.SizeofRtMsg)
	body[0], body[1], body[2], body[3] = family, bits, bits, flow.tos
	body[4] = unix.RT_TABLE_UNSPEC
	var uid, mark [4]byte
	var sourcePort, destinationPort [2]byte
	binary.NativeEndian.PutUint32(uid[:], flow.uid)
	binary.NativeEndian.PutUint32(mark[:], flow.mark)
	binary.BigEndian.PutUint16(sourcePort[:], flow.local.Port())
	binary.BigEndian.PutUint16(destinationPort[:], flow.remote.Port())
	request := encodeNetlinkRequest(unix.RTM_GETROUTE, unix.NLM_F_REQUEST, sequence, body,
		netlinkAttribute(unix.RTA_DST, flow.remote.Addr().AsSlice()),
		netlinkAttribute(unix.RTA_SRC, flow.local.Addr().AsSlice()),
		netlinkAttribute(unix.RTA_UID, uid[:]),
		netlinkAttribute(unix.RTA_IP_PROTO, []byte{unix.IPPROTO_TCP}),
		netlinkAttribute(unix.RTA_SPORT, sourcePort[:]),
		netlinkAttribute(unix.RTA_DPORT, destinationPort[:]),
		netlinkAttribute(unix.RTA_MARK, mark[:]),
	)
	messages, notifications, err := exchangeNetlink(ctx, fd, sequence, request, false)
	if err != nil {
		return routeSelection{}, notifications, err
	}
	if len(messages) != 1 || messages[0].Header.Type != unix.RTM_NEWROUTE {
		return routeSelection{}, notifications, errors.New("tcp: route lookup returned no canonical route")
	}
	selection, err := canonicalRouteMessage(messages[0])
	return selection, notifications, err
}

func querySourceAddressState(
	ctx context.Context,
	fd int,
	sequence uint32,
	local netip.Addr,
) ([]byte, bool, bool, error) {
	family := byte(unix.AF_INET6)
	if local.Is4() {
		family = unix.AF_INET
	}
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = family
	request := encodeNetlinkRequest(unix.RTM_GETADDR, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, sequence, body)
	messages, notifications, err := exchangeNetlink(ctx, fd, sequence, request, true)
	if err != nil {
		return nil, false, notifications, err
	}
	indexes := make([]uint32, 0, 1)
	for _, message := range messages {
		index, matches, parseErr := canonicalAddressMessage(message, local)
		if parseErr != nil {
			return nil, false, notifications, parseErr
		}
		if matches {
			indexes = append(indexes, index)
		}
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	var canonical bytes.Buffer
	for _, index := range indexes {
		var encoded [4]byte
		binary.NativeEndian.PutUint32(encoded[:], index)
		canonical.Write(encoded[:])
	}
	return canonical.Bytes(), len(indexes) != 0, notifications, nil
}

func querySelectedLinkState(
	ctx context.Context,
	fd int,
	sequence uint32,
	index uint32,
) ([]byte, bool, bool, error) {
	body := make([]byte, unix.SizeofIfInfomsg)
	body[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(body[4:8], index)
	request := encodeNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_REQUEST, sequence, body)
	messages, notifications, err := exchangeNetlink(ctx, fd, sequence, request, false)
	if err != nil {
		return nil, false, notifications, err
	}
	if len(messages) != 1 || messages[0].Header.Type != unix.RTM_NEWLINK || len(messages[0].Data) < unix.SizeofIfInfomsg {
		return nil, false, notifications, errors.New("tcp: selected link lookup returned no canonical link")
	}
	message := messages[0]
	attributes, err := syscall.ParseNetlinkRouteAttr(&message)
	if err != nil {
		return nil, false, notifications, fmt.Errorf("tcp: parse selected link attributes: %w", err)
	}
	flags := binary.NativeEndian.Uint32(message.Data[8:12])
	normalizedFlags := flags & uint32(unix.IFF_UP|unix.IFF_RUNNING|unix.IFF_LOWER_UP|unix.IFF_DORMANT)
	operState := byte(0)
	carrier := byte(0xff)
	master := uint32(0)
	for _, attribute := range attributes {
		switch attribute.Attr.Type {
		case unix.IFLA_OPERSTATE:
			if len(attribute.Value) != 0 {
				operState = attribute.Value[0]
			}
		case unix.IFLA_CARRIER:
			if len(attribute.Value) != 0 {
				carrier = attribute.Value[0]
			}
		case unix.IFLA_MASTER:
			if len(attribute.Value) == 4 {
				master = binary.NativeEndian.Uint32(attribute.Value)
			}
		}
	}
	state := make([]byte, 14)
	binary.NativeEndian.PutUint32(state[0:4], index)
	binary.NativeEndian.PutUint32(state[4:8], normalizedFlags)
	binary.NativeEndian.PutUint32(state[8:12], master)
	state[12] = operState
	state[13] = carrier
	usable := normalizedFlags&unix.IFF_UP != 0 && carrier != 0 && operState != 1 && operState != 2 && operState != 3
	return state, usable, notifications, nil
}

func canonicalRouteMessage(message syscall.NetlinkMessage) (routeSelection, error) {
	if len(message.Data) < unix.SizeofRtMsg {
		return routeSelection{}, errors.New("tcp: short route response")
	}
	attributes, err := syscall.ParseNetlinkRouteAttr(&message)
	if err != nil {
		return routeSelection{}, fmt.Errorf("tcp: parse route attributes: %w", err)
	}
	factual := make([]syscall.NetlinkRouteAttr, 0, len(attributes))
	migration := make([]syscall.NetlinkRouteAttr, 0, len(attributes))
	var outputIf uint32
	for _, attribute := range attributes {
		if attribute.Attr.Type == unix.RTA_CACHEINFO || attribute.Attr.Type == unix.RTA_EXPIRES {
			continue
		}
		factual = append(factual, attribute)
		switch attribute.Attr.Type {
		case unix.RTA_OIF:
			if len(attribute.Value) == 4 {
				outputIf = binary.NativeEndian.Uint32(attribute.Value)
			}
			migration = append(migration, attribute)
		case unix.RTA_GATEWAY, unix.RTA_VIA, unix.RTA_MULTIPATH, unix.RTA_TABLE,
			unix.RTA_NEWDST, unix.RTA_ENCAP_TYPE, unix.RTA_ENCAP, 0x1e: // RTA_NH_ID
			migration = append(migration, attribute)
		}
	}
	sortNetlinkAttributes(factual)
	sortNetlinkAttributes(migration)
	var factualState, migrationState bytes.Buffer
	factualState.Write(message.Data[:unix.SizeofRtMsg])
	writeCanonicalAttributes(&factualState, factual)
	// Family, table, scope and route type determine the selected forwarding
	// domain. Protocol, metrics and mutable cache flags are factual diagnostics
	// but do not by themselves justify endpoint replacement.
	migrationState.Write([]byte{message.Data[0], message.Data[4], message.Data[6], message.Data[7]})
	writeCanonicalAttributes(&migrationState, migration)
	routeType := message.Data[7]
	return routeSelection{
		migration: migrationState.Bytes(), factual: factualState.Bytes(), outputIf: outputIf,
		usable: routeType == unix.RTN_UNICAST || routeType == unix.RTN_LOCAL,
	}, nil
}

func canonicalAddressMessage(message syscall.NetlinkMessage, local netip.Addr) (uint32, bool, error) {
	if message.Header.Type != unix.RTM_NEWADDR || len(message.Data) < unix.SizeofIfAddrmsg {
		return 0, false, nil
	}
	attributes, err := syscall.ParseNetlinkRouteAttr(&message)
	if err != nil {
		return 0, false, fmt.Errorf("tcp: parse address attributes: %w", err)
	}
	matched := false
	for _, attribute := range attributes {
		if (attribute.Attr.Type == unix.IFA_LOCAL || attribute.Attr.Type == unix.IFA_ADDRESS) &&
			bytes.Equal(attribute.Value, local.AsSlice()) {
			matched = true
		}
	}
	if !matched {
		return 0, false, nil
	}
	return binary.NativeEndian.Uint32(message.Data[4:8]), true, nil
}

func exchangeNetlink(
	ctx context.Context,
	fd int,
	sequence uint32,
	request []byte,
	dump bool,
) ([]syscall.NetlinkMessage, bool, error) {
	if err := sendNetlink(ctx, fd, request); err != nil {
		return nil, false, err
	}
	var responses []syscall.NetlinkMessage
	notifications := false
	for {
		messages, truncated, err := pollNetlinkMessages(ctx, fd, pathRefreshPollInterval)
		if err != nil {
			return nil, notifications, err
		}
		if truncated {
			return nil, true, errRouteSnapshotUnstable
		}
		complete, unstable, batchErr := consumeNetlinkBatch(messages, sequence, dump, &responses, &notifications)
		if unstable {
			return nil, true, errRouteSnapshotUnstable
		}
		if batchErr != nil {
			return nil, notifications, batchErr
		}
		if complete {
			return responses, notifications, nil
		}
	}
}

func consumeNetlinkBatch(
	messages []syscall.NetlinkMessage,
	sequence uint32,
	dump bool,
	responses *[]syscall.NetlinkMessage,
	notifications *bool,
) (complete, unstable bool, err error) {
	for _, message := range messages {
		if message.Header.Seq != sequence {
			*notifications = *notifications || isRouteRefreshType(message.Header.Type)
			continue
		}
		switch message.Header.Type {
		case unix.NLMSG_ERROR:
			complete = !dump
			if len(message.Data) < 4 {
				if err == nil {
					err = errors.New("tcp: short netlink error")
				}
				continue
			}
			if code := int32(binary.NativeEndian.Uint32(message.Data[:4])); code != 0 && err == nil {
				err = syscall.Errno(-code)
			}
		case unix.NLMSG_DONE:
			complete = true
			unstable = unstable || message.Header.Flags&unix.NLM_F_DUMP_INTR != 0
		case unix.NLMSG_OVERRUN:
			complete = true
			unstable = true
		default:
			*responses = append(*responses, message)
			if !dump {
				complete = true
			}
		}
	}
	return complete, unstable, err
}

func sendNetlink(ctx context.Context, fd int, request []byte) error {
	for {
		err := unix.Sendto(fd, request, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return err
		}
		if err := waitContext(ctx, time.Millisecond); err != nil {
			return err
		}
	}
}

func pollNetlinkMessages(ctx context.Context, fd int, timeout time.Duration) ([]syscall.NetlinkMessage, bool, error) {
	if timeout < 0 {
		timeout = 0
	}
	milliseconds := int(timeout / time.Millisecond)
	if timeout > 0 && milliseconds == 0 {
		milliseconds = 1
	}
	if milliseconds > int(pathRefreshPollInterval/time.Millisecond) {
		milliseconds = int(pathRefreshPollInterval / time.Millisecond)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, context.Cause(ctx)
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP}}
		ready, err := unix.Poll(poll, milliseconds)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, false, err
		}
		if ready == 0 {
			return nil, false, nil
		}
		if poll[0].Revents&unix.POLLNVAL != 0 {
			return nil, false, unix.EBADF
		}
		return drainNetlinkMessages(fd)
	}
}

func drainNetlinkMessages(fd int) ([]syscall.NetlinkMessage, bool, error) {
	buffer := make([]byte, 1<<16)
	var messages []syscall.NetlinkMessage
	truncated := false
	for {
		n, _, flags, sender, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return messages, truncated, nil
			}
			if errors.Is(err, unix.ENOBUFS) {
				return messages, true, nil
			}
			return messages, truncated, err
		}
		if n == 0 {
			return messages, truncated, nil
		}
		netlinkSender, ok := sender.(*unix.SockaddrNetlink)
		if !ok || netlinkSender.Pid != 0 {
			return messages, true, errors.New("tcp: netlink message did not originate from the kernel")
		}
		truncated = truncated || flags&unix.MSG_TRUNC != 0
		parsed, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return messages, true, err
		}
		messages = appendOwnedNetlinkMessages(messages, parsed)
	}
}

func appendOwnedNetlinkMessages(destination, source []syscall.NetlinkMessage) []syscall.NetlinkMessage {
	for _, message := range source {
		message.Data = append([]byte(nil), message.Data...)
		destination = append(destination, message)
	}
	return destination
}

func containsRouteRefreshNotification(messages []syscall.NetlinkMessage, exceptSequence uint32) bool {
	for _, message := range messages {
		if (exceptSequence == 0 || message.Header.Seq != exceptSequence) && isRouteRefreshType(message.Header.Type) {
			return true
		}
	}
	return false
}

func isRouteRefreshType(messageType uint16) bool {
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

func encodeNetlinkRequest(
	messageType uint16,
	flags uint16,
	sequence uint32,
	body []byte,
	attributes ...[]byte,
) []byte {
	length := unix.SizeofNlMsghdr + len(body)
	for _, attribute := range attributes {
		length += len(attribute)
	}
	request := make([]byte, length)
	binary.NativeEndian.PutUint32(request[0:4], uint32(length))
	binary.NativeEndian.PutUint16(request[4:6], messageType)
	binary.NativeEndian.PutUint16(request[6:8], flags)
	binary.NativeEndian.PutUint32(request[8:12], sequence)
	copy(request[unix.SizeofNlMsghdr:], body)
	offset := unix.SizeofNlMsghdr + len(body)
	for _, attribute := range attributes {
		copy(request[offset:], attribute)
		offset += len(attribute)
	}
	return request
}

func netlinkAttribute(attributeType uint16, value []byte) []byte {
	length := 4 + len(value)
	aligned := (length + 3) &^ 3
	attribute := make([]byte, aligned)
	binary.NativeEndian.PutUint16(attribute[0:2], uint16(length))
	binary.NativeEndian.PutUint16(attribute[2:4], attributeType)
	copy(attribute[4:], value)
	return attribute
}

func sortNetlinkAttributes(attributes []syscall.NetlinkRouteAttr) {
	sort.Slice(attributes, func(i, j int) bool {
		if attributes[i].Attr.Type != attributes[j].Attr.Type {
			return attributes[i].Attr.Type < attributes[j].Attr.Type
		}
		return bytes.Compare(attributes[i].Value, attributes[j].Value) < 0
	})
}

func writeCanonicalAttributes(buffer *bytes.Buffer, attributes []syscall.NetlinkRouteAttr) {
	for _, attribute := range attributes {
		var header [6]byte
		binary.NativeEndian.PutUint16(header[0:2], attribute.Attr.Type)
		binary.NativeEndian.PutUint32(header[2:6], uint32(len(attribute.Value)))
		buffer.Write(header[:])
		buffer.Write(attribute.Value)
	}
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeLengthPrefixed(writer byteWriter, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func routeUnavailableError(err error, sourcePresent bool) bool {
	return errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENETUNREACH) ||
		errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.EADDRNOTAVAIL) ||
		errors.Is(err, unix.ENODEV) || (!sourcePresent && errors.Is(err, unix.EINVAL))
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
