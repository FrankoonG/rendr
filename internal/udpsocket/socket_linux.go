//go:build linux

package udpsocket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	quic "github.com/FrankoonG/quic-go"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	udpSegmentDataSize = 2
	udpGRODataSize     = 4
	maxReceiveBatch    = 64
	maxReceiveIovecs   = 256
	maxControlBytes    = 256
	maxSourceAddresses = 64
)

type platformState struct {
	send linuxSendState
	recv linuxReceiveState

	oobScratch [maxControlBytes]byte
	gsoControl [maxControlBytes]byte
	gsoPayload []byte
}

type rawSockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

type rawSockaddrInet6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

type rawSocketAddress struct {
	storage unix.RawSockaddrAny
	length  uint32
}

type linuxMMsgHdr struct {
	header unix.Msghdr
	length uint32
	_      uint32
}

type receiveAddressKey struct {
	family uint16
	port   uint16
	scope  uint32
	addr   [16]byte
}

type linuxReceiveState struct {
	mu        sync.Mutex
	raw       syscall.RawConn
	conn      *net.UDPConn
	bound     func(uintptr) bool
	family    int
	messages  []ipv4.Message
	requested int
	n         int
	errno     syscall.Errno

	headers   [maxReceiveBatch]linuxMMsgHdr
	iovecs    [maxReceiveIovecs]unix.Iovec
	addresses [maxReceiveBatch]unix.RawSockaddrAny
	cache     map[receiveAddressKey]*net.UDPAddr

	gro        bool
	groPayload []byte
	groOOB     [maxControlBytes]byte
	groHeader  linuxMMsgHdr
	groIovec   unix.Iovec
	groAddress unix.RawSockaddrAny
	groBound   func(uintptr) bool
	queued     groQueue
	oneBuffers [1][]byte
	oneMessage [1]ipv4.Message
}

type groQueue struct {
	valid       bool
	payload     []byte
	oobN        int
	flags       int
	address     *net.UDPAddr
	segmentSize int
	offset      int
}

func (r *linuxReceiveState) init(raw syscall.RawConn, conn *net.UDPConn) {
	r.raw = raw
	r.conn = conn
	r.family = socketFamily(conn)
	r.bound = r.recvmmsg
	r.groBound = r.recvGRO
	r.cache = make(map[receiveAddressKey]*net.UDPAddr, 4)
}

func (r *linuxReceiveState) enableGRO() {
	var setErr error
	if err := r.raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); err != nil || setErr != nil {
		return
	}
	r.groPayload = make([]byte, MaxGSOSuperPacket)
	r.gro = true
}

func (r *linuxReceiveState) readBatch(messages []ipv4.Message, flags int) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	if len(messages) > maxReceiveBatch {
		messages = messages[:maxReceiveBatch]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int
	var err error
	if r.gro {
		n, err = r.readGROBatch(messages, flags)
	} else {
		n, err = r.readOrdinaryBatch(messages, flags)
	}
	return n, r.wrapError(err)
}

func (r *linuxReceiveState) readOne(payload, oob []byte) (int, int, int, *net.UDPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.oneBuffers[0] = payload
	r.oneMessage[0] = ipv4.Message{Buffers: r.oneBuffers[:], OOB: oob}
	var (
		n   int
		err error
	)
	if r.gro {
		n, err = r.readGROBatch(r.oneMessage[:], 0)
	} else {
		n, err = r.readOrdinaryBatch(r.oneMessage[:], 0)
	}
	message := r.oneMessage[0]
	r.oneBuffers[0], r.oneMessage[0] = nil, ipv4.Message{}
	if n == 0 || err != nil {
		return 0, 0, 0, nil, r.wrapError(err)
	}
	address, _ := message.Addr.(*net.UDPAddr)
	return message.N, message.NN, message.Flags, address, nil
}

func (r *linuxReceiveState) readOrdinaryBatch(messages []ipv4.Message, flags int) (int, error) {
	iovecIndex := 0
	for index := range messages {
		if len(messages[index].Buffers) > maxReceiveIovecs-iovecIndex {
			return 0, unix.EINVAL
		}
		header := &r.headers[index]
		*header = linuxMMsgHdr{}
		firstIovec := iovecIndex
		for _, buffer := range messages[index].Buffers {
			r.iovecs[iovecIndex] = unix.Iovec{}
			if len(buffer) != 0 {
				r.iovecs[iovecIndex].Base = &buffer[0]
				r.iovecs[iovecIndex].SetLen(len(buffer))
			}
			iovecIndex++
		}
		if iovecIndex != firstIovec {
			header.header.Iov = &r.iovecs[firstIovec]
			header.header.SetIovlen(iovecIndex - firstIovec)
		}
		if len(messages[index].OOB) != 0 {
			header.header.Control = &messages[index].OOB[0]
			header.header.SetControllen(len(messages[index].OOB))
		}
		header.header.Name = (*byte)(unsafe.Pointer(&r.addresses[index]))
		header.header.Namelen = unix.SizeofSockaddrInet6
	}
	r.messages, r.requested, r.n, r.errno = messages, flags, 0, 0
	err := r.raw.Read(r.bound)
	r.messages = nil
	if err != nil {
		return r.n, err
	}
	if r.errno != 0 {
		return r.n, os.NewSyscallError("recvmmsg", r.errno)
	}
	for index := 0; index < r.n; index++ {
		header := &r.headers[index]
		messages[index].N = int(header.length)
		messages[index].NN = int(header.header.Controllen)
		messages[index].Flags = int(header.header.Flags)
		address, parseErr := r.internAddress(&r.addresses[index], header.header.Namelen)
		if parseErr != nil {
			return index, parseErr
		}
		messages[index].Addr = address
	}
	return r.n, nil
}

func (r *linuxReceiveState) recvmmsg(fd uintptr) bool {
	var n uintptr
	var errno syscall.Errno
	for {
		n, _, errno = syscall.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&r.headers[0])),
			uintptr(len(r.messages)),
			uintptr(r.requested),
			0,
			0,
		)
		if errno != unix.EINTR {
			break
		}
	}
	if errno != 0 {
		n = 0
	}
	r.n, r.errno = int(n), errno
	return errno != unix.EAGAIN
}

func (r *linuxReceiveState) readGROBatch(messages []ipv4.Message, flags int) (int, error) {
	if !r.queued.valid {
		if err := r.receiveGRO(flags); err != nil {
			return 0, err
		}
	}
	count := 0
	for count < len(messages) && (r.queued.offset < len(r.queued.payload) || len(r.queued.payload) == 0) {
		message := &messages[count]
		end := r.queued.offset + r.queued.segmentSize
		if end > len(r.queued.payload) {
			end = len(r.queued.payload)
		}
		segment := r.queued.payload[r.queued.offset:end]
		message.N = copyToBuffers(message.Buffers, segment)
		message.NN = copy(message.OOB, r.groOOB[:r.queued.oobN])
		message.Flags = r.queued.flags
		if message.N != len(segment) {
			message.Flags |= unix.MSG_TRUNC
		}
		if message.NN != r.queued.oobN {
			message.Flags |= unix.MSG_CTRUNC
		}
		message.Addr = r.queued.address
		r.queued.offset = end
		count++
	}
	if r.queued.offset == len(r.queued.payload) {
		r.queued = groQueue{}
	}
	return count, nil
}

func (r *linuxReceiveState) receiveGRO(flags int) error {
	r.groHeader = linuxMMsgHdr{}
	r.groIovec.Base = &r.groPayload[0]
	r.groIovec.SetLen(len(r.groPayload))
	r.groHeader.header.Iov = &r.groIovec
	r.groHeader.header.SetIovlen(1)
	r.groHeader.header.Control = &r.groOOB[0]
	r.groHeader.header.SetControllen(len(r.groOOB))
	r.groHeader.header.Name = (*byte)(unsafe.Pointer(&r.groAddress))
	r.groHeader.header.Namelen = unix.SizeofSockaddrInet6
	r.requested, r.n, r.errno = flags, 0, 0
	if err := r.raw.Read(r.groBound); err != nil {
		return err
	}
	if r.errno != 0 {
		return os.NewSyscallError("recvmsg", r.errno)
	}
	address, err := r.internAddress(&r.groAddress, r.groHeader.header.Namelen)
	if err != nil {
		return err
	}
	oobN := int(r.groHeader.header.Controllen)
	segmentSize, found, err := parseUDPGRO(r.groOOB[:oobN])
	if err != nil {
		return err
	}
	if !found {
		segmentSize = r.n
	}
	if segmentSize < 0 || segmentSize > r.n || (segmentSize == 0 && r.n != 0) {
		return unix.EINVAL
	}
	r.queued = groQueue{
		valid:   true,
		payload: r.groPayload[:r.n], oobN: oobN, flags: int(r.groHeader.header.Flags),
		address: address, segmentSize: segmentSize,
	}
	return nil
}

func copyToBuffers(buffers [][]byte, payload []byte) int {
	copied := 0
	for _, buffer := range buffers {
		copied += copy(buffer, payload[copied:])
		if copied == len(payload) {
			break
		}
	}
	return copied
}

func (r *linuxReceiveState) recvGRO(fd uintptr) bool {
	var n uintptr
	var errno syscall.Errno
	for {
		n, _, errno = syscall.Syscall6(
			unix.SYS_RECVMSG,
			fd,
			uintptr(unsafe.Pointer(&r.groHeader.header)),
			uintptr(r.requested),
			0,
			0,
			0,
		)
		if errno != unix.EINTR {
			break
		}
	}
	if errno != 0 {
		n = 0
	}
	r.n, r.errno = int(n), errno
	return errno != unix.EAGAIN
}

func (r *linuxReceiveState) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if r.conn == nil {
		return err
	}
	local, _ := r.conn.LocalAddr().(*net.UDPAddr)
	remote, _ := r.conn.RemoteAddr().(*net.UDPAddr)
	return &net.OpError{Op: "read", Net: local.Network(), Source: local, Addr: remote, Err: err}
}

func parseUDPGRO(oob []byte) (int, bool, error) {
	found, segmentSize := false, 0
	for offset := 0; offset < len(oob); {
		if len(oob)-offset < unix.CmsgLen(0) {
			return 0, false, unix.EINVAL
		}
		header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[offset]))
		messageBytes := int(header.Len)
		if messageBytes < unix.CmsgLen(0) || messageBytes > len(oob)-offset {
			return 0, false, unix.EINVAL
		}
		if header.Level == unix.IPPROTO_UDP && header.Type == unix.UDP_GRO {
			if found || messageBytes-unix.CmsgLen(0) != udpGRODataSize {
				return 0, false, unix.EINVAL
			}
			value := binary.NativeEndian.Uint32(oob[offset+unix.CmsgLen(0) : offset+messageBytes])
			if value == 0 || value > uint32(^uint16(0)) {
				return 0, false, unix.EINVAL
			}
			segmentSize, found = int(value), true
		}
		consumed := cmsgAlign(messageBytes)
		if consumed > len(oob)-offset {
			consumed = messageBytes
		}
		offset += consumed
	}
	return segmentSize, found, nil
}

func (r *linuxReceiveState) internAddress(raw *unix.RawSockaddrAny, length uint32) (*net.UDPAddr, error) {
	key, err := receiveKey(raw, length)
	if err != nil {
		return nil, err
	}
	if address := r.cache[key]; address != nil {
		return address, nil
	}
	address := &net.UDPAddr{Port: int(key.port)}
	if key.family == unix.AF_INET {
		address.IP = append(net.IP(nil), key.addr[:4]...)
	} else {
		address.IP = append(net.IP(nil), key.addr[:]...)
		if key.scope != 0 {
			address.Zone = strconv.FormatUint(uint64(key.scope), 10)
			if iface, lookupErr := net.InterfaceByIndex(int(key.scope)); lookupErr == nil {
				address.Zone = iface.Name
			}
		}
	}
	if len(r.cache) < maxSourceAddresses {
		r.cache[key] = address
	}
	return address, nil
}

func receiveKey(raw *unix.RawSockaddrAny, length uint32) (receiveAddressKey, error) {
	family := raw.Addr.Family
	key := receiveAddressKey{family: family}
	switch family {
	case unix.AF_INET:
		if length < unix.SizeofSockaddrInet4 {
			return receiveAddressKey{}, unix.EINVAL
		}
		address := (*rawSockaddrInet4)(unsafe.Pointer(raw))
		key.port = bits.ReverseBytes16(address.Port)
		copy(key.addr[:4], address.Addr[:])
	case unix.AF_INET6:
		if length < unix.SizeofSockaddrInet6 {
			return receiveAddressKey{}, unix.EINVAL
		}
		address := (*rawSockaddrInet6)(unsafe.Pointer(raw))
		key.port, key.scope = bits.ReverseBytes16(address.Port), address.ScopeID
		copy(key.addr[:], address.Addr[:])
	default:
		return receiveAddressKey{}, unix.EAFNOSUPPORT
	}
	return key, nil
}

type sendAddressKey struct {
	family uint16
	port   uint16
	scope  uint32
	addr   [16]byte
}

type linuxSendState struct {
	raw       syscall.RawConn
	conn      *net.UDPConn
	family    int
	connected bool
	bound     func(uintptr) bool
	batch     func([]ipv4.Message, int) (int, error)

	payload []byte
	oob     []byte
	address *rawSocketAddress
	n       int
	errno   syscall.Errno

	cachedKey     sendAddressKey
	cachedAddress rawSocketAddress
	cacheValid    bool
	pinnedOOB     []byte
}

func (s *Socket) initPlatform(selected policy, source *net.UDPAddr, pinSource bool) {
	raw, err := s.conn.SyscallConn()
	if err != nil {
		return
	}
	s.platform.send.init(raw, s.conn)
	if pinSource {
		s.platform.send.pinnedOOB = pinnedSourceControl(source)
	}
	s.writeMsg = s.platform.send.writeMsg
	s.platform.recv.init(raw, s.conn)
	if selected.gro {
		s.platform.recv.enableGRO()
	}
}

func (s *linuxSendState) init(raw syscall.RawConn, conn *net.UDPConn) {
	s.raw = raw
	s.conn = conn
	s.bound = s.sendmsg
	s.batch = ipv4.NewPacketConn(conn).WriteBatch
	s.connected = conn.RemoteAddr() != nil
	s.family = socketFamily(conn)
}

func socketFamily(conn *net.UDPConn) int {
	family := unix.AF_INET
	raw, err := conn.SyscallConn()
	if err != nil {
		return family
	}
	_ = raw.Control(func(fd uintptr) {
		if address, getErr := unix.Getsockname(int(fd)); getErr == nil {
			switch address.(type) {
			case *unix.SockaddrInet6:
				family = unix.AF_INET6
			}
		}
	})
	return family
}

func (s *linuxSendState) writeMsg(payload, oob []byte, address *net.UDPAddr) (int, int, error) {
	originalOOBBytes := len(oob)
	oob = appendPinnedSourceControl(oob, s.pinnedOOB)
	destination, err := s.destination(address)
	if err != nil {
		return 0, 0, err
	}
	s.payload, s.oob, s.address = payload, oob, destination
	s.n, s.errno = 0, 0
	err = s.raw.Write(s.bound)
	runtime.KeepAlive(payload)
	runtime.KeepAlive(oob)
	runtime.KeepAlive(destination)
	s.payload, s.oob, s.address = nil, nil, nil
	if err != nil {
		return s.n, 0, s.wrapError(address, err)
	}
	if s.errno != 0 {
		return s.n, 0, s.wrapError(address, os.NewSyscallError("sendmsg", s.errno))
	}
	return s.n, originalOOBBytes, nil
}

func appendPinnedSourceControl(oob, pinned []byte) []byte {
	if len(pinned) == 0 || hasPacketInfoControl(oob) {
		return oob
	}
	combined := make([]byte, 0, len(oob)+len(pinned))
	combined = append(combined, oob...)
	return append(combined, pinned...)
}

func pinnedSourceControl(source *net.UDPAddr) []byte {
	if source == nil || len(source.IP) == 0 || source.IP.IsUnspecified() {
		return nil
	}
	if v4 := source.IP.To4(); v4 != nil {
		message := ipv4.ControlMessage{Src: append(net.IP(nil), v4...)}
		if iface := interfaceForSource(source.IP); iface != nil {
			message.IfIndex = iface.Index
		}
		return message.Marshal()
	}
	if v6 := source.IP.To16(); v6 != nil {
		message := ipv6.ControlMessage{Src: append(net.IP(nil), v6...)}
		if source.Zone != "" {
			if iface, err := net.InterfaceByName(source.Zone); err == nil {
				message.IfIndex = iface.Index
			}
		} else if iface := interfaceForSource(source.IP); iface != nil {
			message.IfIndex = iface.Index
		}
		return message.Marshal()
	}
	return nil
}

func interfaceForSource(source net.IP) *net.Interface {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for index := range interfaces {
		addresses, addressErr := interfaces[index].Addrs()
		if addressErr != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && ip.Equal(source) {
				return &interfaces[index]
			}
		}
	}
	return nil
}

func hasPacketInfoControl(oob []byte) bool {
	for len(oob) > 0 {
		header, _, remainder, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return true
		}
		if (header.Level == unix.IPPROTO_IP && header.Type == unix.IP_PKTINFO) ||
			(header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_PKTINFO) {
			return true
		}
		oob = remainder
	}
	return false
}

func (s *linuxSendState) sendmsg(fd uintptr) bool {
	var iov unix.Iovec
	var header unix.Msghdr
	if len(s.payload) != 0 {
		iov.Base = &s.payload[0]
		iov.SetLen(len(s.payload))
		header.Iov = &iov
		header.SetIovlen(1)
	}
	if len(s.oob) != 0 {
		header.Control = &s.oob[0]
		header.SetControllen(len(s.oob))
	}
	if s.address != nil {
		header.Name = (*byte)(unsafe.Pointer(&s.address.storage))
		header.Namelen = s.address.length
	}
	var written uintptr
	var errno syscall.Errno
	for {
		written, _, errno = syscall.Syscall(unix.SYS_SENDMSG, fd, uintptr(unsafe.Pointer(&header)), unix.MSG_NOSIGNAL)
		if errno != unix.EINTR {
			break
		}
	}
	if errno != 0 {
		written = 0
	}
	s.n, s.errno = int(written), errno
	return errno != unix.EAGAIN
}

func (s *linuxSendState) wrapError(address *net.UDPAddr, err error) error {
	local, _ := s.conn.LocalAddr().(*net.UDPAddr)
	remote := address
	if remote == nil {
		remote, _ = s.conn.RemoteAddr().(*net.UDPAddr)
	}
	return &net.OpError{Op: "write", Net: local.Network(), Source: local, Addr: remote, Err: err}
}

func (s *linuxSendState) destination(address *net.UDPAddr) (*rawSocketAddress, error) {
	if s.connected {
		if address != nil {
			return nil, net.ErrWriteToConnected
		}
		return nil, nil
	}
	if address == nil {
		return nil, &net.AddrError{Err: "missing address", Addr: "<nil>"}
	}
	key, err := sendKey(address, s.family)
	if err != nil {
		return nil, err
	}
	if s.cacheValid && key == s.cachedKey {
		return &s.cachedAddress, nil
	}
	s.cachedAddress = rawAddress(key)
	s.cachedKey, s.cacheValid = key, true
	return &s.cachedAddress, nil
}

func sendKey(address *net.UDPAddr, family int) (sendAddressKey, error) {
	if address.Port < 0 || address.Port > 65535 {
		return sendAddressKey{}, &net.AddrError{Err: "invalid port", Addr: address.String()}
	}
	key := sendAddressKey{family: uint16(family), port: uint16(address.Port)}
	if family == unix.AF_INET {
		ip := address.IP.To4()
		if ip == nil {
			return sendAddressKey{}, &net.AddrError{Err: "non-IPv4 address", Addr: address.String()}
		}
		copy(key.addr[:4], ip)
		return key, nil
	}
	ip := address.IP.To16()
	if ip == nil {
		return sendAddressKey{}, &net.AddrError{Err: "invalid IP address", Addr: address.String()}
	}
	copy(key.addr[:], ip)
	if address.Zone != "" {
		if index, parseErr := strconv.ParseUint(address.Zone, 10, 32); parseErr == nil {
			key.scope = uint32(index)
		} else if iface, lookupErr := net.InterfaceByName(address.Zone); lookupErr == nil {
			key.scope = uint32(iface.Index)
		} else {
			return sendAddressKey{}, &net.AddrError{Err: "invalid zone", Addr: address.String()}
		}
	}
	return key, nil
}

func rawAddress(key sendAddressKey) rawSocketAddress {
	var address rawSocketAddress
	if key.family == unix.AF_INET {
		raw := (*rawSockaddrInet4)(unsafe.Pointer(&address.storage))
		raw.Family, raw.Port = unix.AF_INET, bits.ReverseBytes16(key.port)
		copy(raw.Addr[:], key.addr[:4])
		address.length = unix.SizeofSockaddrInet4
		return address
	}
	raw := (*rawSockaddrInet6)(unsafe.Pointer(&address.storage))
	raw.Family, raw.Port, raw.ScopeID = unix.AF_INET6, bits.ReverseBytes16(key.port), key.scope
	copy(raw.Addr[:], key.addr[:])
	address.length = unix.SizeofSockaddrInet6
	return address
}

type packetConnView struct{ socket *Socket }

var _ quic.OOBCapablePacketConn = (*packetConnView)(nil)
var _ net.Conn = (*packetConnView)(nil)

func platformGSOAllowed() bool { return true }

func newPacketConnView(socket *Socket) net.PacketConn { return &packetConnView{socket: socket} }

func (c *packetConnView) ReadFrom(payload []byte) (int, net.Addr, error) {
	return c.socket.readFromPlatform(payload)
}

// x/net's IPv4 packet wrapper requires the concrete PacketConn to also
// implement net.Conn, even though quic-go's public OOB contract doesn't say
// so. These methods preserve the underlying UDPConn semantics; QUIC still
// uses ReadMsgUDP and WriteMsgUDP for packet I/O.
func (c *packetConnView) Read(payload []byte) (int, error) {
	return c.socket.Read(payload)
}

func (c *packetConnView) Write(payload []byte) (int, error) {
	return c.socket.Write(payload)
}

func (c *packetConnView) WriteTo(payload []byte, address net.Addr) (int, error) {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok {
		name := "<nil>"
		if address != nil {
			name = address.String()
		}
		return 0, &net.AddrError{Err: "destination is not UDP", Addr: name}
	}
	n, _, err := c.WriteMsgUDP(payload, nil, udpAddress)
	return n, err
}

func (c *packetConnView) Close() error                       { return c.socket.Close() }
func (c *packetConnView) LocalAddr() net.Addr                { return c.socket.LocalAddr() }
func (c *packetConnView) RemoteAddr() net.Addr               { return c.socket.RemoteAddr() }
func (c *packetConnView) SetDeadline(t time.Time) error      { return c.socket.SetDeadline(t) }
func (c *packetConnView) SetReadDeadline(t time.Time) error  { return c.socket.SetReadDeadline(t) }
func (c *packetConnView) SetWriteDeadline(t time.Time) error { return c.socket.SetWriteDeadline(t) }
func (c *packetConnView) SetReadBuffer(bytes int) error      { return c.socket.SetReadBuffer(bytes) }
func (c *packetConnView) SetWriteBuffer(bytes int) error     { return c.socket.SetWriteBuffer(bytes) }

func (c *packetConnView) SyscallConn() (syscall.RawConn, error) {
	return c.socket.conn.SyscallConn()
}

func (c *packetConnView) ReadMsgUDP(payload, oob []byte) (int, int, int, *net.UDPAddr, error) {
	return c.socket.platform.recv.readOne(payload, oob)
}

func (c *packetConnView) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	return c.socket.platform.recv.readBatch(messages, flags)
}

func (s *Socket) writePlatform(payload []byte, address *net.UDPAddr) (int, error) {
	s.send.Lock()
	defer s.send.Unlock()
	n, _, err := s.writeMsg(payload, nil, address)
	return n, err
}

func (s *Socket) writeToPlatform(payload []byte, address net.Addr) (int, error) {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok {
		name := "<nil>"
		if address != nil {
			name = address.String()
		}
		return 0, &net.AddrError{Err: "destination is not UDP", Addr: name}
	}
	return s.writePlatform(payload, udpAddress)
}

func (s *Socket) readPlatform(payload []byte) (int, error) {
	if !s.platform.recv.gro {
		return s.conn.Read(payload)
	}
	n, _, _, _, err := s.platform.recv.readOne(payload, nil)
	return n, err
}

func (s *Socket) readFromPlatform(payload []byte) (int, net.Addr, error) {
	n, _, _, address, err := s.platform.recv.readOne(payload, nil)
	return n, address, err
}

func (c *packetConnView) WriteMsgUDP(payload, oob []byte, address *net.UDPAddr) (int, int, error) {
	c.socket.send.Lock()
	defer c.socket.send.Unlock()
	return c.writeMsgUDPLocked(payload, oob, address)
}

func (c *packetConnView) writeMsgUDPLocked(payload, oob []byte, address *net.UDPAddr) (int, int, error) {
	segment, err := parseUDPSegment(oob)
	if err != nil {
		return 0, 0, err
	}
	if !segment.found {
		n, oobN, writeErr := c.socket.writeMsg(payload, oob, address)
		if writeErr != nil {
			if n != 0 || oobN != 0 {
				return n, oobN, ambiguousWriteError("ordinary datagram", n, len(payload), writeErr)
			}
			if errors.Is(writeErr, unix.EIO) {
				return 0, 0, ordinaryWriteError(writeErr)
			}
			return 0, 0, writeErr
		}
		if n == len(payload) && oobN == len(oob) {
			c.socket.ordinaryDatagrams.Add(1)
			return n, oobN, nil
		}
		if n != 0 || oobN != 0 {
			return n, oobN, ambiguousWriteError("ordinary datagram", n, len(payload), nil)
		}
		return 0, 0, io.ErrShortWrite
	}
	stripped := c.socket.stripUDPSegment(oob, segment)
	packet, err := splitSuperPacket(payload, segment.size)
	if err != nil {
		return 0, 0, err
	}
	if packet.count == 1 {
		n, oobN, writeErr := c.socket.writeMsg(payload, stripped, address)
		if writeErr != nil {
			if n != 0 || oobN != 0 {
				return n, oobN, ambiguousWriteError("ordinary datagram", n, len(payload), writeErr)
			}
			if errors.Is(writeErr, unix.EIO) {
				return 0, 0, ordinaryWriteError(writeErr)
			}
			return 0, 0, writeErr
		}
		if n != len(payload) || oobN != len(stripped) {
			return n, oobN, ambiguousWriteError("ordinary datagram", n, len(payload), nil)
		}
		c.socket.ordinaryDatagrams.Add(1)
		return n, len(oob), nil
	}
	if c.socket.currentTreatment() == treatmentOrdinary {
		completed, writeErr := writeOrdinarySegments(c.socket.writeMsg, packet, stripped, address, func() {
			c.socket.ordinaryDatagrams.Add(1)
		})
		if writeErr != nil {
			return packet.bytesBefore(completed), 0, writeErr
		}
		return len(payload), len(oob), nil
	}

	c.socket.gsoAttempts.Add(1)
	n, oobN, writeErr := c.socket.writeMsg(payload, oob, address)
	if writeErr == nil {
		if n == len(payload) && oobN == len(oob) {
			c.socket.gsoSegments.Add(uint64(packet.count))
			c.socket.gsoSuperPackets.Add(1)
			return n, oobN, nil
		}
		return n, oobN, ambiguousWriteError("GSO super-packet", n, len(payload), nil)
	}
	if n == 0 && oobN == 0 && isGlobalGSOContradiction(writeErr) {
		c.socket.transitionToFallback(causeRuntimeUnsupported, true)
		return c.replayOrdinary(packet, stripped, address, len(oob))
	}
	if n == 0 && oobN == 0 && isPathGSOContradiction(writeErr) {
		c.socket.transitionToFallback(causePathUnsupported, false)
		return c.replayOrdinary(packet, stripped, address, len(oob))
	}
	if n != 0 || oobN != 0 {
		return n, oobN, ambiguousWriteError("GSO super-packet", n, len(payload), writeErr)
	}
	return 0, 0, writeErr
}

type batchAccounting struct {
	ordinary    uint64
	gsoAttempt  bool
	gsoSegments uint64
}

// WriteBatch preserves x/net's message-prefix contract. It decorates every
// message with the source/OIF pin owned by this socket, strips one-segment GSO
// requests exactly like WriteMsgUDP, and uses Linux sendmmsg through x/net.
func (c *packetConnView) WriteBatch(messages []ipv4.Message, flags int) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	if flags != 0 {
		return 0, fmt.Errorf("udpsocket: unsupported batch flags %#x", flags)
	}
	c.socket.send.Lock()
	defer c.socket.send.Unlock()
	if c.socket.currentTreatment() == treatmentOrdinary || c.socket.platform.send.batch == nil {
		return c.writeBatchSequentialLocked(messages)
	}

	prepared := make([]ipv4.Message, len(messages))
	accounting := make([]batchAccounting, len(messages))
	hasGSO := false
	for i := range messages {
		payload, err := flattenMessageBuffers(messages[i].Buffers)
		if err != nil {
			return i, err
		}
		segment, err := parseUDPSegment(messages[i].OOB)
		if err != nil {
			return i, err
		}
		oob := messages[i].OOB
		if segment.found {
			packet, splitErr := splitSuperPacket(payload, segment.size)
			if splitErr != nil {
				return i, splitErr
			}
			if packet.count == 1 {
				_, oob, _, err = stripUDPSegment(oob)
				if err != nil {
					return i, err
				}
				accounting[i].ordinary = 1
			} else {
				accounting[i].gsoAttempt = true
				accounting[i].gsoSegments = uint64(packet.count)
				hasGSO = true
			}
		} else {
			accounting[i].ordinary = 1
		}
		oob = appendPinnedSourceControl(oob, c.socket.platform.send.pinnedOOB)
		prepared[i] = ipv4.Message{Buffers: [][]byte{payload}, OOB: oob, Addr: messages[i].Addr}
	}

	completed, err := c.socket.platform.send.batch(prepared, flags)
	if completed < 0 || completed > len(messages) {
		return 0, errors.New("udpsocket: invalid sendmmsg completion count")
	}
	c.accountBatchSuccess(prepared, accounting, completed)
	if err == nil {
		return completed, nil
	}
	if completed == 0 && hasGSO && (isGlobalGSOContradiction(err) || isPathGSOContradiction(err)) {
		if isGlobalGSOContradiction(err) {
			c.socket.transitionToFallback(causeRuntimeUnsupported, true)
		} else {
			c.socket.transitionToFallback(causePathUnsupported, false)
		}
		return c.writeBatchSequentialLocked(messages)
	}
	return completed, err
}

func (c *packetConnView) accountBatchSuccess(messages []ipv4.Message, accounting []batchAccounting, completed int) {
	if completed == 0 {
		return
	}
	c.socket.batchCalls.Add(1)
	c.socket.batchDatagrams.Add(uint64(completed))
	for i := 0; i < completed; i++ {
		messageBytes := 0
		for _, buffer := range messages[i].Buffers {
			messageBytes += len(buffer)
		}
		if messages[i].N != 0 && messages[i].N != messageBytes {
			continue
		}
		if accounting[i].gsoAttempt {
			c.socket.gsoAttempts.Add(1)
			c.socket.gsoSuperPackets.Add(1)
			c.socket.gsoSegments.Add(accounting[i].gsoSegments)
		} else {
			c.socket.ordinaryDatagrams.Add(accounting[i].ordinary)
		}
	}
}

func (c *packetConnView) writeBatchSequentialLocked(messages []ipv4.Message) (int, error) {
	for i := range messages {
		payload, err := flattenMessageBuffers(messages[i].Buffers)
		if err != nil {
			return i, err
		}
		address, ok := messages[i].Addr.(*net.UDPAddr)
		if messages[i].Addr != nil && !ok {
			return i, &net.AddrError{Err: "destination is not UDP", Addr: messages[i].Addr.String()}
		}
		n, _, err := c.writeMsgUDPLocked(payload, messages[i].OOB, address)
		if err != nil {
			return i, err
		}
		if n != len(payload) {
			return i, io.ErrShortWrite
		}
	}
	return len(messages), nil
}

func flattenMessageBuffers(buffers [][]byte) ([]byte, error) {
	if len(buffers) == 0 {
		return nil, errors.New("udpsocket: batch message has no payload buffer")
	}
	if len(buffers) == 1 {
		if len(buffers[0]) == 0 {
			return nil, errors.New("udpsocket: batch message has an empty payload")
		}
		return buffers[0], nil
	}
	total := 0
	for _, buffer := range buffers {
		total += len(buffer)
	}
	if total == 0 {
		return nil, errors.New("udpsocket: batch message has an empty payload")
	}
	payload := make([]byte, 0, total)
	for _, buffer := range buffers {
		payload = append(payload, buffer...)
	}
	return payload, nil
}

func (c *packetConnView) replayOrdinary(
	packet superPacket,
	oob []byte,
	address *net.UDPAddr,
	originalOOBBytes int,
) (int, int, error) {
	completed, err := writeOrdinarySegments(c.socket.writeMsg, packet, oob, address, func() {
		c.socket.ordinaryDatagrams.Add(1)
	})
	if err != nil {
		return packet.bytesBefore(completed), 0, err
	}
	return len(packet.payload), originalOOBBytes, nil
}

func (s *Socket) writeBatchPlatform(datagrams [][]byte, payloadBytes, segmentSize int, address *net.UDPAddr) (int, error) {
	s.send.Lock()
	defer s.send.Unlock()
	if s.currentTreatment() == treatmentOrdinary {
		return writeOrdinaryDatagrams(s.writeMsg, datagrams, nil, address, func() {
			s.ordinaryDatagrams.Add(1)
		})
	}
	payload := s.joinDatagrams(datagrams, payloadBytes)
	oob := s.udpSegmentControl(segmentSize)
	s.gsoAttempts.Add(1)
	n, oobN, err := s.writeMsg(payload, oob, address)
	if err == nil {
		if n == len(payload) && oobN == len(oob) {
			s.gsoSegments.Add(uint64(len(datagrams)))
			s.gsoSuperPackets.Add(1)
			return len(datagrams), nil
		}
		return 0, ambiguousWriteError("GSO super-packet", n, len(payload), nil)
	}
	if n != 0 || oobN != 0 {
		return 0, ambiguousWriteError("GSO super-packet", n, len(payload), err)
	}
	if !isGlobalGSOContradiction(err) && !isPathGSOContradiction(err) {
		return 0, err
	}
	if isGlobalGSOContradiction(err) {
		s.transitionToFallback(causeRuntimeUnsupported, true)
	} else {
		s.transitionToFallback(causePathUnsupported, false)
	}
	return writeOrdinaryDatagrams(s.writeMsg, datagrams, nil, address, func() {
		s.ordinaryDatagrams.Add(1)
	})
}

type udpSegmentMessage struct {
	size       int
	start, end int
	found      bool
}

func parseUDPSegment(oob []byte) (udpSegmentMessage, error) {
	var segment udpSegmentMessage
	for offset := 0; offset < len(oob); {
		if len(oob)-offset < unix.CmsgLen(0) {
			return udpSegmentMessage{}, unix.EINVAL
		}
		header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[offset]))
		messageBytes := int(header.Len)
		if messageBytes < unix.CmsgLen(0) || messageBytes > len(oob)-offset {
			return udpSegmentMessage{}, unix.EINVAL
		}
		consumed := cmsgAlign(messageBytes)
		if consumed > len(oob)-offset {
			consumed = messageBytes
		}
		if header.Level == unix.IPPROTO_UDP && header.Type == unix.UDP_SEGMENT {
			if segment.found || messageBytes-unix.CmsgLen(0) != udpSegmentDataSize {
				return udpSegmentMessage{}, unix.EINVAL
			}
			body := oob[offset+unix.CmsgLen(0) : offset+messageBytes]
			segment.size = int(binary.NativeEndian.Uint16(body))
			if segment.size == 0 {
				return udpSegmentMessage{}, unix.EINVAL
			}
			segment.start, segment.end, segment.found = offset, offset+consumed, true
		}
		offset += consumed
	}
	return segment, nil
}

func cmsgAlign(length int) int {
	alignment := int(unsafe.Sizeof(uintptr(0)))
	return (length + alignment - 1) & ^(alignment - 1)
}

func stripUDPSegment(oob []byte) (int, []byte, bool, error) {
	segment, err := parseUDPSegment(oob)
	if err != nil || !segment.found {
		return segment.size, oob, segment.found, err
	}
	if segment.start == 0 {
		return segment.size, oob[segment.end:], true, nil
	}
	if segment.end == len(oob) {
		return segment.size, oob[:segment.start], true, nil
	}
	stripped := make([]byte, 0, len(oob)-(segment.end-segment.start))
	stripped = append(stripped, oob[:segment.start]...)
	stripped = append(stripped, oob[segment.end:]...)
	return segment.size, stripped, true, nil
}

func (s *Socket) stripUDPSegment(oob []byte, segment udpSegmentMessage) []byte {
	if segment.start == 0 {
		return oob[segment.end:]
	}
	if segment.end == len(oob) {
		return oob[:segment.start]
	}
	length := len(oob) - (segment.end - segment.start)
	if length > len(s.platform.oobScratch) {
		buffer := make([]byte, 0, length)
		buffer = append(buffer, oob[:segment.start]...)
		return append(buffer, oob[segment.end:]...)
	}
	buffer := s.platform.oobScratch[:length]
	copy(buffer, oob[:segment.start])
	copy(buffer[segment.start:], oob[segment.end:])
	return buffer
}

type superPacket struct {
	payload     []byte
	segmentSize int
	count       int
}

func splitSuperPacket(payload []byte, segmentSize int) (superPacket, error) {
	if segmentSize <= 0 || len(payload) == 0 || len(payload) > MaxGSOSuperPacket {
		return superPacket{}, unix.EINVAL
	}
	count := (len(payload) + segmentSize - 1) / segmentSize
	if count > MaxGSOSegments {
		return superPacket{}, unix.EINVAL
	}
	return superPacket{payload: payload, segmentSize: segmentSize, count: count}, nil
}

func (p superPacket) segment(index int) []byte {
	start := index * p.segmentSize
	end := start + p.segmentSize
	if end > len(p.payload) {
		end = len(p.payload)
	}
	return p.payload[start:end]
}

func (p superPacket) bytesBefore(segments int) int {
	bytes := segments * p.segmentSize
	if bytes > len(p.payload) {
		return len(p.payload)
	}
	return bytes
}

func writeOrdinarySegments(write writeMsgFunc, packet superPacket, oob []byte, address *net.UDPAddr, onSuccess func()) (int, error) {
	for index := 0; index < packet.count; index++ {
		datagram := packet.segment(index)
		n, oobN, err := write(datagram, oob, address)
		if err != nil {
			if n != 0 || oobN != 0 || index != 0 {
				return index, ambiguousWriteError("ordinary batch", n, len(datagram), err)
			}
			return 0, err
		}
		if n != len(datagram) || oobN != len(oob) {
			if n != 0 || oobN != 0 || index != 0 {
				return index, ambiguousWriteError("ordinary batch", n, len(datagram), nil)
			}
			return 0, io.ErrShortWrite
		}
		onSuccess()
	}
	return packet.count, nil
}

func (s *Socket) joinDatagrams(datagrams [][]byte, total int) []byte {
	if cap(s.platform.gsoPayload) < total {
		s.platform.gsoPayload = make([]byte, total)
	} else {
		s.platform.gsoPayload = s.platform.gsoPayload[:total]
	}
	offset := 0
	for _, datagram := range datagrams {
		offset += copy(s.platform.gsoPayload[offset:], datagram)
	}
	return s.platform.gsoPayload
}

func udpSegmentControl(segmentSize int) []byte {
	oob := make([]byte, unix.CmsgSpace(udpSegmentDataSize))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(udpSegmentDataSize))
	binary.NativeEndian.PutUint16(oob[unix.CmsgSpace(0):], uint16(segmentSize))
	return oob
}

func (s *Socket) udpSegmentControl(segmentSize int) []byte {
	length := unix.CmsgSpace(udpSegmentDataSize)
	oob := s.platform.gsoControl[:length]
	clear(oob)
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(udpSegmentDataSize))
	binary.NativeEndian.PutUint16(oob[unix.CmsgSpace(0):], uint16(segmentSize))
	return oob
}

func isGlobalGSOContradiction(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP)
}

func isPathGSOContradiction(err error) bool {
	// A definite zero-byte permission failure can be specific to the optional
	// UDP_SEGMENT treatment while the same datagrams remain sendable normally.
	// Treat it like EIO only after the active probe had selected GSO. Ordinary
	// sends keep their original errors and are never replayed here.
	return errors.Is(err, unix.EIO) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
}

func ordinaryWriteError(err error) error {
	// quic-go treats every *os.SyscallError(EIO) as a failed GSO send. When
	// gsoSize is zero, its segment replay loop cannot advance. Hide the errno
	// after a definite zero-byte ordinary failure so the connection fails
	// closed instead of retrying or spinning.
	return fmt.Errorf("udpsocket: ordinary datagram write failed (%v)", err)
}
