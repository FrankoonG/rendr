//go:build linux && (amd64 || arm64)

package udpsocket

import (
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// accelerated: sendmmsg and recvmmsg exist on this target (M5-D8).
const accelerated = true

// mmsghdr is the kernel's struct mmsghdr: a msghdr and the byte count the
// call reports for that message (64 bytes on amd64 and arm64).
type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte
}

// batchSys holds a Batch's kernel arrays — one header, one iovec and one
// socket address per message, allocated once in NewBatch and linked once
// (header i points at iovec i).
type batchSys struct {
	hdrs  []mmsghdr
	iovs  []unix.Iovec
	names []unix.RawSockaddrInet6 // a sockaddr_in fits in its first 16 bytes
}

func (s *batchSys) init(b *Batch) {
	s.hdrs = make([]mmsghdr, b.max)
	s.iovs = make([]unix.Iovec, b.max)
	s.names = make([]unix.RawSockaddrInet6, b.max)
	for i := range s.hdrs {
		h := &s.hdrs[i].hdr
		h.Iov = &s.iovs[i]
		h.SetIovlen(1)
	}
}

// prepSend fills headers 0 … e−k−1 with ms[k:e]: each datagram's iovec and
// its destination, encoded for the socket's family (a one-entry cache: a
// destination equal to the previous message's shares its encoding). e is
// end, or the index of the first message whose address cannot be sent on
// this socket, with that message's error.
func (s *batchSys) prepSend(c *Conn, ms []Msg, k, end int) (int, error) {
	for i := k; i < end; i++ {
		j := i - k
		h := &s.hdrs[j].hdr
		m := &ms[i]
		if j > 0 && m.Addr == ms[i-1].Addr {
			prev := &s.hdrs[j-1].hdr
			h.Name, h.Namelen = prev.Name, prev.Namelen
		} else {
			nl, err := encodeAddr(&s.names[j], c.sys.family, m.Addr)
			if err != nil {
				return i, err
			}
			h.Name, h.Namelen = (*byte)(unsafe.Pointer(&s.names[j])), nl
		}
		s.iovs[j].Base = unsafe.SliceData(m.Buf)
		s.iovs[j].SetLen(len(m.Buf))
		h.Control, h.Controllen, h.Flags = nil, 0, 0
		s.hdrs[j].len = 0
	}
	return end, nil
}

// prepRecv points header i at slot ms[i] and room for any source address.
func (s *batchSys) prepRecv(ms []Msg) {
	for i := range ms {
		h := &s.hdrs[i].hdr
		h.Name, h.Namelen = (*byte)(unsafe.Pointer(&s.names[i])), unix.SizeofSockaddrInet6
		h.Control, h.Controllen, h.Flags = nil, 0, 0
		s.hdrs[i].len = 0
		s.iovs[i].Base = unsafe.SliceData(ms[i].Buf)
		s.iovs[i].SetLen(len(ms[i].Buf))
	}
}

// clear drops the references of the first n iovecs to the call's buffers.
func (s *batchSys) clear(n int) {
	for i := range min(n, len(s.iovs)) {
		s.iovs[i] = unix.Iovec{}
	}
}

// connSys is a socket's family (AF_INET or AF_INET6), read once in New: it
// decides how a destination is encoded, as the net package decides it.
type connSys struct {
	family int
}

func (s *connSys) init(rc syscall.RawConn) error {
	var serr error
	err := rc.Control(func(fd uintptr) {
		s.family, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
	})
	if err == nil {
		err = serr
	}
	return err
}

// sendmmsg sends the n prepared messages of b from header k on fd: (cnt,
// nil) with cnt the messages sent, or (0, errno) for the first message
// (the kernel reports an error after the first message only at the next
// call).
func sendmmsg(fd uintptr, b *Batch, k, n int) (int, error) {
	r, _, e := unix.Syscall6(unix.SYS_SENDMMSG, fd, uintptr(unsafe.Pointer(&b.sys.hdrs[k])), uintptr(n), 0, 0, 0)
	if e != 0 {
		return 0, e
	}
	return b.sys.sent(b, k, int(r), n)
}

// sent checks the cnt messages a sendmmsg from header k reported: each
// must have left whole. A datagram reported with another length ends the
// count before it, with ErrInvalidCount for it (L42; the range of cnt is
// the caller's check).
func (s *batchSys) sent(b *Batch, k, cnt, n int) (int, error) {
	for i := range min(cnt, n) {
		if int(s.hdrs[k+i].len) != len(b.ms[b.base+k+i].Buf) {
			return i, ErrInvalidCount
		}
	}
	return cnt, nil
}

// recvmmsg receives up to n messages into b's prepared slots on fd and
// decodes them into b.ms: (cnt, nil), or (0, errno), or (0,
// ErrInvalidCount).
func recvmmsg(fd uintptr, b *Batch, n int) (int, error) {
	r, _, e := unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&b.sys.hdrs[0])), uintptr(n), 0, 0, 0)
	if e != 0 {
		return 0, e
	}
	return b.sys.received(b, int(r), n)
}

// received decodes the cnt messages a recvmmsg of n reported into b.ms:
// each one's length, truncation (MSG_TRUNC, or a full slot: M2's rule)
// and source. A count outside [1, n] or a length outside its slot is
// ErrInvalidCount (L42).
func (s *batchSys) received(b *Batch, cnt, n int) (int, error) {
	if cnt < 1 || cnt > n {
		return 0, ErrInvalidCount
	}
	for i := range cnt {
		h, m := &s.hdrs[i], &b.ms[i]
		k := int(h.len)
		if k > len(m.Buf) {
			return 0, ErrInvalidCount
		}
		m.N = k
		m.Trunc = h.hdr.Flags&unix.MSG_TRUNC != 0 || k == len(m.Buf)
		m.Addr = decodeAddr(&s.names[i])
	}
	return cnt, nil
}

// probe runs call (sendmmsg or recvmmsg) on fd −1 and returns its error:
// EBADF means the call is permitted; ENOSYS or EPERM means absent or
// denied (M5-D15). It never reaches a socket or netfilter.
func probe(call int) error {
	nr := uintptr(unix.SYS_SENDMMSG)
	if call == callRecv {
		nr = unix.SYS_RECVMMSG
	}
	if _, _, e := unix.Syscall6(nr, ^uintptr(0), 0, 0, 0, 0, 0); e != 0 {
		return e
	}
	return nil
}

// encodeAddr writes ap into sa as the net package would for a socket of
// family: on AF_INET an IPv4 or IPv4-mapped address (unmapped); on
// AF_INET6 any address (an IPv4 one mapped), its zone as the scope. It
// returns the address length, or the net package's error.
func encodeAddr(sa *unix.RawSockaddrInet6, family int, ap netip.AddrPort) (uint32, error) {
	if !ap.IsValid() {
		return 0, &net.AddrError{Err: "missing address"}
	}
	a := ap.Addr()
	switch family {
	case unix.AF_INET:
		if !a.Is4() && !a.Is4In6() {
			return 0, &net.AddrError{Err: "non-IPv4 address", Addr: a.String()}
		}
		s4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		*s4 = unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: a.As4()}
		putPort(&s4.Port, ap.Port())
		return unix.SizeofSockaddrInet4, nil
	case unix.AF_INET6:
		*sa = unix.RawSockaddrInet6{Family: unix.AF_INET6, Addr: a.As16(), Scope_id: zoneIndex(a.Zone())}
		putPort(&sa.Port, ap.Port())
		return unix.SizeofSockaddrInet6, nil
	}
	return 0, &net.AddrError{Err: "invalid address family", Addr: a.String()}
}

// decodeAddr reads a source address as the net package's
// ReadMsgUDPAddrPort returns it: AF_INET as an IPv4 address, AF_INET6 as
// an IPv6 one (an IPv4 peer of a dual-stack socket stays IPv4-mapped),
// with the scope's zone. It allocates nothing (a scope's zone comes from
// the zone table; an unknown scope's decimal name allocates).
func decodeAddr(sa *unix.RawSockaddrInet6) netip.AddrPort {
	switch sa.Family {
	case unix.AF_INET:
		s4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		return netip.AddrPortFrom(netip.AddrFrom4(s4.Addr), getPort(&s4.Port))
	case unix.AF_INET6:
		a := netip.AddrFrom16(sa.Addr)
		if sa.Scope_id != 0 {
			a = a.WithZone(zoneName(sa.Scope_id))
		}
		return netip.AddrPortFrom(a, getPort(&sa.Port))
	}
	return netip.AddrPort{}
}

// putPort and getPort store a port in network byte order.
func putPort(p *uint16, port uint16) {
	b := (*[2]byte)(unsafe.Pointer(p))
	b[0], b[1] = byte(port>>8), byte(port)
}

func getPort(p *uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(p))
	return uint16(b[0])<<8 | uint16(b[1])
}
