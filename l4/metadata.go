package l4

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// Commands of Request.Cmd (L4 metadata version 1).
const (
	CmdConnect = 1    // a TCP connection over a stream session
	CmdUDP     = 0x11 // one UDP flow over a packet session (17, UDP's IP protocol number)
)

// Request is what an OPEN's L4 metadata carries.
type Request struct {
	Cmd  uint8  // CmdConnect or CmdUDP
	Addr string // "host:port"; an IPv6 host, and only an IPv6 host, in brackets; a host name is resolved by the passive
	App  []byte // the application's own metadata (aliases the decoded input)
	// First is, for CmdUDP, the flow's first datagram when it rode the OPEN
	// (aliases the decoded input; nil otherwise, always nil for CmdConnect).
	// A Dial hook may read it and must not retain it.
	First []byte
}

// ErrBadAddress reports a malformed or non-canonical target address.
var ErrBadAddress = errors.New("l4: bad target address")

// L4 metadata, version 1 (M4 design §A3.4, M6 design §A3.1):
//
//	"L4" | ver u8 (1) | cmd u8 | atyp u8 | addr | port u16 | tail
//
// atyp 1 is IPv4 (4 bytes), 4 is IPv6 (16 bytes), 3 is a domain (a length
// byte 1–254, then the name). The tail of CmdConnect is app, every
// remaining byte; the tail of CmdUDP is flen u16 | first[flen] | app, where
// flen 0 is the only encoding of "no first datagram". Big-endian.
const (
	metaMagic0, metaMagic1 = 'L', '4'
	metaVersion            = 1

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	metaFixed   = 5   // magic, version, command and atyp
	maxNameLen  = 253 // a domain without its optional trailing dot
	maxLabelLen = 63
	// maxHeader is the longest L4 header: a 253-byte domain with its
	// trailing dot and the port (5 + 1 + 254 + 2).
	maxHeader = metaFixed + 1 + maxNameLen + 1 + 2
	// firstLenLen is the size of CmdUDP's first-datagram length.
	firstLenLen = 2
	// maxUDPMetadata bounds a UDP flow's whole metadata, and with it its
	// first datagram: 65,535 bytes, the length field's range and the
	// largest Handshake.MaxMetadata (M6 design R1-19).
	maxUDPMetadata = 65535
)

// AppendMetadata appends the canonical L4 metadata (version 1) of r to dst:
// the header for r.Addr, then, for CmdUDP, the length of r.First and
// r.First, then r.App. An IP host is encoded as an address (an IPv4-mapped
// IPv6 address as IPv4), any other host as a domain; the dialer resolves
// nothing. Square brackets enclose an IPv6 address only (r.Addr as
// net.JoinHostPort writes it): "[a.test]:80" and "[192.0.2.1]:80" are
// refused, not read as a.test or 192.0.2.1. CmdConnect has no first datagram (r.First must be empty). For
// CmdUDP an empty r.First is encoded as absent (length 0), and a First, or
// a whole metadata, longer than 65,535 bytes is refused ("first datagram
// too long"). A Cmd other than CmdConnect and CmdUDP (the zero value
// included) is refused ("unsupported command"). Address errors wrap
// ErrBadAddress. dst is returned unchanged with an error.
func AppendMetadata(dst []byte, r Request) ([]byte, error) {
	switch {
	case r.Cmd != CmdConnect && r.Cmd != CmdUDP:
		return dst, fmt.Errorf("l4: unsupported command %d", r.Cmd)
	case r.Cmd == CmdConnect && len(r.First) > 0:
		return dst, errors.New("l4: a first datagram (Request.First) is for CmdUDP only")
	}
	host, portText, err := net.SplitHostPort(r.Addr)
	if err != nil {
		return dst, fmt.Errorf("%w: %q: %v", ErrBadAddress, r.Addr, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return dst, fmt.Errorf("%w: %q: port must be 1-65535", ErrBadAddress, r.Addr)
	}
	var (
		atyp byte
		ip   [16]byte // atypIPv4: the first 4 bytes
		hdr  int      // the header's length, through the port
	)
	// Square brackets enclose an IPv6 address and nothing else, as
	// netip.ParseAddrPort reads them. net.SplitHostPort strips them from
	// any host, and net.JoinHostPort adds them only to a host with a
	// colon, so a host "[x]" joined with its port would otherwise travel
	// as the name or address x (a SOCKS5 domain "[A000]" as A000).
	// SplitHostPort succeeded, so r.Addr is not empty.
	bracketed := r.Addr[0] == '['
	// A valid domain never parses as an IP address (its last label is not
	// numeric and it has no colon), so a valid name is encoded without
	// trying netip.ParseAddr, whose error would allocate.
	if why := checkName(host); why == "" && !bracketed {
		atyp, hdr = atypDomain, metaFixed+1+len(host)+2
	} else {
		if bracketed {
			why = "square brackets around a host that is not an IPv6 address"
		}
		a, err := netip.ParseAddr(host)
		if err != nil || bracketed && !a.Is6() {
			return dst, fmt.Errorf("%w: %q: %s", ErrBadAddress, r.Addr, why)
		}
		if a.Zone() != "" {
			return dst, fmt.Errorf("%w: %q: an IPv6 zone cannot be encoded", ErrBadAddress, r.Addr)
		}
		a = a.Unmap()
		if why := checkIP(a); why != "" {
			return dst, fmt.Errorf("%w: %q: %s", ErrBadAddress, r.Addr, why)
		}
		if a.Is4() {
			v4 := a.As4()
			copy(ip[:], v4[:])
			atyp, hdr = atypIPv4, metaFixed+4+2
		} else {
			ip = a.As16()
			atyp, hdr = atypIPv6, metaFixed+16+2
		}
	}
	// The whole metadata's bound also keeps the first datagram's length
	// within its 16 bits.
	if n := hdr + firstLenLen + len(r.First) + len(r.App); r.Cmd == CmdUDP && n > maxUDPMetadata {
		return dst, fmt.Errorf("l4: first datagram too long: %d bytes of first datagram, %d of metadata, at most %d", len(r.First), n, maxUDPMetadata)
	}
	dst = append(dst, metaMagic0, metaMagic1, metaVersion, r.Cmd, atyp)
	switch atyp {
	case atypDomain:
		dst = append(dst, byte(len(host)))
		dst = append(dst, host...)
	case atypIPv4:
		dst = append(dst, ip[:4]...)
	default:
		dst = append(dst, ip[:]...)
	}
	dst = append(dst, byte(port>>8), byte(port))
	if r.Cmd == CmdUDP {
		dst = append(dst, byte(len(r.First)>>8), byte(len(r.First)))
		dst = append(dst, r.First...)
	}
	return append(dst, r.App...), nil
}

// ParseMetadata decodes L4 metadata strictly. The error is a
// *MetadataError whose Code is CodeBadRequest, CodeBadVersion,
// CodeBadCommand or CodeBadAddress. The checks run in that order, each
// before a later byte is used; only Addr is allocated, and App aliases md
// (nil when md ends with the header). Every input it accepts is the
// canonical encoding of its Request: AppendMetadata re-encodes it to the
// same bytes.
func ParseMetadata(md []byte) (Request, error) {
	r, end, err := parseHeader(md, CmdConnect)
	if err != nil {
		return Request{}, err
	}
	if len(md) > end {
		r.App = md[end:]
	}
	return r, nil
}

// ParseUDPMetadata decodes the L4 metadata of a UDP flow strictly, with
// ParseMetadata's check order and canonical rules: the command must be
// CmdUDP (CmdConnect and every other command: CodeBadCommand); after the
// address checks, md must be at most 65,535 bytes long, and after the port
// a two-byte length and that many bytes of first datagram must be present
// (else CodeBadRequest); First and App alias md (First is nil when the
// length is 0, App when nothing follows the first datagram). Every input it
// accepts is the canonical encoding of its Request.
func ParseUDPMetadata(md []byte) (Request, error) {
	r, end, err := parseHeader(md, CmdUDP)
	if err != nil {
		return Request{}, err
	}
	if len(md) > maxUDPMetadata {
		// AppendMetadata encodes no longer UDP metadata, so none is
		// canonical (an OPEN never carries more: Handshake.MaxMetadata).
		return Request{}, &MetadataError{Code: CodeBadRequest, Msg: "UDP metadata longer than 65535 bytes"}
	}
	rest := md[end:]
	if len(rest) < firstLenLen {
		return Request{}, &MetadataError{Code: CodeBadRequest, Msg: "truncated first-datagram length"}
	}
	n := int(rest[0])<<8 | int(rest[1])
	if rest = rest[firstLenLen:]; n > len(rest) {
		return Request{}, &MetadataError{Code: CodeBadRequest, Msg: "truncated first datagram"}
	}
	if n > 0 {
		r.First = rest[:n:n] // its capacity ends where App starts
	}
	if len(rest) > n {
		r.App = rest[n:]
	}
	return r, nil
}

// parseHeader decodes the header of L4 metadata whose command must be cmd:
// the Request with Cmd and Addr, and the header's end (where the port's two
// bytes end). The checks run in ParseMetadata's order, each before a later
// byte is used; only Addr is allocated.
func parseHeader(md []byte, cmd uint8) (Request, int, error) {
	if !Match(md) {
		return Request{}, 0, &MetadataError{Code: CodeBadRequest, Msg: "not L4 metadata"}
	}
	if len(md) < metaFixed {
		return Request{}, 0, &MetadataError{Code: CodeBadRequest, Msg: "truncated header"}
	}
	if md[2] != metaVersion {
		return Request{}, 0, &MetadataError{Code: CodeBadVersion, Msg: numbered("unsupported version ", md[2])}
	}
	if md[3] != cmd {
		return Request{}, 0, &MetadataError{Code: CodeBadCommand, Msg: numbered("unsupported command ", md[3])}
	}
	var (
		buf [maxHeader + 8]byte // "[" IPv6 "]:" port fits as well
		a   = buf[:0]
		end int // the header's end, where the port's two bytes end
	)
	switch atyp, rest := md[4], md[metaFixed:]; atyp {
	case atypIPv4:
		if len(rest) < 4+2 {
			return Request{}, 0, badAddress("truncated IPv4 address")
		}
		ip := netip.AddrFrom4([4]byte(rest[:4]))
		if why := checkIP(ip); why != "" {
			return Request{}, 0, badAddress(why)
		}
		a = ip.AppendTo(a)
		end = metaFixed + 4 + 2
	case atypIPv6:
		if len(rest) < 16+2 {
			return Request{}, 0, badAddress("truncated IPv6 address")
		}
		ip := netip.AddrFrom16([16]byte(rest[:16]))
		if ip.Is4In6() {
			return Request{}, 0, badAddress("an IPv4-mapped address must be atyp 1")
		}
		if why := checkIP(ip); why != "" {
			return Request{}, 0, badAddress(why)
		}
		a = append(a, '[')
		a = ip.AppendTo(a)
		a = append(a, ']')
		end = metaFixed + 16 + 2
	case atypDomain:
		if len(rest) < 1 {
			return Request{}, 0, badAddress("truncated domain")
		}
		n := int(rest[0])
		if len(rest) < 1+n+2 {
			return Request{}, 0, badAddress("truncated domain")
		}
		name := rest[1 : 1+n]
		if why := checkName(name); why != "" {
			return Request{}, 0, badAddress(why)
		}
		a = append(a, name...)
		end = metaFixed + 1 + n + 2
	default:
		return Request{}, 0, badAddress(numbered("unknown address type ", atyp))
	}
	port := uint16(md[end-2])<<8 | uint16(md[end-1])
	if port == 0 {
		return Request{}, 0, badAddress("port 0")
	}
	a = append(a, ':')
	a = strconv.AppendUint(a, uint64(port), 10)
	return Request{Cmd: cmd, Addr: string(a)}, end, nil
}

// Match reports whether md starts with the L4 magic.
func Match(md []byte) bool {
	return len(md) >= 2 && md[0] == metaMagic0 && md[1] == metaMagic1
}

// MetadataError is the error of ParseMetadata and ParseUDPMetadata: the
// Reject code a Server answers the malformed metadata with, and what was
// wrong.
type MetadataError struct {
	Code RejectCode // CodeBadRequest, CodeBadVersion, CodeBadCommand or CodeBadAddress
	Msg  string     // what was wrong (stays on the passive)
}

// Error implements error.
func (e *MetadataError) Error() string {
	return fmt.Sprintf("l4: metadata: %s: %s", e.Code, e.Msg)
}

// numbered returns prefix followed by n in decimal, in one allocation.
func numbered(prefix string, n byte) string {
	var b [32]byte
	return string(strconv.AppendUint(append(b[:0], prefix...), uint64(n), 10))
}

func badAddress(why string) *MetadataError {
	return &MetadataError{Code: CodeBadAddress, Msg: why}
}

// checkIP returns why ip is not a target address, or "": unspecified and
// multicast addresses and the IPv4 limited broadcast are rejected.
func checkIP(ip netip.Addr) string {
	switch {
	case ip.IsUnspecified():
		return "unspecified address"
	case ip.IsMulticast():
		return "multicast address"
	case ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "broadcast address"
	}
	return ""
}

// checkName returns why name is not a canonical domain, or "" (M4 design
// §A3.4, R1-11): labels of 1–63 bytes from [A-Za-z0-9_-] joined by single
// dots, at most 253 bytes without one optional trailing dot (kept: an
// absolute name), and a last label that is neither all decimal digits nor
// "0x"/"0X" followed only by hex digits, the forms inet_aton-style resolvers
// read as an IPv4 literal ("127.1", "2130706433", "0x7f.1"). Every IPv4
// literal ends in such a label and an IPv6 literal needs a colon, so a valid
// name never parses as an IP address.
func checkName[T string | []byte](name T) string {
	n := len(name)
	if n > 0 && name[n-1] == '.' {
		n-- // the optional trailing dot
	}
	switch {
	case n == 0:
		return "empty name"
	case n > maxNameLen:
		return "name longer than 253 bytes"
	}
	start := 0 // the current label's first byte
	for i := 0; i <= n; i++ {
		if i < n && name[i] != '.' {
			if !nameByte(name[i]) {
				return "a name byte outside [A-Za-z0-9_-]"
			}
			continue
		}
		switch l := i - start; {
		case l == 0:
			return "an empty label"
		case l > maxLabelLen:
			return "a label longer than 63 bytes"
		}
		if i == n && numericLabel(name[start:n]) {
			return "a numeric last label (read as an IPv4 literal)"
		}
		start = i + 1
	}
	return ""
}

func nameByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// numericLabel reports whether l is all decimal digits, or "0x"/"0X"
// followed only by hex digits (none included).
func numericLabel[T string | []byte](l T) bool {
	digits, base := l, 10
	if len(l) >= 2 && l[0] == '0' && (l[1] == 'x' || l[1] == 'X') {
		digits, base = l[2:], 16
	}
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		switch {
		case '0' <= c && c <= '9':
		case base == 16 && ('a' <= c && c <= 'f' || 'A' <= c && c <= 'F'):
		default:
			return false
		}
	}
	return true
}
