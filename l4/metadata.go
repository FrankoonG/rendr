package l4

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// CmdConnect is Request.Cmd for a TCP connection, the only command of
// metadata version 1.
const CmdConnect = 1

// Request is what an OPEN's L4 metadata carries.
type Request struct {
	Cmd  uint8  // CmdConnect
	Addr string // "host:port"; an IPv6 host in brackets; a host name is resolved by the passive
	App  []byte // the application's own metadata (aliases the decoded input)
}

// ErrBadAddress reports a malformed or non-canonical target address.
var ErrBadAddress = errors.New("l4: bad target address")

// L4 metadata, version 1 (M4 design §A3.4):
//
//	"L4" | ver u8 (1) | cmd u8 (1) | atyp u8 | addr | port u16 | app
//
// atyp 1 is IPv4 (4 bytes), 4 is IPv6 (16 bytes), 3 is a domain (a length
// byte 1–254, then the name); app is every remaining byte. Big-endian.
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
)

// AppendMetadata appends the canonical L4 metadata (version 1) of r to dst:
// the header for r.Addr, then r.App. An IP host is encoded as an address
// (an IPv4-mapped IPv6 address as IPv4), any other host as a domain; the
// dialer resolves nothing. Errors wrap ErrBadAddress, except for a Cmd
// other than CmdConnect (the zero value included); dst is returned
// unchanged with an error.
func AppendMetadata(dst []byte, r Request) ([]byte, error) {
	if r.Cmd != CmdConnect {
		return dst, fmt.Errorf("l4: unsupported command %d", r.Cmd)
	}
	host, portText, err := net.SplitHostPort(r.Addr)
	if err != nil {
		return dst, fmt.Errorf("%w: %q: %v", ErrBadAddress, r.Addr, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return dst, fmt.Errorf("%w: %q: port must be 1-65535", ErrBadAddress, r.Addr)
	}
	head := [3]byte{metaMagic0, metaMagic1, metaVersion}
	// A valid domain never parses as an IP address (its last label is not
	// numeric and it has no colon), so a valid name is encoded without
	// trying netip.ParseAddr, whose error would allocate.
	if why := checkName(host); why == "" {
		dst = append(dst, head[:]...)
		dst = append(dst, CmdConnect, atypDomain, byte(len(host)))
		dst = append(dst, host...)
		dst = append(dst, byte(port>>8), byte(port))
		return append(dst, r.App...), nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return dst, fmt.Errorf("%w: %q: %s", ErrBadAddress, r.Addr, checkName(host))
	}
	if ip.Zone() != "" {
		return dst, fmt.Errorf("%w: %q: an IPv6 zone cannot be encoded", ErrBadAddress, r.Addr)
	}
	ip = ip.Unmap()
	if why := checkIP(ip); why != "" {
		return dst, fmt.Errorf("%w: %q: %s", ErrBadAddress, r.Addr, why)
	}
	dst = append(dst, head[:]...)
	if ip.Is4() {
		a := ip.As4()
		dst = append(dst, CmdConnect, atypIPv4)
		dst = append(dst, a[:]...)
	} else {
		a := ip.As16()
		dst = append(dst, CmdConnect, atypIPv6)
		dst = append(dst, a[:]...)
	}
	dst = append(dst, byte(port>>8), byte(port))
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
	if !Match(md) {
		return Request{}, &MetadataError{Code: CodeBadRequest, Msg: "not L4 metadata"}
	}
	if len(md) < metaFixed {
		return Request{}, &MetadataError{Code: CodeBadRequest, Msg: "truncated header"}
	}
	if md[2] != metaVersion {
		return Request{}, &MetadataError{Code: CodeBadVersion, Msg: numbered("unsupported version ", md[2])}
	}
	if md[3] != CmdConnect {
		return Request{}, &MetadataError{Code: CodeBadCommand, Msg: numbered("unsupported command ", md[3])}
	}
	var (
		buf [maxHeader + 8]byte // "[" IPv6 "]:" port fits as well
		a   = buf[:0]
		end int // the header's end, where the port's two bytes end
	)
	switch atyp, rest := md[4], md[metaFixed:]; atyp {
	case atypIPv4:
		if len(rest) < 4+2 {
			return Request{}, badAddress("truncated IPv4 address")
		}
		ip := netip.AddrFrom4([4]byte(rest[:4]))
		if why := checkIP(ip); why != "" {
			return Request{}, badAddress(why)
		}
		a = ip.AppendTo(a)
		end = metaFixed + 4 + 2
	case atypIPv6:
		if len(rest) < 16+2 {
			return Request{}, badAddress("truncated IPv6 address")
		}
		ip := netip.AddrFrom16([16]byte(rest[:16]))
		if ip.Is4In6() {
			return Request{}, badAddress("an IPv4-mapped address must be atyp 1")
		}
		if why := checkIP(ip); why != "" {
			return Request{}, badAddress(why)
		}
		a = append(a, '[')
		a = ip.AppendTo(a)
		a = append(a, ']')
		end = metaFixed + 16 + 2
	case atypDomain:
		if len(rest) < 1 {
			return Request{}, badAddress("truncated domain")
		}
		n := int(rest[0])
		if len(rest) < 1+n+2 {
			return Request{}, badAddress("truncated domain")
		}
		name := rest[1 : 1+n]
		if why := checkName(name); why != "" {
			return Request{}, badAddress(why)
		}
		a = append(a, name...)
		end = metaFixed + 1 + n + 2
	default:
		return Request{}, badAddress(numbered("unknown address type ", atyp))
	}
	port := uint16(md[end-2])<<8 | uint16(md[end-1])
	if port == 0 {
		return Request{}, badAddress("port 0")
	}
	a = append(a, ':')
	a = strconv.AppendUint(a, uint64(port), 10)
	r := Request{Cmd: CmdConnect, Addr: string(a)}
	if len(md) > end {
		r.App = md[end:]
	}
	return r, nil
}

// Match reports whether md starts with the L4 magic.
func Match(md []byte) bool {
	return len(md) >= 2 && md[0] == metaMagic0 && md[1] == metaMagic1
}

// MetadataError is ParseMetadata's error: the Reject code a Server answers
// the malformed metadata with, and what was wrong.
type MetadataError struct {
	Code RejectCode
	Msg  string
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
