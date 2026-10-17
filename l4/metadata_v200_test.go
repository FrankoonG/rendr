package l4

import (
	"bytes"
	"errors"
	"net/netip"
	"strconv"
	"testing"
)

// parseMetadataV200 is ParseMetadata exactly as v2.0.0 shipped it (the tag's
// l4/metadata.go, verbatim but for the name): the oracle of M6 design R1-8,
// "ParseMetadata keeps v2.0.0's contract exactly". M6 moved the header
// decoding into parseHeader, shared with ParseUDPMetadata; sameAsV200 holds
// the result, the error's code and message, and App's aliasing to this
// copy. Never edit it: it states the released behaviour.
func parseMetadataV200(md []byte) (Request, error) {
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

// sameAsV200 fails t unless ParseMetadata(md) is what v2.0.0's ParseMetadata
// returns (R1-8): the same Request, App aliasing md at the same offset with
// the same capacity (nil when it was), First nil; or an error of the same
// type, code and message.
func sameAsV200(t *testing.T, md []byte) {
	t.Helper()
	got, gerr := ParseMetadata(md)
	want, werr := parseMetadataV200(md)
	if gerr != nil || werr != nil {
		var g, w *MetadataError
		if !errors.As(gerr, &g) || !errors.As(werr, &w) || g.Code != w.Code || gerr.Error() != werr.Error() {
			t.Fatalf("ParseMetadata(%x) = %v; v2.0.0 returned %v", md, gerr, werr)
		}
		return
	}
	if got.Cmd != want.Cmd || got.Addr != want.Addr || got.First != nil ||
		(got.App == nil) != (want.App == nil) || !bytes.Equal(got.App, want.App) {
		t.Fatalf("ParseMetadata(%x) = %+v; v2.0.0 returned %+v", md, got, want)
	}
	if want.App != nil && (&got.App[0] != &want.App[0] || cap(got.App) != cap(want.App)) {
		t.Fatalf("ParseMetadata(%x): App does not alias md as v2.0.0's does", md)
	}
}
