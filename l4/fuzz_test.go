package l4

import (
	"bytes"
	"encoding/binary"
	"flag"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// FuzzL4Metadata_L44 (M4 design §A3.5, M6 design §A3.5): on every input
// ParseMetadata and ParseUDPMetadata do not panic, leave the input unchanged
// and agree with refParse, an independent statement of M4's §A3.4 and M6's
// §A3.2 built on the net package and regular expressions; an accepted input
// re-encodes to exactly itself and parses back to the same Request; no
// input is accepted by both parsers. Allocations (≤ 1 for an accepted
// input, ≤ 2 for a rejected one: the error and its message) are checked on
// every seed and, while the fuzzing engine runs, on a sample of the inputs.
// Seeds: every golden vector of both files, each truncated by one byte and
// with one trailing byte, and the longest UDP metadata with and without one
// byte more.
func FuzzL4Metadata_L44(f *testing.F) {
	for _, v := range append(loadGolden(f), loadGoldenUDP(f)...) {
		f.Add(v.md)
		if len(v.md) > 0 {
			f.Add(v.md[:len(v.md)-1])
		}
		f.Add(append(bytes.Clone(v.md), 0x2E))
	}
	// The longest UDP metadata AppendMetadata encodes, and one byte more.
	longest := append([]byte{0x4c, 0x34, 0x01, 0x11, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x35, 0x00, 0x01, 0x00}, make([]byte, 65535-14)...)
	f.Add(longest)
	f.Add(append(longest, 0))
	parsers := [...]struct {
		name  string
		cmd   uint8
		parse func([]byte) (Request, error)
	}{
		{"ParseMetadata", CmdConnect, ParseMetadata},
		{"ParseUDPMetadata", CmdUDP, ParseUDPMetadata},
	}
	f.Fuzz(func(t *testing.T, md []byte) {
		in := bytes.Clone(md)
		allocs := !raceEnabled && (!fuzzing() || fuzzAllocChecks.Add(1)%fuzzAllocSampleEvery == 0)
		accepted := 0
		for _, p := range parsers {
			r, err := p.parse(md)
			if !bytes.Equal(md, in) {
				t.Fatalf("%s modified its input", p.name)
			}
			wantAddr, wantFirst, wantApp, wantCode := refParse(md, p.cmd)
			if wantCode != 0 {
				if err == nil {
					t.Fatalf("%s(%x) accepted %+v; refParse: %v", p.name, md, r, wantCode)
				}
				wantMetadataError(t, p.name, err, wantCode)
			} else {
				accepted++
				if err != nil {
					t.Fatalf("%s(%x): %v; refParse accepts %q", p.name, md, err, wantAddr)
				}
				if r.Cmd != p.cmd || r.Addr != wantAddr || !bytes.Equal(r.First, wantFirst) || !bytes.Equal(r.App, wantApp) ||
					(r.First == nil) != (wantFirst == nil) || (r.App == nil) != (wantApp == nil) {
					t.Fatalf("%s(%x) = %+v; refParse: %q %x %x", p.name, md, r, wantAddr, wantFirst, wantApp)
				}
				enc, err := AppendMetadata(nil, r)
				if err != nil {
					t.Fatalf("AppendMetadata(%+v): %v", r, err)
				}
				if !bytes.Equal(enc, md) {
					t.Fatalf("re-encoding %x gave %x", md, enc)
				}
				back, err := p.parse(enc)
				if err != nil || back.Cmd != r.Cmd || back.Addr != r.Addr || !bytes.Equal(back.First, r.First) || !bytes.Equal(back.App, r.App) {
					t.Fatalf("%s(AppendMetadata(%+v)) = %+v, %v", p.name, r, back, err)
				}
			}
			if !allocs {
				continue
			}
			limit := 1.0
			if wantCode != 0 {
				limit = 2
			}
			if a := testing.AllocsPerRun(fuzzAllocRuns, func() { sinkRequest, sinkErr = p.parse(md) }); a > limit {
				t.Fatalf("%s(%x): %v allocations, want ≤ %v", p.name, md, a, limit)
			}
		}
		if accepted > 1 {
			t.Fatalf("both parsers accepted %x", md)
		}
	})
}

// fuzzing reports whether the fuzzing engine runs (rather than the seeds
// being replayed as ordinary subtests).
func fuzzing() bool {
	f := flag.Lookup("test.fuzz")
	return f != nil && f.Value.String() != ""
}

const (
	// fuzzAllocSampleEvery: while fuzzing, one input in this many has its
	// allocations measured (AllocsPerRun stops the world).
	fuzzAllocSampleEvery = 4096
	// fuzzAllocRuns: AllocsPerRun rounds down, so a stray allocation of the
	// fuzzing engine during a measurement does not count.
	fuzzAllocRuns = 64
)

var fuzzAllocChecks atomic.Uint64

var (
	refName    = regexp.MustCompile(`^(?:[A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9_-]{1,63}\.?$`)
	refNumeric = regexp.MustCompile(`^(?:[0-9]+|0[xX][0-9A-Fa-f]*)$`)
)

// refParse is the reference decoder of M4's §A3.4 and M6's §A3.2 for the
// command cmd (CmdConnect or CmdUDP): the request's address, first datagram
// and application metadata, or the Reject code of the first failed check.
func refParse(md []byte, cmd uint8) (addr string, first, app []byte, code RejectCode) {
	switch {
	case len(md) < 2 || string(md[:2]) != "L4", len(md) < 5:
		return "", nil, nil, CodeBadRequest
	case md[2] != 1:
		return "", nil, nil, CodeBadVersion
	case md[3] != cmd:
		return "", nil, nil, CodeBadCommand
	}
	var host string
	rest := md[5:]
	switch md[4] {
	case 1, 4:
		n := 4
		if md[4] == 4 {
			n = 16
		}
		if len(rest) < n+2 {
			return "", nil, nil, CodeBadAddress
		}
		ip := net.IP(bytes.Clone(rest[:n]))
		if n == 16 && ip.To4() != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
			return "", nil, nil, CodeBadAddress
		}
		host, rest = ip.String(), rest[n:]
	case 3:
		if len(rest) < 1 || len(rest) < 1+int(rest[0])+2 {
			return "", nil, nil, CodeBadAddress
		}
		name := string(rest[1 : 1+int(rest[0])])
		bare := name
		if len(bare) > 0 && bare[len(bare)-1] == '.' {
			bare = bare[:len(bare)-1]
		}
		labels := strings.Split(bare, ".")
		if !refName.MatchString(name) || len(bare) > 253 || refNumeric.MatchString(labels[len(labels)-1]) {
			return "", nil, nil, CodeBadAddress
		}
		host, rest = name, rest[1+len(name):]
	default:
		return "", nil, nil, CodeBadAddress
	}
	port := binary.BigEndian.Uint16(rest)
	if port == 0 {
		return "", nil, nil, CodeBadAddress
	}
	rest = rest[2:]
	if cmd == CmdUDP {
		if len(md) > 65535 || len(rest) < 2 {
			return "", nil, nil, CodeBadRequest
		}
		n := int(binary.BigEndian.Uint16(rest))
		if rest = rest[2:]; n > len(rest) {
			return "", nil, nil, CodeBadRequest
		}
		if n > 0 {
			first = rest[:n]
		}
		rest = rest[n:]
	}
	if len(rest) > 0 {
		app = rest
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), first, app, 0
}
