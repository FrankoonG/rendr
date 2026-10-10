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

// FuzzL4Metadata_L44 (M4 design §A3.5): on every input ParseMetadata does
// not panic, leaves the input unchanged and agrees with refParse, an
// independent statement of §A3.4 built on the net package and regular
// expressions; an accepted input re-encodes to exactly itself and
// ParseMetadata(AppendMetadata(r)) == r. Allocations (≤ 1 for an accepted
// input, ≤ 2 for a rejected one: the error and its message) are checked on
// every seed and, while the fuzzing engine runs, on a sample of the inputs.
// Seeds: every golden vector, each truncated by one byte and with one
// trailing byte.
func FuzzL4Metadata_L44(f *testing.F) {
	for _, v := range loadGolden(f) {
		f.Add(v.md)
		if len(v.md) > 0 {
			f.Add(v.md[:len(v.md)-1])
		}
		f.Add(append(bytes.Clone(v.md), 0x2E))
	}
	f.Fuzz(func(t *testing.T, md []byte) {
		in := bytes.Clone(md)
		r, err := ParseMetadata(md)
		if !bytes.Equal(md, in) {
			t.Fatal("ParseMetadata modified its input")
		}
		wantAddr, wantApp, wantCode := refParse(md)
		if wantCode != 0 {
			if err == nil {
				t.Fatalf("ParseMetadata(%x) accepted %+v; refParse: %v", md, r, wantCode)
			}
			wantMetadataError(t, "ParseMetadata", err, wantCode)
		} else {
			if err != nil {
				t.Fatalf("ParseMetadata(%x): %v; refParse accepts %q", md, err, wantAddr)
			}
			if r.Cmd != CmdConnect || r.Addr != wantAddr || !bytes.Equal(r.App, wantApp) {
				t.Fatalf("ParseMetadata(%x) = %+v; refParse: %q %x", md, r, wantAddr, wantApp)
			}
			enc, err := AppendMetadata(nil, r)
			if err != nil {
				t.Fatalf("AppendMetadata(%+v): %v", r, err)
			}
			if !bytes.Equal(enc, md) {
				t.Fatalf("re-encoding %x gave %x", md, enc)
			}
			back, err := ParseMetadata(enc)
			if err != nil || back.Cmd != r.Cmd || back.Addr != r.Addr || !bytes.Equal(back.App, r.App) {
				t.Fatalf("ParseMetadata(AppendMetadata(%+v)) = %+v, %v", r, back, err)
			}
		}
		if raceEnabled || (fuzzing() && fuzzAllocChecks.Add(1)%fuzzAllocSampleEvery != 0) {
			return
		}
		limit := 1.0
		if wantCode != 0 {
			limit = 2
		}
		if a := testing.AllocsPerRun(fuzzAllocRuns, func() { sinkRequest, sinkErr = ParseMetadata(md) }); a > limit {
			t.Fatalf("ParseMetadata(%x): %v allocations, want ≤ %v", md, a, limit)
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

// refParse is the reference decoder of §A3.4: the request's address and
// application metadata, or the Reject code of the first failed check.
func refParse(md []byte) (addr string, app []byte, code RejectCode) {
	switch {
	case len(md) < 2 || string(md[:2]) != "L4", len(md) < 5:
		return "", nil, CodeBadRequest
	case md[2] != 1:
		return "", nil, CodeBadVersion
	case md[3] != 1:
		return "", nil, CodeBadCommand
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
			return "", nil, CodeBadAddress
		}
		ip := net.IP(bytes.Clone(rest[:n]))
		if n == 16 && ip.To4() != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
			return "", nil, CodeBadAddress
		}
		host, rest = ip.String(), rest[n:]
	case 3:
		if len(rest) < 1 || len(rest) < 1+int(rest[0])+2 {
			return "", nil, CodeBadAddress
		}
		name := string(rest[1 : 1+int(rest[0])])
		bare := name
		if len(bare) > 0 && bare[len(bare)-1] == '.' {
			bare = bare[:len(bare)-1]
		}
		labels := strings.Split(bare, ".")
		if !refName.MatchString(name) || len(bare) > 253 || refNumeric.MatchString(labels[len(labels)-1]) {
			return "", nil, CodeBadAddress
		}
		host, rest = name, rest[1+len(name):]
	default:
		return "", nil, CodeBadAddress
	}
	port := binary.BigEndian.Uint16(rest)
	if port == 0 {
		return "", nil, CodeBadAddress
	}
	if rest = rest[2:]; len(rest) > 0 {
		app = rest
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), app, 0
}
