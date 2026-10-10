package l4

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// goldenVector is one line of testdata/meta-v1.txt.
type goldenVector struct {
	name string
	md   []byte
	ok   bool
	addr string     // ok
	app  []byte     // ok
	code RejectCode // bad
}

var codeByName = map[string]RejectCode{
	"BadRequest": CodeBadRequest,
	"BadVersion": CodeBadVersion,
	"BadCommand": CodeBadCommand,
	"BadAddress": CodeBadAddress,
}

func loadGolden(t testing.TB) []goldenVector {
	t.Helper()
	f, err := os.Open("testdata/meta-v1.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []goldenVector
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<16)
	unhex := func(s string) []byte {
		if s == "-" {
			return nil
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("testdata: %q: %v", s, err)
		}
		return b
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fs := strings.Fields(line)
		switch {
		case fs[0] == "ok" && len(fs) == 5:
			out = append(out, goldenVector{name: fs[1], md: unhex(fs[2]), ok: true, addr: fs[3], app: unhex(fs[4])})
		case fs[0] == "bad" && len(fs) == 4:
			code, known := codeByName[fs[3]]
			if !known {
				t.Fatalf("testdata: unknown code in %q", line)
			}
			out = append(out, goldenVector{name: fs[1], md: unhex(fs[2]), code: code})
		default:
			t.Fatalf("testdata: malformed line %q", line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) < 40 {
		t.Fatalf("testdata: only %d vectors", len(out))
	}
	return out
}

// wantMetadataError checks that err is a *MetadataError with code.
func wantMetadataError(t *testing.T, what string, err error, code RejectCode) {
	t.Helper()
	var me *MetadataError
	if !errors.As(err, &me) {
		t.Fatalf("%s: err = %v, want a *MetadataError %v", what, err, code)
	}
	if me.Code != code {
		t.Fatalf("%s: code %v (%s), want %v", what, me.Code, me.Msg, code)
	}
}

// TestL4MetadataGolden_L44: every vector of testdata/meta-v1.txt (M4 design
// §A3.5) decodes to its request, re-encodes to its bytes, and every
// rejection carries its code; the header of every valid vector truncated by
// one byte is rejected CodeBadAddress (a truncated IPv4 header never parses
// as a domain).
func TestL4MetadataGolden_L44(t *testing.T) {
	for _, v := range loadGolden(t) {
		t.Run(v.name, func(t *testing.T) {
			in := bytes.Clone(v.md)
			r, err := ParseMetadata(in)
			if !bytes.Equal(in, v.md) {
				t.Fatal("ParseMetadata modified its input")
			}
			if !v.ok {
				wantMetadataError(t, "ParseMetadata", err, v.code)
				return
			}
			if err != nil {
				t.Fatalf("ParseMetadata: %v", err)
			}
			if r.Cmd != CmdConnect || r.Addr != v.addr || !bytes.Equal(r.App, v.app) {
				t.Fatalf("ParseMetadata = %+v, want Addr %q App %x", r, v.addr, v.app)
			}
			if len(v.app) > 0 && &r.App[0] != &in[len(in)-len(v.app)] {
				t.Fatal("App does not alias the input")
			}
			if !Match(in) {
				t.Fatal("Match = false")
			}
			enc, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: v.addr, App: v.app})
			if err != nil {
				t.Fatalf("AppendMetadata: %v", err)
			}
			if hdr := len(v.md) - len(v.app); !bytes.Equal(enc, v.md[:hdr]) {
				t.Fatalf("AppendMetadata = %x, want the header %x", enc, v.md[:hdr])
			}
			// The application's metadata follows the header (l4.Dial's use).
			if full := append(enc, v.app...); !bytes.Equal(full, v.md) {
				t.Fatalf("header ‖ app = %x, want %x", full, v.md)
			}
			hdr := len(v.md) - len(v.app)
			_, err = ParseMetadata(v.md[:hdr-1])
			wantMetadataError(t, "truncated header", err, CodeBadAddress)
		})
	}
}

// TestL4MetadataMaxHeader_L37: the longest header, a 253-byte domain with its
// trailing dot, is 262 bytes (M4 design §A3.4, R1-28).
func TestL4MetadataMaxHeader_L37(t *testing.T) {
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + "."
	enc, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: name + ":65535"})
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != 262 || maxHeader != 262 {
		t.Fatalf("longest header %d bytes (maxHeader %d), want 262", len(enc), maxHeader)
	}
	if _, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: "x" + name + ":1"}); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("a 254-byte name: err = %v, want ErrBadAddress", err)
	}
}

// TestL4MetadataCanonical_L44: every destination has exactly one encoding
// (L44, M4 design §A3.4, R1-11). The decoder side is the golden file's
// rejections (re-checked here by name, so a vector dropped from the file is
// noticed); the encoder side refuses every address the decoder would, with
// an error wrapping ErrBadAddress and dst unchanged.
func TestL4MetadataCanonical_L44(t *testing.T) {
	required := []string{
		"wrong-magic", "version-2", "cmd-2", "atyp-2", "domain-n-0", "domain-n-255",
		"domain-label-64", "domain-empty-label", "domain-colon", "domain-percent",
		"domain-ipv4-loopback-text", "domain-127.1", "domain-2130706433", "domain-0x7f.1",
		"domain-127.0x1", "domain-a.0X1f", "ipv6-mapped-loopback", "ipv4-unspecified",
		"ipv4-multicast", "ipv4-port-0",
	}
	have := map[string]bool{}
	for _, v := range loadGolden(t) {
		have[v.name] = true
	}
	for _, n := range required {
		if !have[n] {
			t.Errorf("testdata lacks the rejection %q", n)
		}
	}

	bad := []string{
		"", "localhost", "localhost:", ":80", "localhost:0", "localhost:65536",
		"localhost:-1", "localhost:+80", "localhost:0x50", "localhost:http",
		"0.0.0.0:80", "255.255.255.255:80", "224.0.0.1:80", "239.255.255.250:1900",
		"[::]:80", "[ff02::1]:80", "[::ffff:0.0.0.0]:80", "[::ffff:224.0.0.1]:80",
		"[fe80::1%eth0]:80", "[fe80::1%25eth0]:80",
		"127.1:80", "2130706433:80", "0x7f.1:80", "127.0x1:80", "a.0X1f:80", "a.0x:80",
		"127.0.0.1.:80", "1.2.3:80", "01.02.03.04:80", "a..b:80", ".a:80", "a.b..:80", "..:80",
		"a b:80", "a%b:80", "a/b:80", "exämple.com:80", strings.Repeat("a", 64) + ":80",
		strings.Repeat("a.", 126) + "aaa:80", // 255 bytes
		"[a:b]:80", "a:b:80",
	}
	prefix := []byte("keep")
	for _, addr := range bad {
		dst := bytes.Clone(prefix)
		out, err := AppendMetadata(dst, Request{Cmd: CmdConnect, Addr: addr})
		if !errors.Is(err, ErrBadAddress) {
			t.Errorf("AppendMetadata(%q): err = %v, want ErrBadAddress", addr, err)
		}
		if !bytes.Equal(out, prefix) {
			t.Errorf("AppendMetadata(%q) changed dst to %x", addr, out)
		}
	}
	if _, err := AppendMetadata(nil, Request{Cmd: 2, Addr: "localhost:80"}); err == nil || errors.Is(err, ErrBadAddress) {
		t.Errorf("AppendMetadata(Cmd 2): err = %v, want a command error", err)
	}
	if _, err := AppendMetadata(nil, Request{Addr: "localhost:80"}); err == nil {
		t.Error("AppendMetadata(Cmd 0) succeeded")
	}

	// One encoding per destination: every spelling of an address encodes to
	// the canonical bytes (an IPv4-mapped IPv6 address as IPv4).
	same := [][]string{
		{"127.0.0.1:443", "[::ffff:127.0.0.1]:443", "[::FFFF:7f00:1]:443", "[127.0.0.1]:443", "127.0.0.1:0443"},
		{"[::1]:80", "[0:0:0:0:0:0:0:1]:80", "[::0001]:80"},
		{"[2001:db8::1]:65535", "[2001:DB8:0::1]:65535"},
	}
	for _, spellings := range same {
		want, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: spellings[0]})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range spellings[1:] {
			got, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: s})
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("AppendMetadata(%q) = %x, %v; want %x", s, got, err, want)
			}
		}
		if r, err := ParseMetadata(want); err != nil || r.Addr != spellings[0] {
			t.Errorf("ParseMetadata(%x) = %+v, %v; want Addr %q", want, r, err, spellings[0])
		}
	}
	// Names: case and the trailing dot are kept (bytes are canonical, not
	// DNS semantics); names resolvers do not read as IPv4 are accepted.
	for _, addr := range []string{"Example.COM:80", "example.com.:80", "a1.b2:80", "1a.com:80", "a.0xg:80", "x.1e:80", "_a-.-b_:80", "0x.y:80"} {
		enc, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: addr})
		if err != nil {
			t.Errorf("AppendMetadata(%q): %v", addr, err)
			continue
		}
		if enc[4] != atypDomain {
			t.Errorf("AppendMetadata(%q): atyp %d, want a domain", addr, enc[4])
		}
		if r, err := ParseMetadata(enc); err != nil || r.Addr != addr {
			t.Errorf("round trip of %q = %+v, %v", addr, r, err)
		}
	}
}

// TestL4MetadataRoundTrip: ParseMetadata(AppendMetadata(r)) == r for valid
// requests of every address type, with and without application metadata,
// appended after a prefix that stays intact.
func TestL4MetadataRoundTrip(t *testing.T) {
	apps := [][]byte{nil, {0}, []byte("app metadata"), bytes.Repeat([]byte{0xA5}, 3834)}
	addrs := []string{
		"192.0.2.4:1", "198.51.100.1:65535", "127.0.0.1:8080", "203.0.113.9:22",
		"[::1]:443", "[2001:db8::8:800:200c:417a]:80", "[fe80::1]:9", "[64:ff9b::102:304]:53",
		"a:1", "localhost:80", "example.com.:443", "xn--bcher-kva.example:80", "_dmarc.example:25",
		strings.Repeat("l", 63) + ".x:7",
	}
	for _, addr := range addrs {
		for _, app := range apps {
			r := Request{Cmd: CmdConnect, Addr: addr, App: app}
			buf, err := AppendMetadata([]byte("pre"), r)
			if err != nil {
				t.Fatalf("AppendMetadata(%q): %v", addr, err)
			}
			if string(buf[:3]) != "pre" {
				t.Fatalf("AppendMetadata(%q) overwrote dst", addr)
			}
			md := append(buf[3:], app...)
			got, err := ParseMetadata(md)
			if err != nil {
				t.Fatalf("ParseMetadata(AppendMetadata(%q)): %v", addr, err)
			}
			if got.Cmd != r.Cmd || got.Addr != r.Addr || !bytes.Equal(got.App, r.App) || (got.App == nil) != (len(r.App) == 0) {
				t.Fatalf("round trip of %+v gave %+v", r, got)
			}
		}
	}
}

// TestL4MetadataMatch: Match looks at the magic only.
func TestL4MetadataMatch(t *testing.T) {
	for _, c := range []struct {
		md   string
		want bool
	}{{"", false}, {"L", false}, {"L4", true}, {"L4\x09", true}, {"l4\x01", false}, {"4L\x01", false}, {"X4", false}} {
		if got := Match([]byte(c.md)); got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.md, got, c.want)
		}
	}
}

var (
	sinkBytes   []byte
	sinkRequest Request
	sinkErr     error
)

// TestL4MetadataAllocs: AppendMetadata allocates nothing into a sized dst;
// ParseMetadata allocates only the address string (M4 design §A12.6).
func TestL4MetadataAllocs(t *testing.T) {
	addrs := []string{"127.0.0.1:443", "[::ffff:192.0.2.1]:80", "[2001:db8::1]:8080", "localhost:8080", "example.com.:443"}
	dst := make([]byte, 0, maxHeader)
	for _, addr := range addrs {
		r := Request{Cmd: CmdConnect, Addr: addr}
		md, err := AppendMetadata(nil, r)
		if err != nil {
			t.Fatal(err)
		}
		md = append(md, "app"...)
		a := testing.AllocsPerRun(100, func() { sinkBytes, sinkErr = AppendMetadata(dst[:0], r) })
		p := testing.AllocsPerRun(100, func() { sinkRequest, sinkErr = ParseMetadata(md) })
		if sinkErr != nil {
			t.Fatal(sinkErr)
		}
		if raceEnabled {
			continue
		}
		if a != 0 {
			t.Errorf("AppendMetadata(%q): %v allocations, want 0", addr, a)
		}
		if p > 1 {
			t.Errorf("ParseMetadata(%q): %v allocations, want ≤ 1", addr, p)
		}
	}
}
