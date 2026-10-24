package l4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP2: the L4 metadata of a UDP flow (M6 design §A3, §A16.1).

// metaFill returns n bytes counting up from seed.
func metaFill(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

// goldenNamed returns the vector name of vs.
func goldenNamed(t *testing.T, vs []goldenVector, name string) goldenVector {
	t.Helper()
	for _, v := range vs {
		if v.name == name {
			return v
		}
	}
	t.Fatalf("no golden vector %q", name)
	return goldenVector{}
}

// metaV1Frozen is the SHA-256 of testdata/meta-v1.txt as v2.0.0 shipped it.
const metaV1Frozen = "589798703f89880f522b50e61e4dc875a5eaa3e8b158fdfb689823dd30f0693d"

// TestL4MetadataV1Frozen_L44 (M6-D1, R1-8, PA-88): meta-v1.txt is v2.0.0's
// file byte for byte and its vectors keep v2.0.0's codes (version-2
// BadVersion, cmd-2 BadCommand); ParseMetadata accepts command 1 only, so
// commands 2, 3 and 0x11 (CmdUDP, also with a whole UDP tail) are
// BadCommand, and ParseUDPMetadata accepts command 0x11 only. On every
// input of the command sweep ParseMetadata returns what v2.0.0's returns
// (sameAsV200: the same Request or error message).
func TestL4MetadataV1Frozen_L44(t *testing.T) {
	b, err := os.ReadFile(goldenConnect)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != metaV1Frozen {
		t.Fatalf("%s changed: SHA-256 %x, v2.0.0 shipped %s", goldenConnect, sum, metaV1Frozen)
	}
	v1 := loadGolden(t)
	for _, c := range []struct {
		name string
		code RejectCode
	}{{"version-2", CodeBadVersion}, {"cmd-0", CodeBadCommand}, {"cmd-2", CodeBadCommand}} {
		v := goldenNamed(t, v1, c.name)
		if v.ok || v.code != c.code {
			t.Fatalf("%s: listed as %v, want %v", c.name, v.code, c.code)
		}
		_, err := ParseMetadata(v.md)
		wantMetadataError(t, c.name, err, c.code)
	}
	for _, p := range []struct {
		name   string
		parse  func([]byte) (Request, error)
		vector goldenVector
		cmd    byte
	}{
		{"ParseMetadata", ParseMetadata, goldenNamed(t, v1, "ipv4-loopback-443"), CmdConnect},
		{"ParseMetadata", ParseMetadata, goldenNamed(t, loadGoldenUDP(t), "udp-ipv4-loopback-53-nofirst"), CmdConnect},
		{"ParseUDPMetadata", ParseUDPMetadata, goldenNamed(t, loadGoldenUDP(t), "udp-ipv4-loopback-53-nofirst"), CmdUDP},
		{"ParseUDPMetadata", ParseUDPMetadata, goldenNamed(t, v1, "ipv4-loopback-443"), CmdUDP},
	} {
		for c := range 256 {
			md := bytes.Clone(p.vector.md)
			md[3] = byte(c)
			r, err := p.parse(md)
			if p.cmd == CmdConnect {
				sameAsV200(t, md)
			}
			switch {
			case byte(c) != p.cmd:
				wantMetadataError(t, p.name+" of "+p.vector.name+" with command "+numbered("", byte(c)), err, CodeBadCommand)
			case err != nil && p.vector.md[3] == p.cmd:
				t.Fatalf("%s(%x): %v", p.name, md, err)
			case err == nil && r.Cmd != p.cmd:
				t.Fatalf("%s(%x) = %+v, want command %d", p.name, md, r, p.cmd)
			}
		}
	}
}

// TestL4MetadataUDPRoundTrip_L44 (M6-D1, M6-D2, L44):
// ParseUDPMetadata(AppendMetadata(r)) == r for valid CmdUDP requests of
// every address type, with and without a first datagram and application
// metadata, appended after a prefix that stays intact; an empty First is
// encoded as absent (flen 0) and decodes as nil; First and App alias the
// input, First without reaching into App. The UDP header follows M4's
// canonical address rules: every spelling of an address has the CONNECT
// header's bytes but the command, and every address the CONNECT encoder
// refuses is refused with ErrBadAddress, dst unchanged.
func TestL4MetadataUDPRoundTrip_L44(t *testing.T) {
	firsts := [][]byte{nil, {}, {0}, metaFill(29, 1), metaFill(148, 2), metaFill(1438, 3), metaFill(9000, 4)}
	apps := [][]byte{nil, {}, {0}, []byte("app metadata")}
	addrs := []string{
		"192.0.2.4:1", "198.51.100.1:65535", "127.0.0.1:53", "203.0.113.9:47998",
		"[::1]:443", "[2001:db8::8:800:200c:417a]:51820", "[fe80::1]:9", "[64:ff9b::c000:201]:53",
		"a:1", "localhost:53", "example.test.:443", "xn--bcher-kva.test:80", "_dns.test:53",
		strings.Repeat("l", 63) + ".x:7",
	}
	for _, addr := range addrs {
		for _, first := range firsts {
			for _, app := range apps {
				r := Request{Cmd: CmdUDP, Addr: addr, First: first, App: app}
				buf, err := AppendMetadata([]byte("pre"), r)
				if err != nil {
					t.Fatalf("AppendMetadata(%q, %d-byte first): %v", addr, len(first), err)
				}
				if string(buf[:3]) != "pre" {
					t.Fatalf("AppendMetadata(%q) overwrote dst", addr)
				}
				md := buf[3:]
				hdr := len(md) - 2 - len(first) - len(app)
				if md[3] != CmdUDP || int(md[hdr])<<8|int(md[hdr+1]) != len(first) ||
					!bytes.Equal(md[hdr+2:hdr+2+len(first)], first) || !bytes.Equal(md[hdr+2+len(first):], app) {
					t.Fatalf("AppendMetadata(%+v) = %x: not header · flen · first · app", r, md)
				}
				got, err := ParseUDPMetadata(md)
				if err != nil {
					t.Fatalf("ParseUDPMetadata(AppendMetadata(%q, %d-byte first)): %v", addr, len(first), err)
				}
				if got.Cmd != CmdUDP || got.Addr != addr || !bytes.Equal(got.First, first) || !bytes.Equal(got.App, app) ||
					(got.First == nil) != (len(first) == 0) || (got.App == nil) != (len(app) == 0) {
					t.Fatalf("round trip of %+v gave %+v", r, got)
				}
				if len(first) > 0 && (&got.First[0] != &md[hdr+2] || cap(got.First) != len(first)) {
					t.Fatalf("%q: First does not alias the input, or reaches into App", addr)
				}
				if len(app) > 0 && &got.App[0] != &md[len(md)-len(app)] {
					t.Fatalf("%q: App does not alias the input", addr)
				}
				conn, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: addr})
				if err != nil || !bytes.Equal(conn[:3], md[:3]) || conn[3] != CmdConnect || !bytes.Equal(conn[4:], md[4:hdr]) {
					t.Fatalf("%q: the UDP header %x is not the CONNECT header %x (%v) with command 0x11", addr, md[:hdr], conn, err)
				}
			}
		}
	}

	// One encoding per destination, as for CONNECT.
	want, err := AppendMetadata(nil, Request{Cmd: CmdUDP, Addr: "127.0.0.1:53", First: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"[::ffff:127.0.0.1]:53", "[::FFFF:7f00:1]:53", "127.0.0.1:053"} {
		got, err := AppendMetadata(nil, Request{Cmd: CmdUDP, Addr: s, First: []byte{1}})
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("AppendMetadata(CmdUDP, %q) = %x, %v; want %x", s, got, err, want)
		}
	}
	prefix := []byte("keep")
	for _, addr := range []string{
		"", "localhost", ":53", "localhost:0", "localhost:65536", "0.0.0.0:53", "255.255.255.255:53",
		"224.0.0.251:5353", "[::]:53", "[ff02::fb]:5353", "[::ffff:0.0.0.0]:53", "[fe80::1%eth0]:53",
		"127.1:53", "0x7f.1:53", "a..b:53", "a b:53", strings.Repeat("a", 64) + ":53",
		"[a.test]:53", "[127.0.0.1]:53", "[A000]:12336",
	} {
		dst := bytes.Clone(prefix)
		out, err := AppendMetadata(dst, Request{Cmd: CmdUDP, Addr: addr, First: []byte("q")})
		if !errors.Is(err, ErrBadAddress) {
			t.Errorf("AppendMetadata(CmdUDP, %q): err = %v, want ErrBadAddress", addr, err)
		}
		if !bytes.Equal(out, prefix) {
			t.Errorf("AppendMetadata(CmdUDP, %q) changed dst to %x", addr, out)
		}
	}
}

// TestAppendMetadataFirstTooLong (R1-19): AppendMetadata refuses a first
// datagram longer than 65,535 bytes and a UDP metadata longer than 65,535
// bytes with "first datagram too long" (without a first datagram as well:
// DialUDP measures the ride on that encoding), and accepts 65,535 bytes
// exactly, which ParseUDPMetadata decodes while it refuses one byte more
// (CodeBadRequest: accepted inputs stay canonical); the bound is
// wire.MaxMetadata, the OPEN's 16-bit metadata length (l4 cannot import
// internal/wire, so this test ties the two);
// a CONNECT request carries no first datagram; a command other than
// CmdConnect and CmdUDP is "unsupported command". Every refusal returns dst
// unchanged and writes nothing into its spare capacity, and none wraps
// ErrBadAddress.
func TestAppendMetadataFirstTooLong(t *testing.T) {
	longest := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + "."
	refuse := func(what string, r Request, why string) {
		t.Helper()
		const spare = 1 << 17
		dst := make([]byte, 4, 4+spare)
		copy(dst, "keep")
		tail := dst[4:cap(dst)]
		for i := range tail {
			tail[i] = 0xEE
		}
		out, err := AppendMetadata(dst, r)
		if err == nil || !strings.Contains(err.Error(), why) || errors.Is(err, ErrBadAddress) {
			t.Fatalf("%s: err = %v, want %q", what, err, why)
		}
		if string(out) != "keep" {
			t.Fatalf("%s: dst became %d bytes", what, len(out))
		}
		for i, c := range tail {
			if c != 0xEE {
				t.Fatalf("%s: wrote into dst's spare capacity at %d", what, 4+i)
			}
		}
	}
	accept := func(what string, r Request, n int) {
		t.Helper()
		md, err := AppendMetadata(nil, r)
		if err != nil || len(md) != n {
			t.Fatalf("%s: %d bytes, %v; want %d", what, len(md), err, n)
		}
		got, err := ParseUDPMetadata(md)
		if err != nil || !bytes.Equal(got.First, r.First) || !bytes.Equal(got.App, r.App) {
			t.Fatalf("%s: ParseUDPMetadata: %v", what, err)
		}
	}
	const limit = 65535
	if maxUDPMetadata != limit || wire.MaxMetadata != limit {
		t.Fatalf("maxUDPMetadata %d, wire.MaxMetadata %d: want both %d", maxUDPMetadata, wire.MaxMetadata, limit)
	}
	// IPv4: an 11-byte header and the 2-byte length.
	accept("IPv4, 65,535 bytes", Request{Cmd: CmdUDP, Addr: "192.0.2.1:53", First: metaFill(limit-13, 0)}, limit)
	refuse("IPv4, a 65,536th byte of App", Request{Cmd: CmdUDP, Addr: "192.0.2.1:53", First: metaFill(limit-13, 0), App: []byte{1}}, "first datagram too long")
	refuse("IPv4, a 65,536th byte of first", Request{Cmd: CmdUDP, Addr: "192.0.2.1:53", First: metaFill(limit-12, 0)}, "first datagram too long")
	// The longest header: 262 bytes and the length.
	accept("longest domain, 65,535 bytes", Request{Cmd: CmdUDP, Addr: longest + ":53", First: metaFill(limit-264-7, 0), App: metaFill(7, 9)}, limit)
	refuse("longest domain, 65,536 bytes", Request{Cmd: CmdUDP, Addr: longest + ":53", First: metaFill(limit-264-6, 0), App: metaFill(7, 9)}, "first datagram too long")
	refuse("a 65,536-byte first datagram", Request{Cmd: CmdUDP, Addr: "192.0.2.1:53", First: metaFill(limit+1, 0)}, "first datagram too long")
	// No first datagram (flen 0): the same bound.
	accept("IPv4, no first datagram, 65,535 bytes", Request{Cmd: CmdUDP, Addr: "192.0.2.1:53", App: metaFill(limit-13, 0)}, limit)
	refuse("IPv4, no first datagram, 65,536 bytes", Request{Cmd: CmdUDP, Addr: "192.0.2.1:53", App: metaFill(limit-12, 0)}, "first datagram too long")
	// ParseUDPMetadata accepts only what AppendMetadata encodes.
	md, err := AppendMetadata(nil, Request{Cmd: CmdUDP, Addr: "192.0.2.1:53", First: []byte{7}, App: metaFill(limit-14, 0)})
	if err != nil || len(md) != limit {
		t.Fatalf("65,535 bytes with a 1-byte first datagram: %d, %v", len(md), err)
	}
	if r, err := ParseUDPMetadata(md); err != nil || len(r.App) != limit-14 {
		t.Fatalf("ParseUDPMetadata of 65,535 bytes: %v", err)
	}
	_, err = ParseUDPMetadata(append(md, 0))
	wantMetadataError(t, "ParseUDPMetadata of 65,536 bytes", err, CodeBadRequest)
	// CONNECT keeps M4's layout: no first datagram, and no length limit of
	// its own (Handshake.MaxMetadata bounds it).
	refuse("CmdConnect with a first datagram", Request{Cmd: CmdConnect, Addr: "192.0.2.1:80", First: []byte{1}}, "first datagram")
	if md, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: "192.0.2.1:80", First: []byte{}, App: metaFill(limit, 0)}); err != nil || len(md) != 11+limit {
		t.Fatalf("CmdConnect with an empty First and a 65,535-byte App: %d bytes, %v", len(md), err)
	}
	for _, c := range []uint8{0, 2, 3, 0x10, 0x12, 0xff} {
		refuse("command "+numbered("", c), Request{Cmd: c, Addr: "192.0.2.1:53", First: []byte{1}}, "unsupported command")
	}
}

// TestL4UDPFirstBudget_L37 (M6-D4, L37): firstBudget, the largest L4
// metadata with which DialUDP lets a first datagram ride the OPEN, is the
// smallest DatagramCarrier.MTU NewPeer accepts (wire.MinFrameBudget, 537)
// minus the OPEN's fixed cost on a datagram carrier (99 bytes), and the core
// agrees: over a 537-byte datagram link, DialPacket carries firstBudget
// bytes of UDP metadata whole in one 537-byte first datagram (the passive
// decodes its first datagram) and refuses firstBudget + 1 at once with
// ErrMetadataTooLarge, without a factory call.
func TestL4UDPFirstBudget_L37(t *testing.T) {
	cost := wire.PrefaceLen + wire.FrameOverhead + wire.RelHeadLen + wire.OpenFixedLen
	if cost != 99 || wire.MinFrameBudget != 537 || firstBudget != wire.MinFrameBudget-cost {
		t.Fatalf("firstBudget %d, MinFrameBudget %d, OPEN cost %d: want 537 − 99 = 438", firstBudget, wire.MinFrameBudget, cost)
	}
	synctest.Test(t, func(t *testing.T) {
		ov := kitOverrides(worldOpts{})
		d := kitRuntime(t, rendr.Config{}, ov)
		p := kitRuntime(t, rendr.Config{}, ov)
		ln, err := p.Listen(rendr.ListenConfig{})
		if err != nil {
			t.Fatal(err)
		}
		link := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: "min", Accept: ln.HandlePacket, MTU: wire.MinFrameBudget})
		peer, err := d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{rendr.DatagramCarrier{Name: "min", MTU: wire.MinFrameBudget, Dial: link.Dial}}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			peer.Close()
			d.Close()
			p.Close()
			link.Close()
		}()
		meta := func(n int) (md, first []byte) {
			first = metaFill(n-13, 0x40) // the IPv4 header and the length: 13 bytes
			md, err := AppendMetadata(nil, Request{Cmd: CmdUDP, Addr: "192.0.2.1:53", First: first})
			if err != nil || len(md) != n {
				t.Fatalf("%d bytes of metadata: %d, %v", n, len(md), err)
			}
			return md, first
		}

		over, _ := meta(firstBudget + 1)
		if pc, err := peer.DialPacket(context.Background(), rendr.DialOptions{Metadata: over}); pc != nil || !errors.Is(err, rendr.ErrMetadataTooLarge) {
			t.Fatalf("DialPacket with %d bytes of metadata: %v, %v; want ErrMetadataTooLarge", len(over), pc, err)
		}
		if n := link.Stats().Dials; n != 0 {
			t.Fatalf("%d factory calls before the size check, want none", n)
		}

		md, first := meta(firstBudget)
		seen := make(chan []byte, 1)
		go func() {
			pend, err := ln.AcceptPacket(context.Background())
			if err != nil {
				seen <- nil
				return
			}
			seen <- bytes.Clone(pend.Metadata())
			pend.Reject(4000, "done")
		}()
		_, err = peer.DialPacket(context.Background(), rendr.DialOptions{Metadata: md})
		got := <-seen
		if !errors.Is(err, rendr.ErrRejected) || !bytes.Equal(got, md) {
			t.Fatalf("DialPacket with %d bytes of metadata: %v (the passive saw %d bytes); want it carried", len(md), err, len(got))
		}
		if r, err := ParseUDPMetadata(got); err != nil || !bytes.Equal(r.First, first) {
			t.Fatalf("the passive decoded %+v, %v; want the %d-byte first datagram", r, err, len(first))
		}
		if s := link.Stats().Session; s.Oversize != 0 || s.Delivered == 0 {
			t.Fatalf("the session carrier: %+v; want the OPEN delivered within the 537-byte MTU", s)
		}
	})
}
