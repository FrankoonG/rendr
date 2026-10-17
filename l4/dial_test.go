package l4

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// M4 WP4: l4.Dial (§A2.2, §A12.1).

// TestDialBadAddressNoIO: an address the L4 metadata cannot carry fails
// with ErrBadAddress before any network I/O (no factory call).
func TestDialBadAddressNoIO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		for _, addr := range []string{
			"", "host", "host:", "host:0", "host:65536", ":80", "0.0.0.0:80", "[::]:80",
			"224.0.0.1:80", "255.255.255.255:80", "[fe80::1%eth0]:80", "a..b:80",
			"-x.test:http", "127.1:80", "x.0x10:80", strings.Repeat("a", 64) + ".test:80",
		} {
			c, err := Dial(context.Background(), w.peer, addr, rendr.DialOptions{})
			if !errors.Is(err, ErrBadAddress) || c != nil {
				t.Errorf("Dial(%q): %v, %v; want ErrBadAddress", addr, c, err)
			}
		}
		if n := w.links[0].Stats().Dials; n != 0 {
			t.Fatalf("%d carrier dials, want none", n)
		}
		w.shutdown()
	})
}

// TestDialSetsIdleDefault (M4-D41, plan:660): a session from Dial expires
// after DefaultIdleTimeout without traffic (the core keeps no default),
// ending ErrIdleTimeout on the dialer and AbortIdle on the passive, and not
// earlier.
func TestDialSetsIdleDefault(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		d, p := w.open(rendr.DialOptions{})
		if _, err := d.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 5)
		if _, err := p.Read(buf); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		quiet := time.Now()
		time.Sleep(DefaultIdleTimeout - 2*time.Second)
		select {
		case <-d.Done():
			t.Fatalf("the session ended %v after its last byte, before the idle limit", time.Since(quiet))
		default:
		}
		waitDone(t, d, time.Minute)
		waitDone(t, p, time.Minute)
		if el := time.Since(quiet); el > DefaultIdleTimeout+3*time.Second {
			t.Fatalf("the session ended %v after its last byte, want the idle limit %v", el, DefaultIdleTimeout)
		}
		if err := d.Status().Err; !errors.Is(err, rendr.ErrIdleTimeout) {
			t.Fatalf("dialer end %v, want ErrIdleTimeout", err)
		}
		if code, remote, ok := abortCode(p.Status().Err); !ok || code != rendr.AbortIdle || !remote {
			t.Fatalf("passive end %v, want *AbortError{AbortIdle, Remote}", p.Status().Err)
		}
		w.shutdown()
	})
}

// TestDialAppMetadataRoundTrip: the passive decodes the target and the
// application's metadata (DialOptions.Metadata) from the OPEN; the caller's
// Metadata slice is not modified.
func TestDialAppMetadataRoundTrip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		for _, tc := range []struct{ addr, app string }{
			{"[2001:db8::1]:443", "app-bytes"},
			{"example.test:80", ""},
			{"192.0.2.7:8080", "x"},
		} {
			app := []byte(tc.app)
			if len(app) == 0 {
				app = nil
			}
			orig := bytes.Clone(app)
			got := make(chan Request, 1)
			go func() {
				pend, err := w.ln.Accept(context.Background())
				if err != nil {
					t.Errorf("Accept: %v", err)
					got <- Request{}
					return
				}
				r, err := ParseMetadata(bytes.Clone(pend.Metadata()))
				if err != nil {
					t.Errorf("ParseMetadata: %v", err)
				}
				got <- r
				pend.Reject(4000, "done")
			}()
			_, err := Dial(context.Background(), w.peer, tc.addr, rendr.DialOptions{Metadata: app})
			r := <-got
			if !errors.Is(err, rendr.ErrRejected) {
				t.Fatalf("Dial: %v", err)
			}
			if r.Cmd != CmdConnect || r.Addr != tc.addr || string(r.App) != tc.app {
				t.Fatalf("passive decoded %+v, want CONNECT %q with app %q", r, tc.addr, tc.app)
			}
			if !bytes.Equal(app, orig) {
				t.Fatalf("Dial modified the caller's Metadata: %q", app)
			}
		}
		w.shutdown()
	})
}

// TestL4MetadataLimit_L37 (M4-D25, R1-28): the longest L4 header (a
// 253-byte domain with its trailing dot: 262 bytes) plus the application's
// metadata may fill Handshake.MaxMetadata exactly; one byte more fails with
// ErrMetadataTooLarge before any carrier is dialled. The same holds for a
// UDP flow's metadata on a packet session (264 bytes of header with the
// first-datagram length; M6 design §A3.3).
func TestL4MetadataLimit_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		label := strings.Repeat("a", 63)
		name := label + "." + label + "." + label + "." + strings.Repeat("b", 61) + "." // 253 + the dot
		addr := name + ":65535"
		hdr, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: addr})
		if err != nil || len(hdr) != maxHeader || maxHeader != 262 {
			t.Fatalf("the longest header: %d bytes, %v; want 262", len(hdr), err)
		}
		const maxMeta = 4 << 10 // Handshake.MaxMetadata's default
		app := make([]byte, maxMeta-len(hdr)+1)
		if _, err := Dial(context.Background(), w.peer, addr, rendr.DialOptions{Metadata: app}); !errors.Is(err, rendr.ErrMetadataTooLarge) {
			t.Fatalf("Dial with %d bytes of metadata: %v, want ErrMetadataTooLarge", len(hdr)+len(app), err)
		}
		if n := w.links[0].Stats().Dials; n != 0 {
			t.Fatalf("%d carrier dials before the size check, want none", n)
		}
		accepted := make(chan int, 1)
		go func() {
			pend, err := w.ln.Accept(context.Background())
			if err != nil {
				accepted <- -1
				return
			}
			accepted <- len(pend.Metadata())
			pend.Reject(4000, "done")
		}()
		_, err = Dial(context.Background(), w.peer, addr, rendr.DialOptions{Metadata: app[:len(app)-1]})
		if n := <-accepted; !errors.Is(err, rendr.ErrRejected) || n != maxMeta {
			t.Fatalf("Dial with %d bytes of metadata: %v (the passive saw %d); want it carried", maxMeta, err, n)
		}

		// UDP (M6 design §A3.1, §A3.3): the longest UDP header adds the
		// 2-byte first-datagram length (264 bytes); with a first datagram
		// and the application's metadata it may fill MaxMetadata exactly on
		// a packet session, and one byte more fails with
		// ErrMetadataTooLarge before any carrier is dialled.
		udpHdr, err := AppendMetadata(nil, Request{Cmd: CmdUDP, Addr: addr})
		if err != nil || len(udpHdr) != maxHeader+2 {
			t.Fatalf("the longest UDP header: %d bytes, %v; want 264", len(udpHdr), err)
		}
		first, udpApp := make([]byte, maxMeta-len(udpHdr)-10), make([]byte, 11)
		for i := range first {
			first[i] = byte(i)
		}
		over, err := AppendMetadata(nil, Request{Cmd: CmdUDP, Addr: addr, First: first, App: udpApp})
		if err != nil || len(over) != maxMeta+1 {
			t.Fatalf("UDP metadata: %d bytes, %v; want %d", len(over), err, maxMeta+1)
		}
		dials := w.links[0].Stats().Dials
		if pc, err := w.peer.DialPacket(context.Background(), rendr.DialOptions{Metadata: over}); pc != nil || !errors.Is(err, rendr.ErrMetadataTooLarge) {
			t.Fatalf("DialPacket with %d bytes of UDP metadata: %v, %v; want ErrMetadataTooLarge", len(over), pc, err)
		}
		if n := w.links[0].Stats().Dials; n != dials {
			t.Fatalf("%d carrier dials before the size check, want none", n-dials)
		}
		seen := make(chan []byte, 1)
		go func() {
			pend, err := w.ln.AcceptPacket(context.Background())
			if err != nil {
				seen <- nil
				return
			}
			seen <- bytes.Clone(pend.Metadata())
			pend.Reject(4000, "done")
		}()
		_, err = w.peer.DialPacket(context.Background(), rendr.DialOptions{Metadata: over[:maxMeta]})
		got := <-seen
		if !errors.Is(err, rendr.ErrRejected) || len(got) != maxMeta {
			t.Fatalf("DialPacket with %d bytes of UDP metadata: %v (the passive saw %d); want it carried", maxMeta, err, len(got))
		}
		if r, err := ParseUDPMetadata(got); err != nil || r.Addr != addr || !bytes.Equal(r.First, first) || len(r.App) != 10 {
			t.Fatalf("the passive decoded %q, %d-byte first, %d-byte App, %v; want %q, %d, 10", r.Addr, len(r.First), len(r.App), err, addr, len(first))
		}
		w.shutdown()
	})
}

// TestDialRefusalCodeOf: an l4 refusal reaches Dial's caller as a
// *rendr.RejectError whose CodeOf is the code; an application code is not
// an l4 code.
func TestDialRefusalCodeOf(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		for _, tc := range []struct {
			code uint32
			want RejectCode
			ok   bool
		}{
			{uint32(CodeRefused), CodeRefused, true},
			{uint32(CodeDNSNotFound), CodeDNSNotFound, true},
			{4000, 0, false},
		} {
			go func() {
				pend, err := w.ln.Accept(context.Background())
				if err != nil {
					t.Errorf("Accept: %v", err)
					return
				}
				pend.Reject(tc.code, RejectCode(tc.code).String())
			}()
			c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
			if c != nil || !errors.Is(err, rendr.ErrRejected) {
				t.Fatalf("Dial: %v, %v; want a refusal", c, err)
			}
			if code, ok := CodeOf(err); code != tc.want || ok != tc.ok {
				t.Fatalf("CodeOf(%v) = %v, %v; want %v, %v", err, code, ok, tc.want, tc.ok)
			}
		}
		w.shutdown()
	})
}
