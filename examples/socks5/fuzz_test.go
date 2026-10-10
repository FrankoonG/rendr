package main

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/FrankoonG/rendr/v2/l4"
)

// declared is how many bytes of in a SOCKS5 greeting and request declare
// (the spec's lengths, computed apart from the parser): the parser must
// consume exactly these, or all of in when it is shorter.
func declared(in []byte) int {
	n := 2
	if len(in) < n {
		return len(in)
	}
	if in[0] != socksVersion || in[1] == 0 {
		return n
	}
	n += int(in[1])
	if len(in) < n {
		return len(in)
	}
	if bytes.IndexByte(in[2:n], methodNoAuth) < 0 {
		return n
	}
	if len(in) < n+4 {
		return len(in)
	}
	ver, cmd, rsv, atyp := in[n], in[n+1], in[n+2], in[n+3]
	n += 4
	if ver != socksVersion || cmd != cmdConnect || rsv != 0 {
		return n
	}
	switch atyp {
	case atypIPv4:
		n += 4
	case atypIPv6:
		n += 16
	case atypDomain:
		if len(in) < n+1 {
			return len(in)
		}
		n += 1 + int(in[n])
	default:
		return n
	}
	return min(n+2, len(in))
}

// sameDest reports whether addr, an L4 destination, is q's: the same
// port, and the same IP (IPv4-mapped as IPv4; for a domain, the literal it
// spells) or the domain's exact bytes.
func sameDest(addr string, q request) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != strconv.Itoa(int(q.port)) {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return q.atyp == atypDomain && host == string(q.addr)
	}
	want, ok := netip.AddrFromSlice(q.addr)
	if q.atyp == atypDomain {
		want, err = netip.ParseAddr(string(q.addr))
		ok = err == nil
	}
	return ok && ip == want.Unmap()
}

// FuzzSocks5Request_L44 (M4-D46, L44): the handshake parser never panics,
// never reads beyond the declared lengths (the rest stays for Forward),
// answers only the replies of §A10.2, and every accepted request
// round-trips through the encoder.
func FuzzSocks5Request_L44(f *testing.F) {
	g := func(b ...byte) []byte { return append([]byte{socksVersion, 1, methodNoAuth}, b...) }
	f.Add(g(socksVersion, cmdConnect, 0, atypIPv4, 192, 0, 2, 1, 0, 80, 'x'))
	f.Add(g(append([]byte{socksVersion, cmdConnect, 0, atypIPv6}, append(net.ParseIP("2001:db8::1"), 1, 187)...)...))
	f.Add(g(socksVersion, cmdConnect, 0, atypDomain, 6, 'a', '.', 't', 'e', 's', 't', 0, 80, 1, 2, 3))
	f.Add(g(socksVersion, cmdConnect, 0, atypDomain, 0, 0, 80))
	f.Add(g(socksVersion, 2, 0, atypIPv4, 192, 0, 2, 1, 0, 80))
	f.Add(g(socksVersion, cmdConnect, 1, atypIPv4, 192, 0, 2, 1, 0, 80))
	f.Add(g(socksVersion, cmdConnect, 0, 5))
	f.Add(g(4, cmdConnect, 0, atypIPv4))
	f.Add([]byte{socksVersion, 2, 0x02, 0x01, 9, 9})
	f.Add([]byte{socksVersion, 0})
	f.Add([]byte{4, 1, 0, 80, 192, 0, 2, 1, 0})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add(g(socksVersion, cmdConnect, 0, atypDomain, 200, 'a'))
	for _, n := range []int{253, 254, 255} { // the longest domains (the buffer's bound)
		f.Add(appendRequest(append([]byte(nil), greeting...), connectReq(string(bytes.Repeat([]byte{'a'}, n)), 80)))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		rd := bytes.NewReader(in)
		br := bufio.NewReaderSize(rd, readerSize)
		var w bytes.Buffer
		req, fail, err := handshake(br, &w)
		// What the parser left: in its reader and still in rd. Counted
		// without reading it, so no coverage counter depends on the
		// length of the tail (io.ReadAll's loop made longer tails look
		// like new coverage).
		consumed := len(in) - br.Buffered() - rd.Len()
		if want := declared(in); consumed != want {
			t.Fatalf("consumed %d bytes of % x, the lengths declare %d", consumed, in, want)
		}
		switch {
		case err != nil:
			if fail != nil || (w.Len() != 0 && !bytes.Equal(w.Bytes(), methodOK)) {
				t.Fatalf("closed without a reply, yet wrote % x and fail % x", w.Bytes(), fail)
			}
		case fail != nil:
			okFail := bytes.Equal(fail, []byte{socksVersion, methodNone})
			for _, rep := range []byte{repBadCommand, repBadAddress, repFailure} {
				okFail = okFail || (bytes.Equal(fail, reply(rep)) && bytes.Equal(w.Bytes(), methodOK))
			}
			if !okFail {
				t.Fatalf("failure reply % x after % x", fail, w.Bytes())
			}
		default:
			if !bytes.Equal(w.Bytes(), methodOK) {
				t.Fatalf("accepted after the method reply % x", w.Bytes())
			}
			start := 2 + int(in[1])
			if enc := appendRequest(nil, req); !bytes.Equal(enc, in[start:consumed]) {
				t.Fatalf("request % x re-encodes as % x", in[start:consumed], enc)
			}
			// What the front end hands l4 is either refused as a bad
			// address (REP 08) or carried as exactly the requested
			// destination: no byte of a domain changes the target.
			md, err := l4.AppendMetadata(nil, l4.Request{Cmd: l4.CmdConnect, Addr: req.hostport()})
			if err != nil {
				if !errors.Is(err, l4.ErrBadAddress) || repOf(err) != repBadAddress {
					t.Fatalf("hostport %q: %v, want l4.ErrBadAddress (REP 08)", req.hostport(), err)
				}
				return
			}
			got, err := l4.ParseMetadata(md)
			if err != nil || !sameDest(got.Addr, req) {
				t.Fatalf("request %+v travels as %q (%v)", req, got.Addr, err)
			}
		}
	})
}
