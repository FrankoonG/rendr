package quic

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
	qgo "github.com/quic-go/quic-go"
)

// streamGoldenALPN is the ALPN the stream encapsulation below is frozen
// under: a new encapsulation needs a new ALPN, and this test changes with
// it.
const streamGoldenALPN = "rendr/2-q1"

// streamGoldenVectors are the rendr bytes the stream golden carries, in
// write order: wire format v2 golden vectors of the root module
// (internal/wire/testdata/golden.txt), embedded so that the test also runs
// from a download of this module alone. The dialer writes a PREFACE and an
// OPEN, the passive answers with a PREFACE_ACK(OK) and an OPEN_ACK(OK): the
// opening of a session carrier.
var streamGoldenVectors = []struct {
	dialer    bool // written by the dialer, else by the passive
	name, hex string
}{
	{true, "preface", "524e44320200010100000000000000000102030405060708090a0b0c0d0e0f10010203041c09cf4e"},
	{true, "open_mlen0", "01000000200000000100000001c0c1c2c3c4c5c6c7c8c9cacbcccdcecf01010000000084d00080000000000000b388654a"},
	{false, "preface_ack_ok", "524e44320200000200000000000000002122232425262728292a2b2c2d2e2f300102030421d564d1"},
	{false, "open_ack_ok", "020000000a000000010000000100008000000000000000c447e003"},
}

// TestQUICStreamGolden freezes the QUIC stream carrier's encapsulation,
// which no vector file under testdata pins (those are the DATAGRAM
// framing): under the ALPN rendr/2-q1, rendr's bytes travel unframed on
// the connection's first client-initiated bidirectional stream, stream 0,
// in both directions, from the stream's first byte to its FIN. Raw quic-go
// peers stand in for a peer that knows only this encapsulation:
//
//   - runtime: a Runtime dials through StreamCarrier to a raw server, which
//     sees stream 0 and reads a dialer's PREFACE (magic RND2, major 2) as
//     its first 40 bytes;
//   - dialer: the bytes a StreamCarrier conn writes are exactly what the raw
//     server reads on stream 0 up to the FIN, and the raw server's bytes on
//     stream 0 are exactly what the conn reads up to the FIN;
//   - listener: the same between a raw client, which writes the root
//     module's preface vector first on stream 0, and the conn a Listener
//     hands to rendr.
//
// In the rendr tree the embedded vectors are also checked against the root
// module's of the same names.
func TestQUICStreamGolden(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	if ALPN != streamGoldenALPN {
		t.Fatalf("ALPN %q, the stream golden's %q: a new encapsulation version updates this test", ALPN, streamGoldenALPN)
	}
	checkRootStreamVectors(t)
	var dw, pw [][]byte // the dialer's and the passive's writes
	for _, v := range streamGoldenVectors {
		b, err := hex.DecodeString(v.hex)
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if v.dialer {
			dw = append(dw, b)
		} else {
			pw = append(pw, b)
		}
	}
	if err := parseStreamPreface(dw[0]); err != nil {
		t.Fatalf("the preface vector: %v", err)
	}
	if err := parseStreamPreface(pw[0]); err == nil {
		t.Fatal("the preface_ack_ok vector parses as a dialer's PREFACE")
	}
	dAll, pAll := bytes.Join(dw, nil), bytes.Join(pw, nil)

	t.Run("runtime", func(t *testing.T) {
		ln, addr := rawStreamServer(t)
		sc, err := StreamCarrier("q", addr, clientOptions(t))
		if err != nil {
			t.Fatal(err)
		}
		rt, err := rendr.NewRuntime(rendr.Config{})
		if err != nil {
			t.Fatal(err)
		}
		peer, err := rt.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{sc}})
		if err != nil {
			_ = rt.Close()
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		dialed := make(chan error, 1)
		go func() {
			c, err := peer.Dial(ctx, rendr.DialOptions{})
			if c != nil {
				_ = c.Close()
			}
			dialed <- err
		}()
		// No PREFACE_ACK comes: the Dial withdraws at the cancel, before
		// the raw server's connection closes.
		stop := sync.OnceFunc(func() {
			cancel()
			<-dialed
			_ = rt.Close()
		})
		t.Cleanup(stop)
		st := acceptStream0(t, ln)
		b := make([]byte, 40)
		_ = st.SetReadDeadline(time.Now().Add(testEventuallyTime))
		if n, err := io.ReadFull(st, b); err != nil {
			t.Fatalf("stream 0's first 40 bytes: %x, %v", b[:n], err)
		}
		if err := parseStreamPreface(b); err != nil {
			t.Errorf("stream 0 starts with %x, not with a dialer's PREFACE: %v", b, err)
		}
		stop()
	})

	t.Run("dialer", func(t *testing.T) {
		ln, addr := rawStreamServer(t)
		sc, err := StreamCarrier("q", addr, clientOptions(t))
		if err != nil {
			t.Fatal(err)
		}
		c, err := sc.Dial(dialCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		for _, b := range dw { // one Write per vector: no Write is framed either
			if _, err := c.Write(b); err != nil {
				t.Fatal(err)
			}
		}
		st := acceptStream0(t, ln)
		got := make([]byte, len(dAll))
		_ = st.SetReadDeadline(time.Now().Add(testEventuallyTime))
		if n, err := io.ReadFull(st, got); err != nil || !bytes.Equal(got, dAll) {
			t.Fatalf("stream 0 at the raw server starts with %x (%v); the conn wrote %x", got[:n], err, dAll)
		}
		for _, b := range pw {
			if _, err := st.Write(b); err != nil {
				t.Fatal(err)
			}
		}
		_ = st.Close() // the raw server's FIN
		_ = c.SetReadDeadline(time.Now().Add(testEventuallyTime))
		if b, err := io.ReadAll(c); err != nil || !bytes.Equal(b, pAll) {
			t.Fatalf("the conn read %x, then %v; the raw server wrote %x and its FIN on stream 0", b, err, pAll)
		}
		_ = st.SetReadDeadline(time.Now().Add(testEventuallyTime))
		rest := streamGoldenReadAll(st)
		_ = c.Close() // the conn's FIN
		if r := <-rest; r.err != nil || len(r.b) != 0 {
			t.Errorf("after the conn's bytes stream 0 carried %x, then %v; want the conn's FIN", r.b, r.err)
		}
	})

	t.Run("listener", func(t *testing.T) {
		l, f := serveFake(t, Options{})
		qc, err := rawTransport(t).Dial(dialCtx(t), l.Addr(), rawClientTLS(t), quicConfig(nil, 0, false, false))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
		if p := qc.ConnectionState().TLS.NegotiatedProtocol; p != streamGoldenALPN {
			t.Fatalf("negotiated ALPN %q, the stream golden's %q", p, streamGoldenALPN)
		}
		st, err := qc.OpenStreamSync(dialCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		if id := st.StreamID(); id != 0 {
			t.Fatalf("the raw client's first bidirectional stream is stream %d, not 0", id)
		}
		for _, b := range dw {
			if _, err := st.Write(b); err != nil {
				t.Fatal(err)
			}
		}
		_ = st.Close() // the raw client's FIN
		c := f.stream(t)
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetReadDeadline(time.Now().Add(testEventuallyTime))
		if b, err := io.ReadAll(c); err != nil || !bytes.Equal(b, dAll) {
			t.Fatalf("the Listener's conn read %x, then %v; the raw client wrote %x and its FIN on stream 0", b, err, dAll)
		}
		for _, b := range pw {
			if _, err := c.Write(b); err != nil {
				t.Fatal(err)
			}
		}
		_ = st.SetReadDeadline(time.Now().Add(testEventuallyTime))
		back := streamGoldenReadAll(st)
		_ = c.Close() // the conn's FIN
		if r := <-back; r.err != nil || !bytes.Equal(r.b, pAll) {
			t.Errorf("stream 0 at the raw client carried %x, then %v; the conn wrote %x and its FIN", r.b, r.err, pAll)
		}
		// classify counts the carrier after the fake rendr took it.
		eventually(t, "the Listener counted one stream carrier", func() bool { return l.Stats().Streams == 1 })
		if s := l.Stats(); s.BadKind+s.ClassifyTimeouts+s.Datagrams != 0 {
			t.Errorf("listener stats %+v, want one stream carrier and nothing else", s)
		}
	})
}

// rawStreamServer is a raw quic-go server with the Listener's TLS and QUIC
// configuration (one client bidirectional stream per connection).
func rawStreamServer(t *testing.T) (*qgo.Listener, string) {
	t.Helper()
	srvTLS, _ := testTLS(t)
	srvTLS.NextProtos = []string{ALPN}
	tr := rawTransport(t)
	ln, err := tr.Listen(srvTLS, quicConfig(nil, 0, true, true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, tr.Conn.LocalAddr().String()
}

// acceptStream0 takes the raw server's next connection, which must have
// negotiated the stream golden's ALPN, and its first stream, which must be
// stream 0: the client's first bidirectional stream (RFC 9000, 2.1).
func acceptStream0(t *testing.T, ln *qgo.Listener) *qgo.Stream {
	t.Helper()
	qc, err := ln.Accept(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	if p := qc.ConnectionState().TLS.NegotiatedProtocol; p != streamGoldenALPN {
		t.Fatalf("negotiated ALPN %q, the stream golden's %q", p, streamGoldenALPN)
	}
	st, err := qc.AcceptStream(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if id := st.StreamID(); id != 0 {
		t.Fatalf("the carrier's bytes arrived on stream %d, not on stream 0 (the client's first bidirectional stream)", id)
	}
	return st
}

// streamGoldenRead is what streamGoldenReadAll read.
type streamGoldenRead struct {
	b   []byte
	err error
}

// streamGoldenReadAll reads r to its end on a goroutine of its own.
func streamGoldenReadAll(r io.Reader) <-chan streamGoldenRead {
	ch := make(chan streamGoldenRead, 1)
	go func() {
		b, err := io.ReadAll(r)
		ch <- streamGoldenRead{b, err}
	}()
	return ch
}

// streamGoldenCRC is the CRC32C (Castagnoli) table of rendr's PREFACE.
var streamGoldenCRC = crc32.MakeTable(crc32.Castagnoli)

// parseStreamPreface checks b as a dialer's PREFACE of a stream carrier,
// in the order of the root module's wire.ParsePreface (internal to that
// module, so restated here): 40 bytes, the magic "RND2", the CRC32C of
// bytes 0-35 in bytes 36-39, major 2, role 1 (dialer), kind 1 (stream),
// and a non-zero instance and carrier ID.
func parseStreamPreface(b []byte) error {
	switch {
	case len(b) != 40:
		return fmt.Errorf("%d bytes, not 40", len(b))
	case string(b[:4]) != "RND2":
		return fmt.Errorf("magic %q, not %q", b[:4], "RND2")
	case crc32.Checksum(b[:36], streamGoldenCRC) != binary.BigEndian.Uint32(b[36:]):
		return errors.New("bytes 36-39 are not the CRC32C of bytes 0-35")
	case b[4] != 2:
		return fmt.Errorf("major %d, not 2", b[4])
	case b[7] != 1:
		return fmt.Errorf("role %d, not 1 (dialer)", b[7])
	case b[6] != 1:
		return fmt.Errorf("kind %d, not 1 (stream)", b[6])
	case bytes.Equal(b[16:32], make([]byte, 16)) || binary.BigEndian.Uint32(b[32:36]) == 0:
		return errors.New("a zero instance or carrier ID")
	}
	return nil
}

// checkRootStreamVectors compares streamGoldenVectors with the root
// module's wire golden vectors of the same names. In the rendr tree the
// root module's vector file must be there; a download of this module alone
// has no root module above it, and the comparison is left out.
func checkRootStreamVectors(t *testing.T) {
	t.Helper()
	root, err := frozenModuleRoot("github.com/FrankoonG/rendr/v2")
	if err != nil {
		t.Logf("%v: the embedded vectors are compared with the root module's in the rendr tree only", err)
		return
	}
	b, err := os.ReadFile(filepath.Join(root, "internal", "wire", "testdata", "golden.txt"))
	if err != nil {
		t.Fatalf("the root module's wire golden vectors: %v", err)
	}
	have := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			have[f[0]] = f[1]
		}
	}
	for _, v := range streamGoldenVectors {
		if have[v.name] != v.hex {
			t.Errorf("%s is not the root module's wire golden vector of that name (%q)", v.name, have[v.name])
		}
	}
}
