package quic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
	qgo "github.com/quic-go/quic-go"
)

// update rewrites testdata/dgram-q1.txt from what a dialer carrier sends.
// Use it only for a deliberate change of the carrier's encapsulation, which
// needs a new ALPN; testdata/frozen.sha256 changes with it (-refreeze).
var update = flag.Bool("update", false, "rewrite testdata/dgram-q1.txt from a dialer carrier (a new ALPN only)")

const dgramGoldenPath = "testdata/dgram-q1.txt"

const dgramGoldenHeader = `# rendr QUIC carrier DATAGRAM encapsulation golden vectors, one
# "dgram <name> <hex>" line per DATAGRAM payload, in the order a dialer
# carrier sent them, after the negotiated ALPN. Each payload is the
# direction's 4-byte big-endian sequence number (from 0, one per datagram
# handed to quic-go) followed by one rendr datagram; the datagrams are the
# root module's wire golden vectors of the same names.
# Regenerate only with: go test -run TestQUICDatagramGolden -update
# (a new ALPN), then refreeze testdata/frozen.sha256.
`

// dgramGoldenInner are the rendr datagrams of the vectors: frames of the
// root module's internal/wire/testdata/golden.txt (wire format v2).
var dgramGoldenInner = []struct{ name, hex string }{
	{"dgram_empty", "20000000080000000c000000010000000000000001d867a5dc"},
	{"dgram_handle_3", "20000000480000000c000000030000000000000009de6b02e8a48bbb97e65abd2f18544440f3bf3cf9043eb01ef036f7c787e49dde903b12564f7f152cd6a2de1e10610e2e8f1e57d5107ceb08d4bca6ec9edafa58c8506e3e"},
	{"dgram_seq_max", "20000000090000000c000000013fffffffffffffff5a630450c8"},
}

// dgramGolden is a parsed testdata/dgram-q1.txt.
type dgramGolden struct {
	alpn  string
	names []string
	dgs   [][]byte
}

func readDgramGolden(b []byte) (*dgramGolden, error) {
	g := &dgramGolden{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 2 && f[0] == "alpn" && g.alpn == "":
			g.alpn = f[1]
		case len(f) == 3 && f[0] == "dgram":
			d, err := hex.DecodeString(f[2])
			if err != nil {
				return nil, fmt.Errorf("%s: %v", f[1], err)
			}
			g.names, g.dgs = append(g.names, f[1]), append(g.dgs, d)
		default:
			return nil, fmt.Errorf("malformed line %q", line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if g.alpn == "" || len(g.dgs) == 0 {
		return nil, errors.New("no alpn line or no dgram line")
	}
	return g, nil
}

func (g *dgramGolden) format() []byte {
	var b bytes.Buffer
	b.WriteString(dgramGoldenHeader)
	fmt.Fprintf(&b, "alpn %s\n", g.alpn)
	for i, d := range g.dgs {
		fmt.Fprintf(&b, "dgram %s %x\n", g.names[i], d)
	}
	return b.Bytes()
}

// TestQUICDatagramGolden freezes the QUIC carrier's DATAGRAM encapsulation
// (KL-19, ALPN rendr/2-q1) with golden vectors generated from the code: a
// dialer carrier writes the vectors' rendr datagrams to a raw quic-go
// server, which must negotiate the file's ALPN and receive exactly the
// file's DATAGRAM payloads; then a raw quic-go client sends the file's
// payloads to a Listener, whose carrier must deliver exactly the rendr
// datagrams and count no drop. The passive's reading of the sequence
// number is pinned by continuing the file's numbering in code past a
// stall: the drops quic-go's full queue made must be counted exactly from
// the gap. In-tree, the rendr datagrams are also checked against the root
// module's wire golden vectors of the same names.
func TestQUICDatagramGolden(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	inner := make([][]byte, len(dgramGoldenInner))
	for i, v := range dgramGoldenInner {
		b, err := hex.DecodeString(v.hex)
		if err != nil {
			t.Fatal(err)
		}
		inner[i] = b
	}
	checkRootWireVectors(t)

	// Dialer: what the code sends.
	srvTLS, _ := testTLS(t)
	srvTLS.NextProtos = []string{ALPN}
	str := rawTransport(t)
	ln, err := str.Listen(srvTLS, quicConfig(nil, 0, true, true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	dc, err := DatagramCarrier("q", str.Conn.LocalAddr().String(), clientOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	pc, _, err := dc.Dial(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	srv, err := ln.Accept(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.CloseWithError(0, "") })
	got := &dgramGolden{alpn: srv.ConnectionState().TLS.NegotiatedProtocol}
	for i, d := range inner {
		if _, err := pc.WriteTo(d, nil); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), testEventuallyTime)
		b, err := srv.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		got.names, got.dgs = append(got.names, dgramGoldenInner[i].name), append(got.dgs, b)
	}
	if *update {
		if err := os.WriteFile(dgramGoldenPath, got.format(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(dgramGoldenPath)
	if err != nil {
		t.Fatalf("%v (go test -run TestQUICDatagramGolden -update writes it)", err)
	}
	want, err := readDgramGolden(raw)
	if err != nil {
		t.Fatalf("%s: %v", dgramGoldenPath, err)
	}
	if want.alpn != ALPN || got.alpn != want.alpn {
		t.Errorf("ALPN: file %q, negotiated %q, constant %q: the encapsulation is versioned by the ALPN", want.alpn, got.alpn, ALPN)
	}
	if len(want.dgs) != len(got.dgs) {
		t.Fatalf("%s holds %d DATAGRAMs, the carrier sent %d", dgramGoldenPath, len(want.dgs), len(got.dgs))
	}
	for i := range want.dgs {
		if want.names[i] != got.names[i] || !bytes.Equal(want.dgs[i], got.dgs[i]) {
			t.Errorf("DATAGRAM %d: the carrier sent %s %x, the file holds %s %x", i, got.names[i], got.dgs[i], want.names[i], want.dgs[i])
		}
	}

	// Passive: the file's payloads are what a carrier accepts.
	ft := &frameTracer{}
	l, f := serveFake(t, Options{Config: &qgo.Config{Tracer: ft.trace}})
	qc, err := rawTransport(t).Dial(dialCtx(t), l.Addr(), rawClientTLS(t), quicConfig(nil, 0, false, true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	for _, d := range want.dgs {
		if err := qc.SendDatagram(d); err != nil {
			t.Fatal(err)
		}
	}
	d := f.packet(t)
	t.Cleanup(func() { _ = d.Close() })
	buf := make([]byte, DatagramBudget+1)
	_ = d.SetReadDeadline(time.Now().Add(testEventuallyTime))
	for i, w := range inner {
		if n, _, err := d.ReadFrom(buf); err != nil || !bytes.Equal(buf[:n], w) {
			t.Fatalf("passive datagram %d: %x, %v; want %x", i, buf[:n], err, w)
		}
	}
	if s := l.Stats(); s.DatagramDrops != 0 {
		t.Errorf("DatagramDrops %d after the file's consecutive sequence numbers, want 0", s.DatagramDrops)
	}

	// Passive: how it reads the number. The file's numbering continues in
	// code (the header's rule: one per datagram, big-endian, before the
	// datagram); a burst the held pump does not take overflows quic-go's
	// 128-entry queue, and the passive counts exactly the drops the next
	// number's gap shows - a passive that read the number at another
	// offset, in another byte order or not at all counts another number.
	next := uint32(len(want.dgs))
	payload := func(k int) []byte { return inner[k%len(inner)] }
	var burst [][]byte
	for k := range 200 {
		burst = append(burst, append(binary.BigEndian.AppendUint32(nil, next+uint32(k)), payload(k)...))
	}
	parked, release := holdPump(t, d)
	rawSendTraced(t, qc, ft, burst...)
	kept := pinnedRcvQueue + parked() // what the pump took as the hold began, and quic-go's queue
	release()
	eventually(t, "the pump drained quic-go's queue", func() bool { return queued(d) == kept })
	rawSendTraced(t, qc, ft, append(binary.BigEndian.AppendUint32(nil, next+uint32(len(burst))), payload(len(burst))...))
	eventually(t, "the trailing datagram arrived", func() bool { return queued(d) == kept+1 })
	_ = d.SetReadDeadline(time.Now().Add(testEventuallyTime))
	for k := range kept + 1 {
		w := payload(k)
		if k == kept {
			w = payload(len(burst))
		}
		if n, _, err := d.ReadFrom(buf); err != nil || !bytes.Equal(buf[:n], w) {
			t.Fatalf("passive datagram %d after the file's: %x, %v; want %x", k, buf[:n], err, w)
		}
	}
	if s := l.Stats(); s.DatagramDrops != uint64(len(burst)-kept) {
		t.Errorf("DatagramDrops %d after DATAGRAMs %d … %d of which quic-go dropped %d … %d: want %d, counted from %d's gap",
			s.DatagramDrops, next, next+uint32(len(burst)), next+uint32(kept), next+uint32(len(burst))-1, len(burst)-kept, next+uint32(len(burst)))
	}
}

// checkRootWireVectors compares dgramGoldenInner with the root module's
// wire golden vectors when the tree holds them (in-tree builds; a module
// download of the quic module carries only its own directory).
func checkRootWireVectors(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "internal", "wire", "testdata", "golden.txt"))
	if err != nil {
		t.Logf("root wire vectors not in the tree (%v): compared in-tree only", err)
		return
	}
	root := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			root[f[0]] = f[1]
		}
	}
	for _, v := range dgramGoldenInner {
		if root[v.name] != v.hex {
			t.Errorf("%s is not the root wire golden vector of that name (%q)", v.name, root[v.name])
		}
	}
}
