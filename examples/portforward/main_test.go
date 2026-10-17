package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
)

// childEnv makes the test binary run main (TestPortForwardExampleSignalExit's
// children).
const childEnv = "RENDR_PORTFORWARD_TEST_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// output is a subcommand's log, safe for concurrent use; a waiter wakes on
// every write (no polling).
type output struct {
	mu      sync.Mutex
	b       bytes.Buffer
	changed chan struct{}
}

func newOutput() *output { return &output{changed: make(chan struct{})} }

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	close(o.changed)
	o.changed = make(chan struct{})
	return o.b.Write(p)
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.String()
}

// wait returns the submatches of the first match of the line pattern re
// in the output, waiting up to d for it to appear.
func (o *output) wait(t *testing.T, re *regexp.Regexp, d time.Duration) []string {
	t.Helper()
	return o.waitN(t, re, 1, d)[0]
}

// waitN returns the first n matches of the line pattern re (one that
// spans no line end) in the output, waiting up to d for them. Every line
// is scanned once.
func (o *output) waitN(t *testing.T, re *regexp.Regexp, n int, d time.Duration) [][]string {
	t.Helper()
	timer := time.NewTimer(d)
	defer timer.Stop()
	var got [][]string
	for pos := 0; ; {
		o.mu.Lock()
		b := o.b.Bytes()[pos:]
		seg, ch := string(b[:bytes.LastIndexByte(b, '\n')+1]), o.changed
		o.mu.Unlock()
		pos += len(seg)
		if got = append(got, re.FindAllStringSubmatch(seg, -1)...); len(got) >= n {
			return got[:n]
		}
		select {
		case <-ch:
		case <-timer.C:
			t.Fatalf("%d of %d matches of %q within %v in %q", len(got), n, re, d, o.String())
			return nil
		}
	}
}

// proc is one subcommand run in this process.
type proc struct {
	out    *output
	cancel context.CancelFunc
	code   chan int
}

// start runs the subcommand args until stop or the test's end.
func start(t *testing.T, args ...string) *proc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &proc{out: newOutput(), cancel: cancel, code: make(chan int, 1)}
	go func() { p.code <- run(ctx, args, p.out) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-p.code:
		case <-time.After(15 * time.Second):
			t.Errorf("%q still running 15 s after its stop", args)
		}
	})
	return p
}

// stop stops p and checks its exit through the shutdown path (status 0,
// "<sub>: stopped" logged) within the 5-s stop bound and a margin.
func (p *proc) stop(t *testing.T, sub string) {
	t.Helper()
	p.cancel()
	select {
	case code := <-p.code:
		p.code <- code
		if code != 0 || !strings.Contains(p.out.String(), sub+": stopped") {
			t.Fatalf("%s: status %d after its stop, want 0 and %q; output %q", sub, code, sub+": stopped", p.out)
		}
	case <-time.After(8 * time.Second):
		t.Fatalf("%s still running 8 s after its stop; output %q", sub, p.out)
	}
}

var (
	serverLine  = regexp.MustCompile(`server: rendr carriers on (\S+) \(tcp and udp\)`)
	forwardLine = regexp.MustCompile(`client: (udp|tcp) (\S+) to (\S+)`)
)

// startServer runs the server subcommand on a free loopback port and
// returns it with its carrier address.
func startServer(t *testing.T, args ...string) (*proc, string) {
	t.Helper()
	p := start(t, append([]string{"server", "-rendr", "127.0.0.1:0"}, args...)...)
	return p, p.out.wait(t, serverLine, 10*time.Second)[1]
}

// startClient runs the client subcommand with the given -L forwards
// (proto:target; the local address is a free loopback port) and returns
// it with each forward's local address by its -L.
func startClient(t *testing.T, rendrAddr string, fwds []string, args ...string) (*proc, map[string]string) {
	t.Helper()
	a := append([]string{"client", "-rendr", rendrAddr}, args...)
	for _, f := range fwds {
		proto, target, _ := strings.Cut(f, ":")
		a = append(a, "-L", proto+":127.0.0.1:0="+target)
	}
	p := start(t, a...)
	local := map[string]string{}
	for _, m := range p.out.waitN(t, forwardLine, len(fwds), 10*time.Second) {
		local[m[1]+":"+m[3]] = m[2]
	}
	return p, local
}

// TestPortForwardExampleFlags (M6-D31, PA-95): a -L that does not resolve
// to a loopback address exits with status 2 and names the rule unless
// -allow-nonloopback; malformed forwards, targets, modes, sizes, -allow
// entries and stray arguments exit with status 2 before any socket is
// bound; loopback forwards (a name included) serve on loopback until ctx
// ends (status 0).
func TestPortForwardExampleFlags(t *testing.T) {
	for _, l := range []string{"udp:0.0.0.0:0", "tcp:0.0.0.0:0", "udp:[::]:0", "tcp::0", "udp::5000", "udp:192.0.2.1:5000", "tcp:198.51.100.7:0", "udp:[2001:db8::1]:53"} {
		var out bytes.Buffer
		code := run(context.Background(), []string{"client", "-L", l + "=192.0.2.10:53"}, &out)
		if code != 2 || !strings.Contains(out.String(), "not a loopback address") || !strings.Contains(out.String(), "-allow-nonloopback") || forwardLine.MatchString(out.String()) {
			t.Errorf("-L %s: status %d, output %q; want 2 and the loopback rule before any bind", l, code, out.String())
		}
	}
	for _, args := range [][]string{
		nil, {"relay"}, {"client"}, {"client", "extra"},
		{"client", "-L", "127.0.0.1:0=192.0.2.10:53"},      // no protocol
		{"client", "-L", "sctp:127.0.0.1:0=192.0.2.10:53"}, // unknown protocol
		{"client", "-L", "udp:127.0.0.1:0"},                // no target
		{"client", "-L", "udp:=192.0.2.10:53"},             // no local address
		{"client", "-L", "udp:127.0.0.1:0=192.0.2.10"},     // no target port
		{"client", "-L", "udp:127.0.0.1:0=192.0.2.10:0"},   // port 0
		{"client", "-L", "udp:127.0.0.1:0=224.0.0.1:53"},   // multicast target
		{"client", "-L", "udp:127.0.0.1:0=[::]:53"},        // unspecified target
		{"client", "-L", "udp:127.0.0.1:0=bad_name!:53"},   // not a domain
		{"client", "-L", "udp:127.0.0.1:99999=192.0.2.10:53"},
		{"client", "-L", "udp:127.0.0.1:0=192.0.2.10:53", "-mode", "fast"},
		{"client", "-L", "udp:127.0.0.1:0=192.0.2.10:53", "-max-datagram", "545"},
		{"client", "-L", "udp:127.0.0.1:0=192.0.2.10:53", "-max-datagram", "65508"},
		{"client", "-L", "udp:127.0.0.1:0=192.0.2.10:53", "-allow", "192.0.2.10:53"}, // a server flag
		{"server", "-L", "udp:127.0.0.1:0=192.0.2.10:53"},                            // a client flag
		{"server", "-allow", "192.0.2.10"},
		{"server", "-allow", "255.255.255.255:9"},
		{"server", "-mode", "race"},
		{"server", "extra"},
	} {
		var out bytes.Buffer
		if code := run(context.Background(), args, &out); code != 2 || !strings.Contains(out.String(), "usage: portforward") || forwardLine.MatchString(out.String()) {
			t.Errorf("args %q: status %d, output %q; want 2 and the usage before any bind", args, code, out.String())
		}
	}
	// Loopback forms serve on loopback; the stop is status 0.
	p := start(t, "client", "-rendr", "127.0.0.1:1", "-L", "udp:127.0.0.1:0=192.0.2.10:53", "-L", "tcp:localhost:0=192.0.2.10:80", "-L", "udp:[::1]:0=[2001:db8::1]:53", "-mode", "race")
	for _, m := range p.out.waitN(t, forwardLine, 3, 10*time.Second) {
		if ap, err := net.ResolveTCPAddr("tcp", m[2]); err != nil || !ap.IP.IsLoopback() {
			t.Errorf("%s forward listens on %s, want a loopback address", m[1], m[2])
		}
	}
	p.stop(t, "client")
	// -allow-nonloopback lets a wildcard -L through: on Linux only, where a
	// wildcard bind in a test is harmless (a Windows host may prompt).
	if runtime.GOOS == "linux" {
		p := start(t, "client", "-rendr", "127.0.0.1:1", "-allow-nonloopback", "-L", "udp:0.0.0.0:0=192.0.2.10:53", "-L", "tcp:0.0.0.0:0=192.0.2.10:80")
		for _, m := range p.out.waitN(t, forwardLine, 2, 10*time.Second) {
			if ap, err := net.ResolveTCPAddr("tcp", m[2]); err != nil || !ap.IP.IsUnspecified() {
				t.Errorf("%s forward listens on %s, want the wildcard", m[1], m[2])
			}
		}
		p.stop(t, "client")
	}
}

// TestPortForwardExampleStatusLine (M6-D31): a status line names every
// non-zero field of the l4 status by its field name, nested ones with
// their struct's name, ByCode by the code's text in code order, LastErr
// quoted, then the carrier deaths by cause; zero fields are left out.
func TestPortForwardExampleStatusLine(t *testing.T) {
	var u l4.UDPForwardStatus
	fill(t, reflect.ValueOf(&u).Elem(), new(uint64))
	var d carrierDeaths
	for _, ev := range []rendr.Event{
		{Kind: rendr.EventCarrierDown, Cause: rendr.CausePingTimeout},
		{Kind: rendr.EventCarrierDown, Cause: rendr.CausePingTimeout},
		{Kind: rendr.EventCarrierDown, Cause: rendr.CauseTransportError},
		{Kind: rendr.EventCarrierDown, Cause: rendr.CauseLocalClose}, // not a death
		{Kind: rendr.EventCarrierDown, Cause: rendr.CauseRetired},    // not a death
		{Kind: rendr.EventCarrierUp},
		{Kind: rendr.EventMigration, Cause: rendr.CauseQuality},
	} {
		d.event(ev)
	}
	got := string(statusLine("udp", u, &d))
	var want []string
	n := uint64(0)
	for i := range reflect.TypeOf(u).NumField() {
		switch f := reflect.TypeOf(u).Field(i); f.Type.Kind() {
		case reflect.Int, reflect.Uint64:
			n++
			want = append(want, fmt.Sprintf(" %s=%d", f.Name, n))
		case reflect.Struct:
			for j := range f.Type.NumField() {
				n++
				want = append(want, fmt.Sprintf(" %s.%s=%d", f.Name, f.Type.Field(j).Name, n))
			}
		case reflect.Map:
			want = append(want, " ByCode(bad request)=7 ByCode(not allowed)=5 ByCode(dial failed)=9")
		case reflect.Interface:
			want = append(want, ` LastErr="l4: target not allowed: 192.0.2.1:53"`)
		default:
			t.Fatalf("field %s of kind %v: the test does not know it", f.Name, f.Type.Kind())
		}
	}
	want = append(want, " CarrierDeaths(ping_timeout)=2 CarrierDeaths(transport_error)=1")
	if w := "udp:" + strings.Join(want, ""); got != w {
		t.Fatalf("status line\n got %s\nwant %s", got, w)
	}
	var zero carrierDeaths
	if got := string(statusLine("tcp", l4.TCPForwardStatus{}, &zero)); got != "tcp:" {
		t.Fatalf("zero status line %q, want %q", got, "tcp:")
	}
	if got := string(statusLine("l4", l4.ServerStatus{UDP: l4.UDPServerStatus{TooLarge: 3}}, &zero)); got != "l4: UDP.TooLarge=3" {
		t.Fatalf("server status line %q, want %q", got, "l4: UDP.TooLarge=3")
	}
}

// fill gives every number field of v (nested structs included) the next
// value of *n, ByCode three codes out of order and LastErr an error.
func fill(t *testing.T, v reflect.Value, n *uint64) {
	for i := range v.NumField() {
		switch f := v.Field(i); f.Kind() {
		case reflect.Int:
			*n++
			f.SetInt(int64(*n))
		case reflect.Uint64:
			*n++
			f.SetUint(*n)
		case reflect.Struct:
			fill(t, f, n)
		case reflect.Map:
			f.Set(reflect.ValueOf(map[l4.RejectCode]uint64{l4.CodeDialFailed: 9, l4.CodeNotAllowed: 5, l4.CodeBadRequest: 7}))
		case reflect.Interface:
			f.Set(reflect.ValueOf(fmt.Errorf("%w: 192.0.2.1:53", l4.ErrDenied)))
		}
	}
}
