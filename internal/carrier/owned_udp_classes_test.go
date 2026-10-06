package carrier

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// wp5TempErr is an error reporting Temporary(), as an EINTR or EMFILE does
// through the net package's wrappers.
type wp5TempErr struct{ temp bool }

func (e wp5TempErr) Error() string   { return "wp5 temporary error" }
func (e wp5TempErr) Temporary() bool { return e.temp }

// wp5OpErr wraps err as the net package returns a socket call's error.
func wp5OpErr(op string, err error) error {
	return &net.OpError{Op: op, Net: "udp", Err: os.NewSyscallError("wp5"+op, err)}
}

// wp5Errnos are one OS's rows of the error table of rendr's own UDP sockets
// (owned_udp_*_test.go): nil and empty where the OS has none.
type wp5Errnos struct {
	noise     []error // noise on a read and on a write
	sendNoise []error // noise on a write, death on a read (a local packet filter's refusal)
	abort     error   // death on a dialer socket, noise on a listening one
	msgSize   error   // a truncated read, a too-large write
	others    []error // death everywhere
}

// Outcomes of one injected error.
const (
	wp5Death     = iota // read or write: the injected error itself is returned (death, or the caller's deadline)
	wp5Noise            // read: ReadNoise with a nil error; write: ErrNoise
	wp5Truncated        // read: ReadTruncated with a nil error
	wp5TooLarge         // write: a *wire.DatagramTooLargeError with Max 0
)

// TestOwnedUDPErrorClasses: the error table of rendr's own UDP sockets (M2
// design §A6.4) over injected errnos of this OS (owned_udp_*_test.go).
// Reads: ICMP-class errors and ENOBUFS are ReadNoise with a nil error (L58,
// plan:638); EMSGSIZE is a truncation (how Windows fails a truncated read);
// ECONNABORTED ends a dialer socket (an administrative abort unhashes its
// auto-bound port) but is noise on a listening one; the caller's deadline —
// Temporary() too, so it must be judged first — a closed socket and every
// other error are returned. Writes: EMSGSIZE is a
// *wire.DatagramTooLargeError with Max 0, noise ErrNoise, ECONNABORTED death
// on a dialer and noise on a listener, an invalid count death (L42); a
// local packet filter's refusal (EPERM on Unix) loses the datagram, not the
// carrier (M2-D14), but a read never fails so and an EPERM there is death.
// The net.PacketConn view of a dialer token returns a noise error that is
// Temporary() and matches ErrNoise and the errno, which an embedder's
// wrapper hands to NewPacketIO's one table. The "real" subtest proves the
// rows a loopback socket can produce: an oversize datagram is refused by
// the kernel as too large through both tokens, which keep working; an
// expired deadline reaches the caller as a timeout; a closed socket fails
// with net.ErrClosed. The "icmp" subtest proves the ICMP-derived noise
// rows on a real socket where the OS reports them (wp5ReportICMP).
func TestOwnedUDPErrorClasses(t *testing.T) {
	errnos := wp5ErrnoCases()
	type row struct {
		name                   string
		err                    error
		dialerRead, sockRead   int
		dialerWrite, sockWrite int
	}
	deadline := &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
	var rows []row
	for _, e := range errnos.noise {
		rows = append(rows, row{"noise " + e.Error(), wp5OpErr("read", e), wp5Noise, wp5Noise, wp5Noise, wp5Noise})
	}
	for _, e := range errnos.sendNoise {
		rows = append(rows, row{"send noise " + e.Error(), wp5OpErr("read", e), wp5Death, wp5Death, wp5Noise, wp5Noise})
	}
	if errnos.abort != nil {
		rows = append(rows, row{"abort", wp5OpErr("read", errnos.abort), wp5Death, wp5Noise, wp5Death, wp5Noise})
	}
	if errnos.msgSize != nil {
		rows = append(rows, row{"msgsize", wp5OpErr("read", errnos.msgSize), wp5Truncated, wp5Truncated, wp5TooLarge, wp5TooLarge})
	}
	rows = append(rows,
		row{"deadline", deadline, wp5Death, wp5Death, wp5Death, wp5Death},
		row{"closed", &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}, wp5Death, wp5Death, wp5Death, wp5Death},
		row{"temporary", &net.OpError{Op: "read", Net: "udp", Err: wp5TempErr{true}}, wp5Noise, wp5Noise, wp5Noise, wp5Noise},
		row{"not temporary", &net.OpError{Op: "read", Net: "udp", Err: wp5TempErr{false}}, wp5Death, wp5Death, wp5Death, wp5Death},
	)
	for _, e := range errnos.others {
		rows = append(rows, row{"other " + e.Error(), wp5OpErr("read", e), wp5Death, wp5Death, wp5Death, wp5Death})
	}
	var tmp interface{ Temporary() bool }
	if !errors.As(error(deadline), &tmp) || !tmp.Temporary() {
		t.Fatal("premise: an expired deadline reports Temporary(), so the deadline rule must come first")
	}

	o := &OwnedUDP{limit: wp5MaxDatagram, recv: wp5MaxDatagram - 9}
	s := &OwnedUDPSocket{limit: wp5MaxDatagram}
	b := make([]byte, wp5MaxDatagram+1)
	checkRead := func(who string, r row, want int, data []byte, ev ReadEvent, err error) {
		t.Helper()
		ok := data == nil
		switch want {
		case wp5Death:
			ok = ok && err == r.err
		case wp5Noise:
			ok = ok && err == nil && ev == ReadNoise
		case wp5Truncated:
			ok = ok && err == nil && ev == ReadTruncated
		}
		if !ok {
			t.Errorf("%s read, %s: event %d, error %v, %d bytes; want outcome %d", who, r.name, ev, err, len(data), want)
		}
	}
	checkWrite := func(who string, r row, want int, err error) {
		t.Helper()
		var tl *wire.DatagramTooLargeError
		ok := false
		switch want {
		case wp5Death:
			ok = err == r.err
		case wp5Noise:
			ok = err == ErrNoise
		case wp5TooLarge:
			ok = errors.Is(err, wire.ErrDatagramTooLarge) && errors.As(err, &tl) && tl.Max == 0
		}
		if !ok {
			t.Errorf("%s write, %s: %v; want outcome %d", who, r.name, err, want)
		}
	}
	for _, r := range rows {
		data, _, ev, err := o.readResult(b, -1, 0, netip.AddrPort{}, r.err)
		checkRead("dialer", r, r.dialerRead, data, ev, err)
		_, _, ev, err = s.readResult(b, -1, 0, netip.AddrPort{}, r.err)
		checkRead("listener", r, r.sockRead, nil, ev, err)
		checkWrite("dialer", r, r.dialerWrite, udpWriteResult(-1, 100, r.err, false))
		checkWrite("listener", r, r.sockWrite, udpWriteResult(-1, 100, r.err, true))

		// The dialer token's net.PacketConn view: a noise error instead of
		// the bare ErrNoise, everything else as WriteDatagram reports it.
		verr := viewWriteResult(-1, 100, r.err)
		if r.dialerWrite == wp5Noise {
			wp5CheckNoiseError(t, "view write, "+r.name, verr, r.err)
		} else {
			checkWrite("view", r, r.dialerWrite, verr)
		}
	}

	// Counts (L42): a read count outside the buffer and a write count other
	// than the datagram's length end the carrier; the exact count is
	// success.
	for _, n := range []int{-1, len(b) + 1} {
		if _, _, _, err := o.readResult(b, n, 0, netip.AddrPort{}, nil); !errors.Is(err, errUDPReadCount) {
			t.Errorf("dialer read count %d: %v", n, err)
		}
		if _, _, _, err := s.readResult(b, n, 0, netip.AddrPort{}, nil); !errors.Is(err, errUDPReadCount) {
			t.Errorf("listener read count %d: %v", n, err)
		}
	}
	for _, n := range []int{100 - 3, 0, -1, 100 + 1} {
		for _, listening := range []bool{false, true} {
			if err := udpWriteResult(n, 100, nil, listening); !errors.Is(err, errUDPWriteCount) {
				t.Errorf("write count %d of 100 (listening %v): %v", n, listening, err)
			}
		}
		if err := viewWriteResult(n, 100, nil); !errors.Is(err, errUDPWriteCount) {
			t.Errorf("view write count %d of 100: %v", n, err)
		}
	}
	if err := udpWriteResult(100, 100, nil, false); err != nil {
		t.Errorf("an exact write: %v", err)
	}
	if err := viewWriteResult(100, 100, nil); err != nil {
		t.Errorf("an exact view write: %v", err)
	}

	t.Run("real", func(t *testing.T) {
		defer g10NoLeak(t)()
		raw, _ := wp5Listen(t, "udp4")
		defer raw.Close()
		su, _ := wp5Listen(t, "udp4")
		s := NewOwnedUDPSocket(su, wp5MaxDatagram)
		defer s.Close()
		du, _ := wp5Listen(t, "udp4")
		o := NewOwnedUDP(du, wp5AP(raw), wp5Flow, wire.MaxDatagram)
		defer o.Close()
		huge := make([]byte, wire.MaxDatagram+1) // above the largest IPv4 UDP payload
		var tl *wire.DatagramTooLargeError
		if err := o.WriteDatagram(huge); !errors.As(err, &tl) || tl.Max != 0 {
			t.Fatalf("dialer: an oversize datagram: %v; want a DatagramTooLargeError with Max 0", err)
		}
		if err := s.WriteAddrPort(huge, wp5AP(raw)); !errors.As(err, &tl) || tl.Max != 0 {
			t.Fatalf("listener: an oversize datagram: %v; want a DatagramTooLargeError with Max 0", err)
		}
		if err := o.WriteDatagram(wp5Datagram(wp5Flow, 50)); err != nil {
			t.Fatalf("dialer after the refusal: %v", err)
		}
		if err := s.WriteAddrPort([]byte("after"), wp5AP(raw)); err != nil {
			t.Fatalf("listener after the refusal: %v", err)
		}
		got := make([]byte, 100)
		for _, want := range [][]byte{wp5Datagram(wp5Flow, 50), []byte("after")} {
			raw.SetReadDeadline(time.Now().Add(10 * time.Second))
			if n, _, err := raw.ReadFromUDPAddrPort(got); err != nil || !bytes.Equal(got[:n], want) {
				t.Fatalf("the peer read % x, %v; want % x", got[:n], err, want)
			}
		}

		// An expired deadline reaches the caller as a timeout (never noise);
		// a closed socket ends the carrier.
		past := time.Now().Add(-time.Second)
		o.SetDeadline(past)
		s.SetDeadline(past)
		if _, _, ev, err := o.ReadDatagram(make([]byte, o.ReadSize())); !errors.Is(err, os.ErrDeadlineExceeded) || ev == ReadNoise {
			t.Errorf("dialer read past its deadline: event %d, %v; want the timeout", ev, err)
		}
		if _, _, ev, err := s.ReadAddrPort(make([]byte, s.MaxDatagram()+1)); !errors.Is(err, os.ErrDeadlineExceeded) || ev == ReadNoise {
			t.Errorf("listener read past its deadline: event %d, %v; want the timeout", ev, err)
		}
		if err := o.WriteDatagram(wp5Datagram(wp5Flow, 50)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("dialer write past its deadline: %v; want the timeout", err)
		}
		if err := s.WriteAddrPort([]byte("late"), wp5AP(raw)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("listener write past its deadline: %v; want the timeout", err)
		}
		if _, _, err := o.ReadFrom(make([]byte, 100)); !errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrNoise) {
			t.Errorf("dialer ReadFrom past its deadline: %v; want the timeout", err)
		}
		o.Close()
		s.Close()
		if _, _, _, err := o.ReadDatagram(make([]byte, o.ReadSize())); !errors.Is(err, net.ErrClosed) {
			t.Errorf("dialer read after Close: %v; want net.ErrClosed", err)
		}
		if _, _, _, err := s.ReadAddrPort(make([]byte, s.MaxDatagram()+1)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener read after Close: %v; want net.ErrClosed", err)
		}
		if err := o.WriteDatagram(wp5Datagram(wp5Flow, 50)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("dialer write after Close: %v; want net.ErrClosed", err)
		}
	})

	t.Run("icmp", func(t *testing.T) {
		defer g10NoLeak(t)()
		gone, _ := wp5Listen(t, "udp4")
		dead := wp5AP(gone)
		gone.Close() // nothing listens at dead any more: a datagram to it draws an ICMP port unreachable
		du, _ := wp5Listen(t, "udp4")
		o := NewOwnedUDP(du, dead, wp5Flow, wp5MaxDatagram)
		defer o.Close()
		errno := wp5ReportICMP(t, du)
		if errno == nil {
			t.Logf("no ICMP-derived errors are read on this OS (owned_udp_*_test.go): the injected rows cover it")
			return
		}
		su, _ := wp5Listen(t, "udp4")
		s := NewOwnedUDPSocket(su, wp5MaxDatagram)
		defer s.Close()
		wp5ReportICMP(t, su)
		deadline := time.Now().Add(10 * time.Second)
		o.SetDeadline(deadline)
		s.SetDeadline(deadline)
		d := wp5Datagram(wp5Flow, 50)

		// PacketIO: ReadNoise with a nil error, nothing handed over.
		if err := o.WriteDatagram(d); err != nil {
			t.Fatalf("dialer write to a closed port: %v", err)
		}
		if data, _, ev, err := o.ReadDatagram(make([]byte, o.ReadSize())); ev != ReadNoise || err != nil || data != nil {
			t.Fatalf("dialer read after an ICMP error: event %d, %v, %d bytes; want ReadNoise", ev, err, len(data))
		}
		if err := s.WriteAddrPort(d, dead); err != nil {
			t.Fatalf("listener write to a closed port: %v", err)
		}
		if _, _, ev, err := s.ReadAddrPort(make([]byte, s.MaxDatagram()+1)); ev != ReadNoise || err != nil {
			t.Fatalf("listener read after an ICMP error: event %d, %v; want ReadNoise", ev, err)
		}

		// The net.PacketConn view: a Temporary() noise error with the errno.
		if err := o.WriteDatagram(d); err != nil {
			t.Fatalf("dialer write to a closed port: %v", err)
		}
		_, addr, err := o.ReadFrom(make([]byte, 100))
		if addr != nil {
			t.Errorf("ReadFrom after an ICMP error returned the address %v", addr)
		}
		wp5CheckNoiseError(t, "ReadFrom after an ICMP error", err, errno)
	})
}

// wp5CheckNoiseError checks a noise error of the OwnedUDP net.PacketConn
// view: Temporary(), not a timeout, matching ErrNoise and cause (the
// socket's error, or its errno).
func wp5CheckNoiseError(t *testing.T, what string, err, cause error) {
	t.Helper()
	tmp, isTemp := err.(interface{ Temporary() bool })
	to, isTimeout := err.(interface{ Timeout() bool })
	if !errors.Is(err, ErrNoise) || !errors.Is(err, cause) || !isTemp || !tmp.Temporary() ||
		!isTimeout || to.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("%s: %v (%T); want a Temporary() error, not a timeout, matching ErrNoise and %v", what, err, err, cause)
	}
}

// TestOwnedUDPConstructorPanics: the constructors refuse what carrier/udp
// never passes (programming errors): flow ID 0 (§A3.4: never a flow) and a
// MaxDatagram outside 546–65,507 — below the flow header and the smallest
// frame budget, or above a UDP payload. The bounds themselves are accepted.
func TestOwnedUDPConstructorPanics(t *testing.T) {
	peer := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 9)
	lo, hi := wire.MinFrameBudget+wire.FlowHeaderLen, wire.MaxDatagram
	for _, r := range []struct {
		name  string
		build func()
		panic bool
	}{
		{"dialer, flow 0", func() { NewOwnedUDP(nil, peer, 0, wp5MaxDatagram) }, true},
		{"dialer, MaxDatagram below the floor", func() { NewOwnedUDP(nil, peer, wp5Flow, lo-1) }, true},
		{"dialer, MaxDatagram above a UDP payload", func() { NewOwnedUDP(nil, peer, wp5Flow, hi+1) }, true},
		{"dialer, the floor", func() { NewOwnedUDP(nil, peer, wp5Flow, lo) }, false},
		{"dialer, the largest", func() { NewOwnedUDP(nil, peer, ^uint64(0), hi) }, false},
		{"listener, MaxDatagram below the floor", func() { NewOwnedUDPSocket(nil, lo-1) }, true},
		{"listener, MaxDatagram above a UDP payload", func() { NewOwnedUDPSocket(nil, hi+1) }, true},
		{"listener, the floor", func() { NewOwnedUDPSocket(nil, lo) }, false},
		{"listener, the largest", func() { NewOwnedUDPSocket(nil, hi) }, false},
	} {
		panicked := func() (p bool) {
			defer func() { p = recover() != nil }()
			r.build()
			return false
		}()
		if panicked != r.panic {
			t.Errorf("%s: panicked %v, want %v", r.name, panicked, r.panic)
		}
	}
	if lo != 546 {
		t.Errorf("the smallest MaxDatagram is %d, want 546 (carrier/udp's documented range)", lo)
	}
}

// TestOwnedUDPZeroAllocs_L41_L54: a datagram round trip through both tokens
// on loopback — the dialer token's WriteDatagram (flow header in place, one
// WriteToUDPAddrPort), the listening token's ReadAddrPort and WriteAddrPort
// back to the source, the dialer token's ReadDatagram (truncation flags,
// source compare, header check) — allocates nothing (M2-D4, M2-D66; M2
// design §A8.5: the packet gates run over OwnedUDP). Counted in the
// non-race lane only: the race detector makes the poller's sync.Pools drop
// items.
func TestOwnedUDPZeroAllocs_L41_L54(t *testing.T) {
	defer g10NoLeak(t)()
	su, _ := wp5Listen(t, "udp4")
	s := NewOwnedUDPSocket(su, wp5MaxDatagram)
	defer s.Close()
	du, _ := wp5Listen(t, "udp4")
	o := NewOwnedUDP(du, wp5AP(s), wp5Flow, wp5MaxDatagram)
	defer o.Close()
	deadline := time.Now().Add(time.Minute) // bounds a lost datagram; set once, outside the measured rounds
	if err := o.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := s.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	out := wp5Datagram(wp5Flow, 9+1000)
	sbuf := make([]byte, s.MaxDatagram()+1)
	rbuf := make([]byte, o.ReadSize())
	var fail error
	rounds := 0
	round := func() {
		if fail != nil {
			return
		}
		if err := o.WriteDatagram(out); err != nil {
			fail = err
			return
		}
		n, src, ev, err := s.ReadAddrPort(sbuf)
		if err != nil || ev != ReadOK || n != len(out) {
			fail = errors.Join(errors.New("listener read"), err)
			return
		}
		if err := s.WriteAddrPort(sbuf[:n], src); err != nil {
			fail = err
			return
		}
		data, _, ev, err := o.ReadDatagram(rbuf)
		if err != nil || ev != ReadOK || !bytes.Equal(data, out[9:]) {
			fail = errors.Join(errors.New("dialer read"), err)
			return
		}
		rounds++
	}
	for range 20 { // warm up: the poller's operation pools, the deadline timers
		round()
	}
	allocs := testing.AllocsPerRun(100, round)
	if fail != nil {
		t.Fatal(fail)
	}
	if rounds != 20+101 {
		t.Fatalf("%d rounds completed, want %d", rounds, 20+101)
	}
	if carrierRace {
		t.Logf("race lane: %v allocations per round (not asserted)", allocs)
		return
	}
	if allocs != 0 {
		t.Fatalf("%v allocations per datagram round trip", allocs)
	}
}

// TestOwnedUDPLimitFollowsBudget is the *OwnedUDP row of the R1-6 rule
// pinned by TestPacketIOLimitFollowsBudget (named apart: that test lives in
// this package with WP3b). Limit reports the socket's capacity, MaxDatagram
// − 9, for the cmtu offer; SetLimit(cmtu) lowers the receive limit and
// ReadSize with it — a 2 KiB reader buffer class for a QUIC-sized budget —
// while Limit stays; reads judge truncation against the lowered limit
// whatever the caller's buffer length; SetLimit never raises the receive
// limit past Limit. A dialer socket never rebinds.
func TestOwnedUDPLimitFollowsBudget(t *testing.T) {
	defer g10NoLeak(t)()
	raw, _ := wp5Listen(t, "udp4")
	defer raw.Close()
	du, _ := wp5Listen(t, "udp4")
	o := NewOwnedUDP(du, wp5AP(raw), wp5Flow, wire.MaxDatagram)
	defer o.Close()
	if o.Limit() != wire.MaxDatagram-9 || o.ReadSize() != wire.MaxDatagram+1 || o.Headroom() != 9 || o.Flow() != wp5Flow {
		t.Fatalf("Limit %d, ReadSize %d, Headroom %d, Flow %#x", o.Limit(), o.ReadSize(), o.Headroom(), o.Flow())
	}
	o.SetLimit(1152)
	if o.ReadSize() != 1152+9+1 || o.Limit() != wire.MaxDatagram-9 || o.ReadSize() > 2048 {
		t.Fatalf("after SetLimit(1152): ReadSize %d, Limit %d", o.ReadSize(), o.Limit())
	}
	buf := make([]byte, wire.MaxDatagram+1) // the pre-negotiation buffer, still in use
	for _, r := range []struct {
		size int
		ev   ReadEvent
	}{{9 + 1152, ReadOK}, {9 + 1153, ReadTruncated}, {9 + 1152, ReadOK}} {
		wp5Send(t, raw, wp5Datagram(wp5Flow, r.size), wp5AP(o))
		if data, _, ev := wp5Read(t, o, buf); ev != r.ev || (ev == ReadOK && len(data) != r.size-9) {
			t.Fatalf("%d-byte datagram after SetLimit(1152): event %d, %d bytes; want %d", r.size, ev, len(data), r.ev)
		}
	}
	o.SetLimit(wire.MaxDatagram)
	if o.ReadSize() != wire.MaxDatagram+1 {
		t.Fatalf("SetLimit above Limit: ReadSize %d, want %d", o.ReadSize(), wire.MaxDatagram+1)
	}
	if o.WriteDatagramTo(buf, PeerKey{AP: wp5AP(raw)}) != ErrNoRebind || o.SetPeer(PeerKey{AP: wp5AP(raw)}) != ErrNoRebind {
		t.Fatal("a dialer socket rebinds")
	}
}
