package realsock

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestRealUDPHandshakeCounted (R1-2 rule 1, M5 design R3-31; L57): the I/O
// counters of both Runtimes count one dial's datagram handshake. A
// selector packet session is dialled once over carrier/udp (the dialer's
// token) to a udp.Listen socket adopted by FromPacketConn (the passive's
// Source). Loopback neither loses nor creates a datagram, so once nothing
// is in flight what each Runtime counted as sent the other counted as
// received: the dialer's SentDatagrams equal the passive's RecvDatagrams
// and the passive's SentDatagrams the dialer's RecvDatagrams — H1 and its
// copies, the passive's H2 and REL included — in a snapshot that holds
// still for msQuiet (nothing moved). Before the dialer counted its
// handshake's single calls, its SentDatagrams stayed short of the
// passive's RecvDatagrams by the handshake's writes for the session's
// life. Mutants: the unbound write (or read) of the dialer token
// uncounted.
func TestRealUDPHandshakeCounted(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	sock, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := udp.Carrier("u", "udp4", sock.LocalAddr().String(), udp.Options{})
	var dials atomic.Int64
	dial := c.Dial
	c.Dial = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		dials.Add(1)
		return dial(ctx)
	}
	m := newMsPair(t, rendr.Config{}, nil, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}}, []rendr.Carrier{c})
	dc, pc := m.openPacket(rendr.ModeSelector)

	// io is the four I/O counters of both Runtimes: dialer sent, passive
	// received, passive sent, dialer received.
	io := func() [4]uint64 {
		d, p := m.d.Status().Datagram, m.p.Status().Datagram
		return [4]uint64{d.SentDatagrams, p.RecvDatagrams, p.SentDatagrams, d.RecvDatagrams}
	}
	var last [4]uint64
	for deadline := time.Now().Add(10 * time.Second); ; {
		s := io()
		if s[0] == s[1] && s[2] == s[3] {
			time.Sleep(msQuiet)
			if io() == s {
				break // a quiet snapshot: nothing in flight
			}
		}
		last = s
		if time.Now().After(deadline) {
			t.Fatalf("within 10 s no quiet snapshot in which both Runtimes agree: the last read dialer sent %d / passive received %d, passive sent %d / dialer received %d (%d dials)",
				last[0], last[1], last[2], last[3], dials.Load())
		}
		time.Sleep(time.Millisecond)
	}
	fin := [2]rendr.DatagramStatus{m.d.Status().Datagram, m.p.Status().Datagram}
	t.Logf("%d dials; dialer %s; passive %s", dials.Load(), beIO(fin[0]), beIO(fin[1]))
	if dials.Load() < 1 || fin[0].SentDatagrams == 0 || fin[1].SentDatagrams == 0 {
		t.Fatalf("stimulus: %d dials, dialer %s, passive %s", dials.Load(), beIO(fin[0]), beIO(fin[1]))
	}
	for _, s := range fin {
		if s.SentDatagrams < s.SendCalls || s.RecvDatagrams < s.RecvCalls {
			t.Fatalf("a counted call moves at least one datagram: %s", beIO(s))
		}
	}

	dc.Close()
	pc.Close()
	msDone(t, dc.Done(), "the dialer session")
	msDone(t, pc.Done(), "the passive session")
	m.muxZero()
	m.close()
}

// msQuiet is how long a counter snapshot must hold still to be taken as
// one with nothing in flight on loopback.
const msQuiet = 20 * time.Millisecond
