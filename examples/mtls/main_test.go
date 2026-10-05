package main

import (
	"bytes"
	"io"
	"testing"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestRunEchoesOverMutualTLS (design §0.8 V17, §0.10 Y8, §0.12 AA2): the
// example end to end on real loopback sockets — two Runtimes, carrier/tcp
// wrapped in mutually authenticated TLS 1.3, one selector session through
// the passive's Listener.Handle — echoes the message intact and ends the one
// session cleanly at both ends: each final Status (read once Conn.Done was
// closed) reports StateEnded with io.EOF and every byte acknowledged as
// delivered, because each side reads until io.EOF, closes its Conn and
// waits for Conn.Done before its Runtime closes. Y8: when the dialer's
// Runtime closed while the session still waited for DONE, the dialer ended
// with net.ErrClosed and the passive was reset (*rendr.AbortError, peer
// going away) — reproduced on every run with main's greeting, while the
// 1 MiB message hid the race. Nothing is left running once run returned
// (both Runtimes and the TLS server were closed and joined).
func TestRunEchoesOverMutualTLS(t *testing.T) {
	line := []byte("rendr over mutually authenticated TLS carriers\n")
	for _, tc := range []struct {
		name string
		msg  []byte
	}{
		{"greeting", []byte(greeting)},
		{"1MiB", bytes.Repeat(line, (1<<20)/len(line)+1)[:1<<20]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := rendrtest.AssertNoLeak(t)
			p, err := newPKI()
			if err != nil {
				t.Fatalf("newPKI: %v", err)
			}
			r, err := run(p, tc.msg)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if !bytes.Equal(r.echo, tc.msg) {
				t.Fatalf("echoed %d bytes, sent %d (equal prefix %d)", len(r.echo), len(tc.msg), commonPrefix(r.echo, tc.msg))
			}
			n := uint64(len(tc.msg))
			for _, end := range []struct {
				role rendr.Role
				st   rendr.SessionStatus
			}{{rendr.RoleDialer, r.dialer}, {rendr.RolePassive, r.passive}} {
				st := end.st
				if st.Role != end.role || st.ID != r.dialer.ID || st.State != rendr.StateEnded || st.Err != io.EOF {
					t.Errorf("%v end: role %v, session %v, state %v, err %v; want session %v ended with io.EOF",
						end.role, st.Role, st.ID, st.State, st.Err, r.dialer.ID)
				}
				if st.TxBytes != n || st.AckedBytes != n || st.RxBytes != n || st.DeliveredBytes != n {
					t.Errorf("%v end: tx %d, acked %d, rx %d, delivered %d bytes; want %d each",
						end.role, st.TxBytes, st.AckedBytes, st.RxBytes, st.DeliveredBytes, n)
				}
				// Done also waited for the carriers: none is still retiring.
				if len(st.Carriers) == 0 {
					t.Errorf("%v end: no carrier in the final Status", end.role)
				}
				for _, c := range st.Carriers {
					if c.State != rendr.CarrierDead {
						t.Errorf("%v end: carrier %d %v in the final Status, want every carrier dead", end.role, c.ID, c.State)
					}
				}
			}
			check()
		})
	}
}

// commonPrefix returns the length of the longest common prefix of a and b.
func commonPrefix(a, b []byte) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}
