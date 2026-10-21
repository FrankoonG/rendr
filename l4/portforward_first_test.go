package l4

import (
	"bytes"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2"
)

// TestPortForwardFirstInOpenRetry_L37 (M6-D4, R1-4; L37): FirstInOpen
// counts a first datagram only when an OPEN carried it. A first datagram
// the ingress lets ride (its whole metadata within firstBudget) but whose
// OPEN a Handshake.MaxMetadata refuses — the dialer's own (64: refused
// before any I/O) or the passive's (256, a 300-byte datagram: answered
// CodeMetadataSize) — is sent by DialUDP's retry after the open as a
// datagram: FirstInOpen 0, ToSession 1, the passive wrote no first
// datagram from an OPEN, and the target received the datagram exactly
// once (its echo came back). The control: one that rides counts
// FirstInOpen 1.
func TestPortForwardFirstInOpenRetry_L37(t *testing.T) {
	small := func(n int) (c rendr.Config) {
		c.Handshake.MaxMetadata = n
		return c
	}
	for _, tc := range []struct {
		name  string
		pf    pfOpts
		size  int
		rides bool
	}{
		{"dialer limit", pfOpts{dcfg: small(64)}, 60, false},
		{"passive limit", pfOpts{pcfg: small(256)}, 300, false},
		{"rides", pfOpts{}, 60, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newPWWorld(t, pwOpts{pf: tc.pf})
				w.serve()
				a := w.client()
				first := pwTagged(tc.size, 0xA1, 0)
				if bareLen := len(mustUDPMetadata(t, nil)); bareLen+len(first) > firstBudget {
					t.Fatalf("premise: a %d-byte first datagram does not fit firstBudget", len(first))
				}
				pfSend(t, a, first)
				if got := pfRecv(t, a); !bytes.Equal(got, first) {
					t.Fatalf("echo %d bytes, want the first datagram's %d", len(got), len(first))
				}
				_, _, firstSent, flows := w.pas.snapshot()
				st := pwStatus(w.pf)
				t.Logf("passive first datagrams from an OPEN %d; %s", firstSent, pwDescribe(st))
				want := uint64(0)
				if tc.rides {
					want = 1
				}
				if len(flows) != 1 || len(flows[0].received()) != 1 || !bytes.Equal(flows[0].received()[0], first) {
					t.Fatalf("the target did not receive the first datagram exactly once: %d flows", len(flows))
				}
				if uint64(firstSent) != want || st.FirstInOpen != want || st.ToSession != 1 || st.Opened != 1 || st.Failed != 0 {
					t.Fatalf("FirstInOpen %d (the passive wrote %d from an OPEN), want %d; %s", st.FirstInOpen, firstSent, want, pwDescribe(st))
				}
			})
		})
	}
}

// mustUDPMetadata is the kit target's L4 metadata with first.
func mustUDPMetadata(t testing.TB, first []byte) []byte {
	t.Helper()
	md, err := AppendMetadata(nil, Request{Cmd: CmdUDP, Addr: pfTarget, First: first})
	if err != nil {
		t.Fatalf("AppendMetadata: %v", err)
	}
	return md
}
