package rendrtest

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
)

// TestRefuseThenKillRacesADial (I2): "SetRefuse(true), then Kill" leaves
// no carrier, also of a dial that passed its refuse check before them and
// creates its carrier after Kill's snapshot (the Linux race lane: a
// session of TestAllPathsDeadAborts got a new path from such a dial and
// never ended). The dial is refused instead. Both link kinds.
func TestRefuseThenKillRacesADial(t *testing.T) {
	t.Run("Link", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			l := NewLink(LinkConfig{Name: "a", Accept: func(c net.Conn) error { return c.Close() }})
			defer l.Close()
			l.afterCheck = func() {
				l.SetRefuse(true)
				l.Kill()
			}
			c, err := l.Dial(context.Background())
			if c != nil || !errors.Is(err, errRefused) {
				if c != nil {
					c.Close()
				}
				t.Fatalf("a dial racing SetRefuse and Kill: %v, %v; want refused", c, err)
			}
			if st := l.Stats(); st.Dials != 1 || st.DialFailures != 1 || len(l.Carriers()) != 0 {
				t.Fatalf("stats %+v, %d carriers; want one refused dial and no carrier", st, len(l.Carriers()))
			}
		})
	})
	t.Run("DatagramLink", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			l := NewDatagramLink(DatagramLinkConfig{Name: "a", Accept: func(pc net.PacketConn, _ net.Addr) error { return pc.Close() }})
			defer l.Close()
			l.afterCheck = func() {
				l.Refuse(true)
				l.Kill()
			}
			pc, _, err := l.Dial(context.Background())
			if pc != nil || !errors.Is(err, errRefused) {
				if pc != nil {
					pc.Close()
				}
				t.Fatalf("a dial racing Refuse and Kill: %v, %v; want refused", pc, err)
			}
		})
	})
}
