package carrier

import (
	"strings"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestStreamCarrierRejectsRelRack_L43: REL and RACK on a stream carrier —
// sessionless, probe or session — and a core frame larger than the stage
// that is not big DATA (a DGRAM of 20,000 bytes) are protocol violations
// (M2 §A3.6, invariant 6): never a nil-endpoint panic, never skipped as an
// extension, never dispatched to the endpoint.
func TestStreamCarrierRejectsRelRack_L43(t *testing.T) {
	rel := make([]byte, wire.RelHeadLen+wire.FinLen)
	wire.PutRelHead(rel, &wire.RelHead{Cseq: 1, Type: wire.TypeFin, Handle: wire.SessionHandle})
	relClose := make([]byte, wire.RelHeadLen+wire.ReasonLen)
	wire.PutRelHead(relClose, &wire.RelHead{Cseq: 1, Type: wire.TypeClose})
	bigRel := make([]byte, 20000)
	wire.PutRelHead(bigRel, &wire.RelHead{Cseq: 1, Type: wire.TypeOpen, Handle: wire.SessionHandle})
	frames := []struct {
		name   string
		f      hFrame
		detail string
	}{
		{"REL{FIN}", hFrame{t: wire.TypeRel, payload: rel}, "REL on a stream carrier"},
		{"REL{CLOSE}", hFrame{t: wire.TypeRel, payload: relClose}, "REL on a stream carrier"},
		{"RACK", hFrame{t: wire.TypeRack, payload: make([]byte, wire.RackLen)}, "RACK on a stream carrier"},
		{"REL of 20000 bytes", hFrame{t: wire.TypeRel, payload: bigRel}, "REL on a stream carrier"},
		{"DGRAM of 20000 bytes", hFrame{t: wire.TypeDgram, handle: wire.SessionHandle, payload: make([]byte, 20000)}, ""},
	}
	starts := []struct {
		name    string
		session bool
		opts    StartOptions
	}{
		{"sessionless", false, StartOptions{Sessionless: true}},
		{"probe", false, StartOptions{Probe: true}},
		{"session", true, StartOptions{}},
	}
	for _, s := range starts {
		for _, fr := range frames {
			t.Run(s.name+"/"+fr.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					env := hEnv()
					c, p := hPair(t, env, nil)
					ep := &hEP{}
					if s.session {
						c.Start(ep, &hBell{}, s.opts)
					} else {
						c.Start(nil, &hBell{}, s.opts)
					}
					go p.sendFrames(fr.f)
					hWait(t, c)
					dead, cause, detail, _ := c.Death()
					if !dead || cause != CauseProtocolViolation {
						t.Fatalf("death %v %v %q, want protocol_violation", dead, cause, detail)
					}
					want := fr.detail
					if want == "" && s.session {
						want = "DGRAM of 20000 bytes on a stream carrier"
					}
					if want != "" && !strings.Contains(detail, want) {
						t.Fatalf("detail %q, want %q", detail, want)
					}
					ep.mu.Lock()
					n := len(ep.ctrl)
					ep.mu.Unlock()
					if n != 0 {
						t.Fatalf("%d control frames dispatched", n)
					}
					p.close()
				})
			})
		}
	}
}
