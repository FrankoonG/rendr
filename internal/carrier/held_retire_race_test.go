package carrier

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// retireInFillEP is a passive endpoint whose first Fill places nothing
// and, inside that Fill, does what a session's verdict does while the
// carrier's writer runs it: it sets the first response (here a refusal)
// and retires the carrier. Later Fills place that response once.
type retireInFillEP struct {
	hEP
	fills  atomic.Int64
	resp   atomic.Bool
	placed atomic.Bool
}

func (e *retireInFillEP) Fill(c *Conn, b *Batch) {
	if e.fills.Add(1) == 1 {
		e.resp.Store(true)
		c.Retire(wire.CloseRetire)
		return
	}
	if e.resp.Load() && !e.placed.Load() &&
		b.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusRejected, Code: 4242}) {
		e.placed.Store(true)
	}
}

// TestHeldRetireDuringFillAnswersFirst (M4 checkpoint C-L; pool race lane:
// TestEarlyRefusalDrain_L05's application Reject on a dedicated carrier
// read CLOSE instead of its OPEN_ACK): a held passive carrier (StartOptions
// Hold) retired while its writer runs the endpoint's Fill — the session's
// refusal sets the first response and retires the carrier between that
// Fill and the writer's retirement check — still writes the response
// first, then CLOSE. A planned retirement follows only a Fill call that
// started after it was requested (§7.3, as the unheld rounds and the
// datagram writer read it); the held round read it after the call and put
// CLOSE first on the wire.
func TestHeldRetireDuringFillAnswersFirst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		envD, envP := phEnvs()
		a, b := net.Pipe()
		ep := &retireInFillEP{}
		pass := phPassive(envP, b, nil, func(h *Hello) { h.Conn.Start(ep, &hBell{}, StartOptions{Hold: true}) })
		f := Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return a, nil }}
		est, err := Establish(context.Background(), envD, f, envD.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
		ph := <-pass
		if ph.err != nil {
			t.Fatalf("ReadHello: %v", ph.err)
		}
		if err != nil {
			t.Fatalf("Establish: %v", err)
		}
		defer func() {
			est.Conn.Kill(CauseLocalClose, "test end")
			ph.h.Conn.Kill(CauseLocalClose, "test end")
			<-est.Conn.Done()
			<-ph.h.Conn.Done()
		}()
		if n := ep.fills.Load(); n < 2 {
			t.Fatalf("premise: %d Fill calls, want the retiring one and the one that answered", n)
		}
		r, perr := wire.ParseOpenAck(est.Payload)
		if est.Resp.Type != wire.TypeOpenAck || perr != nil || r.Status != wire.StatusRejected || r.Code != 4242 {
			t.Fatalf("the dialer read %v %+v (%v) first, want OPEN_ACK REJECTED 4242 before the CLOSE", est.Resp.Type, r, perr)
		}
	})
}
