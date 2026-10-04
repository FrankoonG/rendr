package rendr

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Sessionless (probe) carriers (design §6.4, plan §3.5): a carrier whose
// first frame is a PING belongs to no session. The passive answers that
// PING (recorded by ReadHello) as its first frame, answers later PINGs,
// never PINGs itself and closes after Sessionless.Idle without a PING or
// on the dialer's CLOSE (the carrier does this itself). At most
// Sessionless.PerInstance such carriers per dialer instance and
// Sessionless.Total per Runtime are held; beyond either cap the new one
// gets CLOSE(capacity) and existing ones are never evicted.

// admitSessionless starts h's carrier as a sessionless carrier and counts
// it, or refuses it: CLOSE(capacity) at either cap, GOAWAY when the Runtime
// is closing (its Close may already have taken its snapshot of these
// carriers). On success the caller watches the carrier (watchSessionless)
// on the handshake goroutine, now a member of rt.slg.
func (rt *Runtime) admitSessionless(h *carrier.Hello, deadline time.Time) (*carrier.Conn, InstanceID, bool) {
	c, inst := h.Conn, InstanceID(h.Preface.Instance)
	rt.mu.Lock()
	switch {
	case rt.closing.Load():
		rt.mu.Unlock()
		c.WriteAndClose(wire.TypeGoAway, 0, 0, []byte{byte(wire.GoAwayShutdown)}, deadline)
		return nil, inst, false
	case !rt.slt.acquire(inst):
		rt.mu.Unlock()
		c.WriteAndClose(wire.TypeClose, 0, 0, []byte{byte(wire.CloseCapacity)}, deadline)
		return nil, inst, false
	}
	rt.sl[c] = struct{}{}
	rt.slg.add()
	rt.mu.Unlock()
	c.Start(nil, nil, carrier.StartOptions{Sessionless: true})
	return c, inst, true
}

// watchSessionless waits for the sessionless carrier's end and only then
// frees its place in the caps (design §6.4: the entry is removed at Done,
// so a carrier that is still closing keeps counting).
func (rt *Runtime) watchSessionless(c *carrier.Conn, inst InstanceID) {
	defer rt.slg.done(nil)
	<-c.Done()
	rt.mu.Lock()
	delete(rt.sl, c)
	rt.mu.Unlock()
	rt.slt.release(inst)
}
