package carrier

import (
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestConnTransportLimitAndKind (integration 2, decisions D21 and D22): a
// datagram Conn reports its transport's capacity (PacketIO.Limit, the
// passive's cmtu_acc bound for a JOIN, M2-D50) through TransportLimit,
// unchanged by SetBudget, which lowers only the receive limit (R1-6); a
// stream Conn reports 0. Stats carries the carrier's kind, so Status never
// infers it from the frame budget.
func TestConnTransportLimitAndKind(t *testing.T) {
	a, _ := newFakeIOPair(1200)
	c := dgConn(dgEnv(), a, 1000, true)
	if got := c.TransportLimit(); got != 1200 {
		t.Fatalf("TransportLimit %d after SetBudget(1000), want the transport's 1200", got)
	}
	if c.RecvLimit() != 1000 {
		t.Fatalf("RecvLimit %d, want 1000", c.RecvLimit())
	}
	if st := c.Stats(); st.Kind != wire.KindDatagram || st.MTU != 1000 {
		t.Fatalf("datagram Stats kind %v MTU %d", st.Kind, st.MTU)
	}
	s := &Conn{}
	if s.TransportLimit() != 0 || s.Kind() != wire.KindStream {
		t.Fatalf("stream Conn: TransportLimit %d kind %v", s.TransportLimit(), s.Kind())
	}
}
