package carrier

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestOwnedUDPFlowHeaderMatchesWire_L58: the raw-UDP flow header that the
// OwnedUDP token builds itself is the one internal/wire defines (M2 design
// §A3.4; integration 1's cross-check of the token against the codec). A
// datagram WriteDatagram sends parses with wire.ParseFlowHeader to the
// token's flow and its rendr bytes; a datagram built with
// wire.PutFlowHeader for the token's flow is handed over by ReadDatagram,
// and one of another flow or another version is a bad envelope.
func TestOwnedUDPFlowHeaderMatchesWire_L58(t *testing.T) {
	lo := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	listen := func() *net.UDPConn {
		u, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo, 0)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { u.Close() })
		if err := u.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		return u
	}
	peer, tok := listen(), listen()
	peerAP := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	tokAP := tok.LocalAddr().(*net.UDPAddr).AddrPort()
	const flow = 0x0123456789abcdef
	o := NewOwnedUDP(tok, peerAP, flow, 1232)
	payload := []byte("rendr bytes behind the flow header")

	b := make([]byte, o.Headroom()+len(payload))
	copy(b[o.Headroom():], payload)
	if err := o.WriteDatagram(b); err != nil {
		t.Fatalf("WriteDatagram: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := peer.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	got, rest, err := wire.ParseFlowHeader(buf[:n])
	if err != nil || got != flow || !bytes.Equal(rest, payload) {
		t.Fatalf("ParseFlowHeader = %#x %q %v, want %#x %q", got, rest, err, uint64(flow), payload)
	}

	rbuf := make([]byte, o.ReadSize())
	for _, tc := range []struct {
		name    string
		flow    uint64
		version byte
		want    ReadEvent
	}{
		{"its flow", flow, wire.FlowVersion, ReadOK},
		{"another flow", flow + 1, wire.FlowVersion, ReadBadEnvelope},
		{"another version", flow, wire.FlowVersion + 1, ReadBadEnvelope},
	} {
		d := make([]byte, wire.FlowHeaderLen+len(payload))
		wire.PutFlowHeader(d, tc.flow)
		d[0] = tc.version
		copy(d[wire.FlowHeaderLen:], payload)
		if _, err := peer.WriteToUDPAddrPort(d, tokAP); err != nil {
			t.Fatalf("%s: peer write: %v", tc.name, err)
		}
		data, _, ev, err := o.ReadDatagram(rbuf)
		if err != nil || ev != tc.want || (ev == ReadOK && !bytes.Equal(data, payload)) {
			t.Fatalf("%s: ReadDatagram = %q, event %v, error %v; want event %v", tc.name, data, ev, err, tc.want)
		}
		o.Release()
	}
}
