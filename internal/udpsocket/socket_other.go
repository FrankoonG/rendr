//go:build !linux

package udpsocket

import "net"

type platformState struct{}

func platformGSOAllowed() bool { return false }

func newPacketConnView(socket *Socket) net.PacketConn { return socket }

func (s *Socket) initPlatform(policy, *net.UDPAddr, bool) {}

func (s *Socket) readPlatform(payload []byte) (int, error) { return s.conn.Read(payload) }

func (s *Socket) readFromPlatform(payload []byte) (int, net.Addr, error) {
	return s.conn.ReadFrom(payload)
}

func (s *Socket) writePlatform(payload []byte, _ *net.UDPAddr) (int, error) {
	return s.conn.Write(payload)
}

func (s *Socket) writeToPlatform(payload []byte, address net.Addr) (int, error) {
	return s.conn.WriteTo(payload, address)
}

func (s *Socket) writeBatchPlatform(datagrams [][]byte, _ int, _ int, address *net.UDPAddr) (int, error) {
	return writeOrdinaryDatagrams(func(payload, _ []byte, destination *net.UDPAddr) (int, int, error) {
		var (
			n   int
			err error
		)
		if destination == nil {
			n, err = s.conn.Write(payload)
		} else {
			n, err = s.conn.WriteToUDP(payload, destination)
		}
		return n, 0, err
	}, datagrams, nil, address, func() {
		s.ordinaryDatagrams.Add(1)
	})
}
