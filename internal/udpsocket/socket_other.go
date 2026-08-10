//go:build !linux

package udpsocket

import "net"

func platformGSOAllowed() bool { return false }

func newPacketConnView(socket *Socket) net.PacketConn { return socket }

func (s *Socket) writeBatchPlatform(datagrams [][]byte, _ []byte, _ int, address *net.UDPAddr) (int, error) {
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
