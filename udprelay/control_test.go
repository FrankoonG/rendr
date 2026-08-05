package udprelay

import "github.com/FrankoonG/rendr"

type packetControl interface {
	rendr.PacketConn
	rendr.MigrationController
	rendr.PathController
	rendr.ConnectionObserver
}
