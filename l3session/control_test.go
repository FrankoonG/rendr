package l3session

import "github.com/FrankoonG/rendr"

type streamControl interface {
	rendr.Conn
	rendr.MigrationController
	rendr.ConnectionObserver
}

type packetControl interface {
	rendr.PacketConn
	rendr.MigrationController
	rendr.ConnectionObserver
}
