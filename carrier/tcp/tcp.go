// Package tcp is rendr's built-in plaintext TCP carrier (plan §8, ≤ 300
// lines): a listener and a factory whose connections have TCP keepalive
// disabled on both ends (rendr's PING is the only liveness authority, L26)
// and TCP_NODELAY on, and that refuse non-loopback addresses unless
// AllowNonLoopback is set (plan §1.4: plaintext, for tests and trusted
// networks). Its connections carry rendr's ownership token, so the carrier
// writer uses zero-copy vectored writes on them.
package tcp

import (
	"errors"
	"net"

	"github.com/FrankoonG/rendr/v2"
)

// ErrNonLoopback is returned by Listen and by the factory's Dial for a
// non-loopback address without Options.AllowNonLoopback.
var ErrNonLoopback = errors.New("rendr/carrier/tcp: non-loopback address requires AllowNonLoopback")

// Options configure the built-in TCP carrier.
type Options struct {
	// AllowNonLoopback permits non-loopback addresses. rendr provides no
	// confidentiality or authentication; only enable this on a trusted
	// network or inside the embedder's authenticated encrypted channel.
	AllowNonLoopback bool
}

// Listen listens on network ("tcp", "tcp4", "tcp6") and address. Accepted
// connections have keepalive disabled and NODELAY set and are rendr-owned.
// Pass the result to rendr.FromListener. A non-loopback address fails with
// ErrNonLoopback unless allowed.
func Listen(network, address string, o Options) (net.Listener, error) {
	panic("unimplemented: M1b")
}

// Carrier returns a StreamCarrier named name that dials network/address
// with net.Dialer{KeepAlive: -1}, then SetKeepAlive(false) and
// SetNoDelay(true), honouring ctx. A non-loopback address fails with
// ErrNonLoopback unless allowed.
func Carrier(name, network, address string, o Options) rendr.StreamCarrier {
	panic("unimplemented: M1b")
}
