package l4

import (
	"context"
	"errors"
	"net"
)

// ServeTCP accepts connections from ln until ctx is done or Accept fails
// permanently (temporary errors back off 5–100 ms) and forwards each to
// target ("host:port", resolved by the passive; validated before the first
// Accept: ErrBadAddress). A connection beyond MaxConns, or whose Dial
// fails, is reset. ServeTCP owns ln from the call on and closes it when it
// returns, after every connection it started ended. A Unix-domain listener
// counts as loopback.
//
// Skeleton (M6 wave 0): not implemented yet; it closes ln and returns the
// error.
func (f *PortForward) ServeTCP(ctx context.Context, ln net.Listener, target string) error {
	ln.Close()
	return errors.New("l4: not implemented")
}
