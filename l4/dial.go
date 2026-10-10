package l4

import (
	"context"
	"errors"

	"github.com/FrankoonG/rendr/v2"
)

// Dial opens a stream session to addr ("host:port") through p, with o as
// for Peer.Dial; o.Metadata travels after the address as Request.App. The
// returned Conn has DefaultIdleTimeout set. Errors: ErrBadAddress (before
// any network I/O) and the Peer.Dial errors; an l4 Server's refusal is a
// *rendr.RejectError whose code CodeOf reports. With o.EarlyReturn the
// refusal is the first Read's or Write's error instead.
//
// Not implemented yet: it returns errors.ErrUnsupported.
func Dial(ctx context.Context, p *rendr.Peer, addr string, o rendr.DialOptions) (*rendr.Conn, error) {
	return nil, errors.ErrUnsupported // M4 WP4
}
