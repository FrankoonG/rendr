package l4

import (
	"context"

	"github.com/FrankoonG/rendr/v2"
)

// Dial opens a stream session to addr ("host:port") through p, with o as
// for Peer.Dial; o.Metadata travels after the address as Request.App. The
// returned Conn has DefaultIdleTimeout set. Errors: ErrBadAddress (before
// any network I/O) and the Peer.Dial errors; an l4 Server's refusal is a
// *rendr.RejectError whose code CodeOf reports. With o.EarlyReturn the
// refusal is the first Read's or Write's error instead.
func Dial(ctx context.Context, p *rendr.Peer, addr string, o rendr.DialOptions) (*rendr.Conn, error) {
	md, err := AppendMetadata(make([]byte, 0, maxHeader+len(o.Metadata)), Request{Cmd: CmdConnect, Addr: addr, App: o.Metadata})
	if err != nil {
		return nil, err
	}
	o.Metadata = md
	c, err := p.Dial(ctx, o)
	if err != nil {
		return nil, err
	}
	// net.ErrClosed only: the session already ended, and its first Read or
	// Write reports why.
	c.SetIdleTimeout(DefaultIdleTimeout)
	return c, nil
}
