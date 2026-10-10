package l4

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// ForwardResult reports how a Forward ended.
type ForwardResult struct {
	ToSession, ToLocal int64 // bytes moved in each direction
	Clean              bool  // both directions ended with a FIN
	SessionErr         error // the session's error when not clean, as Read or Write returned it
	LocalErr           error // local's read or write error when not clean
}

// Err returns nil after a clean exchange, else SessionErr or LocalErr.
func (r ForwardResult) Err() error {
	switch {
	case r.Clean:
		return nil
	case r.SessionErr != nil:
		return r.SessionErr
	}
	return r.LocalErr
}

// Forward moves bytes between the session c and local until both
// directions ended, the session ended, or ctx is done, then closes both. A
// FIN from local becomes c.CloseWrite; the session's io.EOF becomes
// CloseWrite on local when local has one (else local stays open for the
// reverse direction); any other end of either side resets the other
// (c.Abort(AbortReset, …); local: SetLinger(0) where offered, then Close).
// When the session ends uncleanly while local still has a direction open (a
// peer that ignores FIN or never reads), local is reset at once; after a
// clean end the last bytes and the FIN are written first, within a bound.
// A Conn still opening (EarlyReturn) is read only after local's first
// bytes were written to it, or after 20 ms. ctx ending aborts the session
// (AbortShutdown) and resets local. Forward owns c and local from the call
// on, sets no deadlines on them during the transfer, and starts two
// goroutines that end before it returns.
//
// Not implemented yet: it returns a result whose SessionErr is
// errors.ErrUnsupported and moves nothing.
func Forward(ctx context.Context, c *rendr.Conn, local net.Conn) ForwardResult {
	return ForwardResult{SessionErr: errors.ErrUnsupported} // M4 WP4
}

// Forward's internals (M4 design §A7; WP4 owns them, WP5 calls them).
var (
	// cleanJoinMax bounds the wait for the pumps after a clean session end
	// (R1-1): Linger's default; l4's tests lower it.
	cleanJoinMax = 30 * time.Second
	// earlyFirstWriteWait bounds pump B's hold of its first Read on a
	// Conn still opening (R1-15, M4-D57); l4's tests change it.
	earlyFirstWriteWait = 20 * time.Millisecond
	// bufPool holds the pumps' 32 KiB buffers (M4-D36: one per pump, no
	// allocation per chunk in steady state).
	bufPool = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}
)

// resetConn resets local: SetDeadline(now), SetLinger(0) where offered,
// then Close (M4-D37, M4-D40; L52).
func resetConn(local net.Conn) {
	// M4 WP4
}
