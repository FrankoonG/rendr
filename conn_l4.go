package rendr

import (
	"errors"
	"time"
)

// Abort resets the session now: an RST with code goes to the peer, whose
// pending and later Reads and Writes return *AbortError{Code: code, Msg:
// msg (at most 255 bytes), Remote: true}; data not yet delivered in either
// direction is discarded; this side's calls return net.ErrClosed; Done
// closes once the session's carriers are released. code must be at least
// 256 (smaller codes are rendr's); otherwise Abort returns an error and does
// nothing. It is idempotent; after the session ended it does nothing; after
// Close it replaces the linger with the reset; on a session dialled with
// EarlyReturn that has no answer yet it withdraws the OPEN. Abort, Close,
// CloseWrite and a peer's RST racing resolve to one end.
//
// Not implemented yet: it returns errors.ErrUnsupported and does nothing.
func (c *Conn) Abort(code AbortCode, msg string) error {
	return errors.ErrUnsupported // M4 WP1
}

// SetIdleTimeout overrides Config.IdleTimeout for this session from now on,
// with the same meaning and clamp: 0 turns idle expiry off, other values are
// clamped to 10 s–24 h. The idle clock is not restarted. Both roles. It
// returns net.ErrClosed once the session has ended.
//
// Not implemented yet: it returns errors.ErrUnsupported and changes
// nothing.
func (c *Conn) SetIdleTimeout(d time.Duration) error {
	return errors.ErrUnsupported // M4 WP1
}
