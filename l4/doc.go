// Package l4 carries TCP connections over rendr stream sessions. A dialer
// opens one session per connection with Dial, naming the target in the
// OPEN's metadata; a passive Runtime runs a Server on a Listener, which dials
// each target while its session is pending, confirms on success or rejects
// with one of the RejectCode values, and forwards bytes both ways. Forward
// is the forwarder on both ends: half-closes cross in both directions; a
// reset or failure on either side becomes a reset on the other, never a
// clean end of stream; a session that ends releases its socket at once,
// also when the socket's peer ignores FIN or never reads. Sessions are
// idle-limited to DefaultIdleTimeout unless changed. The package does no
// authentication: a Server dials whatever a dialer asks for unless its Dial
// hook refuses (ErrDenied) — the default dials any address the host can
// reach, its loopback and private networks included; policy that must hold
// for every path to an address checks the resolved address
// (net.Dialer.Control), not Request.Addr. After local's FIN, Forward
// reads nothing more from local, so a later close of local is not
// observable (TCP sends nothing for it): such a session ends when the far
// side ends it, at its idle limit, or when ctx ends.
//
// Not implemented yet: this is the M4 skeleton; every function returns
// errors.ErrUnsupported (or its zero result) until its work package lands.
package l4
