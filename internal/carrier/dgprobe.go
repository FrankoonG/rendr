package carrier

// PING retry, MTU probe and rebind challenge of datagram carriers (M2-D23,
// M2-D24, M2-D27; M2 design §A5.11, §A5.13 and Revision 1, R1-13, R1-14).

// dgProbe is the MTU probe and PING-retry bookkeeping (dgprobe.go): the
// PacketPing-cadence PING count, the outstanding probe's id and whether its
// own PONG arrived, and the consecutive failures. The PING retry at the RTO
// applies to session and probe carriers alike (R1-13).
type dgProbe struct{}

// dgChallenge is the rebind state (dgprobe.go): passive flows — the
// candidate source, its nonce, send time, due flag and resend time (an
// unanswered challenge is resent at the REL RTO until its 2-s expiry, also
// by a held writer: the challenge is no PING record; R1-14), the last
// challenge time and the commits of the last minute; every datagram
// carrier — the challenge-PONG slot answering a PING with id 0.
type dgChallenge struct{}
