package carrier

// PING retry, MTU probe and rebind challenge of datagram carriers (M2-D23,
// M2-D24, M2-D27; M2 design §A5.11, §A5.13).

// dgProbe is the MTU probe and PING-retry bookkeeping (dgprobe.go): the
// PacketPing-cadence PING count, the outstanding probe's id and whether its
// own PONG arrived, and the consecutive failures.
type dgProbe struct{}

// dgChallenge is the rebind state (dgprobe.go): passive flows — the
// candidate source, its nonce, send time and due flag, the last challenge
// time and the commits of the last minute; every datagram carrier — the
// challenge-PONG slot answering a PING with id 0.
type dgChallenge struct{}
