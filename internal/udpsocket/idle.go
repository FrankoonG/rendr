package udpsocket

import "time"

// IdleRelease is the idle-release period of the batched readers of rendr's
// own sockets (M5 design R1-5 rule 3; plan:774): a dialer carrier's reader
// (internal/carrier) and a listening socket's Source (internal/udpflow)
// keep the extras of a read at depth two or more — the Reader's Batch and
// their read slots beyond slot 0 — across shorter parks, and once a read
// stayed parked holding them for a whole period the idle release returns
// them (Reader.TryRelease), so an idle reader holds them within
// 2 × IdleRelease of its last datagram. One value for both readers; their
// packages take it as their default (tests lower it there), and each
// package's TestBatchIdleReleaseShared pins it, as the root package's
// plan:774 rows bound their waits by it.
const IdleRelease = time.Second
