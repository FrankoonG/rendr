package carrier

// Cause says why a carrier ended (plan §3.6 DeathCause). Values are
// numerically identical to rendr.Cause.
type Cause uint8

// Causes.
const (
	CauseNone              Cause = 0
	CausePingTimeout       Cause = 1 // the oldest committed PING stayed unanswered beyond the death deadline
	CauseWriteStall        Cause = 2 // one batch write exceeded the stall window
	CauseTransportError    Cause = 3 // EOF, RST, read/write error, (0, nil), invalid counts, panic or Goexit in the conn
	CauseProtocolViolation Cause = 4 // decode, CRC, fseq, ACK beyond sent, window overrun, conflicting FIN, bad handle/type/flags
	CauseInstanceMismatch  Cause = 5 // PREFACE_ACK instance differs from the session's bound instance
	CauseGoAway            Cause = 6 // the peer sent GOAWAY
	CauseLocalClose        Cause = 7 // closed by this side (session end, Runtime/Peer close, lost race)
	CauseRetired           Cause = 8 // planned CLOSE exchange completed (or a peer CLOSE); not a death
	CauseQuality           Cause = 9 // never a carrier end: the cause of a quality migration event
)

// String returns the plan §3.6 name: "ping_timeout", "write_stall",
// "transport_error", "protocol_violation", "instance_mismatch", "goaway",
// "local_close", "retired", "quality", or "none".
func (c Cause) String() string {
	switch c {
	case CausePingTimeout:
		return "ping_timeout"
	case CauseWriteStall:
		return "write_stall"
	case CauseTransportError:
		return "transport_error"
	case CauseProtocolViolation:
		return "protocol_violation"
	case CauseInstanceMismatch:
		return "instance_mismatch"
	case CauseGoAway:
		return "goaway"
	case CauseLocalClose:
		return "local_close"
	case CauseRetired:
		return "retired"
	case CauseQuality:
		return "quality"
	}
	return "none"
}

// Death reports whether c is a death cause (everything but none, retired
// and quality). A retired carrier is not a death: it sets no failed mark,
// triggers no immediate same-factory redial and is never counted as a death
// migration. Losing a selector's active lane to it is still a routing loss
// that the session repairs by fallback or race (design §7.3).
func (c Cause) Death() bool { return c != CauseNone && c != CauseRetired && c != CauseQuality }
