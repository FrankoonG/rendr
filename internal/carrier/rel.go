package carrier

// The reliable control sublayer of datagram carriers (M2-D16…M2-D18; M2
// design §A5.9 and Revision 1, R1-2, R1-3, R1-17, R1-18).

// relState is the REL sublayer of one carrier, both directions (rel.go,
// WP3a): sender — next and oldest unacknowledged cseq, ≤ wire.RelWindow
// entries of at most wire.RelMaxPayload bytes, the retransmission count of
// the oldest, its due time and the blocked flag; receiver — the cumulative
// point, ≤ wire.RelWindow − 1 held inner frames and the RACK-due flag.
// Only the oldest unacknowledged cseq is ever retransmitted; SACK bits are
// validated and otherwise ignored (R1-18). The retransmission timer is
// armed after the datagram carrying a new REL was attempted — written,
// refused as too large or lost to noise — and only while una ≠ next; it is
// cleared when una reaches next (R1-2). The handshakes set the start values
// with initSend and initRecv (R1-3).
type relState struct{}

// initSend sets the sender's start: next = una = next (the first cseq this
// side will assign). Called by the handshakes before the Conn is returned
// (R1-3's table: FirstCseq + 1 on a dialer whose H1 carried REL{FirstCseq},
// FirstCseq otherwise).
func (r *relState) initSend(next uint32) {
	panic("unimplemented: M2")
}

// initRecv sets the receiver's cumulative point: the cseq of the last REL
// of the peer already dispatched by the handshake (R1-3's table:
// FirstCseq where the handshake carried a REL{FirstCseq} in that
// direction, FirstCseq − 1 where it carried none — probe handshakes).
func (r *relState) initRecv(cum uint32) {
	panic("unimplemented: M2")
}

// RelRoom returns the REL frames a reliable frame could still reserve on
// this carrier now: wire.RelWindow minus those outstanding; 0 on stream
// carriers and on a dead carrier. A session whose reliable PACK found no REL
// room on its duty lane moves the PACK duty to a live lane whose RelRoom is
// positive (R1-17). It takes Conn.mu (Session.mu → Conn.mu).
func (c *Conn) RelRoom() int {
	panic("unimplemented: M2")
}
