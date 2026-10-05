package carrier

// The reliable control sublayer of datagram carriers (M2-D16…M2-D18; M2
// design §A5.9).

// relState is the REL sublayer of one carrier, both directions (rel.go):
// sender — next and oldest unacknowledged cseq, ≤ wire.RelWindow entries of
// at most wire.RelMaxPayload bytes, the retransmission count of the oldest,
// its due time and the blocked flag; receiver — the cumulative point, ≤
// wire.RelWindow − 1 held inner frames and the RACK-due flag.
type relState struct{}
