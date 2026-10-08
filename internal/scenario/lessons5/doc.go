// Package lessons5 holds rendr's packet-session lesson scenarios of L12,
// L39, L40 and L43 (M2 design §A8.3, the WP10a rows; Revision 1, R1-10 and
// R1-23): two Runtimes built with testhooks.NewRuntime, joined by
// rendrtest.DatagramLinks (and rendrtest.Links where a stream carrier or a
// stream session takes part) inside testing/synctest bubbles, driven only
// through the public API. Every scenario proves that its stimulus happened
// (link counters, carrier and session status, retransmission hooks), that
// the load was reached, and that the data arrived intact (the seq, size,
// CRC-32C and body of every test datagram; SHA-256 for streams). The
// package has no production code.
package lessons5
