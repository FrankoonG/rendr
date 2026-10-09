// Package lessons6 holds rendr's packet-session lesson scenarios of L06,
// L24, L28, L32 and L37 (M2 design §A8.3, the WP10b rows; Revision 1,
// R1-23): two Runtimes built with testhooks.NewRuntime, joined by
// rendrtest.DatagramLinks (and rendrtest.Links where a stream carrier
// takes part) inside testing/synctest bubbles, driven only through the
// public API. Every scenario proves that its stimulus happened (link
// counters, carrier and session status, events), that the load was
// reached, and that the data arrived intact (the seq, size, CRC-32C and
// body of every test datagram). The package has no production code.
package lessons6
