// Package lessons7 holds rendr's packet-session lesson scenarios of L58
// (UDP floods), L59 (NAT rebinding) and the idle cost of a packet session
// (M2-D65) (M2 design §A8.3, the WP10c rows; Revision 1, R1-23): two
// Runtimes built with testhooks.NewRuntime, joined by a
// rendrtest.DatagramHub (the passive listens on its socket through
// rendr.FromPacketConn) or by rendrtest.DatagramLinks, inside
// testing/synctest bubbles, driven only through the public API. Every
// scenario proves that its stimulus happened (hub and link counters,
// carrier and session status, the datagrams on the wire), that the load
// was reached, and that the data arrived intact (the seq, size, CRC-32C
// and body of every test datagram). The package has no production code.
package lessons7
