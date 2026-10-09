// Package packet holds rendr's packet-session scenarios and gates (M2
// design §A8.3, the WP11 rows, and §A8.5): the re-ported msess packet
// failover tests, the G3, G4-pkt and G5-pkt gold criteria at reduced scale,
// and the end-to-end zero-allocation gate and packet-rate benchmark over
// carrier/udp on loopback.
//
// The scenarios run two Runtimes built with testhooks.NewRuntime, joined by
// rendrtest.DatagramLinks, inside testing/synctest bubbles and drive them
// only through the public API. Every scenario proves that its stimulus
// happened (link counters, carrier and session status, events), that the
// load was reached, and that the data arrived intact (the seq, size,
// CRC-32C and body of every test datagram). The gates use real loopback
// sockets outside bubbles. The package has no production code.
package packet
