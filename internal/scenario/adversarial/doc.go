// Package adversarial holds rendr's fseq/CRC adversarial set (M3 design
// §A9.3; plan:650; L41, L43, L69): a path or relay that damages, drops,
// duplicates, replays or splices the frames of a carrier — a
// rendrtest.Tamper between the two ends of every stream carrier, the
// DatagramLink replay and splice controls, the DatagramHub's flow
// replay, and a bit-flipping datagram conn — kills only the carrier it attacked (stream) or loses only the
// datagrams it damaged (datagram), never corrupts or duplicates
// application data, and never harms another session beyond a migration.
//
// Every row runs against each carrier setup of the suite's setup table:
// dedicated carriers of selector, bond and race sessions, and four
// selector, bond or race sessions sharing one MUX trunk per link (the MUX
// rows add TestAdvMuxSpliceCrossTrunk_L43 and
// TestAdvMuxHandleConfusion_L43_L14). The scenarios
// run two Runtimes built with testhooks.NewRuntime, joined by rendrtest
// links inside testing/synctest bubbles, and drive them only through the
// public API. Each proves that its stimulus fired (the tamper's or the
// conn's counters), that the attacked carrier ended as the row expects,
// that every session's data arrived intact (PRNG-verified bytes, verified
// datagrams), that no application call failed, and that the migrations are
// the expected ones. The package has no production code.
package adversarial
