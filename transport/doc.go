// Package transport defines the contract between the rendr engine
// and a concrete network transport (tcp, quic, udp_opaque, gvisor, ...).
//
// The transport contract has two responsibilities the engine cannot
// fulfil itself:
//
//  1. Hide path liveness from Read/Write. A PathConn signals death
//     via OnDeath, never by surfacing an error from Read or Write.
//     The engine relies on this to keep the application-visible
//     net.Conn alive across a path swap (CLAUDE.md hard rule #1).
//
//  2. Classify the cause of any death as either CleanClose (an
//     orderly remote BYE / io.EOF on a known-quiesced stream) or
//     TransportError (any timeout, reset, handshake failure, idle
//     kill, ...). The engine migrates on TransportError and tears
//     down on CleanClose. Misclassifying TransportError as
//     CleanClose is the hy2scale Phase 1 regression we will not
//     repeat (CLAUDE.md hard rule #2).
package transport
