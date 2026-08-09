// Package tcpquarantine owns short-lived nftables rules that isolate both
// directions of one IPv4 TCP connection during a destructive endpoint change.
//
// Every mutation is submitted as one nft batch. A command result is never
// treated as authoritative: the package independently lists and validates the
// resulting table before publishing an installed or released lease.
package tcpquarantine
