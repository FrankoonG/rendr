// Package xrayglue is the bridge between rendr and xray-core.
//
// Per docs/xray-integration.md, rendr core stays xray-agnostic; the
// glue lives here in the regress submodule (which has its own
// go.mod) so xray-core's heavy dependency footprint never lands in
// the root rendr module.
//
// Two responsibilities:
//
//  1. Glue B (rendr-above-xray, regress side): wrap a full xray
//     outbound chain into a rendr StreamPathFactory or
//     PacketPathFactory. Used by docs/regression-suite.md §7 T3
//     matrix to back each path-profile (direct / relay / nested /
//     reverse / TLS / REALITY / MLKEM) with real xray protocol code.
//
//  2. Glue A (rendr-below-xray, regress side): register rendr as
//     xray streamSettings.network = "rendr" via
//     transport.internet.RegisterTransportDialer so the same
//     in-process xray-core instance can stack a protocol (vmess /
//     vless / ...) atop a rendr Conn. Used for the X-style
//     compatibility sub-suite.
//
// External (non-test) embedders that want the same patterns can
// copy the small glue files — they're ~30 lines each.
package xrayglue
