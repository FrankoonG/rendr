package matrix

import (
	"testing"
)

// TestT3StreamNestedTwoLayer — PYS-N-1 (nested 2-layer chain).
//
// DEFERRED.
//
// xray supports proxy chaining via SenderConfig.ProxySettings.Tag:
// outbound A's dial path can be redirected to outbound B's
// Dispatch, layering protocol B around protocol A. The mechanism
// is in app/proxyman/outbound/handler.go:274 (handler.Dial:
// "if h.senderSettings.ProxySettings.HasTag()") and is part of the
// public xray-core surface — but the tagged-chain pattern is
// configured via JSON in real deployments, with tag references
// resolved by the outbound manager at startup. No programmatic
// scenario test in xray-core upstream exercises it; the protobuf
// shape works (ProxyConfig{Tag: ...}) but the inner-vs-outer
// target plumbing has non-obvious semantics (inner outbound's
// protocol target is what the outer protocol's encoded "next hop"
// becomes; the outer's Vnext-style address is what the wire
// actually dials).
//
// Writing a verified 2-layer SS-2022 / VLESS chain end-to-end with
// rendr migration on top is its own ~150-LOC effort with a real
// risk of false-positives if the inner/outer relationship is
// mis-encoded. Defer until a JSON-equivalent reference is
// available or until the docs/regression-suite.md author chooses
// to land it.
//
// rendr-side note: rendr's PathFactory wraps the final net.Conn
// from xray, so nesting depth is transparent to rendr's migration
// engine. This case is about exercising xray's chain plumbing
// itself, not about a different rendr code path. The
// stream.ss2022-via-relay case already covers
// rendr-over-encrypted-protocol-via-intermediate-hop in spirit.
func TestT3StreamNestedTwoLayer(t *testing.T) {
	t.Skip("xray-core proxy chain (SenderConfig.ProxySettings.Tag) needs reference encoding; tracked, not gating")
}

// TestT3StreamReverseOutbound — PYS-V-1 (reverse).
//
// DEFERRED.
//
// xray reverse proxy lets a server behind NAT initiate the
// connection to a "portal" running on the public network; clients
// reach the server via the portal's reverse-bridge inbound.
// Configuring this in-process needs both the bridge inbound + the
// portal outbound + matching reverse.Config on both sides. The
// session bridging logic is also stateful — datagrams need to flow
// in a specific direction for the tunnel to come up.
//
// Same disposition as nested: shape is achievable, no upstream
// programmatic scenario test to crib from. rendr's path migration
// is transparent to which direction the underlying conn was
// initiated — the relay topology case already proves migration
// works through a multi-hop path. Defer reverse until needed.
func TestT3StreamReverseOutbound(t *testing.T) {
	t.Skip("xray reverse outbound is configurable but needs reference encoding; tracked, not gating")
}
