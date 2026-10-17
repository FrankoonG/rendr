package l4

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// UDP flow defaults.
const (
	DefaultFlowIdle      = 180 * time.Second // FlowIdle.Stream
	DefaultFlowShortIdle = 30 * time.Second  // FlowIdle.Short
	DefaultMaxFlows      = 4096              // Server.MaxFlows and PortForward.MaxFlows
)

// FlowIdle are a UDP flow's two idle limits. A zero field takes its
// default; others are clamped to 10 s–24 h, and Short to at most Stream. A
// negative field turns idle expiry off for that class (a negative Short
// for both): unlike Server.IdleTimeout's negative, the Runtime's
// Config.IdleTimeout does not apply then, because l4 has set the session's
// limit.
type FlowIdle struct {
	Short  time.Duration // until the flow is a stream (DefaultFlowShortIdle)
	Stream time.Duration // once it is (DefaultFlowIdle)
}

// The clamp of a FlowIdle class (M6-D8: Conn.SetIdleTimeout's range).
const (
	minFlowIdle = 10 * time.Second
	maxFlowIdle = 24 * time.Hour
)

// limits returns the SetIdleTimeout values of the two classes, 0 meaning
// off: a zero field takes its default, a positive one is clamped to
// 10 s–24 h, a negative one is off, a negative Short makes both off, and a
// Short above a Stream that is on is lowered to it.
func (fi FlowIdle) limits() (short, stream time.Duration) {
	if fi.Short < 0 {
		return 0, 0
	}
	short, stream = classLimit(fi.Short, DefaultFlowShortIdle), classLimit(fi.Stream, DefaultFlowIdle)
	if stream > 0 && short > stream {
		short = stream
	}
	return short, stream
}

// classLimit is one class's value: d's default when d is 0, off (0) when
// d is negative, else d clamped to 10 s–24 h.
func classLimit(d, def time.Duration) time.Duration {
	switch {
	case d == 0:
		return def
	case d < 0:
		return 0
	}
	return min(max(d, minFlowIdle), maxFlowIdle)
}

// firstBudget is the largest whole L4 metadata of a UDP flow (header,
// first-datagram length, first datagram and App) with which DialUDP lets
// the first datagram ride the OPEN (M6-D4): 537, the smallest
// DatagramCarrier.MTU NewPeer accepts (wire.MinFrameBudget), minus 99, the
// OPEN's fixed cost on a datagram carrier, so a first datagram never makes
// DialPacket fail ErrMetadataTooLarge on the datagram budget
// (TestL4UDPFirstBudget_L37 ties it to the core rule).
const firstBudget = 438

// promoteMode is a rule of O-1 (M6-D9, M6-D29, R1-7): when a flow becomes
// a stream at one end, and which flows a full PortForward table may evict.
// One constant, promoteRule, selects it for both; tests select either rule
// through ruleForTest.
type promoteMode uint8

const (
	// promoteOnReply is the owner's literal rule: a flow is a stream at an
	// end from the first datagram that moves there in the second
	// direction (its first reply); a full table evicts only held entries.
	promoteOnReply promoteMode = iota + 1
	// promoteActive is O-1 (a), Linux conntrack's rule with a gap reset
	// (R1-23): a flow is a stream at an end once, within one activity
	// period (a run of datagrams with no gap of streamAfter or more; a gap
	// starts a new period), datagrams moved in both directions and the
	// period has lasted streamAfter; a full table may also evict an open
	// flow that never became a stream and has been idle for at least 1 s.
	promoteActive
)

// promoteRule is the rule in force: O-1 (a), decided on 2026-10-17 (the
// M6 design's delegate decisions; the owner may overrule, which changes
// only this constant). The other rule stays implemented and tested.
const promoteRule = promoteActive

// streamAfter is promoteActive's activity period and gap.
const streamAfter = 2 * time.Second

// ruleForTest, when non-zero, holds the promoteMode that replaces
// promoteRule (tests only: the rows of the other rule, R1-7). Tests set it
// before the forwards or PortForwards they observe start. It is
// package-global: a test that sets it must not run in parallel with
// another l4 test (no l4 test calls t.Parallel).
var ruleForTest atomic.Uint32

// activeRule returns the rule in force: promoteRule unless a test selected
// the other through ruleForTest.
func activeRule() promoteMode {
	if r := promoteMode(ruleForTest.Load()); r != 0 {
		return r
	}
	return promoteRule
}

// DialUDP opens a packet session for one UDP flow to addr ("host:port")
// through p, with o as for Peer.DialPacket; o.Metadata travels after the
// address as Request.App. first, if not empty, is the flow's first
// datagram: it rides the OPEN when the whole L4 metadata is at most 438
// bytes, else DialUDP writes it with WriteTo right after the open; if the
// OPEN with it fails ErrMetadataTooLarge (this Runtime's or the passive's
// Handshake.MaxMetadata), DialUDP opens once more without it and writes it
// after the open. Either way it is sent at most once and, as any datagram,
// may be lost; a first datagram that rides is sent with the OPEN whenever
// the OPEN is sent, outside Packet.MaxAge. DialUDP does not retain first.
// The session has DefaultFlowIdle set (an application that pumps the flow
// itself may change it with SetIdleTimeout; ForwardPacket applies the
// classes). Its MaxPayload is the largest datagram the flow carries (the
// package's "UDP flows" section). Errors: ErrBadAddress (before any network
// I/O); ErrPacketTooLarge for a first datagram that does not ride and is
// above the session's MaxPayload (DialUDP has closed the session);
// Peer.DialPacket's errors (ErrProtocol for o.EarlyReturn,
// ErrMetadataTooLarge, ErrCapacity, ErrNoPath, ErrVersion, ctx); an l4
// Server's refusal is a *rendr.RejectError whose code CodeOf reports. A
// Server without UDP, or a v2.0.0 passive, never serves the flow:
// ErrCapacity after the passive's AcceptTimeout.
func DialUDP(ctx context.Context, p *rendr.Peer, addr string, first []byte, o rendr.DialOptions) (*rendr.PacketConn, error) {
	app := o.Metadata
	// The metadata without the first datagram: the address check, before any
	// network I/O, and the retry's OPEN (R1-4).
	bare, err := AppendMetadata(make([]byte, 0, maxHeader+firstLenLen+len(app)), Request{Cmd: CmdUDP, Addr: addr, App: app})
	if err != nil {
		return nil, err
	}
	o.Metadata = bare
	rides := len(first) > 0 && len(bare)+len(first) <= firstBudget
	if rides {
		if o.Metadata, err = AppendMetadata(make([]byte, 0, len(bare)+len(first)), Request{Cmd: CmdUDP, Addr: addr, App: app, First: first}); err != nil {
			return nil, err
		}
	}
	pc, err := p.DialPacket(ctx, o)
	if rides && errors.Is(err, rendr.ErrMetadataTooLarge) {
		// This Runtime's Handshake.MaxMetadata refused it before any I/O, or
		// the passive's answered CodeMetadataSize before admitting a session:
		// no target received the first datagram. Once more without it, and
		// it follows the open, so it is still sent at most once (M6-D4,
		// R1-4).
		o.Metadata, rides = bare, false
		pc, err = p.DialPacket(ctx, o)
	}
	if err != nil {
		return nil, err
	}
	// net.ErrClosed only: the session already ended, and its first ReadFrom
	// or WriteTo reports why.
	pc.SetIdleTimeout(DefaultFlowIdle)
	if len(first) > 0 && !rides {
		// WriteTo copies the datagram: first is not retained. Any other error
		// is the session's end, which its next call reports (as Dial's
		// SetIdleTimeout above); the datagram is lost with it.
		if _, err := pc.WriteTo(first, nil); errors.Is(err, rendr.ErrPacketTooLarge) {
			pc.Close() // R1-9: an error never comes with a live session
			return nil, err
		}
	}
	return pc, nil
}
