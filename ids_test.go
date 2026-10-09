package rendr

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
)

// TestIDStrings checks the ID and Addr text forms.
func TestIDStrings(t *testing.T) {
	inst := InstanceID{0x01, 0xab, 15: 0xff}
	sid := SessionID{0xde, 0xad, 15: 0x01}
	if s := inst.String(); s != "01ab0000000000000000000000000000"[:30]+"ff" || len(s) != 32 {
		t.Fatalf("InstanceID.String() = %q", s)
	}
	if s := sid.String(); s != "dead00000000000000000000000000"+"01" {
		t.Fatalf("SessionID.String() = %q", s)
	}
	if !(InstanceID{}).IsZero() || inst.IsZero() {
		t.Fatal("IsZero")
	}
	var a net.Addr = Addr{Instance: inst, Session: sid}
	if a.Network() != "rendr" || a.String() != inst.String()+"/"+sid.String() {
		t.Fatalf("Addr %q %q", a.Network(), a.String())
	}
}

type zeroThenReader struct{ zeros int }

func (r *zeroThenReader) Read(p []byte) (int, error) {
	if r.zeros > 0 {
		r.zeros--
		clear(p)
		return len(p), nil
	}
	for i := range p {
		p[i] = byte(i + 1)
	}
	return len(p), nil
}

type failReader struct{}

var errSource = errors.New("entropy source failed")

func (failReader) Read([]byte) (int, error) { return 0, errSource }

// TestRandomIDs checks the ID draws of plan §3.4 and L47: crypto/rand IDs
// are never zero and differ; an all-zero draw is redrawn; a source that
// only yields zeros or fails is reported, never turned into a zero ID.
func TestRandomIDs(t *testing.T) {
	seen := make(map[InstanceID]bool)
	for i := 0; i < 100; i++ {
		id, err := newInstanceID(rand.Reader)
		if err != nil || id.IsZero() || seen[id] {
			t.Fatalf("draw %d: %v %v (repeat %v)", i, id, err, seen[id])
		}
		seen[id] = true
		sid, err := newSessionID(rand.Reader)
		if err != nil || sid == (SessionID{}) {
			t.Fatalf("session draw %d: %v %v", i, sid, err)
		}
	}
	id, err := newInstanceID(&zeroThenReader{zeros: 3})
	if err != nil || id.IsZero() || id[0] != 1 {
		t.Fatalf("zero draws were not redrawn: %v %v", id, err)
	}
	if id, err := newSessionID(&zeroThenReader{zeros: 4}); !errors.Is(err, errZeroIDs) || id != (SessionID{}) {
		t.Fatalf("a zero-only source: %v %v", id, err)
	}
	if _, err := newInstanceID(failReader{}); !errors.Is(err, errSource) {
		t.Fatalf("a failing source: %v", err)
	}
	if _, err := newInstanceID(bytes.NewReader(make([]byte, 7))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a short source: %v", err)
	}
}

// TestEnumStrings checks every enum name, including the fallbacks for
// values a newer peer or milestone might add.
func TestEnumStrings(t *testing.T) {
	cases := []struct{ got, want string }{
		{Mode(0).String(), "mode(0)"}, {ModeSelector.String(), "selector"}, {ModeBond.String(), "bond"}, {Mode(3).String(), "mode(3)"},
		{KindStream.String(), "stream"}, {Kind(2).String(), "datagram"}, {Kind(3).String(), "kind(3)"},
		{RoleDialer.String(), "dialer"}, {RolePassive.String(), "passive"}, {Role(9).String(), "role(9)"},
		{StatePending.String(), "pending"}, {StateOpen.String(), "open"}, {StateClosing.String(), "closing"},
		{StateEnded.String(), "ended"}, {State(0).String(), "state(0)"},
		{CarrierJoining.String(), "joining"}, {CarrierActive.String(), "active"}, {CarrierMember.String(), "member"},
		{CarrierRetiring.String(), "retiring"}, {CarrierDead.String(), "dead"}, {CarrierState(200).String(), "carrier(200)"},
		{CauseNone.String(), "none"}, {CausePingTimeout.String(), "ping_timeout"}, {CauseWriteStall.String(), "write_stall"},
		{CauseTransportError.String(), "transport_error"}, {CauseProtocolViolation.String(), "protocol_violation"},
		{CauseInstanceMismatch.String(), "instance_mismatch"}, {CauseGoAway.String(), "goaway"},
		{CauseLocalClose.String(), "local_close"}, {CauseRetired.String(), "retired"}, {CauseQuality.String(), "quality"},
		{Cause(77).String(), "none"},
		{EventCarrierUp.String(), "carrier_up"}, {EventCarrierDown.String(), "carrier_down"}, {EventMigration.String(), "migration"},
		{EventNoPathStart.String(), "no_path_start"}, {EventNoPathEnd.String(), "no_path_end"},
		{EventSessionEnd.String(), "session_end"}, {EventKind(0).String(), "event(0)"}, {EventKind(255).String(), "event(255)"},
		{EvidenceUnknown.String(), "unknown"}, {EvidenceFresh.String(), "fresh"}, {EvidenceHeld.String(), "held"},
		{EvidenceStale.String(), "stale"}, {Evidence(9).String(), "unknown"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	for _, v := range []uint64{0, 7, 10, 255, 1 << 32, ^uint64(0)} {
		if got := itoa(v); got != strconv.FormatUint(v, 10) {
			t.Errorf("itoa(%d) = %q", v, got)
		}
	}
}
