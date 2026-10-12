package l4

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/v2"
)

// allCodes are the thirteen Reject codes with their fixed class texts (M4
// design §A6.5).
var allCodes = []struct {
	code RejectCode
	text string
}{
	{CodeBadRequest, "bad request"},
	{CodeBadVersion, "unsupported version"},
	{CodeBadCommand, "unsupported command"},
	{CodeBadAddress, "bad address"},
	{CodeNotAllowed, "not allowed"},
	{CodeRefused, "connection refused"},
	{CodeNetUnreachable, "network unreachable"},
	{CodeHostUnreachable, "host unreachable"},
	{CodeTimeout, "connect timeout"},
	{CodeDNSNotFound, "name not found"},
	{CodeDNSFailure, "name resolution failed"},
	{CodeCapacity, "capacity"},
	{CodeDialFailed, "dial failed"},
}

// TestRejectCodeTexts: every code has its fixed text (the Reject message a
// Server sends, so it carries no raw error), within the 255-byte Reject
// message limit, distinct from every other; the codes are consecutive in the
// l4 range, far above the reserved application range; an unknown code
// prints its number.
func TestRejectCodeTexts(t *testing.T) {
	seen := map[string]bool{}
	for i, c := range allCodes {
		if got := c.code.String(); got != c.text {
			t.Errorf("%#x.String() = %q, want %q", uint32(c.code), got, c.text)
		}
		if len(c.text) > 255 || c.text == "" || seen[c.text] {
			t.Errorf("text %q: empty, longer than 255 bytes or repeated", c.text)
		}
		seen[c.text] = true
		if want := RejectCode(0x4C340001 + i); c.code != want || uint32(c.code)>>8 != 0x4C3400 {
			t.Errorf("code %d = %#x, want %#x in the l4 range", i, uint32(c.code), uint32(want))
		}
		e := &MetadataError{Code: c.code, Msg: "why"}
		if !strings.Contains(e.Error(), c.text) || !strings.Contains(e.Error(), "why") {
			t.Errorf("MetadataError.Error() = %q", e.Error())
		}
	}
	for _, c := range []RejectCode{0, 0x4C340000, 0x4C34000E, 0x4C340101, 256} {
		if got, want := c.String(), fmt.Sprintf("l4 code %#08x", uint32(c)); got != want {
			t.Errorf("unknown %#x.String() = %q, want %q", uint32(c), got, want)
		}
	}
	if uint32(AbortReset) != 0x4C340101 || uint32(AbortShutdown) != 0x4C340102 {
		t.Error("abort codes moved")
	}
}

// TestCodeOf: CodeOf reports an l4 Server's refusal, wrapped or not, and
// nothing else: an application's own Reject code, an abort, the bare
// sentinel and local errors are not l4 codes.
func TestCodeOf(t *testing.T) {
	for _, c := range allCodes {
		re := &rendr.RejectError{Code: uint32(c.code), Msg: c.text}
		for _, err := range []error{re, fmt.Errorf("dial: %w", re), errors.Join(errors.New("x"), re)} {
			if got, ok := CodeOf(err); !ok || got != c.code {
				t.Errorf("CodeOf(%v) = %v, %v; want %v", err, got, ok, c.code)
			}
		}
	}
	for _, err := range []error{
		nil,
		errors.New("refused"),
		rendr.ErrRejected,
		&rendr.RejectError{Code: 256},
		&rendr.RejectError{Code: 0x4C340000},
		&rendr.RejectError{Code: 0x4C34000E},
		&rendr.RejectError{Code: uint32(AbortReset)},
		&rendr.AbortError{Code: AbortReset, Remote: true},
		&MetadataError{Code: CodeBadAddress},
		ErrBadAddress,
	} {
		if got, ok := CodeOf(err); ok {
			t.Errorf("CodeOf(%v) = %v, true; want false", err, got)
		}
	}
}
