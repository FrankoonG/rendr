package virtualif

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorReasonIsInspectable(t *testing.T) {
	base := errors.New("permission denied")
	err := &Error{Op: "tun probe", Reason: ReasonTUNPermissionDenied, Err: base}
	if !errors.Is(err, base) {
		t.Fatal("wrapped error not preserved")
	}
	if !strings.Contains(err.Error(), string(ReasonTUNPermissionDenied)) {
		t.Fatalf("error string lacks reason: %q", err.Error())
	}
}
