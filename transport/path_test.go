package transport

import "testing"

func TestPathSpecCloneOwnsOpts(t *testing.T) {
	original := PathSpec{Transport: "test", Address: "peer", Opts: map[string]string{"key": "value"}}
	clone := original.Clone()
	original.Opts["key"] = "caller"
	if got := clone.Opts["key"]; got != "value" {
		t.Fatalf("clone option = %q, want value", got)
	}
	clone.Opts["key"] = "snapshot"
	if got := original.Opts["key"]; got != "caller" {
		t.Fatalf("original option = %q, want caller", got)
	}
}
