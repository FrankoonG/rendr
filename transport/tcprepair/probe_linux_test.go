//go:build linux

package tcprepair

import (
	"os"
	"strings"
	"testing"
)

func TestAvailableExpectation(t *testing.T) {
	expect := os.Getenv("RENDR_EXPECT_TCPREPAIR")
	if expect == "" {
		t.Skip("expectation env unset")
	}
	err := Available()
	switch expect {
	case "available":
		if err != nil {
			t.Fatalf("Available(): %v", err)
		}
	case "unavailable":
		if err == nil {
			t.Fatal("Available() unexpectedly succeeded")
		}
		if !strings.Contains(err.Error(), "CAP_NET_ADMIN required") {
			t.Fatalf("unexpected unavailable error: %v", err)
		}
		if strings.Contains(strings.ToLower(err.Error()), "gvisor") {
			t.Fatalf("low-level capability probe promised a backend fallback: %v", err)
		}
	default:
		t.Fatalf("unknown expectation %q", expect)
	}
}
