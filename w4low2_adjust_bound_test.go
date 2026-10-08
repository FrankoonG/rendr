package rendr

import (
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// TestConfigAdjustmentsBounded (W4-L2-2): every Listen call whose
// ListenConfig is clamped records "Listen[i]." adjustments, and Status
// copies the list on every call. Under Listen and Close churn the list
// stays bounded: the Config's records are all kept, then at most
// maxListenAdjust Listen records, the latest ones, in call order.
func TestConfigAdjustmentsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt, err := NewRuntime(Config{Window: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close()
		const cycles = 1000
		for range cycles {
			ln, err := rt.Listen(ListenConfig{AcceptTimeout: time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			if err := ln.Close(); err != nil {
				t.Fatal(err)
			}
		}
		// The latest call records one more adjustment than the others.
		if _, err := rt.Listen(ListenConfig{AcceptBacklog: -5, AcceptTimeout: time.Millisecond}); err != nil {
			t.Fatal(err)
		}
		adj := rt.Status().ConfigAdjustments
		if len(adj) > 1+maxListenAdjust {
			t.Fatalf("%d adjustments after %d Listen calls, want at most %d", len(adj), cycles+1, 1+maxListenAdjust)
		}
		if len(adj) != 1+maxListenAdjust || !strings.HasPrefix(adj[0], "Window: 1 → ") {
			t.Fatalf("adjustments %q: want the Config record first, then %d Listen records", adj, maxListenAdjust)
		}
		last := "Listen[" + strconv.Itoa(cycles) + "]."
		if !strings.HasPrefix(adj[len(adj)-2], last+"AcceptBacklog: -5 → 1 ") ||
			!strings.HasPrefix(adj[len(adj)-1], last+"AcceptTimeout: 1ms → 100ms ") {
			t.Fatalf("latest records %q, want the last Listen's two", adj[len(adj)-2:])
		}
		// The kept Listen records are the latest ones, in call order.
		first := cycles - (maxListenAdjust - 2)
		for k, a := range adj[1 : len(adj)-2] {
			want := "Listen[" + strconv.Itoa(first+k) + "].AcceptTimeout: 1ms → 100ms "
			if !strings.HasPrefix(a, want) {
				t.Fatalf("record %d %q, want prefix %q", k+1, a, want)
			}
		}
	})
}
