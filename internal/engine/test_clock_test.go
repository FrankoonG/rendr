package engine

import (
	"testing"
	"time"
)

func installEngineNowForTest(t *testing.T, now func() time.Time) {
	t.Helper()
	if now == nil {
		t.Fatal("cannot install a nil engine test clock")
	}
	installed := &engineNowSource{call: now}
	if previous := engineNowOverride.Swap(installed); previous != nil {
		engineNowOverride.Store(previous)
		t.Fatal("another engine test clock is already installed")
	}
	t.Cleanup(func() {
		if !engineNowOverride.CompareAndSwap(installed, nil) {
			t.Error("engine test clock ownership changed before cleanup")
		}
	})
}
