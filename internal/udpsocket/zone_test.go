package udpsocket

import (
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// TestZoneTable (L41, L55; synctest, every target): a zoned IPv6 address
// costs a lookup in the zone table's snapshot — no interface dump and no
// allocation per datagram — and resolves as the net package resolves it
// (an interface name, else a decimal index). Unknown zones refetch the
// interfaces at most once per zoneMissRefresh, and the snapshot is
// refetched when it is zoneRefresh old.
func TestZoneTable(t *testing.T) {
	seams(t)
	var fetches atomic.Int64
	ifs := []net.Interface{{Index: 1, Name: "lo"}, {Index: 7, Name: "eth7"}}
	interfacesFn = func() ([]net.Interface, error) {
		fetches.Add(1)
		return ifs, nil
	}
	synctest.Test(t, func(t *testing.T) {
		if zoneName(7) != "eth7" || zoneIndex("eth7") != 7 || zoneIndex("lo") != 1 || zoneIndex("") != 0 {
			t.Fatalf("eth7 → %d, 7 → %q, lo → %d", zoneIndex("eth7"), zoneName(7), zoneIndex("lo"))
		}
		for range 1000 {
			zoneName(7)
			zoneIndex("lo")
		}
		if n := fetches.Load(); n != 1 {
			t.Fatalf("%d interface fetches for 2,004 known lookups; want 1", n)
		}
		if a := testing.AllocsPerRun(100, func() { zoneName(7); zoneIndex("eth7") }); a != 0 && !raceEnabled {
			t.Fatalf("%v allocations per known lookup", a)
		}
		// Unknown zones: the decimal form, and no fetch storm.
		for range 100 {
			if zoneName(9) != "9" || zoneIndex("5") != 5 || zoneIndex("eth9") != 0 {
				t.Fatalf("unknown zones: 9 → %q, \"5\" → %d, eth9 → %d", zoneName(9), zoneIndex("5"), zoneIndex("eth9"))
			}
		}
		if n := fetches.Load(); n != 1 {
			t.Fatalf("%d fetches after 300 misses within the miss period; want 1", n)
		}
		// A fresh snapshot serves known zones without a fetch, also once a
		// miss period has passed.
		time.Sleep(zoneMissRefresh)
		for range 100 {
			zoneName(7)
			zoneIndex("lo")
		}
		if n := fetches.Load(); n != 1 {
			t.Fatalf("%d fetches for known zones %v after the first; want 1", n, zoneMissRefresh)
		}
		// An interface added: seen at the first miss after the period.
		ifs = append(ifs, net.Interface{Index: 9, Name: "eth9"})
		if zoneName(9) != "eth9" || zoneIndex("eth9") != 9 || fetches.Load() != 2 {
			t.Fatalf("after the miss period: 9 → %q, eth9 → %d, %d fetches; want eth9, 9, 2", zoneName(9), zoneIndex("eth9"), fetches.Load())
		}
		// A stale snapshot is refetched once.
		time.Sleep(zoneRefresh)
		for range 100 {
			zoneName(7)
		}
		if n := fetches.Load(); n != 3 {
			t.Fatalf("%d fetches after the snapshot aged %v; want 3", n, zoneRefresh)
		}
	})
}
