package udpsocket

import (
	"errors"
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

// TestZoneTableFirstFetchConcurrent (R3-11, L55; synctest, every target):
// while the process's first interface fetch runs, a concurrent lookup
// waits for its snapshot — as the net package's zone cache blocks on its
// lock — instead of answering with the decimal fallback ("eth7" → 0, 7 →
// "7"), and the waiter costs no second fetch. Mutant: the losers of the
// first fetch return the empty table.
func TestZoneTableFirstFetchConcurrent(t *testing.T) {
	seams(t)
	synctest.Test(t, func(t *testing.T) {
		var fetches atomic.Int64
		gate, entered := make(chan struct{}), make(chan struct{})
		interfacesFn = func() ([]net.Interface, error) {
			if fetches.Add(1) == 1 {
				close(entered)
				<-gate // the first fetch is slow
			}
			return []net.Interface{{Index: 1, Name: "lo"}, {Index: 7, Name: "eth7"}}, nil
		}
		type answer struct {
			index uint32
			name  string
		}
		first := make(chan uint32, 1)
		go func() { first <- zoneIndex("eth7") }()
		<-entered
		second := make(chan answer, 1)
		go func() { second <- answer{zoneIndex("eth7"), zoneName(7)} }()
		synctest.Wait() // the second lookup ran as far as it can while the fetch is blocked
		var early *answer
		select {
		case a := <-second:
			early = &a
		default:
		}
		close(gate)
		if i := <-first; i != 7 {
			t.Errorf("the fetching lookup: eth7 → %d, want 7", i)
		}
		if early != nil {
			t.Fatalf("during the first fetch a concurrent lookup answered eth7 → %d, 7 → %q; want it to wait for the snapshot", early.index, early.name)
		}
		if a := <-second; a.index != 7 || a.name != "eth7" {
			t.Fatalf("the waiting lookup: eth7 → %d, 7 → %q; want 7, eth7", a.index, a.name)
		}
		if n := fetches.Load(); n != 1 {
			t.Fatalf("%d fetches; want 1 (the waiter uses the first fetch's snapshot)", n)
		}
	})
}

// TestZoneTableFetchError (R3-11; synctest, every target): a failed fetch
// while no snapshot exists does not hold the miss period: the next lookup
// fetches again — as the net package forces a refresh at every miss — and
// resolves the name, with no time passing. Mutant: the miss gate kept after
// a failed first fetch (eth7 → 0 for a whole zoneMissRefresh).
func TestZoneTableFetchError(t *testing.T) {
	seams(t)
	synctest.Test(t, func(t *testing.T) {
		var fetches atomic.Int64
		interfacesFn = func() ([]net.Interface, error) {
			if fetches.Add(1) == 1 {
				return nil, errors.New("interface dump failed")
			}
			return []net.Interface{{Index: 1, Name: "lo"}, {Index: 7, Name: "eth7"}}, nil
		}
		if i := zoneIndex("eth7"); i != 0 || fetches.Load() != 1 {
			t.Fatalf("with the fetch failing: eth7 → %d after %d fetches; want the decimal fallback 0 after 1", i, fetches.Load())
		}
		if i, name := zoneIndex("eth7"), zoneName(7); i != 7 || name != "eth7" {
			t.Fatalf("after a failed fetch, no time passed: eth7 → %d, 7 → %q; want 7, eth7", i, name)
		}
		if n := fetches.Load(); n != 2 {
			t.Fatalf("%d fetches; want 2 (the failed one, then one snapshot)", n)
		}
	})
}

// TestZoneTableClockStepBack (R3-11; every target): a clock that steps
// back never makes an old snapshot look fresh or the fetch gate shut. The
// snapshot is taken outside a synctest bubble; inside it time.Now reads
// 2000-01-01 with no monotonic reading — a clock stepped back by decades,
// as a wall clock may be (production reads the monotonic clock, which
// never steps; the bubble is the only way to step the table's clock). An
// interface added in between is seen after 2 × zoneRefresh. Mutant: the
// wall clock without the step-back expiry (time.Now().UnixNano() and the
// old comparisons): "9", 0 and a single fetch.
func TestZoneTableClockStepBack(t *testing.T) {
	seams(t)
	var fetches atomic.Int64
	ifs := []net.Interface{{Index: 1, Name: "lo"}}
	interfacesFn = func() ([]net.Interface, error) {
		fetches.Add(1)
		return ifs, nil
	}
	if zoneName(1) != "lo" {
		t.Fatalf("1 → %q, want lo", zoneName(1))
	}
	ifs = append(ifs, net.Interface{Index: 9, Name: "eth9"})
	synctest.Test(t, func(t *testing.T) {
		time.Sleep(2 * zoneRefresh)
		if name, i := zoneName(9), zoneIndex("eth9"); name != "eth9" || i != 9 {
			t.Fatalf("after %v: 9 → %q, eth9 → %d, %d fetches; want eth9, 9", 2*zoneRefresh, name, i, fetches.Load())
		}
	})
}
