//go:build race

package udpflow

// raceEnabled: the race detector allocates on its own paths (sync.Pool
// drops items on purpose), so the allocation gates are asserted only in
// the non-race lane (M5 design §A10.3).
const raceEnabled = true
