//go:build race

package carrier

// carrierRace: throughput ratios and allocation gates are asserted only in
// the non-race lane (design §11.1); the race detector slows the data path
// and makes sync.Pool drop items on purpose. The name is specific to the
// carrier runtime tests so that it cannot collide with another file's race
// constant in this package.
const carrierRace = true
