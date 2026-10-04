//go:build race

package carrier

// bufRaceEnabled: the race detector makes sync.Pool drop items on purpose,
// so the buffer-pool allocation gate is asserted only in the non-race lane
// (design §11.1). The name is specific to the buffer tests so that it cannot
// collide with another file's race constant in this package.
const bufRaceEnabled = true
