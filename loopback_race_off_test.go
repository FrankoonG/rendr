//go:build !race

package rendr_test

// loopbackRace reports the race detector (allocation and throughput
// assertions run only without it, design §11.1).
const loopbackRace = false
