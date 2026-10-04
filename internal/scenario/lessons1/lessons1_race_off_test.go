//go:build !race

package lessons1

// lessonsRace: CPU-heavy scenarios shrink their volume under the race
// detector (design §11.1), so the package stays fast in the race lane.
const lessonsRace = false
