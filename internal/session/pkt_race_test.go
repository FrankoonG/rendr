//go:build race

package session

// dpRaceEnabled: the packet plane's allocation and timing gates are
// asserted in the non-race lane only (M2 design §A8.5); the functional
// checks run in both. The name is WP6a's, so it cannot collide with
// another work package's race constant in this package.
const dpRaceEnabled = true
