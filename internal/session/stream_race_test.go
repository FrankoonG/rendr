//go:build race

package session

// streamRaceEnabled: allocation and timing gates of the stream tests are
// asserted only in the non-race lane (design §11.1); the functional checks
// run in both. The name is specific to the stream tests so that it cannot
// collide with another work package's race constant in this package.
const streamRaceEnabled = true
