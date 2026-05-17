package rendr

import "fmt"

// Mode selects how the engine uses the set of available paths.
type Mode uint8

const (
	// ModePrime picks the single best-scoring path and migrates only
	// when another path beats the current one by the hysteresis margin
	// for at least dwell, with cooldown between switches.
	ModePrime Mode = 1
	// ModeBond splits frames across paths to aggregate throughput.
	ModeBond Mode = 2
	// ModeRace duplicates every frame across all paths and dedupes on
	// receive. Bandwidth equals the single best path; latency equals
	// the minimum across paths.
	ModeRace Mode = 3
)

func (m Mode) String() string {
	switch m {
	case ModePrime:
		return "prime"
	case ModeBond:
		return "bond"
	case ModeRace:
		return "race"
	default:
		return fmt.Sprintf("mode(%d)", uint8(m))
	}
}

// Valid reports whether m is one of the defined modes.
func (m Mode) Valid() bool {
	return m == ModePrime || m == ModeBond || m == ModeRace
}
