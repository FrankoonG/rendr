package rendr

import (
	"fmt"

	"github.com/FrankoonG/rendr/proto"
)

// Mode selects how the engine uses the set of available paths.
type Mode uint8

const (
	// ModeSelector picks the single best-scoring path and migrates only
	// when another path beats the current one by the hysteresis margin
	// for at least dwell, with cooldown between switches.
	ModeSelector Mode = 1
	// ModeBond splits frames across paths to aggregate throughput.
	ModeBond Mode = 2
	// ModeRace duplicates every frame across all paths and dedupes on
	// receive. Bandwidth equals the single best path; latency equals
	// the minimum across paths.
	ModeRace Mode = 3
)

func (m Mode) String() string {
	switch m {
	case ModeSelector:
		return "selector"
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
	return m == ModeSelector || m == ModeBond || m == ModeRace
}

func (m Mode) executionKind() (proto.ExecutionKind, bool) {
	switch m {
	case ModeSelector:
		return proto.ExecutionKindSelector, true
	case ModeBond:
		return proto.ExecutionKindBond, true
	case ModeRace:
		return proto.ExecutionKindRace, true
	default:
		return proto.ExecutionKindInvalid, false
	}
}
