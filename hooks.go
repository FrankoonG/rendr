package rendr

import "github.com/FrankoonG/rendr/v2/internal/testhooks"

func init() { testhooks.Install(newRuntimeForTest) }

// newRuntimeForTest builds a Runtime from cfg (a Config) with ov applied after
// normalization, bypassing clamps and constraints (internal/testhooks).
func newRuntimeForTest(cfg any, ov *testhooks.Overrides) (any, error) {
	panic("unimplemented: M1b")
}
