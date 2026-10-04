package rendr

import (
	"fmt"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

func init() { testhooks.Install(newRuntimeForTest) }

// newRuntimeForTest builds a Runtime from cfg (a Config) with ov applied after
// normalization, bypassing clamps and constraints (internal/testhooks). ov
// is copied: changing it afterwards has no effect on the Runtime.
func newRuntimeForTest(cfg any, ov *testhooks.Overrides) (any, error) {
	var c Config
	switch v := cfg.(type) {
	case Config:
		c = v
	case *Config:
		if v != nil {
			c = *v
		}
	case nil:
	default:
		return nil, fmt.Errorf("rendr/testhooks: NewRuntime: cfg is %T, want rendr.Config", cfg)
	}
	rt, err := newRuntime(c, ov)
	if err != nil {
		return nil, err
	}
	return rt, nil
}
