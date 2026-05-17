package xray

import (
	"errors"
	"fmt"
)

var (
	errNilConfig           = errors.New("rendr/xray: nil Config")
	errNoPaths             = errors.New("rendr/xray: Config has no Paths")
	errBondNotYetSupported = errors.New("rendr/xray: Mode=bond not yet supported (M8 pending)")
	errUnknownMode         = errors.New("rendr/xray: unknown Mode")
)

func errPathNoTransport(i int) error {
	return fmt.Errorf("rendr/xray: Paths[%d].Transport empty", i)
}

func errPathNoAddress(i int, transport string) error {
	return fmt.Errorf("rendr/xray: Paths[%d] (%s) Address empty", i, transport)
}
