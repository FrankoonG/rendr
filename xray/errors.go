package xray

import (
	"errors"
	"fmt"
)

var (
	errNilConfig       = errors.New("rendr/xray: nil Config")
	errNoPaths         = errors.New("rendr/xray: Config has no Paths")
	errUnknownMode     = errors.New("rendr/xray: unknown Mode")
	errNilListenConfig = errors.New("rendr/xray: nil ListenConfig")
	errNoListenPaths   = errors.New("rendr/xray: ListenConfig has no Paths")
)

func errPathNoTransport(i int) error {
	return fmt.Errorf("rendr/xray: Paths[%d].Transport empty", i)
}

func errPathNoAddress(i int, transport string) error {
	return fmt.Errorf("rendr/xray: Paths[%d] (%s) Address empty", i, transport)
}
