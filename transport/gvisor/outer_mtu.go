package gvisor

import (
	"errors"
	"fmt"
	"syscall"
)

// ErrOuterMTU identifies a definite zero-byte outer UDP rejection caused by
// the active path MTU. Callers can use errors.Is without depending on errno.
var ErrOuterMTU = errors.New("gvisor: outer UDP datagram rejected by path MTU")

// OuterMTUError is the stable error form for an EMSGSIZE outer UDP write.
// DatagramBytes is the attempted UDP payload size; MaxDatagramBytes is the
// protocol-v5 DATA ceiling derived from the IPv6 minimum MTU.
type OuterMTUError struct {
	DatagramBytes    int
	MaxDatagramBytes int
	PathMTU          int
	RequiredPathMTU  int
	Err              error
}

func (e *OuterMTUError) Error() string {
	if e == nil {
		return ErrOuterMTU.Error()
	}
	if e.PathMTU > 0 || e.RequiredPathMTU > 0 {
		return fmt.Sprintf("%s: datagram=%d max-data=%d path-mtu=%d required=%d: %v",
			ErrOuterMTU, e.DatagramBytes, e.MaxDatagramBytes, e.PathMTU, e.RequiredPathMTU, e.Err)
	}
	return fmt.Sprintf("%s: datagram=%d max-data=%d: %v",
		ErrOuterMTU, e.DatagramBytes, e.MaxDatagramBytes, e.Err)
}

func (e *OuterMTUError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *OuterMTUError) Is(target error) bool { return target == ErrOuterMTU }

func classifyOuterMTUError(datagramBytes int, err error) error {
	if err == nil || errors.Is(err, ErrOuterMTU) || !errors.Is(err, syscall.EMSGSIZE) {
		return err
	}
	return newOuterMTUError(datagramBytes, 0, 0, err)
}

func newOuterMTUError(datagramBytes, pathMTU, requiredPathMTU int, err error) *OuterMTUError {
	return &OuterMTUError{
		DatagramBytes: datagramBytes, MaxDatagramBytes: outerMaxDatagramSize,
		PathMTU: pathMTU, RequiredPathMTU: requiredPathMTU, Err: err,
	}
}
