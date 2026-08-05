//go:build !linux

package tcprepair

import "errors"

// Available reports that TCP_REPAIR is outside the current platform's
// capability set. Backend fallback is a rendr planner decision, not a promise
// made by this low-level probe.
func Available() error {
	return errors.New("tcprepair: TCP_REPAIR only supported on Linux")
}
