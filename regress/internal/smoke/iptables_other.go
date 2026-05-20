//go:build !linux

package smoke

import "errors"

// iptablesDropSrcPort always errors on non-Linux. G4 / G5 iptables
// variants are Linux-only; smoke dispatchers gate on runtime.GOOS so
// this stub should never actually fire.
func iptablesDropSrcPort(_ int) (func() error, error) {
	return nil, errors.New("iptables-based path kill only supported on Linux")
}
