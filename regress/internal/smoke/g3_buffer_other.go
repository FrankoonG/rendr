//go:build !linux

package smoke

import "errors"

// G3UDPBufferPreflight rejects the Linux-only 100k-pps fixture elsewhere.
func G3UDPBufferPreflight() error {
	return errors.New("G3 100k-pps prerequisite unavailable: Linux is required")
}
