//go:build !linux

package environment

import "context"

func capturePlatform(context.Context, *Snapshot) error {
	return nil
}
