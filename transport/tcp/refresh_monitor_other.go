//go:build !linux || !amd64

package tcp

import (
	"context"
	"errors"
)

func newPathRefreshMonitor(context.Context, *PathConn) (pathRefreshMonitor, error) {
	return nil, errors.New("tcp: route/source refresh monitor is unsupported")
}
