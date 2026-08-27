//go:build linux && amd64 && !rendr_experimental_tcprepair

package tcp

import (
	"context"
	"errors"
)

func newPathRefreshMonitor(context.Context, *PathConn) (pathRefreshMonitor, error) {
	return nil, errors.New("tcp: route/source refresh monitor requires the experimental TCP_REPAIR implementation")
}
