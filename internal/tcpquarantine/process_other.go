//go:build !linux

package tcpquarantine

import (
	"errors"
	"os"
	"time"
)

var nonLinuxProcessStart = uint64(time.Now().UnixNano())

func currentProcessIdentity() (processIdentity, error) {
	return processIdentity{
		pidNamespaceInode: 1,
		pid:               uint64(os.Getpid()),
		startTime:         nonLinuxProcessStart,
	}, nil
}

func observeProcessIdentity(identity processIdentity) (processState, error) {
	current, _ := currentProcessIdentity()
	if identity == current {
		return processStateAlive, nil
	}
	return processStateUnknown, errors.New("process liveness is only available on Linux")
}
