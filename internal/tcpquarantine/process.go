package tcpquarantine

import "errors"

type processIdentity struct {
	pidNamespaceDevice uint64
	pidNamespaceInode  uint64
	pid                uint64
	startTime          uint64
}

func (identity processIdentity) valid() bool {
	return (identity.pidNamespaceDevice != 0 || identity.pidNamespaceInode != 0) &&
		identity.pid != 0 && identity.startTime != 0
}

type processState uint8

const (
	processStateUnknown processState = iota
	processStateAlive
	processStateDead
)

func validateObservedProcessState(state processState, err error) (processState, error) {
	switch state {
	case processStateAlive, processStateDead:
		if err != nil {
			return processStateUnknown, errors.Join(ErrProcessStateUnknown, err)
		}
		return state, nil
	default:
		return processStateUnknown, errors.Join(ErrProcessStateUnknown, err)
	}
}
