package tcpquarantine

import (
	"errors"
	"fmt"
)

var ErrExecutionScopeChanged = errors.New("tcpquarantine: network namespace scope changed")

type namespaceScope struct {
	platform string
	device   uint64
	inode    uint64
}

func (scope namespaceScope) valid() bool {
	return scope.platform != "" && (scope.platform != "linux" || scope.device != 0 || scope.inode != 0)
}

func requireNamespaceScope(expected namespaceScope) error {
	if !expected.valid() {
		return ErrExecutionScopeChanged
	}
	current, err := currentNamespaceScope()
	if err != nil {
		return errors.Join(ErrExecutionScopeChanged, err)
	}
	if current != expected {
		return fmt.Errorf("%w: expected %+v got %+v", ErrExecutionScopeChanged, expected, current)
	}
	return nil
}
