//go:build !linux

package tcpquarantine

import "runtime"

func currentNamespaceScope() (namespaceScope, error) {
	return namespaceScope{platform: runtime.GOOS, inode: 1}, nil
}
