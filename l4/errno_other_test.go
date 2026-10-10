//go:build !unix && !plan9

package l4

import "syscall"

// symRows: no errno symbols are mapped here (Windows, js, wasip1). On
// Windows the symbol ECONNREFUSED is an invented value the net package
// never returns, so it maps to nothing.
func symRows() []classifyRow {
	return []classifyRow{{"symbol ECONNREFUSED", syscall.ECONNREFUSED, CodeDialFailed}}
}
