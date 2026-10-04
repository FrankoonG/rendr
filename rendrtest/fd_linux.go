package rendrtest

import (
	"os"
	"strconv"
)

// openFDs lists this process's open file descriptors as "fd -> target"
// (the listing's own descriptor excluded); nil if /proc is unreadable.
func openFDs() map[string]bool {
	d, err := os.Open("/proc/self/fd")
	if err != nil {
		return nil
	}
	defer d.Close()
	self := strconv.FormatUint(uint64(d.Fd()), 10)
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil
	}
	fds := make(map[string]bool, len(names))
	for _, n := range names {
		if n == self {
			continue
		}
		if target, err := os.Readlink("/proc/self/fd/" + n); err == nil { // else closed meanwhile
			fds[n+" -> "+target] = true
		}
	}
	return fds
}
