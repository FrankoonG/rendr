//go:build linux

package chaos

import (
	"os"
	"os/exec"
)

func testCanManageTC() bool {
	_, err := exec.LookPath("tc")
	return os.Geteuid() == 0 && err == nil
}
