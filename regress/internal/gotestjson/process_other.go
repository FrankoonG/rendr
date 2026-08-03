//go:build !linux

package gotestjson

import "os/exec"

func configureProcessGroup(_ *exec.Cmd) {}
