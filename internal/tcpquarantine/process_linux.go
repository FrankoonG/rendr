//go:build linux

package tcpquarantine

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func currentProcessIdentity() (processIdentity, error) {
	device, inode, err := statNamespace("/proc/self/ns/pid")
	if err != nil {
		return processIdentity{}, err
	}
	startTime, err := readProcessStartTime("/proc/self/stat", uint64(os.Getpid()))
	if err != nil {
		return processIdentity{}, err
	}
	identity := processIdentity{
		pidNamespaceDevice: device,
		pidNamespaceInode:  inode,
		pid:                uint64(os.Getpid()),
		startTime:          startTime,
	}
	if !identity.valid() {
		return processIdentity{}, ErrProcessStateUnknown
	}
	return identity, nil
}

func observeProcessIdentity(identity processIdentity) (processState, error) {
	if !identity.valid() {
		return processStateUnknown, ErrProcessStateUnknown
	}
	current, err := currentProcessIdentity()
	if err != nil {
		return processStateUnknown, err
	}
	if identity.pidNamespaceDevice != current.pidNamespaceDevice ||
		identity.pidNamespaceInode != current.pidNamespaceInode {
		return processStateUnknown, errors.New("owner belongs to a different PID namespace")
	}

	statPath := fmt.Sprintf("/proc/%d/stat", identity.pid)
	startBefore, err := readProcessStartTime(statPath, identity.pid)
	if errors.Is(err, os.ErrNotExist) {
		return processStateDead, nil
	}
	if err != nil {
		return processStateUnknown, err
	}
	if startBefore != identity.startTime {
		return processStateDead, nil
	}
	device, inode, err := statNamespace(fmt.Sprintf("/proc/%d/ns/pid", identity.pid))
	if errors.Is(err, os.ErrNotExist) {
		return processStateDead, nil
	}
	if err != nil {
		return processStateUnknown, err
	}
	if device != identity.pidNamespaceDevice || inode != identity.pidNamespaceInode {
		return processStateDead, nil
	}
	startAfter, err := readProcessStartTime(statPath, identity.pid)
	if errors.Is(err, os.ErrNotExist) {
		return processStateDead, nil
	}
	if err != nil {
		return processStateUnknown, err
	}
	if startAfter != startBefore {
		return processStateDead, nil
	}
	return processStateAlive, nil
}

func statNamespace(path string) (uint64, uint64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer unix.Close(fd)
	var state unix.Stat_t
	if err := unix.Fstat(fd, &state); err != nil {
		return 0, 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return uint64(state.Dev), state.Ino, nil
}

func readProcessStartTime(path string, expectedPID uint64) (uint64, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	line := strings.TrimSpace(string(payload))
	closeIndex := strings.LastIndexByte(line, ')')
	openIndex := strings.IndexByte(line, '(')
	if openIndex <= 0 || closeIndex <= openIndex || closeIndex+2 > len(line) {
		return 0, errors.New("malformed process stat record")
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(line[:openIndex]), 10, 64)
	if err != nil || pid != expectedPID {
		return 0, fmt.Errorf("process stat PID mismatch: got %q want %d", strings.TrimSpace(line[:openIndex]), expectedPID)
	}
	// Fields after comm start at field 3 (state); starttime is field 22.
	fields := strings.Fields(line[closeIndex+1:])
	if len(fields) <= 19 {
		return 0, errors.New("process stat record has no starttime")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return 0, fmt.Errorf("invalid process starttime %q", fields[19])
	}
	return startTime, nil
}
