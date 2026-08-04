//go:build linux

package gotestjson

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
)

var cgroupInvocationCounter atomic.Uint64

type cgroupV2Containment struct {
	path string
	dir  *os.File
}

// tryCgroupV2Containment returns nil when the current cgroup is not delegated
// or atomic CLONE_INTO_CGROUP placement is unavailable. It never changes
// parent controllers or signals processes outside its newly-created leaf.
func tryCgroupV2Containment(cmd *exec.Cmd) (*cgroupV2Containment, error) {
	parent, err := currentCgroupV2Directory()
	if err != nil {
		return nil, nil
	}
	path, err := makeInvocationCgroup(parent)
	if err != nil {
		return nil, nil
	}
	cgroup := &cgroupV2Containment{path: path}
	cgroup.dir, err = os.Open(path)
	if err != nil {
		if removeErr := os.Remove(path); removeErr != nil {
			return nil, fmt.Errorf("open invocation cgroup: %w; remove failed: %v", err, removeErr)
		}
		return nil, nil
	}

	// UseCgroupFD relies on clone3(CLONE_INTO_CGROUP), which is newer than
	// rendr's minimum kernel. Prove it with an inert child before applying it
	// to the real command, then fall back without a start/attach race.
	probe := exec.Command("/bin/true")
	probe.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgroup.dir.Fd()),
	}
	if err := probe.Run(); err != nil {
		if cleanupErr := cgroup.closeAndRemove(); cleanupErr != nil {
			return nil, fmt.Errorf("probe atomic cgroup placement: %w; cleanup failed: %v", err, cleanupErr)
		}
		return nil, nil
	}

	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = int(cgroup.dir.Fd())
	return cgroup, nil
}

func makeInvocationCgroup(parent string) (string, error) {
	for range 8 {
		name := fmt.Sprintf(
			"rendr-gotestjson-%d-%d",
			os.Getpid(),
			cgroupInvocationCounter.Add(1),
		)
		path := filepath.Join(parent, name)
		if err := os.Mkdir(path, 0o700); err == nil {
			return path, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("exhausted invocation cgroup names")
}

func currentCgroupV2Directory() (string, error) {
	cgroupData, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	cgroupPath := ""
	for _, line := range strings.Split(string(cgroupData), "\n") {
		if strings.HasPrefix(line, "0::") {
			cgroupPath = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if cgroupPath == "" || !strings.HasPrefix(cgroupPath, "/") {
		return "", errors.New("unified cgroup membership not found")
	}

	mountData, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	bestRoot := ""
	bestMount := ""
	for _, line := range strings.Split(string(mountData), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 || !strings.HasPrefix(parts[1], "cgroup2 ") {
			continue
		}
		fields := strings.Fields(parts[0])
		if len(fields) < 5 {
			continue
		}
		root := unescapeMountInfo(fields[3])
		if !pathWithinCgroupRoot(cgroupPath, root) || len(root) < len(bestRoot) {
			continue
		}
		bestRoot = root
		bestMount = unescapeMountInfo(fields[4])
	}
	if bestMount == "" {
		return "", errors.New("cgroup v2 mount not found")
	}

	relative := strings.TrimPrefix(cgroupPath, bestRoot)
	relative = strings.TrimPrefix(relative, "/")
	directory := filepath.Join(bestMount, filepath.FromSlash(relative))
	rel, err := filepath.Rel(bestMount, directory)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("current cgroup resolves outside cgroup v2 mount")
	}
	return directory, nil
}

func pathWithinCgroupRoot(path, root string) bool {
	if root == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == root || strings.HasPrefix(path, strings.TrimSuffix(root, "/")+"/")
}

func unescapeMountInfo(value string) string {
	replacer := strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return replacer.Replace(value)
}

func (c *cgroupV2Containment) processIDs() ([]int, error) {
	if c == nil || c.path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Join(c.path, "cgroup.procs"))
	if err != nil {
		return nil, fmt.Errorf("read invocation cgroup processes: %w", err)
	}
	var pids []int
	for _, field := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 0 {
			return nil, fmt.Errorf("parse invocation cgroup PID %q", field)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func (c *cgroupV2Containment) killAll() error {
	if c == nil || c.path == "" {
		return nil
	}
	killPath := filepath.Join(c.path, "cgroup.kill")
	if err := os.WriteFile(killPath, []byte("1"), 0); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.EOPNOTSUPP) {
		return fmt.Errorf("kill invocation cgroup: %w", err)
	}
	pids, err := c.processIDs()
	if err != nil {
		return err
	}
	return killProcessIDs(pids)
}

func (c *cgroupV2Containment) closeAndRemove() error {
	if c == nil || c.path == "" {
		return nil
	}
	var errs []error
	if c.dir != nil {
		if err := c.dir.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close invocation cgroup: %w", err))
		}
		c.dir = nil
	}
	if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove invocation cgroup: %w", err))
	}
	if len(errs) == 0 {
		c.path = ""
	}
	return errors.Join(errs...)
}
