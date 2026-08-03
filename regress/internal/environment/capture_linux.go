//go:build linux

package environment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var linuxSysctlPaths = map[string]string{
	"net.core.rmem_default":           "/proc/sys/net/core/rmem_default",
	"net.core.rmem_max":               "/proc/sys/net/core/rmem_max",
	"net.core.wmem_default":           "/proc/sys/net/core/wmem_default",
	"net.core.wmem_max":               "/proc/sys/net/core/wmem_max",
	"net.ipv4.tcp_congestion_control": "/proc/sys/net/ipv4/tcp_congestion_control",
	"net.ipv4.tcp_mtu_probing":        "/proc/sys/net/ipv4/tcp_mtu_probing",
	"net.ipv4.tcp_rmem":               "/proc/sys/net/ipv4/tcp_rmem",
	"net.ipv4.tcp_wmem":               "/proc/sys/net/ipv4/tcp_wmem",
	"net.ipv4.udp_rmem_min":           "/proc/sys/net/ipv4/udp_rmem_min",
	"net.ipv4.udp_wmem_min":           "/proc/sys/net/ipv4/udp_wmem_min",
}

func capturePlatform(ctx context.Context, snapshot *Snapshot) error {
	var err error
	if snapshot.KernelRelease, err = readMandatory("kernel release", "/proc/sys/kernel/osrelease"); err != nil {
		return err
	}
	if snapshot.BootID, err = readMandatory("boot ID", "/proc/sys/kernel/random/boot_id"); err != nil {
		return err
	}
	if snapshot.CPU.OnlineSet, err = readMandatory("online CPU set", "/sys/devices/system/cpu/online"); err != nil {
		return err
	}
	cpuInfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return fmt.Errorf("read CPU model inventory: %w", err)
	}
	snapshot.CPU.Models, err = parseCPUModels(cpuInfo)
	if err != nil {
		return err
	}
	processStatus, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("read process allowed CPU list: %w", err)
	}
	snapshot.CPU.ProcessAllowed, err = parseProcessAllowedCPUs(processStatus)
	if err != nil {
		return err
	}
	if snapshot.Clocksource, err = readMandatory("clocksource", "/sys/devices/system/clocksource/clocksource0/current_clocksource"); err != nil {
		return err
	}
	memory, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return fmt.Errorf("read total memory: %w", err)
	}
	snapshot.TotalMemoryBytes, err = parseMemTotal(memory)
	if err != nil {
		return err
	}

	for _, name := range mandatoryLinuxSysctls {
		path, ok := linuxSysctlPaths[name]
		if !ok {
			return fmt.Errorf("mandatory socket sysctl %q has no source", name)
		}
		value, err := readMandatory("socket sysctl "+name, path)
		if err != nil {
			return err
		}
		snapshot.SocketSysctls = append(snapshot.SocketSysctls, Sysctl{Name: name, Value: value})
	}

	tcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(tcCtx, "tc", "-j", "qdisc", "show").Output()
	if err != nil {
		if errors.Is(tcCtx.Err(), context.DeadlineExceeded) {
			return errors.New("capture qdisc state: tc timed out")
		}
		return fmt.Errorf("capture qdisc state with tc -j qdisc show: %w", err)
	}
	snapshot.QDisc = QDisc{Supported: true, State: output}
	return nil
}

func readMandatory(label, path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	value := normalizeValue(string(b))
	if value == "" {
		return "", fmt.Errorf("read %s: source %s is empty", label, path)
	}
	return value, nil
}

func parseMemTotal(contents []byte) (uint64, error) {
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "MemTotal:" {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return 0, fmt.Errorf("read total memory: malformed MemTotal line %q", line)
		}
		kilobytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || kilobytes > ^uint64(0)/1024 {
			return 0, fmt.Errorf("read total memory: malformed MemTotal value %q", fields[1])
		}
		if kilobytes == 0 {
			return 0, errors.New("read total memory: MemTotal is zero")
		}
		return kilobytes * 1024, nil
	}
	return 0, errors.New("read total memory: MemTotal is missing")
}
