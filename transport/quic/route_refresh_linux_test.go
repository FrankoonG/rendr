//go:build linux

package quic

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"golang.org/x/sys/unix"
)

func TestOpenCIDRouteChangeWatcherLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	watcher, err := openRouteChangeWatcherPlatform(ctx)
	if err != nil {
		cancel()
		t.Fatalf("open route change watcher: %v", err)
	}
	cancel()
	watcher.Close()
	select {
	case _, ok := <-watcher.Events():
		if ok {
			t.Fatal("route watcher emitted an event after Close")
		}
	default:
		t.Fatal("route watcher event channel remains open after Close")
	}
}

func TestPrivilegedCIDRouteChangeWatcherReceivesKernelEvent(t *testing.T) {
	requirePrivilegedCIDRouteWatchNamespace(t)
	if output, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("bring up isolated loopback: %v: %s", err, output)
	}

	ctx, cancel := context.WithCancel(context.Background())
	watcher, err := openRouteChangeWatcherPlatform(ctx)
	if err != nil {
		cancel()
		t.Fatalf("open route change watcher: %v", err)
	}
	defer func() {
		cancel()
		watcher.Close()
	}()

	const destination = "198.18.0.1/32"
	defer exec.Command("ip", "route", "del", destination, "dev", "lo").Run()
	if output, err := exec.Command("ip", "route", "replace", destination, "dev", "lo").CombinedOutput(); err != nil {
		t.Fatalf("replace isolated test route: %v: %s", err, output)
	}
	select {
	case _, ok := <-watcher.Events():
		if !ok {
			t.Fatal("route watcher closed before reporting the kernel event")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("route watcher did not report the kernel route replacement")
	}
}

func TestPrivilegedCIDRouteChangeRefreshesWithoutPolling(t *testing.T) {
	requirePrivilegedCIDRouteWatchNamespace(t)
	for _, arguments := range [][]string{
		{"link", "add", "qra", "type", "dummy"},
		{"link", "add", "qrb", "type", "dummy"},
		{"addr", "add", "192.0.2.2/32", "dev", "qra"},
		{"addr", "add", "198.51.100.2/32", "dev", "qrb"},
		{"link", "set", "qra", "up"},
		{"link", "set", "qrb", "up"},
		{"route", "replace", "198.18.0.1/32", "dev", "qra", "src", "192.0.2.2"},
	} {
		if output, err := exec.Command("ip", arguments...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", arguments, err, output)
		}
	}
	defer exec.Command("ip", "link", "del", "qra").Run()
	defer exec.Command("ip", "link", "del", "qrb").Run()

	ctx, cancelContext := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelContext()
	remote := &net.UDPAddr{IP: net.ParseIP("198.18.0.1"), Port: 443}
	baseline, err := observeRouteSource(ctx, remote)
	if err != nil {
		t.Fatalf("observe initial route: %v", err)
	}
	owner, err := newCIDOwner(
		newFakeCIDConnection(), leafmobility.RoleDialer, leafmobility.SessionPacket,
		fakeCIDTransport(baseline.source, new(atomic.Int64)), baseline, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	bindCIDRefreshClaim(t, owner, leafmobility.SessionPacket, 201)
	owner.mu.Lock()
	owner.remote = remote
	owner.refreshPoll = 2 * time.Second
	owner.refreshDelay = 10 * time.Millisecond
	owner.mu.Unlock()
	events := make(chan leafmobility.RefreshEvidence, 1)
	cancelRefresh, err := owner.subscribeRefresh(ctx, func(evidence leafmobility.RefreshEvidence) {
		events <- evidence
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancelRefresh()
		if err := owner.releaseResources(); err != nil {
			t.Errorf("release owner: %v", err)
		}
	}()

	for i := 0; i < 10; i++ {
		device, source := "qrb", "198.51.100.2"
		if i%2 == 1 {
			device, source = "qra", "192.0.2.2"
		}
		started := time.Now()
		arguments := []string{"route", "replace", "198.18.0.1/32", "dev", device, "src", source}
		if output, err := exec.Command("ip", arguments...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", arguments, err, output)
		}
		select {
		case evidence := <-events:
			snapshot, validateErr := evidence.ValidateFor(owner.claim, 0)
			if validateErr != nil || snapshot.Reason != leafmobility.RefreshReasonRouteSourceChanged {
				t.Fatalf("refresh %d evidence=%+v err=%v", i+1, snapshot, validateErr)
			}
			if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
				t.Fatalf("refresh %d took %s and appears to have waited for polling", i+1, elapsed)
			}
			if err := owner.commitRefresh(evidence); err != nil {
				t.Fatalf("commit refresh %d: %v", i+1, err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("route replacement %d did not drive factual refresh before polling", i+1)
		}
	}
}

func requirePrivilegedCIDRouteWatchNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("RENDR_QUIC_ROUTE_WATCH_TEST") != "1" {
		t.Skip("privileged route watcher expectation is unset")
	}
	selfNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("read current network namespace: %v", err)
	}
	initNamespace, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatalf("read initial network namespace: %v", err)
	}
	if selfNamespace == initNamespace {
		t.Fatal("privileged route watcher test must run in a dedicated network namespace")
	}
}

func TestJoinCIDRouteNetlinkGroupsAllowsOnlyOptionalNexthopFailure(t *testing.T) {
	baseGroups := []int{
		unix.RTNLGRP_LINK,
		unix.RTNLGRP_IPV4_IFADDR, unix.RTNLGRP_IPV6_IFADDR,
		unix.RTNLGRP_IPV4_ROUTE, unix.RTNLGRP_IPV6_ROUTE,
		unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE,
	}
	for _, test := range []struct {
		name      string
		failGroup int
		failErr   error
		wantErr   error
		wantCalls int
	}{
		{name: "all groups", wantCalls: len(baseGroups) + 1},
		{name: "old kernel nexthop EINVAL", failGroup: unix.RTNLGRP_NEXTHOP, failErr: unix.EINVAL, wantCalls: len(baseGroups) + 1},
		{name: "old kernel nexthop ENOPROTOOPT", failGroup: unix.RTNLGRP_NEXTHOP, failErr: unix.ENOPROTOOPT, wantCalls: len(baseGroups) + 1},
		{name: "required group failure", failGroup: unix.RTNLGRP_IPV4_ROUTE, failErr: unix.EPERM, wantErr: unix.EPERM, wantCalls: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			var groups []int
			err := joinCIDRouteNetlinkGroups(17, func(fd, level, option, group int) error {
				if fd != 17 || level != unix.SOL_NETLINK || option != unix.NETLINK_ADD_MEMBERSHIP {
					t.Fatalf("setsockopt arguments fd=%d level=%d option=%d", fd, level, option)
				}
				groups = append(groups, group)
				if group == test.failGroup {
					return test.failErr
				}
				return nil
			})
			if !errors.Is(err, test.wantErr) || test.wantErr == nil && err != nil {
				t.Fatalf("join error=%v want=%v", err, test.wantErr)
			}
			if len(groups) != test.wantCalls {
				t.Fatalf("membership calls=%v want count=%d", groups, test.wantCalls)
			}
		})
	}
}

func TestCIDRouteChangeMessageFilter(t *testing.T) {
	if !containsCIDRouteChange([]syscall.NetlinkMessage{
		{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}},
		{Header: syscall.NlMsghdr{Type: unix.RTM_DELADDR}},
	}) {
		t.Fatal("route change batch was ignored")
	}
	if containsCIDRouteChange([]syscall.NetlinkMessage{
		{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}},
		{Header: syscall.NlMsghdr{Type: unix.NLMSG_ERROR}},
	}) {
		t.Fatal("non-route netlink batch triggered a refresh")
	}
}
