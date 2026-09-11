//go:build linux && amd64

package tcp

import (
	"bytes"
	"errors"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestJoinTCPRouteNetlinkGroupsOnlyToleratesUnavailableNexthopGroup(t *testing.T) {
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
		{name: "all groups available", wantCalls: len(baseGroups) + 1},
		{name: "old kernel EINVAL", failGroup: unix.RTNLGRP_NEXTHOP, failErr: unix.EINVAL, wantCalls: len(baseGroups) + 1},
		{name: "old kernel ENOPROTOOPT", failGroup: unix.RTNLGRP_NEXTHOP, failErr: unix.ENOPROTOOPT, wantCalls: len(baseGroups) + 1},
		{name: "unexpected nexthop failure", failGroup: unix.RTNLGRP_NEXTHOP, failErr: unix.EPERM, wantErr: unix.EPERM, wantCalls: len(baseGroups) + 1},
		{name: "required group failure", failGroup: unix.RTNLGRP_IPV4_ROUTE, failErr: unix.EINVAL, wantErr: unix.EINVAL, wantCalls: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			var groups []int
			err := joinTCPRouteNetlinkGroups(17, func(fd, level, option, group int) error {
				if fd != 17 || level != unix.SOL_NETLINK || option != unix.NETLINK_ADD_MEMBERSHIP {
					t.Fatalf("setsockopt arguments fd=%d level=%d option=%d", fd, level, option)
				}
				groups = append(groups, group)
				if group == test.failGroup {
					return test.failErr
				}
				return nil
			})
			if !errors.Is(err, test.wantErr) || (test.wantErr == nil && err != nil) {
				t.Fatalf("join error=%v want=%v", err, test.wantErr)
			}
			if len(groups) != test.wantCalls {
				t.Fatalf("membership calls=%v want count=%d", groups, test.wantCalls)
			}
			for index, group := range baseGroups {
				if index >= len(groups) {
					break
				}
				if groups[index] != group {
					t.Fatalf("membership call %d group=%d want=%d", index, groups[index], group)
				}
			}
		})
	}
}

func TestNetlinkBatchProcessesTrailingNotifications(t *testing.T) {
	for _, test := range []struct {
		name     string
		dump     bool
		terminal syscall.NetlinkMessage
	}{
		{
			name:     "single response",
			terminal: syscall.NetlinkMessage{Header: syscall.NlMsghdr{Seq: 7, Type: unix.RTM_NEWROUTE}, Data: []byte{1}},
		},
		{
			name:     "dump done",
			dump:     true,
			terminal: syscall.NetlinkMessage{Header: syscall.NlMsghdr{Seq: 7, Type: unix.NLMSG_DONE}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			messages := []syscall.NetlinkMessage{
				test.terminal,
				{Header: syscall.NlMsghdr{Seq: 0, Type: unix.RTM_DELADDR}, Data: []byte{2}},
			}
			var responses []syscall.NetlinkMessage
			notifications := false
			complete, unstable, err := consumeNetlinkBatch(messages, 7, test.dump, &responses, &notifications)
			if err != nil || !complete || unstable || !notifications {
				t.Fatalf("complete=%t unstable=%t notifications=%t err=%v", complete, unstable, notifications, err)
			}
			if !test.dump && len(responses) != 1 {
				t.Fatalf("responses=%d want=1", len(responses))
			}
		})
	}
}

func TestOwnedNetlinkMessagesDoNotAliasReceiveBuffer(t *testing.T) {
	buffer := []byte{1, 2, 3, 4}
	owned := appendOwnedNetlinkMessages(nil, []syscall.NetlinkMessage{{Data: buffer}})
	copy(buffer, []byte{9, 9, 9, 9})
	if len(owned) != 1 || !bytes.Equal(owned[0].Data, []byte{1, 2, 3, 4}) {
		t.Fatalf("owned payload=%v", owned)
	}
}

func TestPathRefreshDebounceIsBoundedByFirstNotification(t *testing.T) {
	start := time.Unix(100, 0)
	pending := false
	var due time.Time
	armPathRefresh(&pending, &due, start)
	want := start.Add(pathRefreshDebounce)
	for offset := time.Millisecond; offset < 10*pathRefreshDebounce; offset += time.Millisecond {
		armPathRefresh(&pending, &due, start.Add(offset))
	}
	if !pending || due != want {
		t.Fatalf("pending=%t due=%v want=%v", pending, due, want)
	}
}
