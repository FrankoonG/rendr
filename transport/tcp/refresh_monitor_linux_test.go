//go:build linux && amd64

package tcp

import (
	"bytes"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

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
