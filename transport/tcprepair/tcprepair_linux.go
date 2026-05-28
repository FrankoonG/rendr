//go:build linux

package tcprepair

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// Linux TCP_REPAIR socket-option constants. Defined here instead of
// imported because golang.org/x/sys/unix doesn't (as of writing)
// surface TCP_REPAIR_WINDOW with a stable name across versions.
const (
	tcpRepair       = 19
	tcpRepairQueue  = 20
	tcpQueueSeq     = 21
	tcpRepairOpts   = 22
	tcpTimestamp    = 24
	tcpRepairWindow = 29
	tcpInfoOpt      = 11
	tcpNoQueue      = 0
	tcpRecvQueue    = 1
	tcpSendQueue    = 2
	tcpDumpQueueCap = 65536 // initial bytes per queue dump in Snapshot
	tcpDumpQueueMax = 64 << 20
)

// State is the immutable snapshot of one server-side TCP connection's
// kernel state. Produced by Snapshot, consumed by Restore.
type State struct {
	LocalAddr  *net.TCPAddr
	RemoteAddr *net.TCPAddr
	SendSeq    uint32
	RecvSeq    uint32
	Info       tcpInfo
	Timestamp  uint32
	Window     tcpRepairWindowVal
	RecvQueue  []byte
	SendQueue  []byte
}

// tcpInfo / tcpRepairWindowVal mirror the kernel structs.
type tcpInfo struct {
	State, CaState, Retransmits, Probes, Backoff, Options uint8
	Wscale, DeliveryRateAppLimited                        uint8
	Rto, Ato, SndMss, RcvMss                              uint32
	Unacked, Sacked, Lost, Retrans, Fackets               uint32
	LastDataSent, LastAckSent, LastDataRecv, LastAckRecv  uint32
	PMtu, RcvSsthresh, Rtt, Rttvar, SndSsthresh, SndCwnd  uint32
	Advmss, Reordering                                    uint32
	RcvRtt, RcvSpace                                      uint32
	TotalRetrans                                          uint32
}

type tcpRepairWindowVal struct {
	SndWl1 uint32
	SndWnd uint32
	MaxWnd uint32
	RcvWnd uint32
	RcvWup uint32
}

// Snapshot captures all state needed to rebuild a TCP socket
// equivalent to c. Caller MUST keep c alive (and unread/unwritten)
// during this call — Snapshot toggles TCP_REPAIR mode on the live
// fd, peeks at the kernel queues, and resets TCP_REPAIR before
// returning.
//
// Snapshot does NOT close c. The canonical migration sequence
// installs an iptables DROP on the 5-tuple, calls Snapshot, then
// closes c, then Restore on a new fd, then removes the iptables rule.
func Snapshot(c *net.TCPConn) (*State, error) {
	la, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("tcprepair: LocalAddr is not *net.TCPAddr")
	}
	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("tcprepair: RemoteAddr is not *net.TCPAddr")
	}
	s := &State{LocalAddr: la, RemoteAddr: ra}

	err := control(c, func(fd int) error {
		if err := setInt(fd, tcpRepair, 1); err != nil {
			return fmt.Errorf("enter repair: %w", err)
		}

		if err := setInt(fd, tcpRepairQueue, tcpSendQueue); err != nil {
			return fmt.Errorf("queue=send: %w", err)
		}
		ss, err := getInt(fd, tcpQueueSeq)
		if err != nil {
			return fmt.Errorf("get send_seq: %w", err)
		}
		s.SendSeq = uint32(ss)
		s.SendQueue, err = dumpQueue(fd)
		if err != nil {
			return fmt.Errorf("dump send queue: %w", err)
		}

		if err := setInt(fd, tcpRepairQueue, tcpRecvQueue); err != nil {
			return fmt.Errorf("queue=recv: %w", err)
		}
		rs, err := getInt(fd, tcpQueueSeq)
		if err != nil {
			return fmt.Errorf("get recv_seq: %w", err)
		}
		s.RecvSeq = uint32(rs)
		s.RecvQueue, err = dumpQueue(fd)
		if err != nil {
			return fmt.Errorf("dump recv queue: %w", err)
		}

		if err := setInt(fd, tcpRepairQueue, tcpNoQueue); err != nil {
			return fmt.Errorf("queue=none: %w", err)
		}

		ibuf := unsafe.Slice((*byte)(unsafe.Pointer(&s.Info)), int(unsafe.Sizeof(s.Info)))
		if _, err := getRaw(fd, tcpInfoOpt, ibuf); err != nil {
			return fmt.Errorf("get tcp_info: %w", err)
		}
		ts, err := getInt(fd, tcpTimestamp)
		if err != nil {
			return fmt.Errorf("get ts: %w", err)
		}
		s.Timestamp = uint32(ts)
		wbuf := unsafe.Slice((*byte)(unsafe.Pointer(&s.Window)), int(unsafe.Sizeof(s.Window)))
		if _, err := getRaw(fd, tcpRepairWindow, wbuf); err != nil {
			return repairWindowError("get repair_window", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Restore builds a new TCP socket equivalent to the connection that
// produced s. Returns the new fd (already out of REPAIR mode);
// caller wraps via os.NewFile + net.FileConn. Caller is responsible
// for installing/removing an iptables DROP on s.LocalAddr+s.RemoteAddr
// to suppress the brief RST window between original close and new
// socket exit-of-REPAIR.
func Restore(s *State) (int, error) {
	if s == nil {
		return -1, errors.New("tcprepair: nil State")
	}
	if s.LocalAddr == nil || s.RemoteAddr == nil {
		return -1, errors.New("tcprepair: State has nil addresses")
	}
	if s.LocalAddr.IP.To4() == nil || s.RemoteAddr.IP.To4() == nil {
		return -1, errors.New("tcprepair: IPv6 not yet supported")
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, fmt.Errorf("socket: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			syscall.Close(fd)
		}
	}()

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return -1, fmt.Errorf("SO_REUSEADDR: %w", err)
	}
	if err := setInt(fd, tcpRepair, 1); err != nil {
		return -1, fmt.Errorf("enter repair on new: %w", err)
	}

	if err := syscall.Bind(fd, sockaddrIPv4(s.LocalAddr)); err != nil {
		return -1, fmt.Errorf("bind: %w", err)
	}

	// CRIU pattern: TCP_QUEUE_SEQ on SEND sets snd_nxt; injecting
	// unACKed send-queue data via write() does NOT advance snd_nxt
	// (it just populates the queue under snd_nxt). So we set snd_nxt
	// to the post-snapshot value directly. On RECV however, writing
	// to TCP_REPAIR_QUEUE=RECV DOES advance rcv_nxt, so we need to
	// set the start point BEFORE the injection range.
	if err := setInt(fd, tcpRepairQueue, tcpSendQueue); err != nil {
		return -1, fmt.Errorf("queue=send: %w", err)
	}
	if err := setInt(fd, tcpQueueSeq, int(s.SendSeq)); err != nil {
		return -1, fmt.Errorf("set send_seq: %w", err)
	}
	if err := setInt(fd, tcpRepairQueue, tcpRecvQueue); err != nil {
		return -1, fmt.Errorf("queue=recv: %w", err)
	}
	recvStart := s.RecvSeq - uint32(len(s.RecvQueue))
	if err := setInt(fd, tcpQueueSeq, int(recvStart)); err != nil {
		return -1, fmt.Errorf("set recv_seq: %w", err)
	}

	if err := syscall.Connect(fd, sockaddrIPv4(s.RemoteAddr)); err != nil {
		return -1, fmt.Errorf("connect: %w", err)
	}

	// Inject queue contents FIRST. Recv inject advances rcv_nxt;
	// send inject populates the unACKed window. Setting
	// TCP_REPAIR_WINDOW before this would EINVAL because rcv_wup
	// (snapshotted post-receive) would exceed the pre-inject
	// rcv_nxt.
	if len(s.RecvQueue) > 0 {
		if err := setInt(fd, tcpRepairQueue, tcpRecvQueue); err != nil {
			return -1, fmt.Errorf("queue=recv for inject: %w", err)
		}
		n, err := syscall.Write(fd, s.RecvQueue)
		if err != nil {
			return -1, fmt.Errorf("inject recv queue: %w", err)
		}
		if n != len(s.RecvQueue) {
			return -1, fmt.Errorf("inject recv: wrote %d/%d", n, len(s.RecvQueue))
		}
	}
	if len(s.SendQueue) > 0 {
		if err := setInt(fd, tcpRepairQueue, tcpSendQueue); err != nil {
			return -1, fmt.Errorf("queue=send for inject: %w", err)
		}
		n, err := syscall.Write(fd, s.SendQueue)
		if err != nil {
			return -1, fmt.Errorf("inject send queue: %w", err)
		}
		if n != len(s.SendQueue) {
			return -1, fmt.Errorf("inject send: wrote %d/%d", n, len(s.SendQueue))
		}
	}

	wbuf := unsafe.Slice((*byte)(unsafe.Pointer(&s.Window)), int(unsafe.Sizeof(s.Window)))
	if err := setRaw(fd, tcpRepairWindow, wbuf); err != nil {
		return -1, repairWindowError("set repair_window", err)
	}

	// TCP_TIMESTAMP may soft-fail on some kernels; tolerate.
	_ = setInt(fd, tcpTimestamp, int(s.Timestamp))

	if err := setInt(fd, tcpRepairQueue, tcpNoQueue); err != nil {
		return -1, fmt.Errorf("queue=none: %w", err)
	}
	if err := setInt(fd, tcpRepair, 0); err != nil {
		return -1, fmt.Errorf("exit repair: %w", err)
	}

	cleanup = false
	return fd, nil
}

func repairWindowError(op string, err error) error {
	if errors.Is(err, syscall.ENOPROTOOPT) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("%s: %w (TCP_REPAIR_WINDOW requires Linux >= 4.5; use gvisor fallback)", op, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}

func sockaddrIPv4(addr *net.TCPAddr) *syscall.SockaddrInet4 {
	sa := &syscall.SockaddrInet4{Port: addr.Port}
	ip4 := addr.IP.To4()
	copy(sa.Addr[:], ip4)
	return sa
}

func control(c *net.TCPConn, fn func(fd int) error) error {
	sc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := sc.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {
		return err
	}
	return inner
}

func setInt(fd, opt, value int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, opt, value)
}

func getInt(fd, opt int) (int, error) {
	return syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, opt)
}

func getRaw(fd, opt int, buf []byte) (int, error) {
	plen := uint32(len(buf))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(syscall.IPPROTO_TCP), uintptr(opt),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&plen)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(plen), nil
}

func setRaw(fd, opt int, buf []byte) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(syscall.IPPROTO_TCP), uintptr(opt),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func dumpQueue(fd int) ([]byte, error) {
	capacity := tcpDumpQueueCap
	for {
		buf := make([]byte, capacity)
		n, _, err := syscall.Recvfrom(fd, buf, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, nil
			}
			return nil, err
		}
		if n < len(buf) {
			return append([]byte(nil), buf[:n]...), nil
		}
		if capacity >= tcpDumpQueueMax {
			return nil, fmt.Errorf("queue dump exceeded %d bytes", tcpDumpQueueMax)
		}
		capacity *= 2
		if capacity > tcpDumpQueueMax {
			capacity = tcpDumpQueueMax
		}
	}
}
