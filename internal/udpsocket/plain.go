//go:build !(linux && (amd64 || arm64))

package udpsocket

import (
	"errors"
	"syscall"
)

// accelerated reports whether this target has the batch calls: on every
// target but Linux amd64/arm64 a Conn is always in ModePlain (M5-D8), and
// WriteBatch and ReadBatch run the per-datagram loop of conn.go (one
// WriteToUDPAddrPort per datagram, stopping at the first error; one
// ReadMsgUDPAddrPort per ReadBatch).
const accelerated = false

// batchSys is empty here: no system call uses a Batch's arrays. (Tests that
// drive ModeBatch through fake calls read the messages from Batch.ms.)
type batchSys struct{}

func (s *batchSys) init(*Batch) {}

func (s *batchSys) prepSend(c *Conn, ms []Msg, k, end int) (int, error) { return end, nil }

func (s *batchSys) prepRecv([]Msg) {}

func (s *batchSys) clear(int) {}

// connSys is empty here.
type connSys struct{}

func (s *connSys) init(syscall.RawConn) error { return nil }

func sendmmsg(fd uintptr, b *Batch, k, n int) (int, error) { return 0, errors.ErrUnsupported }

func recvmmsg(fd uintptr, b *Batch, n int) (int, error) { return 0, errors.ErrUnsupported }

func probe(int) error { return errors.ErrUnsupported }
