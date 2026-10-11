//go:build !(linux && (amd64 || arm64))

package udpsocket

import "errors"

// accelerated reports whether this target has the batch calls: on every
// target but Linux amd64/arm64 a Conn is always in ModePlain (M5-D8).
const accelerated = false

// batchSys is empty here: no call uses a Batch's arrays.
type batchSys struct{}

func (s *batchSys) init(*Batch) {}

// connSys is empty here.
type connSys struct{}

func sendmmsg(fd uintptr, b *Batch, k, n int) (int, error) { return 0, errors.ErrUnsupported }

func recvmmsg(fd uintptr, b *Batch, n int) (int, error) { return 0, errors.ErrUnsupported }

func probe() error { return errors.ErrUnsupported }

// writeBatch and readBatch are never reached here (no Conn is in
// ModeBatch); they keep the plain behaviour.
func (c *Conn) writeBatch(b *Batch, ms []Msg) (int, error) { return c.writePlain(ms) }

func (c *Conn) readBatch(b *Batch, ms []Msg) (int, error) { return c.readPlain(&ms[0]) }
