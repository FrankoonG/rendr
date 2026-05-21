package smoke

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr"
)

// G1TCPRepairOpts drives the TCP_REPAIR same-tuple rebuild smoke. It
// intentionally uses one path: the migration action is the path-local
// rebuild itself, not a switch to another attached path.
type G1TCPRepairOpts struct {
	Size       int64
	Migrations int
}

func (o *G1TCPRepairOpts) withDefaults() {
	if o.Size <= 0 {
		o.Size = 30 << 20
	}
	if o.Migrations <= 0 {
		o.Migrations = 3
	}
}

// RunG1TCPRepairSameTuple verifies that a tcprepair path can rebuild
// itself in place without surfacing an application-visible error. The
// server side is ordinary ListenTCP; the client path uses the tcprepair
// transport and triggers MigratePathLocalAddr("", same tuple) at evenly
// spaced points across the transfer.
func RunG1TCPRepairSameTuple(ctx context.Context, opts G1TCPRepairOpts) Result {
	opts.withDefaults()
	t0 := time.Now()
	name := fmt.Sprintf("G1-tcprepair (%dMiB, %d same-tuple rebuilds)", opts.Size>>20, opts.Migrations)

	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("listen: %w", err))
	}
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c, err := ln.Accept(actx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	client, err := (&rendr.Dialer{
		Mode: rendr.ModePrime,
		Paths: []rendr.PathSpec{
			{Transport: "tcprepair", Address: ln.Addr().String()},
		},
	}).Dial(ctx)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("dial: %w", err))
	}
	defer client.Close()

	var server rendr.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		return FromError(name, time.Since(t0), fmt.Errorf("accept: %w", err))
	case <-time.After(15 * time.Second):
		return FromError(name, time.Since(t0), fmt.Errorf("accept timeout"))
	}
	defer server.Close()

	payload := make([]byte, opts.Size)
	for i := range payload {
		payload[i] = byte(i*17 + 3)
	}
	hSent := sha256.Sum256(payload)

	recvErr := make(chan error, 1)
	progress := make(chan int64, 64)
	hRecv := sha256.New()
	go func() {
		buf := make([]byte, 256*1024)
		var got int64
		for got < opts.Size {
			n, err := server.Read(buf)
			if err != nil {
				recvErr <- err
				return
			}
			hRecv.Write(buf[:n])
			got += int64(n)
			publishTCPRepairProgress(progress, got)
		}
		recvErr <- nil
	}()

	admin, ok := client.(rendr.AdminConn)
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("client conn is not rendr.AdminConn"))
	}
	pathID := admin.ActivePath()
	if pathID == 0 {
		return FromError(name, time.Since(t0), fmt.Errorf("no active path"))
	}

	migPts := make([]int64, opts.Migrations)
	for i := 0; i < opts.Migrations; i++ {
		migPts[i] = opts.Size * int64(i+1) / int64(opts.Migrations+1)
	}

	const chunk = int64(64 * 1024)
	var written int64
	var migIdx int
	var serverGot int64
	for written < opts.Size {
		select {
		case err := <-recvErr:
			if err != nil {
				return FromError(name, time.Since(t0), fmt.Errorf("recv before write complete: %w", err))
			}
			return FromError(name, time.Since(t0), fmt.Errorf("receiver finished after %d/%d bytes", written, opts.Size))
		case <-ctx.Done():
			return FromError(name, time.Since(t0), fmt.Errorf("context before write complete: %w", ctx.Err()))
		default:
		}
		end := written + chunk
		if end > opts.Size {
			end = opts.Size
		}
		n, err := client.Write(payload[written:end])
		if err != nil {
			return FromError(name, time.Since(t0), fmt.Errorf("write at %d: %w", written, err))
		}
		written += int64(n)
		for migIdx < len(migPts) && written >= migPts[migIdx] {
			// Keep this same-tuple gate focused on clean TCP_REPAIR
			// socket rebuilds. Cross-queue active-stream repair remains
			// covered by lower-level snapshot tests and future migration
			// work; the phase-2 gate should fail clearly instead of
			// hanging on an in-flight queue stall.
			if err := waitTCPRepairProgress(ctx, recvErr, progress, &serverGot, written); err != nil {
				return FromError(name, time.Since(t0), fmt.Errorf("wait before same-tuple rebuild %d: %w", migIdx, err))
			}
			if err := admin.MigratePathLocalAddr(pathID, ""); err != nil {
				return FromError(name, time.Since(t0), fmt.Errorf("same-tuple rebuild %d: %w", migIdx, err))
			}
			migIdx++
		}
	}
	if err := waitTCPRepairProgress(ctx, recvErr, progress, &serverGot, opts.Size); err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("recv: %w", err))
	}

	elapsed := time.Since(t0)
	sentHex := fmt.Sprintf("%x", hSent[:])
	recvHex := fmt.Sprintf("%x", hRecv.Sum(nil))
	r := Result{
		Name:     name,
		Duration: elapsed,
		Detail: map[string]any{
			"elapsed_seconds": elapsed.Seconds(),
			"throughput_mb_s": float64(opts.Size) / elapsed.Seconds() / 1e6,
			"repairs_done":    migIdx,
			"sha256_match":    sentHex == recvHex,
		},
	}
	if sentHex != recvHex {
		r.Failure = fmt.Sprintf("SHA-256 mismatch: sent=%s recv=%s", sentHex, recvHex)
		return r
	}
	if migIdx < opts.Migrations {
		r.Failure = fmt.Sprintf("repairs_done=%d, want >= %d", migIdx, opts.Migrations)
		return r
	}
	return r
}

func publishTCPRepairProgress(ch chan int64, got int64) {
	select {
	case ch <- got:
		return
	default:
	}
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- got:
	default:
	}
}

func waitTCPRepairProgress(ctx context.Context, recvErr <-chan error, progress <-chan int64, current *int64, want int64) error {
	for *current < want {
		select {
		case got := <-progress:
			if got > *current {
				*current = got
			}
		case err := <-recvErr:
			if err != nil {
				return err
			}
			*current = want
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
