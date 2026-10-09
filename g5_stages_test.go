package rendr

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// g5StageBytes is the charge of one started carrier's reader stage: one
// 16 KiB-class buffer (16 KiB + carrier.ClassSlack = 16,448 bytes).
const g5StageBytes = carrier.BigData + carrier.ClassSlack

// g5Carriers returns the live carriers of the sessions of conns.
func g5Carriers(conns []*Conn) int64 {
	var n int64
	for _, c := range conns {
		n += int64(len(liveCarriers(c.Status())))
	}
	return n
}

// g5Accounts checks Status.BufferedBytes of rt against its two accounts
// while nothing moves: the data account (MaxBufferedBytes) holds want
// bytes (-1: any amount) and the reader stages are those of exactly the
// live carriers of conns, outside the data account. It returns the stage
// bytes.
func g5Accounts(t testing.TB, side string, rt *Runtime, conns []*Conn, want int64) (stages int64) {
	t.Helper()
	data := rt.budget.Used()
	stages = g5Carriers(conns) * g5StageBytes
	if want >= 0 && data != want {
		t.Errorf("%s: %d bytes in the MaxBufferedBytes account, want %d (the reader stages of %d carriers must not be in it)",
			side, data, want, stages/g5StageBytes)
	}
	if got := rt.Status().BufferedBytes; got != data+stages {
		t.Errorf("%s: BufferedBytes %d, want data %d + reader stages %d = %d", side, got, data, stages, data+stages)
	}
	return stages
}

// g5Deliver sends n bytes of PRNG(seed) from w to r, half-closes w, and
// checks the SHA-256 of what r received and its io.EOF.
func g5Deliver(w, r *Conn, n int64, seed uint64) error {
	want, err := rendrtest.Digest(rendrtest.PRNG(seed), n)
	if err != nil {
		return err
	}
	werr := make(chan error, 1)
	go func() {
		_, err := io.Copy(onlyWriter{w}, io.LimitReader(rendrtest.PRNG(seed), n))
		if err == nil {
			err = w.CloseWrite()
		}
		werr <- err
	}()
	got, err := rendrtest.Digest(r, n)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("SHA-256 of the %d bytes received differs from the bytes sent", n)
	}
	var x [1]byte
	if k, err := r.Read(x[:]); k != 0 || err != io.EOF {
		return fmt.Errorf("read after %d bytes: (%d, %v), want io.EOF", n, k, err)
	}
	return <-werr
}

// TestG5IdleStagesLeaveDataBudget_L15 (design §0.14 B2): every started
// carrier's reader stage (16 KiB + 64) is charged to a fixed account of
// its own, outside MaxBufferedBytes: neither the send-chunk admission nor
// the window advertisement sees it, while Status.BufferedBytes reports data
// + stages. With MaxBufferedBytes 512 KiB on both Runtimes, 40 idle sessions
// opened after an existing one put 42 stages (690,816 bytes, 132 % of the
// budget, counting the new session's) on each side. The new session still
// opens with full windows, and it and the existing session each deliver
// 256 KiB both ways intact (SHA-256) and finish with io.EOF; before the fix
// the stages filled the budget, so the new session advertised window 0 and
// no Write of either session got a send chunk (0 of 256 KiB delivered).
// The data account is empty while every session is idle, BufferedBytes is
// data + stages before and after the transfers, and 0 after Close (R7).
func TestG5IdleStagesLeaveDataBudget_L15(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			budget = 512 << 10 // MaxBufferedBytes of both Runtimes
			idle   = 40        // idle sessions opened after the existing one
			size   = 256 << 10 // bytes each session delivers in each direction
		)
		ov := &testhooks.Overrides{MaxBufferedBytes: budget}
		e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
		peer := e.dedicatedPeer() // one reader stage per session's carrier (M3-D2)
		var (
			mu      sync.Mutex
			passive = make(map[SessionID]*Conn)
		)
		acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) {
			c, err := pc.Confirm()
			if err == nil {
				mu.Lock()
				passive[c.ID()] = c
				mu.Unlock()
			}
			return c, err
		})
		defer acc.stop()
		var dialed []*Conn
		dial := func() *Conn {
			t.Helper()
			c, err := peer.Dial(context.Background(), DialOptions{})
			if err != nil {
				t.Fatalf("Dial %d: %v", len(dialed), err)
			}
			dialed = append(dialed, c)
			return c
		}
		ends := func(dc *Conn) (*Conn, *Conn) {
			t.Helper()
			synctest.Wait()
			mu.Lock()
			defer mu.Unlock()
			pc := passive[dc.ID()]
			if pc == nil {
				t.Fatalf("session %v: no confirmed passive end", dc.ID())
			}
			return dc, pc
		}
		accounts := func(when string, want int64) (stages [2]int64) {
			t.Helper()
			synctest.Wait()
			mu.Lock()
			pcs := make([]*Conn, 0, len(passive))
			for _, c := range passive {
				pcs = append(pcs, c)
			}
			mu.Unlock()
			stages[0] = g5Accounts(t, "dialer "+when, e.d, dialed, want)
			stages[1] = g5Accounts(t, "passive "+when, e.p, pcs, want)
			return stages
		}

		ed, ep := ends(dial()) // the existing session: opened while the budget is empty
		for range idle {
			dial()
		}
		fd, fp := ends(dial()) // the new session
		stages := accounts("with every session idle", 0)
		for i, rt := range []*Runtime{e.d, e.p} {
			if open := rt.Status().Sessions.Open; open != idle+2 || stages[i] != (idle+2)*g5StageBytes || stages[i] <= rt.budget.Max() || rt.budget.Max() != budget {
				t.Fatalf("stimulus: %d open sessions with %d bytes of reader stages, want %d sessions with one carrier each, whose stages exceed MaxBufferedBytes %d (%d)",
					open, stages[i], idle+2, budget, rt.budget.Max())
			}
		}
		for _, c := range []*Conn{fd, fp} {
			if st := c.Status(); st.Window <= 0 || st.PeerWindow <= 0 {
				t.Errorf("new session %v (%v): Window %d, PeerWindow %d; the stages made the receive window 0",
					c.ID(), st.Role, st.Window, st.PeerWindow)
			}
		}

		type flow struct {
			name string
			w, r *Conn
			err  error
		}
		flows := []*flow{
			{name: "existing, dialer to passive", w: ed, r: ep},
			{name: "existing, passive to dialer", w: ep, r: ed},
			{name: "new, dialer to passive", w: fd, r: fp},
			{name: "new, passive to dialer", w: fp, r: fd},
		}
		var wg sync.WaitGroup
		for i, f := range flows {
			wg.Go(func() { f.err = g5Deliver(f.w, f.r, size, uint64(50+i)) })
		}
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Minute):
			for _, f := range flows {
				t.Errorf("%s: %d of %d bytes delivered in 2 virtual minutes (window %d, peer window %d)",
					f.name, f.r.Status().DeliveredBytes, size, f.r.Status().Window, f.w.Status().PeerWindow)
			}
			for _, rt := range []*Runtime{e.d, e.p} {
				t.Errorf("Runtime %v: MaxBufferedBytes account %d of %d, BufferedBytes %d",
					rt.InstanceID(), rt.budget.Used(), rt.budget.Max(), rt.Status().BufferedBytes)
			}
			t.FailNow() // the cleanups close both Runtimes, which ends the stuck Writes and Reads
		}
		for _, f := range flows {
			if f.err != nil {
				t.Errorf("%s: %v", f.name, f.err)
			}
		}
		for _, c := range []*Conn{ed, ep, fd, fp} {
			if st := c.Status(); st.DeliveredBytes != size || st.TxBytes != size {
				t.Errorf("session %v (%v): delivered %d, sent %d, want %d each", c.ID(), st.Role, st.DeliveredBytes, st.TxBytes, size)
			}
		}
		accounts("after the transfers", -1)
		for _, c := range []*Conn{ed, ep, fd, fp} {
			c.Close()
		}
		for _, c := range []*Conn{ed, ep, fd, fp} {
			e2eDone(t, c, time.Minute)
			if st := c.Status(); st.Err != io.EOF {
				t.Errorf("session %v (%v) ended with %v, want io.EOF", c.ID(), st.Role, st.Err)
			}
		}
		e.close() // BufferedBytes 0 on both Runtimes once they are closed (R7)
	})
}
