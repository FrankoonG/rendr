package rendr

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// esaHeld delays the bytes of its first Write after the PREFACE until the
// PREFACE_ACK was read through it, and runs onAck then: a dialer whose
// OPEN reaches the passive only after something changed between the
// passive's gate and its admission (Runtime.Close's first step).
type esaHeld struct {
	net.Conn
	once  sync.Once
	acked chan struct{}
	onAck func()
	read  int
}

func (c *esaHeld) Write(p []byte) (int, error) {
	first := false
	c.once.Do(func() { first = true })
	if !first || len(p) <= wire.PrefaceLen {
		return c.Conn.Write(p)
	}
	n, err := c.Conn.Write(p[:wire.PrefaceLen])
	if err != nil {
		return n, err
	}
	<-c.acked
	m, err := c.Conn.Write(p[wire.PrefaceLen:])
	return n + m, err
}

func (c *esaHeld) Read(p []byte) (int, error) {
	if c.read < wire.PrefaceLen && len(p) > wire.PrefaceLen-c.read {
		p = p[:wire.PrefaceLen-c.read]
	}
	n, err := c.Conn.Read(p)
	c.read += n
	if c.read == wire.PrefaceLen && n > 0 {
		c.onAck()
		close(c.acked)
	}
	return n, err
}

// TestEstablishEarlySyncConnAdmission (R1-5, M4-D58; the admission half of
// TestEstablishEarlySyncConn): a dialer's first flight with 64 KiB of
// early data over a raw net.Pipe to a real Runtime's Listener, whose
// admission refuses it before any session reader exists — a full backlog
// (CAPACITY CodeBacklog → ErrCapacity), MaxSessions (CAPACITY
// CodeMaxSessions → ErrCapacity), oversized metadata (BAD_REQUEST
// CodeMetadataSize → ErrMetadataTooLarge) and a Runtime whose Close began
// between the gate and the admission (GOING_AWAY → ErrCapacity): the
// dialer reads the typed OPEN_ACK at once, never a "preface" transport
// failure at the handshake deadline, because the refusal's closer drains
// the flight while it writes the answer (Hooks.Drained reports it), and no
// state is left.
func TestEstablishEarlySyncConnAdmission(t *testing.T) {
	early := bytes.Repeat([]byte{0x5a}, wire.EarlyWindow)
	dataLen := wire.FrameOverhead + wire.DataPrefixLen + len(early)
	const bigMeta = 1000
	for _, tc := range []struct {
		name    string
		cfg     Config
		lcfg    ListenConfig
		meta    int
		closing bool
		setup   func(t *testing.T, rt *Runtime, ln *Listener) (cleanup func())
		status  wire.AckStatus
		code    uint32
		drained int
	}{
		{name: "backlog full", lcfg: ListenConfig{AcceptBacklog: 1},
			setup: func(t *testing.T, rt *Runtime, ln *Listener) func() {
				if ln.reserve(kindIdxStream) != reserveOK { // the one slot: an admission in progress
					t.Fatal("reserve")
				}
				return func() { ln.unreserve(kindIdxStream) }
			}, status: wire.StatusCapacity, code: wire.CodeBacklog, drained: dataLen},
		{name: "MaxSessions", cfg: Config{MaxSessions: 1},
			setup: func(t *testing.T, rt *Runtime, ln *Listener) func() {
				if !rt.table.placeDialer(SessionID(wpSID(99))) { // the one unit
					t.Fatal("placeDialer")
				}
				return func() { rt.table.ended(dialerKey(SessionID(wpSID(99))), nil, session.Verdict{}, time.Now()) }
			}, status: wire.StatusCapacity, code: wire.CodeMaxSessions, drained: dataLen},
		{name: "oversized metadata", cfg: Config{Handshake: HandshakeLimits{MaxMetadata: 64}}, meta: bigMeta,
			status: wire.StatusBadRequest, code: wire.CodeMetadataSize, drained: wire.OpenFixedLen + bigMeta + wire.TrailerLen + dataLen},
		{name: "GOING_AWAY", closing: true, status: wire.StatusGoingAway, drained: dataLen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var dmu sync.Mutex
				var drained []int
				ov := &testhooks.Overrides{Hooks: &testhooks.Hooks{Drained: func(n int) {
					dmu.Lock()
					drained = append(drained, n)
					dmu.Unlock()
				}}}
				rt := wpTestRuntime(t, tc.cfg, ov)
				ln := wpListen(t, rt, tc.lcfg)
				cleanup := func() {}
				if tc.setup != nil {
					cleanup = tc.setup(t, rt, ln)
				}
				a, b := net.Pipe()
				defer a.Close()
				if err := ln.Handle(b); err != nil {
					t.Fatalf("Handle: %v", err)
				}
				var dc net.Conn = a
				if tc.closing {
					dc = &esaHeld{Conn: a, acked: make(chan struct{}), onAck: func() {
						rt.closing.Store(true) // as between Close's first step and its drain of the handshakes
					}}
				}
				env := &carrier.Env{
					Local:   wpInst(0xe7),
					Timing:  carrier.Timing{DialTimeout: 10 * time.Second, AbandonWait: time.Second},
					IDs:     carrier.NewIDAllocator(0),
					Abandon: carrier.NewAbandonPool(16),
					Bufs:    carrier.NewBufPool(),
					Budget:  carrier.NewBudget(1 << 30),
				}
				f := carrier.Factory{Name: "pipe", Dial: func(context.Context) (net.Conn, error) { return dc, nil }}
				start := time.Now()
				est, err := carrier.EstablishEarly(context.Background(), env, f, env.IDs.Next(), wire.TypeOpen,
					wpOpen(wpSID(1), wire.KindStream, 1, bytes.Repeat([]byte{'m'}, tc.meta)), early, nil)
				if took := time.Since(start); err != nil || took != 0 {
					t.Fatalf("EstablishEarly after %v of the handshake deadline: %v", took, err)
				}
				a2, perr := wire.ParseOpenAck(est.Payload)
				if est.Resp.Type != wire.TypeOpenAck || perr != nil || a2.Status != tc.status || a2.Code != tc.code || est.Early != len(early) {
					t.Fatalf("answer %v %+v (%v, Early %d), want OPEN_ACK %v code %d after the whole flight", est.Resp.Type, a2, perr, est.Early, tc.status, tc.code)
				}
				est.Conn.Kill(carrier.CauseLocalClose, "test end")
				<-est.Conn.Done()
				synctest.Wait()
				if tc.closing {
					rt.closing.Store(false)
				}
				cleanup()
				wpNoState(t, rt)
				dmu.Lock()
				got := append([]int(nil), drained...)
				dmu.Unlock()
				if len(got) != 1 || got[0] != tc.drained {
					t.Fatalf("Drained reports %v, want one report of %d bytes (the unread rest of the flight)", got, tc.drained)
				}
				if env.Abandon.Len() != 0 {
					t.Fatalf("dialer abandoned %d", env.Abandon.Len())
				}
				rt.Close()
			})
		})
	}
}
