package rendr

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
)

// engineBackedConn is the concrete rendr.Conn returned by Dial and
// Accept. It embeds the net.Conn surface provided by the engine and
// exposes the rendr-specific Paths/SetMode/FlowID methods.
type engineBackedConn struct {
	e    *engine.Engine
	conn *engine.Conn

	mode    atomic.Uint32 // Mode
	closing atomic.Bool   // local-Close in flight; gates BYE send
}

func newEngineBackedConn(e *engine.Engine, c *engine.Conn, mode Mode) *engineBackedConn {
	bc := &engineBackedConn{e: e, conn: c}
	bc.mode.Store(uint32(mode))
	e.SetMode(uint32(mode))
	return bc
}

func (c *engineBackedConn) Read(p []byte) (int, error)  { return c.conn.Read(p) }
func (c *engineBackedConn) Write(p []byte) (int, error) { return c.conn.Write(p) }

// Close sends a CTRL_BYE on the active path so the peer surfaces a
// clean io.EOF rather than tripping its migration machinery, then
// tears the engine down. BYE failure is non-fatal: if the active
// path is already dead the peer will see ordinary transport silence
// up to its migration budget.
func (c *engineBackedConn) Close() error {
	if !c.closing.Swap(true) && !c.e.IsClosed() {
		_ = c.e.SendBye(proto.ByeNormal)
	}
	return c.conn.Close()
}
func (c *engineBackedConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *engineBackedConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *engineBackedConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *engineBackedConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *engineBackedConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *engineBackedConn) Paths() []PathInfo {
	return c.e.Paths()
}

func (c *engineBackedConn) FlowID() [16]byte { return c.e.FlowID() }

// SetMode enforces the legal transitions documented in docs/modes.md.
//   - prime ↔ race: allowed
//   - prime → bond: allowed (M8+ only; for now stub rejects bond)
//   - bond → prime: allowed
//   - race → bond: forbidden (race has no per-path order; bond needs it)
//   - bond → race: forbidden
func (c *engineBackedConn) SetMode(m Mode) error {
	if !m.Valid() {
		return ErrModeSwitchIllegal
	}
	cur := Mode(c.mode.Load())
	if cur == m {
		return nil
	}
	if cur == ModeRace && m == ModeBond {
		return ErrModeSwitchIllegal
	}
	if cur == ModeBond && m == ModeRace {
		return ErrModeSwitchIllegal
	}
	c.mode.Store(uint32(m))
	c.e.SetMode(uint32(m))
	return nil
}

// Engine returns the underlying engine for in-package tests and the
// listener-side path attach logic. Not part of the public API.
func (c *engineBackedConn) Engine() *engine.Engine { return c.e }

// Migrate switches the active path to id. Exposed to external admin
// surfaces (chaos harness, runtime balancers) via the AdminConn
// interface assertion.
func (c *engineBackedConn) Migrate(id uint32) error { return c.e.Migrate(id) }

// ActivePath returns the currently-active path id.
func (c *engineBackedConn) ActivePath() uint32 { return c.e.ActivePath() }

// State returns the bridge lifecycle stage as a short string.
func (c *engineBackedConn) State() string { return c.e.State().String() }

// RecvQueueHWM returns the reorder-buffer high-water mark.
func (c *engineBackedConn) RecvQueueHWM() int { return c.e.RecvQueueHighWaterMark() }

// RecvDups returns the cumulative count of duplicate frames reaped.
func (c *engineBackedConn) RecvDups() uint64 { return c.e.RecvDups() }

// BondStuckSkips returns the cumulative bond stuck-skip count.
func (c *engineBackedConn) BondStuckSkips() uint64 { return c.e.BondStuckSkips() }

// Mode returns the current operational mode.
func (c *engineBackedConn) Mode() Mode { return Mode(c.mode.Load()) }

// Stats returns a coherent snapshot of the observable state.
// Paths is filled from engine.Paths() which is taken under a read
// lock, so the snapshot is consistent across the path set.
func (c *engineBackedConn) Stats() ConnStats {
	return ConnStats{
		FlowID:         c.e.FlowID(),
		State:          c.e.State().String(),
		Mode:           Mode(c.mode.Load()),
		ActivePath:     c.e.ActivePath(),
		Paths:          c.e.Paths(),
		RecvQueueHWM:   c.e.RecvQueueHighWaterMark(),
		RecvDups:       c.e.RecvDups(),
		BondStuckSkips: c.e.BondStuckSkips(),
	}
}

// RemovePath gracefully detaches path id from the engine.
func (c *engineBackedConn) RemovePath(id uint32) error {
	return c.e.RemovePath(id)
}

// AddPath dials a path matching spec and attaches it to this
// engine via BRIDGE_TAG. The new path joins the existing flow on
// the server side without breaking the application's Conn.
func (c *engineBackedConn) AddPath(spec PathSpec) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := dialPath(ctx, spec)
	if err != nil {
		return 0, err
	}
	if err := engine.PerformClientBridgeTag(pc, c.e.FlowID()); err != nil {
		_ = pc.Close()
		return 0, err
	}
	id, err := c.e.AttachPath(pc, spec)
	if err != nil {
		_ = pc.Close()
		return 0, err
	}
	return id, nil
}
