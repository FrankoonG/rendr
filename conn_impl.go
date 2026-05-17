package rendr

import (
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
	// M1 only implements prime; allow setting to/from anything but
	// reject bond/race entirely until M7/M8 land.
	if m != ModePrime {
		return ErrNotImplemented
	}
	c.mode.Store(uint32(m))
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
