package engine

import (
	"fmt"

	"github.com/FrankoonG/rendr/transport"
)

type localAddrPathMigrator interface {
	MigratePathLocalAddr(newLocal string) (transport.PathConn, error)
}

// MigratePathLocalAddr asks the named path to rebuild itself while
// preserving the same logical path id. The current implementation is
// intended for TCP_REPAIR-style transports that can recreate the
// underlying socket without surfacing an application-visible error.
//
// If the path rebuild fails after the old socket has already been
// torn down, the path is treated as a transport death and the engine's
// normal failover / migration-budget machinery takes over.
func (e *Engine) MigratePathLocalAddr(id uint32, newLocal string) error {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()

	e.pathsMu.Lock()
	slot, ok := e.paths[id]
	if !ok {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: migrate local addr on unknown path %d", id)
	}
	migrator, ok := slot.conn.(localAddrPathMigrator)
	if !ok {
		e.pathsMu.Unlock()
		return fmt.Errorf("engine: path %d transport does not support local-addr migration", id)
	}
	slot.maintenance.Store(true)
	e.pathsMu.Unlock()

	newConn, err := migrator.MigratePathLocalAddr(newLocal)
	if err != nil {
		e.pathsMu.Lock()
		if cur, ok := e.paths[id]; ok && cur == slot {
			slot.maintenance.Store(false)
		}
		e.pathsMu.Unlock()
		e.onPathDeath(id, slot.gen, transport.CauseTransportError, err)
		return err
	}

	recvQSize := 64
	if e.Packetized() {
		recvQSize = 1024
	}
	newSlot := &pathSlot{
		id:              slot.id,
		gen:             0,
		conn:            newConn,
		spec:            slot.spec,
		localTXTargetID: slot.localTXTargetID,
		peerTXTargetID:  slot.peerTXTargetID,
		attached:        slot.attached,
		recvQ:           make(chan recvFrame, recvQSize),
		dispatchQ:       make(chan pathDispatchJob, pathDispatchQueueSize),
		quit:            make(chan struct{}),
		doneR:           make(chan struct{}),
		doneW:           make(chan struct{}),
	}

	e.pathsMu.Lock()
	if cur, ok := e.paths[id]; !ok || cur != slot {
		e.pathsMu.Unlock()
		_ = newConn.Close()
		return fmt.Errorf("engine: path %d changed during local-addr migration", id)
	}
	newSlot.gen = e.nextPathGenerationLocked()
	e.paths[id] = newSlot
	slot.closeQuit()
	e.pathsMu.Unlock()

	gen := newSlot.gen
	newConn.OnDeath(func(cause transport.DeathCause, err error) {
		e.onPathDeath(id, gen, cause, err)
	})
	go e.readerLoop(newSlot)
	go e.pathWriterLoop(newSlot)
	go e.proberLoop(newSlot)
	return nil
}
