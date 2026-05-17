package engine

import "sync"

// BridgeTable maps flow_id -> Engine on the server side. Server-side
// listeners use it to attach migrating paths to the correct engine.
type BridgeTable struct {
	mu sync.Mutex
	m  map[[16]byte]*Engine
}

// NewBridgeTable returns an empty table.
func NewBridgeTable() *BridgeTable {
	return &BridgeTable{m: make(map[[16]byte]*Engine)}
}

// Put registers an engine. Returns false if the flow_id was already
// present (caller likely received a HELLO collision; the right
// response is to BYE the new path).
func (b *BridgeTable) Put(id [16]byte, e *Engine) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[id]; ok {
		return false
	}
	b.m[id] = e
	return true
}

// Get fetches the engine for id, if any.
func (b *BridgeTable) Get(id [16]byte) (*Engine, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.m[id]
	return e, ok
}

// Remove drops id from the table. Idempotent.
func (b *BridgeTable) Remove(id [16]byte) {
	b.mu.Lock()
	delete(b.m, id)
	b.mu.Unlock()
}

// Len returns the current size; for diagnostics.
func (b *BridgeTable) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.m)
}

// Snapshot returns a copy of all flow ids in the table.
func (b *BridgeTable) Snapshot() [][16]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([][16]byte, 0, len(b.m))
	for k := range b.m {
		out = append(out, k)
	}
	return out
}
