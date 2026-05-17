package transport

import (
	"fmt"
	"sync"
)

// Registry maps transport names to Transport implementations. The
// engine looks transports up by name from PathSpec.Transport.
type Registry struct {
	mu sync.RWMutex
	m  map[string]Transport
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{m: make(map[string]Transport)}
}

// Register installs t under its Name(). Duplicate names error.
func (r *Registry) Register(t Transport) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.m[t.Name()]; ok {
		return fmt.Errorf("transport: %q already registered", t.Name())
	}
	r.m[t.Name()] = t
	return nil
}

// MustRegister panics if Register fails; convenient for init().
func (r *Registry) MustRegister(t Transport) {
	if err := r.Register(t); err != nil {
		panic(err)
	}
}

// Lookup returns the Transport with the given name, or an error.
func (r *Registry) Lookup(name string) (Transport, error) {
	r.mu.RLock()
	t, ok := r.m[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("transport: %q not registered", name)
	}
	return t, nil
}

// Names returns a snapshot of registered transport names. Useful in tests.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for k := range r.m {
		out = append(out, k)
	}
	return out
}

// Default is the process-wide registry that init() functions in
// transport sub-packages register into. Production code reads from
// Default; tests can build their own Registry instead.
var Default = NewRegistry()
