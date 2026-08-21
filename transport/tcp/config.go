package tcp

import (
	"errors"
	"fmt"
	"net"
	"reflect"

	"github.com/FrankoonG/rendr/transport"
)

// PathRole identifies which side created one owned TCP path.
type PathRole string

const (
	PathRoleDialer   PathRole = "dialer"
	PathRoleAcceptor PathRole = "acceptor"
)

// DispatchTracePath identifies the path for which a dispatch tracer is being
// created. Addresses are snapshots taken after dial or accept succeeds.
type DispatchTracePath struct {
	Role       PathRole
	LocalAddr  string
	RemoteAddr string
}

// DispatchTracerFactory creates one tracer per owned TCP path. The factory is
// called before the path is published to the engine, so the tracer observes
// the first DATA dispatch and remains bound across endpoint generations.
// Factories may be called concurrently for independent paths.
type DispatchTracerFactory func(DispatchTracePath) (transport.FrameDispatchTracer, error)

// Config controls optional properties of TCP paths created by Transport.
// The zero value preserves the default behavior.
type Config struct {
	// WriteBufferBytes requests SO_SNDBUF before a socket is published. The
	// kernel may round or clamp the value. Zero preserves the OS default.
	WriteBufferBytes int

	// NewDispatchTracer creates a path-local observer for authorized DATA
	// writes without exposing or transferring ownership of the raw socket.
	// Factories and tracers must return promptly and must not call into rendr.
	// A factory panic rejects and closes the unpublished path. Begin/Finish
	// panics are contained because diagnostics cannot alter DATA delivery.
	// FinishFrameDispatch completes before its associated write returns, but a
	// concurrent PathConn.Close is not a tracer-lifetime barrier; retain tracer
	// state until every application I/O goroutine using that path has returned.
	NewDispatchTracer DispatchTracerFactory
}

func (config Config) validate() error {
	if config.WriteBufferBytes < 0 {
		return fmt.Errorf("tcp: WriteBufferBytes=%d is negative", config.WriteBufferBytes)
	}
	return nil
}

func (config Config) configurePath(conn *net.TCPConn, role PathRole) (
	tracer transport.FrameDispatchTracer,
	returnErr error,
) {
	if conn == nil {
		return nil, errors.New("tcp: configure nil TCP connection")
	}
	if config.WriteBufferBytes > 0 {
		if err := conn.SetWriteBuffer(config.WriteBufferBytes); err != nil {
			return nil, fmt.Errorf("tcp: set write buffer to %d bytes: %w", config.WriteBufferBytes, err)
		}
	}
	if config.NewDispatchTracer == nil {
		return nil, nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			tracer = nil
			if recoveredErr, ok := recovered.(error); ok {
				returnErr = fmt.Errorf("tcp: dispatch tracer factory panicked: %w", recoveredErr)
			} else {
				returnErr = fmt.Errorf("tcp: dispatch tracer factory panicked: %v", recovered)
			}
		}
	}()
	tracer, err := config.NewDispatchTracer(DispatchTracePath{
		Role: role, LocalAddr: conn.LocalAddr().String(), RemoteAddr: conn.RemoteAddr().String(),
	})
	if err != nil {
		return nil, fmt.Errorf("tcp: create dispatch tracer: %w", err)
	}
	if tracer != nil && isNilTCPConfigInterface(tracer) {
		return nil, errors.New("tcp: dispatch tracer factory returned a typed nil")
	}
	return tracer, nil
}

func (config Config) withoutDispatchTracer() Config {
	config.NewDispatchTracer = nil
	return config
}

func isNilTCPConfigInterface(value any) bool {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
