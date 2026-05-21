//go:build !linux

package tcprepair

import (
	"context"
	"errors"

	"github.com/FrankoonG/rendr/transport"
)

// Transport compiles on non-Linux but is unavailable at runtime.
type Transport struct{}

// New returns a non-Linux stub transport.
func New() *Transport { return &Transport{} }

func init() {
	if err := transport.Default.Register(New()); err != nil {
		panic(err)
	}
}

func (*Transport) Name() string { return "tcprepair" }

// Available reports the platform limitation on non-Linux builds.
func Available() error {
	return errors.New("tcprepair: TCP_REPAIR only supported on Linux")
}

func (*Transport) DialPath(context.Context, transport.PathSpec) (transport.PathConn, error) {
	return nil, Available()
}

func (*Transport) Probe(context.Context, transport.PathSpec) (transport.PathQuality, error) {
	return transport.PathQuality{}, Available()
}
