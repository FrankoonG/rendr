// Package dispatchtrust defines the module-private frame ownership boundary
// shared by the engine and built-in transports.
package dispatchtrust

import "github.com/FrankoonG/rendr/transport"

// Token prevents external adapters from claiming the owned-frame contract.
// Only packages inside this module can import this internal package.
type Token struct {
	sealed struct{}
}

// OwnedFrameWriter accepts replay-ledger-owned bytes for the duration of one
// synchronous call. Implementations must neither retain nor mutate frame.
type OwnedFrameWriter interface {
	WriteOwnedFrameDispatch(Token, []byte, transport.FrameDispatchAuthorization) (int, error)
}

// Write invokes the sealed owned-frame path.
func Write(
	writer OwnedFrameWriter,
	frame []byte,
	authorization transport.FrameDispatchAuthorization,
) (int, error) {
	return writer.WriteOwnedFrameDispatch(Token{}, frame, authorization)
}
