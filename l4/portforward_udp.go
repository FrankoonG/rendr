package l4

import (
	"context"
	"errors"
)

// ServeUDP reads sock until ctx is done or sock is closed and forwards the
// datagrams of every client source address to target as one flow. A
// datagram from a new client opens a flow: it rides the OPEN when it fits
// (DialUDP), the client's later datagrams wait (at most 8 and 16 KiB, at
// most 1 s) until the flow is open (at most 12 s); a client whose open
// failed, or whose flow the far end closed within 5 s of its open, is not
// dialled again for 5 s; replies go to the client's address. When MaxFlows
// is reached, a new client takes the place of an idle (≥ 1 s) flow that
// never became a stream, or its datagram is dropped and counted (a client
// still held after a failed open makes room first). A datagram longer than
// the flow's MaxPayload is dropped and counted. Socket errors of the
// system-call class are counted and backed off. ServeUDP owns sock from
// the call on and closes it when it returns, after every flow it started
// ended.
//
// Skeleton (M6 wave 0): not implemented yet; it closes sock and returns
// the error.
func (f *PortForward) ServeUDP(ctx context.Context, sock UDPSocket, target string) error {
	sock.Close()
	return errors.New("l4: not implemented")
}

// Flows returns a snapshot of the UDP flows (diagnostics: it allocates and
// calls Status on every open flow's session).
//
// Skeleton (M6 wave 0): no flow is listed.
func (f *PortForward) Flows() []FlowInfo { return nil }
