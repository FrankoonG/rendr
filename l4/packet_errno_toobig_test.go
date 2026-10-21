//go:build !plan9

package l4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestForwardPacketICMPTooBigIsNoise_L58_L71 (M6-D15, R1-2; L58, L71): a
// size errno that a local Read returns without a datagram — EMSGSIZE (this
// OS's symbol) and WSAEMSGSIZE, bare and wrapped, as (0, err) — is no
// datagram above MaxPayload: Unix truncates a longer datagram silently,
// and a connected socket reports an ICMP fragmentation-needed or
// packet-too-big of an earlier send as EMSGSIZE on its next call (a path
// toward the target with a smaller MTU). Each counts LocalNoise, never
// TooLarge; the flow goes on and the datagram after each is delivered. An
// io.ErrShortBuffer without a count stays TooLarge (a datagram longer than
// the buffer by its own word). The filled-buffer rows (Windows' truncation,
// (n, io.ErrShortBuffer)) are TestForwardPacketOversize_L37_L71's.
func TestForwardPacketICMPTooBigIsNoise_L58_L71(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPFWorld(t, pfOpts{})
		dc, pc := w.dial(rendr.DialOptions{})
		app, local := rendrtest.NewDatagramPipe(rendrtest.DatagramPipeConfig{})
		ctx, cancel := context.WithCancel(context.Background())
		res := pfForward(ctx, dc, local, FlowIdle{})
		var size []pfErrno
		for _, e := range pfSizeErrnos() {
			size = append(size, pfWrapped(e)...)
		}
		rows := append(size, pfErrno{"io.ErrShortBuffer", io.ErrShortBuffer})
		for i, e := range rows {
			local.Inject(e.err, false) // the next Read returns (0, err)
			d := pfData(30, byte(i))
			pfSend(t, app, d)
			if got, err := pfRecvPC(t, pc); err != nil || !bytes.Equal(got, d) {
				t.Fatalf("%s on Read: the next datagram %d bytes, %v", e.name, len(got), err)
			}
		}
		back := pfData(9, 0xD0)
		pc.WriteTo(back, nil)
		pfExpect(t, app, back) // the flow goes on both ways
		cancel()
		r := <-res
		if r.LocalNoise != uint64(len(size)) || r.TooLarge != 1 || r.ToSession != uint64(len(rows)) || r.ToLocal != 1 ||
			r.LocalErr != nil || !errors.Is(r.SessionErr, context.Canceled) {
			t.Fatalf("result %+v: want LocalNoise %d (the size errnos without a datagram), TooLarge 1 (io.ErrShortBuffer), every next datagram moved, no end", r, len(size))
		}
		if c := local.Counts(); c.Injected != uint64(len(rows)) {
			t.Fatalf("stimulus: %d injected errors returned, want %d", c.Injected, len(rows))
		}
		w.shutdown()
	})
}
