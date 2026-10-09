package rendr

import (
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestOpenModeAboveMaxBadRequest_L44: since M3 the codec accepts modes 1 to
// wire.MaxMode (3) and rejects every larger mode byte with wire.ErrValue
// (M3 design §A3.5); admission answers such an OPEN BAD_REQUEST CodeBadMode,
// as in M2, before any session state exists (the M3 rows of
// TestOpenRefusedBeforeState_L44_L48, which pins mode 0 and mode 4).
func TestOpenModeAboveMaxBadRequest_L44(t *testing.T) {
	sid := wpSID(2)
	for _, mode := range []uint8{wire.MaxMode + 1, 0xff} {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			d := wpConnect(t, ln, wpInst(0xd3), 9)
			d.hello(rt)
			sent := d.sendAsync(wire.TypeOpen, 0, wpOpen(sid, wire.KindStream, mode, nil))
			a := d.expectOpenAck(wire.StatusBadRequest, wire.CodeBadMode)
			if a.Window != 0 || len(a.Msg) != 0 {
				t.Fatalf("mode %d: non-canonical refusal %+v", mode, a)
			}
			d.expectEOF()
			<-sent
			synctest.Wait()
			wpNoState(t, rt)
			d.close()
			rt.Close()
		})
	}
}
