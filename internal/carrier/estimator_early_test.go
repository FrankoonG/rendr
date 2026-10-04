package carrier

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestEarlyPongsReleaseCapacity_L23_L32: every PONG arrives before its
// PING's Write call returned (the hook returns 10 ms after the bytes left),
// as on a synchronous conn at GOMAXPROCS=1, where the peer runs while the
// writer is still inside Write. Those PONGs are no RTT or rate evidence
// (L23), yet they prove delivery: the PONG watermark advances and the
// cap-blocked writer resumes (C5), so a 4 MiB bulk source drains at the
// capacity floor's pace instead of stalling for good after the first cap.
func TestEarlyPongsReleaseCapacity_L23_L32(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, func(nc net.Conn) net.Conn {
			return &hookConn{Conn: nc, onWrite: func(nc net.Conn, b []byte) (int, error) {
				n, err := nc.Write(b)
				time.Sleep(10 * time.Millisecond) // the PONG arrives before this Write returns
				return n, err
			}}
		})
		p.autoPong(nil)
		const total = 4 << 20
		src := newSource(env, ChunkSize, true)
		defer src.chunk.Release()
		src.offer(total)
		start := time.Now()
		c.Start(src, &hBell{}, StartOptions{})
		for p.dataBytes() < total && time.Since(start) < time.Minute {
			time.Sleep(100 * time.Millisecond)
		}
		took := time.Since(start)
		got, st, pings := p.dataBytes(), c.Stats(), p.count(wire.TypePing)
		if dead, cause, detail, _ := c.Death(); dead {
			t.Fatalf("judged dead: %v %s", cause, detail)
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
		// Stimulus: the PINGs flowed and every PONG raced its commit (not
		// one RTT or rate sample), and the load exceeded the cap many times.
		if pings < 16 || st.SRTT != 0 || st.Rate != 0 || st.Cap != env.Timing.CapFloor {
			t.Fatalf("stimulus missing: %d PINGs, srtt %v, rate %v, cap %d", pings, st.SRTT, st.Rate, st.Cap)
		}
		if got != total {
			t.Fatalf("stalled: %d of %d bytes delivered after %v (in flight %d, cap %d)", got, total, took, st.Inflight, st.Cap)
		}
		t.Logf("%d bytes in %v at the %d-byte cap with %d early PONGs", got, took, st.Cap, pings)
	})
}
