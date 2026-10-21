package mux

import (
	"bytes"
	"context"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// heldMaxAge is Packet.MaxAge's default (100 ms), which neither Runtime of
// TestMuxFirstReplyAgesFromPlaceable_L40 changes.
const heldMaxAge = 100 * time.Millisecond

// heldSecond is when, after its first reply, each passive of
// TestMuxFirstReplyAgesFromPlaceable_L40 writes its second: past MaxAge,
// and in the go-frame arm before the go frame (one round trip, 150 ms,
// after the Confirm).
const heldSecond = heldMaxAge + 20*time.Millisecond

// heldWithin bounds a reply's arrival after its dial in
// TestMuxFirstReplyAgesFromPlaceable_L40: the hold's round trips plus, in
// the rel-room arms, the REL retransmission of the lost OPEN_ACK
// (RelRTOInit 300 ms before the trunk's first RTT sample, at most
// 2·RelRTOMin after it) and the views queued behind it.
const heldWithin = 2 * time.Second

// TestMuxFirstReplyAgesFromPlaceable_L40 (L40; M3-D8, M2-D35; the
// m6-design decision on core defect B, 2026-10-21): datagrams the passive
// writes as its session is confirmed wait in the session until the view
// can place them — for REL room for its OPEN_ACK, then for the dialer's go
// frame (M3-D8) — and age (Packet.MaxAge) only from that moment: none is
// dropped DropAge before the view could place it, neither when the view
// first places nor by a later WriteTo while the view still waits.
//
//   - go-frame: a second packet session on a datagram trunk with a 150-ms
//     round trip (≥ MaxAge): the replies wait about one round trip for the
//     go frame.
//   - go-frame/stream: the same on a stream MUX trunk, which holds a view
//     for its go frame too (no REL window).
//   - rel-room: 63 packet sessions opened in one instant on one datagram
//     trunk (its 64 views with the first; 10-ms round trip): their
//     OPEN_ACKs share the trunk's 8-frame REL window, and the datagram of
//     the first of them is lost on the way, so the other views wait for
//     REL room until its retransmission (RelRTOMin 200 ms at least), then
//     for their go frames.
//
// Each arm runs selector and race sessions (race ages its queue in its own
// head step).
//
// Premise: every session shares the one trunk (one factory call).
// Stimulus: each passive writes its first reply right after its Confirm
// and its second heldSecond (120 ms) later; a first reply waits longer
// than MaxAge in the passive session (its arrival less its write and its
// one-way flight).
// PASS: both replies of every session reach its dialer intact and in
// order within heldWithin of the dial, no passive session counts DropAge,
// and Runtime.Close leaves nothing.
func TestMuxFirstReplyAgesFromPlaceable_L40(t *testing.T) {
	for _, arm := range []struct {
		name     string
		mode     rendr.Mode
		oneWay   time.Duration
		sessions int  // opened together after the trunk's first session
		dropAck  bool // the passive → dialer direction drops the datagram of the first of their OPEN_ACKs
		stream   bool // a stream MUX trunk instead of a datagram trunk
	}{
		{"go-frame", rendr.ModeSelector, 75 * time.Millisecond, 1, false, false},
		{"go-frame/race", rendr.ModeRace, 75 * time.Millisecond, 1, false, false},
		{"go-frame/stream", rendr.ModeSelector, 75 * time.Millisecond, 1, false, true},
		{"go-frame/stream/race", rendr.ModeRace, 75 * time.Millisecond, 1, false, true},
		{"rel-room", rendr.ModeSelector, 5 * time.Millisecond, 63, true, false}, // with the first: the 64 views of a datagram trunk
		{"rel-room/race", rendr.ModeRace, 5 * time.Millisecond, 63, true, false},
	} {
		t.Run(arm.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newWorld(t, worldOpts{}, linkSpec{name: "u", oneWay: arm.oneWay, dgram: !arm.stream})
				peer := w.peer("u")
				first := w.openPacket(peer, "first", rendr.ModeSelector) // view 1: it opens the trunk
				if arm.dropAck {
					w.dlink("u").DropNext(rendrtest.Down, rendrtest.FrameOpenAck, 1)
				}
				var mu sync.Mutex
				var wg sync.WaitGroup
				ends := make([]ppair, arm.sessions)
				wrote, got := make([]time.Time, arm.sessions), make([]time.Time, arm.sessions)
				for i := range arm.sessions {
					key := "s" + strconv.Itoa(i)
					wg.Go(func() { // the passive: a reply right after the Confirm, another heldSecond later
						pc := <-w.packetCh(key)
						at := time.Now()
						mu.Lock()
						ends[i].p, wrote[i] = pc, at
						mu.Unlock()
						for k, r := range []string{"a ", "b "} {
							sleepUntil(at.Add(time.Duration(k) * heldSecond))
							if _, err := pc.WriteTo([]byte(r+key), nil); err != nil {
								t.Errorf("passive %s: %v", key, err)
								return
							}
						}
					})
					wg.Go(func() {
						start := time.Now()
						dc, err := peer.DialPacket(context.Background(), rendr.DialOptions{Mode: arm.mode, Metadata: []byte(key)})
						if err != nil {
							t.Errorf("DialPacket %s: %v", key, err)
							return
						}
						mu.Lock()
						ends[i].d = dc
						mu.Unlock()
						b := make([]byte, 2048)
						dc.SetReadDeadline(start.Add(heldWithin))
						for k, r := range []string{"a ", "b "} {
							n, _, err := dc.ReadFrom(b)
							if err != nil {
								t.Errorf("L40: %s's reply %d, written at its Confirm or while its view waited, never arrived: %v", key, k, err)
								return
							}
							if want := r + key; !bytes.Equal(b[:n], []byte(want)) {
								t.Errorf("integrity: %s received %q, want %q", key, b[:n], want)
								return
							}
							if k == 0 {
								mu.Lock()
								got[i] = time.Now()
								mu.Unlock()
							}
						}
					})
				}
				wg.Wait()
				var dropAge uint64
				var held time.Duration // the longest wait of a first reply in the passive: write to arrival, less its one-way flight
				for i, e := range ends {
					if e.p != nil {
						dropAge += e.p.Status().Packet.DropAge
					}
					if !got[i].IsZero() {
						held = max(held, got[i].Sub(wrote[i])-arm.oneWay)
					}
				}
				t.Logf("%s: longest wait of a first reply in the passive %v (rtt %v, MaxAge %v); passive DropAge %d", arm.name, held, 2*arm.oneWay, heldMaxAge, dropAge)
				if dropAge != 0 {
					t.Fatalf("L40: the passive dropped %d replies DropAge before their views could place them", dropAge)
				}
				if t.Failed() {
					t.FailNow()
				}
				if d := w.dials("u"); d != 1 {
					t.Fatalf("premise: %d factory calls, want the sessions on one trunk", d)
				}
				if held <= heldMaxAge {
					t.Fatalf("stimulus: the longest wait of a first reply in the passive was %v, want above MaxAge (%v)", held, heldMaxAge)
				}
				for _, e := range ends {
					e.d.Close()
					e.p.Close()
				}
				first.d.Close()
				first.p.Close()
				w.noViolation()
				w.close()
			})
		})
	}
}
