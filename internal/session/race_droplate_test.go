package session

import (
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestRaceCopyBeyondDedupWindowIsDropLate_L39 (KL-15; WP16-RACE-2, §A6.4
// as amended): on a race receiver a copy of a datagram that was received
// and read counts in Duplicates while its seq is inside the dedup window,
// and in DropLate once it is DedupBits seqs or more behind the newest
// accepted seq (SeqWindow.Accept answers WindowLate; no contiguity
// watermark tells it from a datagram that was missing). The application
// never sees it a second time. Judges read DropLate as loss attribution
// only for a datagram that was actually missing (B1.0). Helpers are WP3's
// ("rc") and the packet harness's ("dp").
func TestRaceCopyBeyondDedupWindowIsDropLate_L39(t *testing.T) {
	const width = wire.DefaultSeqWindowBits
	s := dpSession(dpOpt{role: RolePassive, mode: ModeRace, dedupBits: width})
	l1, _ := dpAddLane(s, 1, true, true)
	l2, _ := dpAddLane(s, 2, true, true)
	rcPktRace(s)
	buf := make([]byte, 64)
	const last = width + 9 // 0 … width+9 on lane 1: seqs 0 … 9 leave the window
	for seq := uint64(0); seq <= last; seq++ {
		if err := dpDatagram(l1, seq, dpPayload(seq, 16)); err != nil {
			t.Fatalf("seq %d on lane 1: %v", seq, err)
		}
		if n, err := s.ReadFrom(buf); err != nil || dpID(buf[:n]) != seq {
			t.Fatalf("read %v (%v), want seq %d", buf[:n], err, seq)
		}
	}
	// Lane 2's copies: 0 … 9 are beyond the window, 10 … 19 inside it.
	for seq := uint64(0); seq < 20; seq++ {
		if err := dpDatagram(l2, seq, dpPayload(seq, 16)); err != nil {
			t.Fatalf("copy of seq %d on lane 2: %v", seq, err)
		}
	}
	c := dpCtr(s)
	if c.Received != last+1 || c.DropLate != 10 || c.Duplicates != 10 {
		t.Fatalf("counters %+v; want Received %d, DropLate 10 (the copies beyond the window), Duplicates 10 (those inside it)", c, last+1)
	}
	if q := dpLocked(s, func(_ *stream, pk *packet) int { return pk.rx.n }); q != 0 {
		t.Fatalf("%d datagrams queued for the application after the copies, want 0: a copy is never delivered again", q)
	}
	dpEnd(s, errClosed)
}
