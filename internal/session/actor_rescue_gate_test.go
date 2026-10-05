package session

import (
	"crypto/sha256"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The holder's own rescue duplicate between two sessions over
// rendrtest.Link (design §4.11, §0.8 V3; L34): a duplicate can only help a
// receiver that dropped bytes it held out of order, and only DATA sent on
// more than one lane leaves bytes out of order. A bond that only ever sent
// on one member therefore never duplicates its stuck head, however long the
// receiving application leaves it unread. Package-level helpers of these
// tests start with "rg".

// TestActorRescueSlowReaderSingleMember_L34: a bond whose only member
// carries 2 MiB to a reader that takes 256 KiB, then pauses for a second,
// eight times. In every pause the sender's head stays stuck for far longer
// than RescueWait, with up to a window of bytes unacknowledged that the
// receiver holds in order and unread — the rescue check runs on a stuck
// head each time. The receiver cannot have dropped anything, so no rescue
// is ever sent: RetransmittedBytes stays 0 on the sender, and the stream
// arrives intact (SHA-256). Before the fix every pause cost a 64 KiB
// duplicate. Both directions: the passive's rescue check follows the same
// rule over its own sends.
func TestActorRescueSlowReaderSingleMember_L34(t *testing.T) {
	for _, passiveSends := range []bool{false, true} {
		name := "dialer-sends"
		if passiveSends {
			name = "passive-sends"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { rgSlowReader(t, passiveSends) })
		})
	}
}

func rgSlowReader(t *testing.T, passiveSends bool) {
	const (
		n      = 2 << 20
		bursts = 8
		pause  = time.Second
		settle = 100 * time.Millisecond // the burst's ACKs reach the sender
		seed   = 97
	)
	w := acNewWorld(t, nil)
	defer w.teardown()
	a, b := w.open(ModeBond, nil, w.link("p1"))
	acWaitFor(t, time.Second, "the member carries data on both ends", func() bool {
		return a.dataMembers() == 1 && b.dataMembers() == 1
	})
	src, dst := a, b
	if passiveSends {
		src, dst = b, a
	}
	if wait := w.a.p.RescueMin; pause-settle <= 2*wait {
		t.Fatalf("a pause of %v is too short to prove anything against RescueMin %v", pause, wait)
	}
	want, err := rendrtest.Digest(rendrtest.PRNG(seed), n)
	if err != nil {
		t.Fatal(err)
	}
	wdone := make(chan error, 1)
	go func() {
		err := acWritePRNG(src, n, seed)
		if err == nil {
			err = src.CloseWrite()
		}
		wdone <- err
	}()

	h := sha256.New()
	v := rendrtest.NewVerifier(seed, n)
	buf := make([]byte, 32<<10)
	stuck := 0
	for i := range bursts {
		for got := 0; got < n/bursts; {
			k, err := dst.Read(buf[:min(len(buf), n/bursts-got)])
			h.Write(buf[:k])
			if _, verr := v.Write(buf[:k]); verr != nil {
				t.Fatalf("burst %d: %v", i, verr)
			}
			got += k
			if err != nil {
				t.Fatalf("burst %d: read after %d bytes: %v", i, got, err)
			}
		}
		if i == bursts-1 {
			break
		}
		// The pause: once the burst's ACKs arrived, the head stays put.
		time.Sleep(settle)
		base0, next0 := rsSent(src)
		time.Sleep(pause - settle)
		base1, next1 := rsSent(src)
		if base1 == base0 && next1 > base1 && next0 > base0 {
			stuck++
		}
	}
	k, err := dst.Read(buf)
	if k != 0 {
		t.Fatalf("%d bytes beyond the stream", k)
	}
	if verr := v.Done(err); verr != nil {
		t.Fatal(verr)
	}
	if err := <-wdone; err != nil {
		t.Fatalf("writer: %v", err)
	}
	var sum [32]byte
	if h.Sum(sum[:0]); sum != want {
		t.Fatalf("SHA-256 of the received stream %x, want %x", sum, want)
	}
	if stuck < bursts-2 {
		t.Fatalf("the head stayed stuck with bytes unacknowledged through %d of %d pauses (stimulus)", stuck, bursts-1)
	}
	if d := rhDropped(dst); d != 0 {
		t.Fatalf("the receiver dropped %d bytes: it held data out of order (stimulus)", d)
	}
	if r := src.Status().RetransmittedBytes; r != 0 {
		t.Fatalf("%d bytes retransmitted to a receiver that held every byte in order (%d pauses with the head stuck)", r, stuck)
	}
	t.Logf("%d pauses with the head stuck past RescueWait, no duplicate", stuck)
}
