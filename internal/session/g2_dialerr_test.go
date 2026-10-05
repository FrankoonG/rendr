package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestG2DialErrorHidesEOF_L01 (design §0.14 B13; invariant 1): a carrier
// whose far end closed during its handshake failed as a carrier. The Dial
// error that wraps that last carrier error — ErrNoPath at the grace, or the
// context's error — never matches io.EOF or io.ErrUnexpectedEOF, so it
// cannot read as the end of a stream; errors.As still finds the
// *carrier.EstablishError with its transport detail, every other identity
// in the chain still matches, and the text is unchanged.
func TestG2DialErrorHidesEOF_L01(t *testing.T) {
	t.Run("wrap", func(t *testing.T) {
		est := func(err error) *carrier.EstablishError {
			return &carrier.EstablishError{Stage: "preface", Cause: carrier.CauseTransportError, Err: err}
		}
		cases := []struct {
			name string
			last error
			keep error // an identity of last that must still match (nil: none)
		}{
			{"eof", est(io.EOF), nil},
			{"unexpected-eof", est(io.ErrUnexpectedEOF), nil},
			{"wrapped-eof", est(fmt.Errorf("read: %w", io.EOF)), nil},
			{"bare-eof", io.EOF, nil},
			{"deadline", est(os.ErrDeadlineExceeded), os.ErrDeadlineExceeded},
		}
		for _, tc := range cases {
			for _, outer := range []error{ErrNoPath, context.Canceled} {
				err := wrapLast(outer, tc.last)
				if !errors.Is(err, outer) {
					t.Errorf("%s: %v does not match %v", tc.name, err, outer)
				}
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					t.Errorf("%s: %v matches io.EOF or io.ErrUnexpectedEOF", tc.name, err)
				}
				if want := outer.Error() + " (last carrier error: " + tc.last.Error() + ")"; err.Error() != want {
					t.Errorf("%s: text %q, want %q", tc.name, err.Error(), want)
				}
				var ee *carrier.EstablishError
				if want, ok := tc.last.(*carrier.EstablishError); ok && (!errors.As(err, &ee) || ee != want) {
					t.Errorf("%s: errors.As found %v, want the carrier error", tc.name, ee)
				}
				if tc.keep != nil && !errors.Is(err, tc.keep) {
					t.Errorf("%s: %v no longer matches %v", tc.name, err, tc.keep)
				}
			}
		}
		if err := wrapLast(ErrNoPath, nil); err != ErrNoPath {
			t.Errorf("wrapLast without a carrier error: %v, want ErrNoPath itself", err)
		}
	})
	for _, tc := range []struct {
		name    string
		readErr error // what the dialer's conn reports where the PREFACE_ACK should be
		ctx     bool  // Dial's context ends first (else the grace)
	}{
		{"handshake-eof", io.EOF, false},
		{"handshake-unexpected-eof", io.ErrUnexpectedEOF, false},
		{"handshake-eof-ctx", io.EOF, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { g2DialHandshakeEOF(t, tc.readErr, tc.ctx) })
		})
	}
}

// g2DialHandshakeEOF dials a peer that reads the dialer's PREFACE and OPEN
// and closes without an answer: the dialer's PREFACE_ACK read ends in
// io.EOF (after its hello was written, so that is the carrier error),
// reported as readErr by the dialer's conn (a transport such as TLS reports
// a stream cut inside a record as io.ErrUnexpectedEOF). Every attempt
// fails that way until the grace (ErrNoPath) or Dial's context ends.
func g2DialHandshakeEOF(t *testing.T, readErr error, withCtx bool) {
	// The far ends are joined after the teardown closed the link: Link.Close
	// joins its Accept calls, so no far end starts after that (the failed
	// Dial's session withdraws in the background and may still be dialling).
	var far sync.WaitGroup
	defer far.Wait()
	w := acNewWorld(t, nil)
	defer w.teardown()
	l1 := rendrtest.NewLink(rendrtest.LinkConfig{Name: "p1", Accept: g2CloseAfterHello(&far)})
	l1.SetDelay(acLinkDelay, 0)
	w.links = append(w.links, l1)
	spec := w.spec(ModeSelector, l1)
	spec.Params.Grace = 2 * time.Second
	spec.Factories[0].Dial = func(ctx context.Context) (net.Conn, error) {
		c, err := l1.Dial(ctx)
		if err != nil {
			return nil, err
		}
		return &g2EOFConn{Conn: c, as: readErr}, nil
	}
	ctx := context.Background()
	want := ErrNoPath
	if withCtx {
		spec.Params.Grace = 30 * time.Second
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		want = context.DeadlineExceeded
	}
	s, err := w.dial(ctx, spec, nil)
	if s != nil || !errors.Is(err, want) {
		t.Fatalf("Dial = %v, %v; want %v", s, err, want)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Dial error %q matches io.EOF or io.ErrUnexpectedEOF", err)
	}
	var ee *carrier.EstablishError
	if !errors.As(err, &ee) || ee.Stage != "preface" || ee.Cause != carrier.CauseTransportError || !errors.Is(ee, readErr) {
		t.Fatalf("Dial error %q: errors.As found %+v, want the preface-stage transport error %v", err, ee, readErr)
	}
	var ne net.Error
	if !errors.As(err, &ne) || ne.Timeout() != withCtx {
		t.Fatalf("Dial error %q: net.Error %v, Timeout() want %v", err, ne, withCtx)
	}
	if n := l1.Stats().Dials; n < 2 {
		t.Fatalf("%d factory calls, want the redials of a carrier failure (stimulus)", n)
	}
}

// g2CloseAfterHello returns a link Accept whose far end reads the dialer's
// PREFACE and first frame, then closes without answering (a peer that went
// away mid-handshake). wg tracks the far ends.
func g2CloseAfterHello(wg *sync.WaitGroup) func(net.Conn) error {
	return func(nc net.Conn) error {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer nc.Close()
			var b [wire.PrefaceLen + wire.HeaderLen]byte
			if _, err := io.ReadFull(nc, b[:]); err != nil {
				return
			}
			h, err := wire.ParseHeader(b[wire.PrefaceLen:])
			if err != nil {
				return
			}
			_, _ = io.CopyN(io.Discard, nc, int64(h.Len)+wire.TrailerLen)
		}()
		return nil
	}
}

// g2EOFConn reports the io.EOF its conn reads as the error as.
type g2EOFConn struct {
	net.Conn
	as error
}

func (c *g2EOFConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == io.EOF {
		err = c.as
	}
	return n, err
}
