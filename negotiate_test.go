package rendr

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// scriptedPassive is a factory whose every carrier is answered by a
// scripted passive (the far end of a net.Pipe) instead of a Runtime: it
// reads the dialer's PREFACE and first frame — Establish writes both in
// one Write while it waits for the PREFACE_ACK (design §0.8 V1) — writes
// answer(preface, first) byte for byte, then reads until the dialer
// closes. Every goroutine it starts has ended once wg is waited for.
type scriptedPassive struct {
	t      testing.TB
	answer func(p wire.Preface, first wire.Frame) []byte
	wg     sync.WaitGroup
	dials  atomic.Int32
}

func (s *scriptedPassive) carrier(name string) StreamCarrier {
	return StreamCarrier{Name: name, Dial: func(context.Context) (net.Conn, error) {
		s.dials.Add(1)
		a, b := net.Pipe()
		s.wg.Go(func() {
			defer b.Close()
			var pb [wire.PrefaceLen]byte
			if _, err := io.ReadFull(b, pb[:]); err != nil {
				return
			}
			p, err := wire.ParsePreface(pb[:])
			if err != nil {
				s.t.Errorf("the dialer sent an invalid PREFACE: %v", err)
				return
			}
			var hb [wire.HeaderLen]byte
			if _, err := io.ReadFull(b, hb[:]); err != nil {
				return
			}
			h, err := wire.ParseHeader(hb[:])
			if err != nil {
				s.t.Errorf("the dialer's first frame: %v", err)
				return
			}
			rest := make([]byte, int(h.Len)+wire.TrailerLen)
			if _, err := io.ReadFull(b, rest); err != nil {
				return
			}
			if _, err := b.Write(s.answer(p, wire.Frame{Header: h, Payload: rest[:h.Len]})); err != nil {
				return
			}
			io.Copy(io.Discard, b)
		})
		return a, nil
	}}
}

// prefaceAck encodes a PREFACE_ACK answering p; edit may change bytes 0–35,
// after which the CRC is recomputed (a well-formed answer of that shape).
func prefaceAck(p wire.Preface, st wire.PrefaceStatus, inst [16]byte, edit func(b []byte)) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPrefaceAck(b, &wire.PrefaceAck{Minor: wire.Minor, Status: st, Instance: inst, CarrierID: p.CarrierID})
	if edit != nil {
		edit(b)
		binary.BigEndian.PutUint32(b[36:40], wire.CRC(b[:36]))
	}
	return b
}

// frameAfterAck appends one passive frame to a PREFACE_ACK, with the first
// fseq of the passive's direction: the PREFACE_ACK's CRC field (§0.13 A6).
func frameAfterAck(ack []byte, ty wire.Type, flags uint8, payload []byte) []byte {
	var handle uint32
	if !ty.CarrierLevel() {
		handle = wire.SessionHandle
	}
	return wire.AppendFrame(ack, wire.Header{Type: ty, Flags: flags, Fseq: wire.PrefaceFseq(ack), Handle: handle}, payload)
}

// TestHandshakeNegotiationTyped_L44 (as amended by P19): a dialer meeting
// scripted passives that answer the way an incompatible or broken peer
// would gets the typed error within 200 ms (L44, design §5.1, §6.6, §9).
// A well-formed PREFACE_ACK of major 1 or 3 (magic, major byte and CRC
// valid, other fields arbitrary), PREFACE_ACK VERSION and FEATURE are
// ErrVersion; OPEN_ACK BAD_REQUEST is ErrProtocol, with CodeMetadataSize
// ErrMetadataTooLarge. A zero InstanceID in the PREFACE_ACK and a DATA
// frame before OPEN_ACK are malformed answers — carrier errors, retried
// until NoPathGrace (here 150 ms) — and end as ErrNoPath wrapping the
// protocol-violation carrier error, within 200 ms. Every error is a
// net.Error with Timeout false; no session or MaxSessions unit remains.
func TestHandshakeNegotiationTyped_L44(t *testing.T) {
	passive := wpInst(0x44)
	cases := []struct {
		name   string
		answer func(p wire.Preface, first wire.Frame) []byte
		want   error
		retry  bool // a carrier error: the dialer retries until the grace
	}{
		{"major 1", func(p wire.Preface, _ wire.Frame) []byte {
			return prefaceAck(p, wire.PrefaceOK, passive, func(b []byte) { b[4] = 1 })
		}, ErrVersion, false},
		{"major 3 with other fields", func(p wire.Preface, _ wire.Frame) []byte {
			return prefaceAck(p, wire.PrefaceOK, passive, func(b []byte) { b[4] = 3; b[6] = 0x77; clear(b[16:32]) })
		}, ErrVersion, false},
		{"PREFACE_ACK VERSION", func(p wire.Preface, _ wire.Frame) []byte {
			return prefaceAck(p, wire.PrefaceVersion, passive, nil)
		}, ErrVersion, false},
		{"PREFACE_ACK FEATURE", func(p wire.Preface, _ wire.Frame) []byte {
			return prefaceAck(p, wire.PrefaceFeature, passive, nil)
		}, ErrVersion, false},
		{"OPEN_ACK BAD_REQUEST", func(p wire.Preface, _ wire.Frame) []byte {
			var b [wire.OpenAckFixedLen]byte
			n := wire.PutOpenAck(b[:], &wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeBadValue})
			return frameAfterAck(prefaceAck(p, wire.PrefaceOK, passive, nil), wire.TypeOpenAck, 0, b[:n])
		}, ErrProtocol, false},
		{"OPEN_ACK BAD_REQUEST metadata", func(p wire.Preface, _ wire.Frame) []byte {
			var b [wire.OpenAckFixedLen]byte
			n := wire.PutOpenAck(b[:], &wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeMetadataSize})
			return frameAfterAck(prefaceAck(p, wire.PrefaceOK, passive, nil), wire.TypeOpenAck, 0, b[:n])
		}, ErrMetadataTooLarge, false},
		{"zero InstanceID", func(p wire.Preface, _ wire.Frame) []byte {
			return prefaceAck(p, wire.PrefaceOK, [16]byte{}, func([]byte) {})
		}, ErrNoPath, true},
		{"DATA before OPEN_ACK", func(p wire.Preface, _ wire.Frame) []byte {
			var b [wire.DataPrefixLen + 4]byte
			wire.PutDataOffset(b[:], 0)
			return frameAfterAck(prefaceAck(p, wire.PrefaceOK, passive, nil), wire.TypeData, 0, b[:])
		}, ErrNoPath, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{NoPathGrace: 150 * time.Millisecond})
				sp := &scriptedPassive{t: t, answer: tc.answer}
				p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{sp.carrier("scripted")}})
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				c, err := p.Dial(context.Background(), DialOptions{})
				el := time.Since(start)
				var ne net.Error
				if c != nil || !errors.Is(err, tc.want) || !errors.As(err, &ne) || ne.Timeout() || el > 200*time.Millisecond {
					t.Fatalf("Dial = %v, %v after %v; want %v within 200 ms", c, err, el, tc.want)
				}
				if tc.retry {
					var ee *carrier.EstablishError
					if !errors.As(err, &ee) || ee.Cause != carrier.CauseProtocolViolation {
						t.Fatalf("%v does not wrap a protocol-violation carrier error", err)
					}
					if el < 150*time.Millisecond || sp.dials.Load() < 1 {
						t.Fatalf("ErrNoPath after %v and %d dials, want at the 150 ms grace", el, sp.dials.Load())
					}
				} else if n := sp.dials.Load(); n != 1 {
					t.Fatalf("a typed answer was retried: %d dials", n)
				}
				rt.Close()
				sp.wg.Wait()
				wpNoState(t, rt)
			})
		})
	}
}
