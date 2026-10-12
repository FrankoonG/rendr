package carrier

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestEstablishJoinEndCode_L47 (WP13 B-1, L47): a stream JOIN carrier
// offers wire.OptEndCode in its PREFACE (an OPEN carrier does not). Only
// when the PREFACE_ACK echoes it may the JOIN_ACK be the coded
// UNKNOWN_SESSION: Established.EndCode reports the code and Payload is the
// canonical JOIN_ACK the session decodes. Without the echo a coded
// JOIN_ACK is a protocol violation (ErrReserved, the M3 rule), as is a
// code on any other status, and an OptEndCode echo the dialer did not
// offer fails the attempt like an unsolicited OptMux.
func TestEstablishJoinEndCode_L47(t *testing.T) {
	coded := func(st wire.AckStatus, code uint32) []byte {
		b := make([]byte, wire.JoinAckLen)
		wire.PutJoinAckMux(b, &wire.JoinAck{Status: st}, code)
		return b
	}
	for _, tc := range []struct {
		name     string
		first    wire.Type
		ackOpt   uint32
		resp     []byte // the JOIN_ACK payload (nil: OPEN_ACK(OK))
		wantCode uint32
		bad      bool // a protocol violation
	}{
		{"negotiated, coded UNKNOWN_SESSION", wire.TypeJoin, wire.OptEndCode, coded(wire.StatusUnknownSession, 0x5000), 0x5000, false},
		{"negotiated, canonical UNKNOWN_SESSION", wire.TypeJoin, wire.OptEndCode, coded(wire.StatusUnknownSession, 0), 0, false},
		{"negotiated, OK", wire.TypeJoin, wire.OptEndCode, func() []byte {
			b := make([]byte, wire.JoinAckLen)
			wire.PutJoinAck(b, &wire.JoinAck{Status: wire.StatusOK})
			return b
		}(), 0, false},
		{"not echoed, coded UNKNOWN_SESSION", wire.TypeJoin, 0, coded(wire.StatusUnknownSession, 0x5000), 0, true},
		{"negotiated, coded CAPACITY", wire.TypeJoin, wire.OptEndCode, coded(wire.StatusCapacity, 7), 0, true},
		{"negotiated, high half set", wire.TypeJoin, wire.OptEndCode, func() []byte {
			b := coded(wire.StatusUnknownSession, 1)
			b[1] = 1
			return b
		}(), 0, true},
		{"OPEN, unsolicited echo", wire.TypeOpen, wire.OptEndCode, nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				f, ends := pipeFactory(0, "f0")
				id := env.IDs.Next()
				spc := make(chan *scriptedPassive, 1)
				go func() {
					spc <- runPassive(<-ends, func(wire.Preface, wire.Frame) []byte {
						ab := make([]byte, wire.PrefaceLen)
						wire.PutPrefaceAck(ab, &wire.PrefaceAck{Minor: wire.Minor, Status: wire.PrefaceOK, Opt: tc.ackOpt, Instance: hPassiveInst, CarrierID: id})
						rf := env.Presets.fseqFrom(ab)
						if tc.resp == nil {
							return append(ab, frameAt(wire.TypeOpenAck, 0, rf, wire.SessionHandle, okOpenAck())...)
						}
						return append(ab, frameAt(wire.TypeJoinAck, 0, rf, wire.SessionHandle, tc.resp)...)
					})
				}()
				payload := phJoin()
				if tc.first == wire.TypeOpen {
					payload = openPayload(0)
				}
				est, err := Establish(context.Background(), env, f, id, tc.first, payload, nil)
				sp := <-spc
				if want := tc.first == wire.TypeJoin; (sp.preface.Opt&wire.OptEndCode != 0) != want {
					t.Errorf("PREFACE opt %#x: OptEndCode offered %v, want %v", sp.preface.Opt, !want, want)
				}
				if tc.bad {
					var ee *EstablishError
					if est != nil || !errors.As(err, &ee) || ee.Cause != CauseProtocolViolation {
						t.Fatalf("Establish = %v, %v; want a protocol violation", est, err)
					}
					<-sp.done
					return
				}
				if err != nil {
					t.Fatalf("Establish: %v", err)
				}
				a, perr := wire.ParseJoinAck(est.Payload)
				if est.EndCode != tc.wantCode || perr != nil || est.Ack.Opt != tc.ackOpt {
					t.Fatalf("EndCode %#x (want %#x), canonical payload %+v %v, ack opt %#x", est.EndCode, tc.wantCode, a, perr, est.Ack.Opt)
				}
				est.Conn.Kill(CauseLocalClose, "test end")
				hWait(t, est.Conn)
				<-sp.done
			})
		})
	}
}
