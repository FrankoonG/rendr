package l3ingress

import (
	"errors"
	"net/netip"
	"testing"
)

func TestBuildSessionRequestMapsTCPAndUDP(t *testing.T) {
	root := struct{ name string }{"root"}
	tcpID := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.20"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("203.0.113.20"),
		DstPort: 443,
	}
	tcpReq, err := BuildSessionRequest(PacketEvent{
		Meta: PacketMeta{Identity: tcpID},
		Flow: FlowMeta{L3Identity: tcpID},
		Ref:  FlowRef{Identity: tcpID, Generation: 7},
		Decision: FlowDecision{
			Peer:   "peer-a",
			Root:   root,
			Egress: "direct",
			Labels: map[string]string{"class": "interactive"},
		},
		Decided: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tcpReq.Kind != SessionKindStream || tcpReq.Identity != tcpID || tcpReq.Ref.Generation != 7 || tcpReq.Peer != "peer-a" || tcpReq.Root != root || tcpReq.Egress != "direct" || !tcpReq.PreserveL3Identity {
		t.Fatalf("tcp request=%+v", tcpReq)
	}
	tcpReq.Labels["class"] = "mutated"

	udpID := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.21"),
		SrcPort: 50000,
		DstIP:   netip.MustParseAddr("203.0.113.53"),
		DstPort: 53,
	}
	udpReq, err := BuildSessionRequest(PacketEvent{
		Meta: PacketMeta{Identity: udpID},
		Flow: FlowMeta{L3Identity: udpID},
		Decision: FlowDecision{
			Peer:   "peer-b",
			Root:   root,
			Egress: "dns-egress",
			Labels: map[string]string{"class": "bulk"},
		},
		Decided: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if udpReq.Kind != SessionKindPacket || udpReq.Identity != udpID || udpReq.Egress != "dns-egress" || udpReq.Labels["class"] != "bulk" {
		t.Fatalf("udp request=%+v", udpReq)
	}
}

func TestBuildSessionRequestRejectsMismatchedFlowRef(t *testing.T) {
	id := L3Identity{
		Proto: ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.41"), SrcPort: 50000,
		DstIP: netip.MustParseAddr("203.0.113.41"), DstPort: 53,
	}
	other := id
	other.SrcPort++
	for _, ref := range []FlowRef{
		{Identity: other, Generation: 1},
		{Identity: id, Generation: 0},
	} {
		_, err := BuildSessionRequest(PacketEvent{
			Meta: PacketMeta{Identity: id}, Flow: FlowMeta{L3Identity: id}, Ref: ref,
			Decision: FlowDecision{Peer: "peer-a", Root: "root", Egress: "direct"}, Decided: true,
		})
		var sessionErr *SessionError
		if !errors.As(err, &sessionErr) || sessionErr.Reason != ReasonSessionFlowRefMismatch {
			t.Fatalf("ref=%+v error=%v, want %s", ref, err, ReasonSessionFlowRefMismatch)
		}
	}
}

func TestBuildSessionRequestRejectsInvalidDecisions(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.30"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("203.0.113.30"),
		DstPort: 443,
	}
	root := "root"
	cases := []struct {
		name string
		ev   PacketEvent
		want SessionErrorReason
	}{
		{
			name: "undecided",
			ev:   PacketEvent{Meta: PacketMeta{Identity: id}},
			want: ReasonSessionUndecided,
		},
		{
			name: "denied",
			ev: PacketEvent{
				Meta:     PacketMeta{Identity: id},
				Decision: FlowDecision{Deny: true, DenyReason: "policy_blocked"},
				Decided:  true,
			},
			want: ReasonSessionDenied,
		},
		{
			name: "missing peer",
			ev: PacketEvent{
				Meta:     PacketMeta{Identity: id},
				Decision: FlowDecision{Root: root, Egress: "direct"},
				Decided:  true,
			},
			want: ReasonSessionMissingPeer,
		},
		{
			name: "missing root",
			ev: PacketEvent{
				Meta:     PacketMeta{Identity: id},
				Decision: FlowDecision{Peer: "peer-a", Egress: "direct"},
				Decided:  true,
			},
			want: ReasonSessionMissingRoot,
		},
		{
			name: "missing egress",
			ev: PacketEvent{
				Meta:     PacketMeta{Identity: id},
				Decision: FlowDecision{Peer: "peer-a", Root: root},
				Decided:  true,
			},
			want: ReasonSessionMissingEgress,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildSessionRequest(tc.ev)
			var se *SessionError
			if !errors.As(err, &se) {
				t.Fatalf("got %T %v, want SessionError", err, err)
			}
			if se.Reason != tc.want {
				t.Fatalf("reason=%s want %s", se.Reason, tc.want)
			}
		})
	}
}

func TestBuildSessionRequestRejectsIdentityMismatch(t *testing.T) {
	packetID := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.40"),
		SrcPort: 50000,
		DstIP:   netip.MustParseAddr("203.0.113.40"),
		DstPort: 53,
	}
	flowID := packetID
	flowID.SrcPort = 50001
	_, err := BuildSessionRequest(PacketEvent{
		Meta:     PacketMeta{Identity: packetID},
		Flow:     FlowMeta{L3Identity: flowID},
		Decision: FlowDecision{Peer: "peer-a", Root: "root", Egress: "direct"},
		Decided:  true,
	})
	var se *SessionError
	if !errors.As(err, &se) {
		t.Fatalf("got %T %v, want SessionError", err, err)
	}
	if se.Reason != ReasonSessionIdentityMismatch {
		t.Fatalf("reason=%s want %s", se.Reason, ReasonSessionIdentityMismatch)
	}
}
