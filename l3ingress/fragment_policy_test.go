package l3ingress

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

const fragmentAdversarialRepetitions = 64

func TestParseRejectsIPv4FragmentsFailClosed(t *testing.T) {
	first := ipv4FragmentPacket(0, true, 24)
	nonInitial := ipv4FragmentPacket(24, false, 24)
	overlapping := ipv4FragmentPacket(16, false, 24)
	malformedLength := ipv4FragmentPacket(0, true, 20)
	dontFragmentAndMore := ipv4FragmentPacket(0, true, 24)
	nonInitial[9] = byte(ProtocolTCP)
	malformedLength[9] = 47
	dontFragmentAndMore[9] = byte(ProtocolICMP)
	binary.BigEndian.PutUint16(dontFragmentAndMore[6:8], 0x6000)
	assertIPv4FragmentsOverlap(t, first, overlapping)
	if payloadLen := len(malformedLength) - 20; payloadLen%8 == 0 {
		t.Fatalf("ipv4 malformed fixture payload=%d is unexpectedly 8-byte aligned", payloadLen)
	}
	if flags := binary.BigEndian.Uint16(dontFragmentAndMore[6:8]) & 0x6000; flags != 0x6000 {
		t.Fatalf("ipv4 malformed fixture flags=%#x want DF|MF", flags)
	}

	for _, fixture := range []struct {
		name   string
		packet []byte
	}{
		{name: "first", packet: first},
		{name: "non-initial", packet: nonInitial},
		{name: "overlapping", packet: overlapping},
		{name: "malformed-length", packet: malformedLength},
		{name: "dont-fragment-and-more", packet: dontFragmentAndMore},
	} {
		assertParseRejectedUnchanged(t, "ipv4 "+fixture.name, fixture.packet, ReasonFragmentedPacket)
	}

	truncated := ipv4FragmentPacket(0, true, 20)
	binary.BigEndian.PutUint16(truncated[2:4], uint16(len(truncated)+8))
	assertParseRejectedUnchanged(t, "ipv4 truncated", truncated, ReasonShortPacket)
}

func TestParseRejectsIPv6FragmentsFailClosed(t *testing.T) {
	first := ipv6FragmentPacket(0, true, 16)
	nonInitial := ipv6FragmentPacket(16, false, 16)
	overlapping := ipv6FragmentPacket(8, false, 16)
	atomic := ipv6FragmentPacket(0, false, 8)
	nonInitial[40] = byte(ProtocolTCP)
	atomic[40] = 47
	reservedBits := append([]byte(nil), atomic...)
	binary.BigEndian.PutUint16(reservedBits[42:44], 0x0002)
	malformedLength := ipv6FragmentPacket(0, true, 10)
	malformedLength[40] = byte(ProtocolICMPv6)
	afterExtension := ipv6FragmentAfterDestinationOptions()
	assertIPv6FragmentsOverlap(t, first, overlapping)
	if reserved := binary.BigEndian.Uint16(reservedBits[42:44]) & 0x0006; reserved == 0 {
		t.Fatal("ipv6 malformed fixture does not set Fragment reserved bits")
	}
	if payloadLen := len(malformedLength) - 48; payloadLen%8 == 0 {
		t.Fatalf("ipv6 malformed fixture payload=%d is unexpectedly 8-byte aligned", payloadLen)
	}

	for _, fixture := range []struct {
		name   string
		packet []byte
	}{
		{name: "first", packet: first},
		{name: "non-initial", packet: nonInitial},
		{name: "overlapping", packet: overlapping},
		{name: "atomic", packet: atomic},
		{name: "reserved-bits", packet: reservedBits},
		{name: "malformed-length", packet: malformedLength},
		{name: "after-extension", packet: afterExtension},
	} {
		assertParseRejectedUnchanged(t, "ipv6 "+fixture.name, fixture.packet, ReasonFragmentedPacket)
	}

	truncated := make([]byte, 44)
	truncated[0] = 0x60
	binary.BigEndian.PutUint16(truncated[4:6], 4)
	truncated[6] = 44
	assertParseRejectedUnchanged(t, "ipv6 truncated", truncated, ReasonShortPacket)

	beyondPayload := make([]byte, 48)
	beyondPayload[0] = 0x60
	beyondPayload[6] = 44
	assertParseRejectedUnchanged(t, "ipv6 fragment beyond payload", beyondPayload, ReasonShortPacket)
}

func TestPumpFragmentsHaveNoFlowSideEffects(t *testing.T) {
	fixtures := [][]byte{
		ipv4FragmentPacket(0, true, 24),
		ipv4FragmentPacket(16, false, 24),
		ipv4FragmentPacket(24, false, 24),
		ipv6FragmentPacket(0, true, 16),
		ipv6FragmentPacket(8, false, 16),
		ipv6FragmentPacket(0, false, 8),
	}
	originals := clonePackets(fixtures)
	packets := make([][]byte, 0, fragmentAdversarialRepetitions*len(fixtures))
	for i := 0; i < fragmentAdversarialRepetitions; i++ {
		for j := len(fixtures) - 1; j >= 0; j-- {
			packets = append(packets, fixtures[(j+i)%len(fixtures)])
		}
	}

	routerCalls := 0
	flowObservations := 0
	table := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
		routerCalls++
		return FlowDecision{Peer: "must-not-exist"}, nil
	}, FlowTableOptions{Observer: FlowObserverFunc(func(FlowSnapshot) {
		flowObservations++
	})})
	parseErrors := 0
	handlerCalls := 0
	pump := &Pump{
		Device:    &fakeDevice{packets: packets},
		FlowTable: table,
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			handlerCalls++
			return nil
		}),
		OnParseError: func(packet []byte, err error) {
			parseErrors++
			var parseError *ParseError
			if !errors.As(err, &parseError) || parseError.Reason != ReasonFragmentedPacket {
				t.Fatalf("parse error %d = %T %v, want %s", parseErrors, err, err, ReasonFragmentedPacket)
			}
			packet[0] = 0
		},
	}
	if err := pump.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantErrors := fragmentAdversarialRepetitions * len(fixtures)
	if parseErrors != wantErrors {
		t.Fatalf("parse errors=%d want %d", parseErrors, wantErrors)
	}
	if routerCalls != 0 || handlerCalls != 0 || flowObservations != 0 {
		t.Fatalf("fragment side effects: router=%d handler=%d observer=%d", routerCalls, handlerCalls, flowObservations)
	}
	if snapshots := table.Snapshots(); len(snapshots) != 0 {
		t.Fatalf("fragment flows=%+v, want none", snapshots)
	}
	table.mu.Lock()
	active, pending, closed := len(table.active), len(table.pending), len(table.closed)
	nextGeneration := table.nextGeneration
	table.mu.Unlock()
	if active != 0 || pending != 0 || closed != 0 || nextGeneration != 0 {
		t.Fatalf("fragment table state active=%d pending=%d closed=%d next_generation=%d", active, pending, closed, nextGeneration)
	}
	if status := pump.Status(); status.PacketFailures != 0 || status.HasLastFailure {
		t.Fatalf("parse rejection leaked into flow-local failures: %+v", status)
	}
	for i := range fixtures {
		if !bytes.Equal(fixtures[i], originals[i]) {
			t.Fatalf("parse callback mutated source fixture %d", i)
		}
	}
}

func TestFragmentPolicyParserMutationControl(t *testing.T) {
	ipv4Control := ipv4Packet(byte(ProtocolUDP), [4]byte{192, 0, 2, 10}, [4]byte{198, 51, 100, 20}, 5353, 53000)
	assertParseAcceptedUnchanged(t, "ipv4 control", ipv4Control)
	ipv4Mutated := append([]byte(nil), ipv4Control...)
	binary.BigEndian.PutUint16(ipv4Mutated[6:8], 0x2000)
	assertParseRejectedUnchanged(t, "ipv4 first-fragment mutation", ipv4Mutated, ReasonFragmentedPacket)

	ipv6Control, err := BuildUDPPacket(L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("2001:db8::1"),
		SrcPort: 0x1100,
		DstIP:   netip.MustParseAddr("2001:db8::2"),
		DstPort: 0,
	}, []byte{0, 1, 0, 2, 0xa5, 0xa5, 0xa5, 0xa5})
	if err != nil {
		t.Fatal(err)
	}
	assertParseAcceptedUnchanged(t, "ipv6 control", ipv6Control)
	ipv6Mutated := append([]byte(nil), ipv6Control...)
	ipv6Mutated[6] = 44
	assertParseRejectedUnchanged(t, "ipv6 atomic-fragment mutation", ipv6Mutated, ReasonFragmentedPacket)
}

func assertParseRejectedUnchanged(t *testing.T, name string, packet []byte, reason ParseReason) {
	t.Helper()
	before := append([]byte(nil), packet...)
	meta, err := ParsePacket(packet)
	if meta != (PacketMeta{}) {
		t.Fatalf("%s returned partial metadata: %+v", name, meta)
	}
	assertReason(t, err, reason)
	if !bytes.Equal(packet, before) {
		t.Fatalf("%s mutated its input", name)
	}
}

func assertParseAcceptedUnchanged(t *testing.T, name string, packet []byte) {
	t.Helper()
	before := append([]byte(nil), packet...)
	if _, err := ParsePacket(packet); err != nil {
		t.Fatalf("%s rejected: %v", name, err)
	}
	if !bytes.Equal(packet, before) {
		t.Fatalf("%s mutated its input", name)
	}
}

func ipv4FragmentPacket(offset int, more bool, payloadLen int) []byte {
	packet := make([]byte, 20+payloadLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 0x1234)
	fragmentField := uint16(offset / 8)
	if more {
		fragmentField |= 0x2000
	}
	binary.BigEndian.PutUint16(packet[6:8], fragmentField)
	packet[8] = 64
	packet[9] = byte(ProtocolUDP)
	copy(packet[12:16], []byte{192, 0, 2, 10})
	copy(packet[16:20], []byte{198, 51, 100, 20})
	if payloadLen >= 8 {
		binary.BigEndian.PutUint16(packet[20:22], 5353)
		binary.BigEndian.PutUint16(packet[22:24], 53000)
		binary.BigEndian.PutUint16(packet[24:26], uint16(payloadLen))
	}
	return packet
}

func ipv6FragmentPacket(offset int, more bool, fragmentPayloadLen int) []byte {
	packet := make([]byte, 40+8+fragmentPayloadLen)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+fragmentPayloadLen))
	packet[6] = 44
	packet[7] = 64
	src := netip.MustParseAddr("2001:db8::10").As16()
	dst := netip.MustParseAddr("2001:db8::20").As16()
	copy(packet[8:24], src[:])
	copy(packet[24:40], dst[:])
	packet[40] = byte(ProtocolUDP)
	fragmentField := uint16(offset/8) << 3
	if more {
		fragmentField |= 1
	}
	binary.BigEndian.PutUint16(packet[42:44], fragmentField)
	binary.BigEndian.PutUint32(packet[44:48], 0x12345678)
	if fragmentPayloadLen >= 8 {
		binary.BigEndian.PutUint16(packet[48:50], 5353)
		binary.BigEndian.PutUint16(packet[50:52], 53000)
		binary.BigEndian.PutUint16(packet[52:54], uint16(fragmentPayloadLen))
	}
	return packet
}

func ipv6FragmentAfterDestinationOptions() []byte {
	packet := make([]byte, 64)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 24)
	packet[6] = 60
	packet[7] = 64
	packet[40] = 44
	packet[41] = 0
	packet[48] = byte(ProtocolUDP)
	packet[50] = 0
	packet[51] = 1
	return packet
}

func clonePackets(packets [][]byte) [][]byte {
	cloned := make([][]byte, len(packets))
	for i := range packets {
		cloned[i] = append([]byte(nil), packets[i]...)
	}
	return cloned
}

func assertIPv4FragmentsOverlap(t *testing.T, first, later []byte) {
	t.Helper()
	if !bytes.Equal(first[4:6], later[4:6]) || !bytes.Equal(first[12:20], later[12:20]) || first[9] != later[9] {
		t.Fatal("ipv4 overlap fixtures do not share one fragment identity")
	}
	firstStart, firstEnd := ipv4FragmentSpan(first)
	laterStart, laterEnd := ipv4FragmentSpan(later)
	if firstStart >= laterEnd || laterStart >= firstEnd {
		t.Fatalf("ipv4 ranges [%d,%d) and [%d,%d) do not overlap", firstStart, firstEnd, laterStart, laterEnd)
	}
}

func ipv4FragmentSpan(packet []byte) (int, int) {
	start := int(binary.BigEndian.Uint16(packet[6:8])&0x1fff) * 8
	return start, start + len(packet) - int(packet[0]&0x0f)*4
}

func assertIPv6FragmentsOverlap(t *testing.T, first, later []byte) {
	t.Helper()
	if !bytes.Equal(first[8:40], later[8:40]) || !bytes.Equal(first[44:48], later[44:48]) || first[40] != later[40] {
		t.Fatal("ipv6 overlap fixtures do not share one fragment identity")
	}
	firstStart, firstEnd := ipv6FragmentSpan(first)
	laterStart, laterEnd := ipv6FragmentSpan(later)
	if firstStart >= laterEnd || laterStart >= firstEnd {
		t.Fatalf("ipv6 ranges [%d,%d) and [%d,%d) do not overlap", firstStart, firstEnd, laterStart, laterEnd)
	}
}

func ipv6FragmentSpan(packet []byte) (int, int) {
	start := int((binary.BigEndian.Uint16(packet[42:44])>>3)&0x1fff) * 8
	return start, start + len(packet) - 48
}
