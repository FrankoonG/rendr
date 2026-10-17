package wire

// M6 (M6 design §A3.3, §A3.4): L4 UDP adds no frame, flag or PREFACE bit; a
// UDP flow's l4 metadata is opaque OPEN metadata. Its size rows are in
// TestControlFrameSizes_L37, built from these hand-built byte layouts (the
// l4 encoder's bounds are proven in package l4).

// l4MetaUDPIPv4 is the l4 metadata of a UDP flow to 127.0.0.1:53 without a
// first datagram or an application part: the 11-byte IPv4 header with
// command 0x11 and the 2-byte first-datagram length 0 (the vector
// udp-ipv4-loopback-53-nofirst of l4/testdata/meta-v1-udp.txt).
func l4MetaUDPIPv4() []byte {
	return []byte{0x4c, 0x34, 0x01, 0x11, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x35, 0x00, 0x00}
}

// l4MetaUDPBudget is the largest l4 metadata with which l4.DialUDP lets a
// flow's first datagram ride the OPEN: 438 bytes, MinFrameBudget minus the
// 99 bytes of a datagram carrier's first datagram that are not metadata —
// the IPv4 header to 192.0.2.1:53, the length 425 and a 425-byte first
// datagram.
func l4MetaUDPBudget() []byte {
	b := []byte{0x4c, 0x34, 0x01, 0x11, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x35, 0x01, 0xa9}
	return append(b, pattern(425, 0x11)...)
}

// packetOpenWith is the golden packet OPEN carrying metadata md.
func packetOpenWith(md []byte) Open {
	o := gPacketOpen()
	o.Metadata = md
	return o
}
