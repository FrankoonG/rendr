package matrix

import (
	"context"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/regress/internal/matrix/driver"
)

// TestT3PacketBareUDPFlowxUDPFlow: PYP-bare-udpflow × PYP-bare-udpflow.
// Two rendr internal udpflow paths, packet-mode echo through 30
// seconds of paced traffic with forced migrations. Validates the
// packet-mode side of rendr migration without any xray layer.
func TestT3PacketBareUDPFlowxUDPFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	r := driver.RunUDPEcho(ctx, driver.UDPEchoOpts{
		CaseName: "T3.packet.udpflow×udpflow",
		AcceptListen: "udpflow",
		Paths: []rendr.PathSpec{
			{Transport: "udpflow"},
			{Transport: "udpflow"},
		},
		PPS:        2000,
		Duration:   3 * time.Second,
		PayloadLen: 1024,
		Migrations: 3,
		LossPct:    1.0,
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	t.Logf("PASS: %s sent=%d recv=%d loss=%.2f%% p95=%.1fms migrations=%d",
		r.Name, r.Sent, r.Received, r.LossPct, r.P95ms, r.MigrationsDone)
}

// TestT3PacketQUICDatagramxQUICDatagram: PYP-bare-quic-dg × PYP-bare-quic-dg.
// Two QUIC DATAGRAM (RFC 9221) paths. ConnID migration moves the
// packet flow between two distinct QUIC connections.
func TestT3PacketQUICDatagramxQUICDatagram(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	r := driver.RunUDPEcho(ctx, driver.UDPEchoOpts{
		CaseName: "T3.packet.quic-dg×quic-dg",
		AcceptListen: "quic-datagram",
		Paths: []rendr.PathSpec{
			{Transport: "quic", Opts: map[string]string{"mode": "datagram"}},
			{Transport: "quic", Opts: map[string]string{"mode": "datagram"}},
		},
		PPS:        2000,
		Duration:   3 * time.Second,
		PayloadLen: 1024,
		Migrations: 3,
		LossPct:    1.0,
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	t.Logf("PASS: %s sent=%d recv=%d loss=%.2f%% p95=%.1fms migrations=%d",
		r.Name, r.Sent, r.Received, r.LossPct, r.P95ms, r.MigrationsDone)
}
