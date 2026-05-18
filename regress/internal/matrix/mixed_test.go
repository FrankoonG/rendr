package matrix

import (
	"context"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/regress/internal/matrix/driver"
	"github.com/FrankoonG/rendr/regress/internal/xrayglue"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/uuid"
)

// TestT3MixedBareTCPxVlessVisionTLS — proves rendr's Dialer mixes
// built-in PathSpec transports (tcp/quic/udpflow via
// transport.Default) with factory-supplied paths in the same
// session. Path A uses the global "tcp" adapter; Path B routes
// through an xray VLESS+Vision+TLS outbound. Migration moves between
// the two on the fly.
//
// Architecturally this is the "PathFactory rules don't shadow
// built-in transports for names not registered" guarantee in action:
// even though "tcp" is also a valid name to register a factory under
// (and we don't), the global registry handles it.
func TestT3MixedBareTCPxVlessVisionTLS(t *testing.T) {
	vlessServerPort := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	srv := startVlessVisionServer(t, vlessServerPort, userID, ct)
	defer srv.Close()
	cli := startVlessVisionClient(t, vlessServerPort, userID, ctHash)
	defer cli.Close()

	factory := xrayglue.XrayInstanceAsStreamFactory(cli)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName: "T3.stream.bare-tcp × vless+vision+tls",
		Paths: []rendr.PathSpec{
			{Transport: "tcp"},                       // built-in
			{Transport: "xray-vless-vision-tls"},     // factory
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-vless-vision-tls", Stream: factory},
		},
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	if !r.SHA256Match || r.MigrationsDone == 0 {
		t.Fatalf("mixed case: sha=%v migs=%d", r.SHA256Match, r.MigrationsDone)
	}
	t.Logf("PASS: %s elapsed=%s migrations=%d", r.Name, r.Elapsed, r.MigrationsDone)
}

// TestT3ThreePath_SS_VMess_Vless: 3-path combo. Each path uses a
// distinct xray protocol; rendr migrates among all three during the
// 30 MiB file transfer. Verifies the path-set N>2 codepath of the
// engine + that several factories coexist cleanly on the same
// Dialer.
func TestT3ThreePath_SS_VMess_Vless(t *testing.T) {
	// SS-2022 setup.
	ssPort := pickFreePort(t)
	ssKey := randomSSKey(t)
	const ssMethod = "2022-blake3-aes-128-gcm"
	ssSrv := startSSServer(t, ssPort, ssMethod, ssKey)
	defer ssSrv.Close()
	ssCli := startSSClient(t, ssPort, ssMethod, ssKey)
	defer ssCli.Close()

	// VMess setup.
	vmessPort := pickFreePort(t)
	vmessUID := protocol.NewID(uuid.New()).String()
	vmessSrv := startVMessServer(t, vmessPort, vmessUID)
	defer vmessSrv.Close()
	vmessCli := startVMessClient(t, vmessPort, vmessUID)
	defer vmessCli.Close()

	// VLESS+Vision+TLS setup.
	vlessPort := pickFreePort(t)
	vlessUID := protocol.NewID(uuid.New()).String()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	vlessSrv := startVlessVisionServer(t, vlessPort, vlessUID, ct)
	defer vlessSrv.Close()
	vlessCli := startVlessVisionClient(t, vlessPort, vlessUID, ctHash)
	defer vlessCli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName: "T3.stream.3-path ss × vmess × vless+vision+tls",
		Paths: []rendr.PathSpec{
			{Transport: "xray-ss2022"},
			{Transport: "xray-vmess"},
			{Transport: "xray-vless-vision-tls"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-ss2022", Stream: xrayglue.XrayInstanceAsStreamFactory(ssCli)},
			{Name: "xray-vmess", Stream: xrayglue.XrayInstanceAsStreamFactory(vmessCli)},
			{Name: "xray-vless-vision-tls", Stream: xrayglue.XrayInstanceAsStreamFactory(vlessCli)},
		},
		MigrationFractions: []float64{0.25, 0.5, 0.75},
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	if !r.SHA256Match || r.MigrationsDone == 0 {
		t.Fatalf("3-path: sha=%v migs=%d", r.SHA256Match, r.MigrationsDone)
	}
	t.Logf("PASS: %s elapsed=%s migrations=%d", r.Name, r.Elapsed, r.MigrationsDone)
}
