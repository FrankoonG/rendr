package smoke

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/udprelay"
)

// HysteriaRelayOpts configures the M11 real Hysteria 2-over-udprelay smoke.
type HysteriaRelayOpts struct {
	Paths      int
	Migrations int
	DataSize   int
}

func (o *HysteriaRelayOpts) withDefaults() {
	if o.Paths <= 0 {
		o.Paths = 2
	}
	if o.Migrations <= 0 {
		o.Migrations = 2
	}
	if o.DataSize <= 0 {
		o.DataSize = 8 << 20
	}
}

// HysteriaAvailable reports whether a Hysteria 2 CLI is available for tests.
func HysteriaAvailable() bool {
	_, err := exec.LookPath("hysteria")
	return err == nil
}

// RunHysteriaRelay runs a real Hysteria 2 client/server pair over rendr's UDP
// relay endpoint, then migrates the rendr packet carrier underneath a built-in
// Hysteria speedtest transfer.
func RunHysteriaRelay(ctx context.Context, opts HysteriaRelayOpts) Result {
	opts.withDefaults()
	t0 := time.Now()
	name := fmt.Sprintf("Hysteria2-over-UDP-relay (%d bytes, %d paths, %d migrations)", opts.DataSize, opts.Paths, opts.Migrations)
	if !HysteriaAvailable() {
		return FromError(name, time.Since(t0), fmt.Errorf("hysteria binary not found"))
	}

	tmp, err := os.MkdirTemp("", "rendr-hy2-*")
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("temp dir: %w", err))
	}
	defer os.RemoveAll(tmp)
	certFile := filepath.Join(tmp, "cert.pem")
	keyFile := filepath.Join(tmp, "key.pem")
	if err := writeSelfSignedCert(certFile, keyFile); err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("cert: %w", err))
	}

	hyServerPort, err := reserveUDPPort()
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("reserve hysteria server port: %w", err))
	}
	auth := "rendr-hy2-secret"
	serverCfg := filepath.Join(tmp, "server.yaml")
	clientCfg := filepath.Join(tmp, "client.yaml")
	if err := os.WriteFile(serverCfg, []byte(hysteriaServerConfig(hyServerPort, auth, certFile, keyFile)), 0600); err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("write server config: %w", err))
	}
	serverProc, err := startHysteriaProcess(ctx, "server", serverCfg)
	if err != nil {
		return FromError(name, time.Since(t0), err)
	}
	defer serverProc.stop()
	if err := serverProc.waitHealthy(500 * time.Millisecond); err != nil {
		return FromError(name, time.Since(t0), err)
	}

	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("rendr listen: %w", err))
	}
	defer ln.Close()
	serverReady := make(chan *udprelay.Relay, 1)
	serverErr := make(chan error, 1)
	go func() {
		r, err := udprelay.Serve(ctx, udprelay.ServeConfig{
			Listener:   ln,
			LocalAddr:  "127.0.0.1:0",
			TargetAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(hyServerPort)),
		})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- r
	}()

	paths := make([]rendr.PathSpec, opts.Paths)
	for i := range paths {
		paths[i] = rendr.PathSpec{Transport: "udpflow", Address: ln.Addr().String()}
	}
	clientRelay, err := udprelay.Dial(ctx, udprelay.DialConfig{
		Dialer: &rendr.Dialer{
			Mode:  rendr.ModePrime,
			Paths: paths,
		},
		LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("client relay dial: %w", err))
	}
	defer clientRelay.Close()
	var serverRelay *udprelay.Relay
	select {
	case serverRelay = <-serverReady:
	case err := <-serverErr:
		return FromError(name, time.Since(t0), fmt.Errorf("server relay serve: %w", err))
	case <-ctx.Done():
		return FromError(name, time.Since(t0), ctx.Err())
	case <-time.After(5 * time.Second):
		return FromError(name, time.Since(t0), fmt.Errorf("server relay accept timeout"))
	}
	defer serverRelay.Close()
	if err := waitRelayPaths(clientRelay.PacketConn(), serverRelay.PacketConn(), opts.Paths); err != nil {
		return FromError(name, time.Since(t0), err)
	}

	if err := os.WriteFile(clientCfg, []byte(hysteriaClientConfig(clientRelay.LocalAddr().String(), auth)), 0600); err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("write client config: %w", err))
	}
	admin := clientRelay.PacketConn().(rendr.AdminPacketConn)
	speedLog, err := runHysteriaSpeedtest(ctx, clientCfg, opts.DataSize, opts.Migrations, admin)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("%w; speedtest log: %s; server log: %s", err, speedLog, serverProc.logTail()))
	}
	if got := admin.MigrationCount(); got < uint64(opts.Migrations) {
		return FromError(name, time.Since(t0), fmt.Errorf("migration count=%d want >=%d", got, opts.Migrations))
	}

	elapsed := time.Since(t0)
	return Result{
		Name:     name,
		Duration: elapsed,
		Detail: map[string]any{
			"bytes":           opts.DataSize,
			"paths":           opts.Paths,
			"requested_migs":  opts.Migrations,
			"migration_count": admin.MigrationCount(),
			"elapsed_seconds": elapsed.Seconds(),
		},
	}
}

func hysteriaServerConfig(port int, auth, certFile, keyFile string) string {
	return fmt.Sprintf(`listen: 127.0.0.1:%d
auth:
  type: password
  password: %s
tls:
  cert: %s
  key: %s
quic:
  mtu: 1200
  disablePathMTUDiscovery: true
sniff:
  enable: false
speedTest: true
`, port, auth, certFile, keyFile)
}

func hysteriaClientConfig(serverAddr, auth string) string {
	return fmt.Sprintf(`server: %s
auth: %s
bandwidth:
  up: 20 mbps
  down: 20 mbps
tls:
  insecure: true
quic:
  mtu: 1200
  disablePathMTUDiscovery: true
`, serverAddr, auth)
}

type hysteriaProcess struct {
	cmd  *exec.Cmd
	log  bytes.Buffer
	done chan error
}

func startHysteriaProcess(ctx context.Context, mode, config string) (*hysteriaProcess, error) {
	bin, err := exec.LookPath("hysteria")
	if err != nil {
		return nil, err
	}
	p := &hysteriaProcess{done: make(chan error, 1)}
	cmd := exec.CommandContext(ctx, bin, "--disable-update-check", "--log-level", "info", mode, "-c", config)
	cmd.Stdout = &p.log
	cmd.Stderr = &p.log
	p.cmd = cmd
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start hysteria %s: %w", mode, err)
	}
	go func() { p.done <- cmd.Wait() }()
	return p, nil
}

func (p *hysteriaProcess) waitHealthy(d time.Duration) error {
	select {
	case err := <-p.done:
		return fmt.Errorf("hysteria exited early: %w; log: %s", err, p.logTail())
	case <-time.After(d):
		return nil
	}
}

func (p *hysteriaProcess) stop() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(time.Second):
	}
}

func (p *hysteriaProcess) logTail() string {
	const max = 1024
	s := p.log.String()
	if len(s) > max {
		return s[len(s)-max:]
	}
	return s
}

func writeSelfSignedCert(certFile, keyFile string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		return err
	}
	return os.WriteFile(keyFile, keyPEM, 0600)
}

func runHysteriaSpeedtest(ctx context.Context, config string, dataSize, migrations int, admin rendr.AdminPacketConn) (string, error) {
	bin, err := exec.LookPath("hysteria")
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "--disable-update-check", "--log-level", "info", "speedtest", "-c", config, "--data-size", strconv.Itoa(dataSize), "--use-bytes")
	var log bytes.Buffer
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err := cmd.Start(); err != nil {
		return logTail(log.String()), fmt.Errorf("start hysteria speedtest: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for i := 0; i < migrations; i++ {
		select {
		case err := <-done:
			return logTail(log.String()), fmt.Errorf("hysteria speedtest exited before migration %d/%d: %w", i+1, migrations, err)
		case <-time.After(250 * time.Millisecond):
		}
		if err := migrateRelay(admin); err != nil {
			_ = cmd.Process.Kill()
			return logTail(log.String()), fmt.Errorf("migrate: %w", err)
		}
	}
	err = <-done
	if err != nil {
		return logTail(log.String()), fmt.Errorf("hysteria speedtest: %w", err)
	}
	return logTail(log.String()), nil
}

func logTail(s string) string {
	const max = 1024
	if len(s) > max {
		return s[len(s)-max:]
	}
	return s
}
