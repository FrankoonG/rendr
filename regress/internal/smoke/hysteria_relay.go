package smoke

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/udprelay"
)

const (
	hysteriaProcessJoinTimeout = 3 * time.Second
	hysteriaProcessWaitDelay   = time.Second
	hysteriaMustStopEvidence   = "chaos_teardown_unsafe"
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
func RunHysteriaRelay(ctx context.Context, opts HysteriaRelayOpts) (result Result) {
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
	defer func() {
		applyHysteriaProcessError(&result, name, t0, serverProc.stop(hysteriaProcessJoinTimeout))
		if result.Failure != "" {
			if serverLog := serverProc.logTail(); serverLog != "" {
				result.Failure += "; server log: " + serverLog
			}
		}
	}()
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
		result = FromError(name, time.Since(t0), fmt.Errorf("%w; speedtest log: %s", err, speedLog))
		applyHysteriaMustStop(&result, err)
		return result
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
	role        string
	cmd         *exec.Cmd
	log         bytes.Buffer
	done        chan struct{}
	waitErr     error
	containment *hysteriaProcessContainment
}

type hysteriaProcessContainment struct {
	kill    func() error
	confirm func(time.Duration) error
}

// hysteriaProcessJoinError means a killed child could not be reaped within
// the teardown bound. Continuing the tier in this process is unsafe.
type hysteriaProcessJoinError struct {
	Role    string
	Timeout time.Duration
}

func (e *hysteriaProcessJoinError) Error() string {
	return fmt.Sprintf("%s process did not join within %s after kill", e.Role, e.Timeout)
}

func (e *hysteriaProcessJoinError) MustStop() bool { return true }

// hysteriaProcessTeardownError means Wait returned but the platform could not
// prove that the contained process tree was gone.
type hysteriaProcessTeardownError struct {
	Role    string
	Timeout time.Duration
	Cause   error
}

func (e *hysteriaProcessTeardownError) Error() string {
	return fmt.Sprintf("%s process teardown was not confirmed within %s: %v", e.Role, e.Timeout, e.Cause)
}

func (e *hysteriaProcessTeardownError) Unwrap() error { return e.Cause }

func (e *hysteriaProcessTeardownError) MustStop() bool { return true }

func startHysteriaProcess(ctx context.Context, mode, config string) (*hysteriaProcess, error) {
	bin, err := exec.LookPath("hysteria")
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, "--disable-update-check", "--log-level", "info", mode, "-c", config)
	return startHysteriaCommand(cmd, "hysteria "+mode)
}

func startHysteriaCommand(cmd *exec.Cmd, role string) (*hysteriaProcess, error) {
	if cmd == nil {
		return nil, fmt.Errorf("start %s: command is nil", role)
	}
	containment, err := configureHysteriaProcessContainment(cmd)
	if err != nil {
		return nil, fmt.Errorf("contain %s: %w", role, err)
	}
	p := &hysteriaProcess{
		role:        role,
		cmd:         cmd,
		done:        make(chan struct{}),
		containment: containment,
	}
	cmd.WaitDelay = hysteriaProcessWaitDelay
	cmd.Stdout = &p.log
	cmd.Stderr = &p.log
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", role, err)
	}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

func (p *hysteriaProcess) waitHealthy(d time.Duration) error {
	select {
	case <-p.done:
		if p.waitErr == nil {
			return fmt.Errorf("hysteria exited early; log: %s", p.logTail())
		}
		return fmt.Errorf("hysteria exited early: %w; log: %s", p.waitErr, p.logTail())
	case <-time.After(d):
		return nil
	}
}

func (p *hysteriaProcess) stop(joinTimeout time.Duration) error {
	if p == nil {
		return nil
	}
	if joinTimeout <= 0 {
		joinTimeout = hysteriaProcessJoinTimeout
	}
	deadline := time.Now().Add(joinTimeout)
	var killErr error
	if p.containment == nil || p.containment.kill == nil {
		killErr = fmt.Errorf("%s process has no containment kill function", p.role)
	} else if err := p.containment.kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		killErr = fmt.Errorf("kill %s process: %w", p.role, err)
	}
	if !p.joined() {
		remaining := time.Until(deadline)
		if remaining <= 0 || !waitHysteriaProcess(p.done, remaining) {
			return errors.Join(killErr, &hysteriaProcessJoinError{Role: p.role, Timeout: joinTimeout})
		}
	}

	remaining := time.Until(deadline)
	if p.containment == nil || p.containment.confirm == nil {
		cause := fmt.Errorf("%s process has no containment verification function", p.role)
		return errors.Join(killErr, &hysteriaProcessTeardownError{Role: p.role, Timeout: joinTimeout, Cause: cause})
	}
	if err := p.containment.confirm(remaining); err != nil {
		return errors.Join(killErr, &hysteriaProcessTeardownError{Role: p.role, Timeout: joinTimeout, Cause: err})
	}
	return killErr
}

func waitHysteriaProcess(done <-chan struct{}, limit time.Duration) bool {
	if limit <= 0 {
		return false
	}
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func (p *hysteriaProcess) joined() bool {
	if p == nil || p.done == nil {
		return true
	}
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *hysteriaProcess) logTail() string {
	if p == nil || !p.joined() {
		return ""
	}
	const max = 1024
	s := p.log.String()
	if len(s) > max {
		return s[len(s)-max:]
	}
	return s
}

func applyHysteriaProcessError(result *Result, name string, started time.Time, err error) {
	if result == nil || err == nil {
		return
	}
	result.Name = name
	result.Duration = time.Since(started)
	if result.Detail == nil {
		result.Detail = make(map[string]any)
	}
	if applyHysteriaMustStop(result, err) {
		return
	}
	if result.Failure == "" {
		result.Failure = err.Error()
	} else {
		result.Failure += "; " + err.Error()
	}
}

func applyHysteriaMustStop(result *Result, err error) bool {
	if result == nil || err == nil {
		return false
	}
	var mustStop interface {
		error
		MustStop() bool
	}
	if errors.As(err, &mustStop) && mustStop.MustStop() {
		reason := result.Failure
		if reason == "" {
			reason = err.Error()
		} else if !strings.Contains(reason, err.Error()) {
			reason += "; " + err.Error()
		}
		if result.InvalidReason != "" {
			reason = result.InvalidReason + "; " + reason
		}
		result.Failure = ""
		result.InvalidReason = reason
		if result.Detail == nil {
			result.Detail = make(map[string]any)
		}
		result.Detail[hysteriaMustStopEvidence] = err.Error()
		return true
	}
	return false
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
	p, err := startHysteriaCommand(cmd, "hysteria speedtest")
	if err != nil {
		return "", err
	}
	return runHysteriaSpeedtestProcess(cctx, p, migrations, func() error {
		return migrateRelay(admin)
	}, 250*time.Millisecond, hysteriaProcessJoinTimeout)
}

func runHysteriaSpeedtestProcess(
	ctx context.Context,
	p *hysteriaProcess,
	migrations int,
	migrate func() error,
	migrationInterval time.Duration,
	joinTimeout time.Duration,
) (string, error) {
	if p == nil {
		return "", fmt.Errorf("hysteria speedtest process is nil")
	}
	if migrate == nil && migrations > 0 {
		stopErr := p.stop(joinTimeout)
		return p.logTail(), errors.Join(fmt.Errorf("hysteria speedtest migrate function is nil"), stopErr)
	}
	if migrationInterval <= 0 {
		migrationInterval = 250 * time.Millisecond
	}
	for i := 0; i < migrations; i++ {
		timer := time.NewTimer(migrationInterval)
		select {
		case <-p.done:
			timer.Stop()
			waitErr := p.waitErr
			stopErr := p.stop(joinTimeout)
			return p.logTail(), errors.Join(earlyHysteriaExitError(waitErr, i+1, migrations), stopErr)
		case <-ctx.Done():
			timer.Stop()
			stopErr := p.stop(joinTimeout)
			return p.logTail(), errors.Join(fmt.Errorf("hysteria speedtest canceled: %w", ctx.Err()), stopErr)
		case <-timer.C:
		}
		if err := migrate(); err != nil {
			stopErr := p.stop(joinTimeout)
			return p.logTail(), errors.Join(fmt.Errorf("migrate: %w", err), stopErr)
		}
	}

	select {
	case <-p.done:
		waitErr := p.waitErr
		stopErr := p.stop(joinTimeout)
		if waitErr != nil {
			return p.logTail(), errors.Join(fmt.Errorf("hysteria speedtest: %w", waitErr), stopErr)
		}
		return p.logTail(), stopErr
	case <-ctx.Done():
		stopErr := p.stop(joinTimeout)
		return p.logTail(), errors.Join(fmt.Errorf("hysteria speedtest canceled: %w", ctx.Err()), stopErr)
	}
}

func earlyHysteriaExitError(waitErr error, migration, migrations int) error {
	if waitErr == nil {
		return fmt.Errorf("hysteria speedtest exited before migration %d/%d", migration, migrations)
	}
	return fmt.Errorf("hysteria speedtest exited before migration %d/%d: %w", migration, migrations, waitErr)
}
