package smoke

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/udprelay"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// WireGuardRelayOpts configures the M11 real WireGuard-over-udprelay smoke.
type WireGuardRelayOpts struct {
	Messages    int
	MessageSize int
	Paths       int
	Migrations  int
}

func (o *WireGuardRelayOpts) withDefaults() {
	if o.Messages <= 0 {
		o.Messages = 64
	}
	if o.MessageSize <= 0 {
		o.MessageSize = 256
	}
	if o.Paths <= 0 {
		o.Paths = 2
	}
	if o.Migrations <= 0 {
		o.Migrations = 2
	}
	if o.Migrations > o.Messages {
		o.Migrations = o.Messages
	}
}

// RunWireGuardRelay runs a real wireguard-go userspace tunnel over rendr's
// UDP relay endpoint, then migrates the rendr packet carrier underneath an
// active tunnel TCP echo stream.
func RunWireGuardRelay(ctx context.Context, opts WireGuardRelayOpts) Result {
	opts.withDefaults()
	t0 := time.Now()
	name := fmt.Sprintf("WireGuard-over-UDP-relay (%d messages, %d paths, %d migrations)", opts.Messages, opts.Paths, opts.Migrations)

	clientIP := netip.MustParseAddr("10.77.0.1")
	serverIP := netip.MustParseAddr("10.77.0.2")
	clientPort, err := reserveUDPPort()
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("reserve client wireguard port: %w", err))
	}
	serverPort, err := reserveUDPPort()
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("reserve server wireguard port: %w", err))
	}

	clientPriv, clientPub, err := wgKeypair()
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("client keypair: %w", err))
	}
	serverPriv, serverPub, err := wgKeypair()
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("server keypair: %w", err))
	}

	serverTUN, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("server netstack: %w", err))
	}
	serverDev := device.NewDevice(serverTUN, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg-server: "))
	defer serverDev.Close()
	if err := serverDev.IpcSet(wgConfig(serverPriv, clientPub, serverPort, "", clientIP)); err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("server wg config: %w", err))
	}
	if err := serverDev.Up(); err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("server wg up: %w", err))
	}

	echoLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: net.IP(serverIP.AsSlice()), Port: 8097})
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("server tunnel listen: %w", err))
	}
	defer echoLn.Close()
	go serveWireGuardTCPEcho(echoLn)

	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("rendr listen: %w", err))
	}
	defer ln.Close()
	serverRelay, err := udprelay.Listen(ctx, udprelay.ServeConfig{
		Listener:   ln,
		LocalAddr:  "127.0.0.1:0",
		TargetAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)),
	})
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("server relay listen: %w", err))
	}
	defer serverRelay.Close()

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
	if err := waitServerRelay(clientRelay.PacketConn(), serverRelay, opts.Paths); err != nil {
		return FromError(name, time.Since(t0), err)
	}

	clientTUN, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("client netstack: %w", err))
	}
	clientDev := device.NewDevice(clientTUN, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg-client: "))
	defer clientDev.Close()
	if err := clientDev.IpcSet(wgConfig(clientPriv, serverPub, clientPort, clientRelay.LocalAddr().String(), serverIP)); err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("client wg config: %w", err))
	}
	if err := clientDev.Up(); err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("client wg up: %w", err))
	}

	tcpConn, err := dialWireGuardTCP(ctx, func(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
		return clientNet.DialContextTCP(ctx, addr)
	}, serverIP, 8097)
	if err != nil {
		return FromError(name, time.Since(t0), err)
	}
	defer tcpConn.Close()

	admin := clientRelay.PacketConn().(rendr.AdminPacketConn)
	migrateAt := migrationPoints(opts.Messages, opts.Migrations)
	payload := make([]byte, opts.MessageSize)
	reply := make([]byte, opts.MessageSize)
	for i := 0; i < opts.Messages; i++ {
		fillWireGuardPayload(payload, i)
		if err := tcpConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return FromError(name, time.Since(t0), fmt.Errorf("set tcp deadline: %w", err))
		}
		if err := writeFull(tcpConn, payload); err != nil {
			return FromError(name, time.Since(t0), fmt.Errorf("message %d write: %w", i, err))
		}
		if _, err := io.ReadFull(tcpConn, reply); err != nil {
			return FromError(name, time.Since(t0), fmt.Errorf("message %d read: %w", i, err))
		}
		if !bytes.Equal(reply, payload) {
			return FromError(name, time.Since(t0), fmt.Errorf("message %d echo mismatch", i))
		}
		if _, ok := migrateAt[i]; ok {
			if err := migrateRelay(admin); err != nil {
				return FromError(name, time.Since(t0), fmt.Errorf("migrate: %w", err))
			}
		}
	}
	if got := admin.MigrationCount(); got < uint64(opts.Migrations) {
		return FromError(name, time.Since(t0), fmt.Errorf("migration count=%d want >=%d", got, opts.Migrations))
	}

	elapsed := time.Since(t0)
	return Result{
		Name:     name,
		Duration: elapsed,
		Detail: map[string]any{
			"messages":        opts.Messages,
			"bytes":           opts.Messages * opts.MessageSize,
			"paths":           opts.Paths,
			"requested_migs":  opts.Migrations,
			"migration_count": admin.MigrationCount(),
			"elapsed_seconds": elapsed.Seconds(),
		},
	}
}

func wgConfig(privateKey, peerPublic []byte, listenPort int, endpoint string, allowedIP netip.Addr) string {
	lines := []string{
		"private_key", hex.EncodeToString(privateKey),
		"listen_port", strconv.Itoa(listenPort),
		"replace_peers", "true",
		"public_key", hex.EncodeToString(peerPublic),
		"protocol_version", "1",
	}
	if endpoint != "" {
		lines = append(lines,
			"endpoint", endpoint,
			"persistent_keepalive_interval", "1",
		)
	}
	lines = append(lines,
		"replace_allowed_ips", "true",
		"allowed_ip", allowedIP.String()+"/32",
	)
	return uapiCfg(lines...)
}

func wgKeypair() ([]byte, []byte, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, nil, err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return priv[:], pub, nil
}

func uapiCfg(cfg ...string) string {
	var b bytes.Buffer
	for i, s := range cfg {
		b.WriteString(s)
		if i%2 == 0 {
			b.WriteByte('=')
		} else {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func reserveUDPPort() (int, error) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)
	return addr.Port, nil
}

func serveWireGuardTCPEcho(ln interface {
	Accept() (net.Conn, error)
}) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			buf := make([]byte, 64<<10)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					if werr := writeFull(c, buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}
}

func dialWireGuardTCP(ctx context.Context, dial func(context.Context, *net.TCPAddr) (net.Conn, error), addr netip.Addr, port int) (net.Conn, error) {
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		dialCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		c, err := dial(dialCtx, &net.TCPAddr{IP: net.IP(addr.AsSlice()), Port: port})
		cancel()
		if err == nil {
			return c, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("wireguard tunnel tcp dial timeout: %w", lastErr)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func fillWireGuardPayload(buf []byte, seq int) {
	prefix := []byte(fmt.Sprintf("wireguard-relay-%04d:", seq))
	copy(buf, prefix)
	for i := len(prefix); i < len(buf); i++ {
		buf[i] = byte(seq + i)
	}
}
