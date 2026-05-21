package smoke

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/udprelay"
)

// UDPRelayOpts configures the M11 self-managed UDP relay smoke.
type UDPRelayOpts struct {
	Packets    int
	Paths      int
	Migrations int
	Server     bool
}

func (o *UDPRelayOpts) withDefaults() {
	if o.Packets <= 0 {
		o.Packets = 128
	}
	if o.Paths <= 0 {
		o.Paths = 2
	}
	if o.Migrations <= 0 {
		o.Migrations = 1
	}
	if o.Migrations > o.Packets {
		o.Migrations = o.Packets
	}
}

// RunUDPRelay verifies that a UDP application talking to a local
// udprelay endpoint survives a rendr PacketConn migration underneath.
func RunUDPRelay(ctx context.Context, opts UDPRelayOpts) Result {
	opts.withDefaults()
	t0 := time.Now()
	name := fmt.Sprintf("UDP-relay-smoke (%d packets, %d paths, %d migrations)", opts.Packets, opts.Paths, opts.Migrations)
	if opts.Server {
		name += " via Listen"
	}

	echo, echoAddr, err := startUDPEcho()
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("echo listen: %w", err))
	}
	defer echo.Close()

	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("rendr listen: %w", err))
	}
	defer ln.Close()

	var server *udprelay.Server
	var serverReady chan *udprelay.Relay
	var serverErr chan error
	if opts.Server {
		server, err = udprelay.Listen(ctx, udprelay.ServeConfig{
			Listener:   ln,
			LocalAddr:  "127.0.0.1:0",
			TargetAddr: echoAddr.String(),
		})
		if err != nil {
			return FromError(name, time.Since(t0), fmt.Errorf("relay listen: %w", err))
		}
		defer server.Close()
	} else {
		serverReady = make(chan *udprelay.Relay, 1)
		serverErr = make(chan error, 1)
		go func() {
			r, err := udprelay.Serve(ctx, udprelay.ServeConfig{
				Listener:   ln,
				LocalAddr:  "127.0.0.1:0",
				TargetAddr: echoAddr.String(),
			})
			if err != nil {
				serverErr <- err
				return
			}
			serverReady <- r
		}()
	}

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
		return FromError(name, time.Since(t0), fmt.Errorf("relay dial: %w", err))
	}
	defer clientRelay.Close()

	if opts.Server {
		if err := waitServerRelay(clientRelay.PacketConn(), server, opts.Paths); err != nil {
			return FromError(name, time.Since(t0), err)
		}
	} else {
		var serverRelay *udprelay.Relay
		select {
		case serverRelay = <-serverReady:
		case err := <-serverErr:
			return FromError(name, time.Since(t0), fmt.Errorf("relay serve: %w", err))
		case <-ctx.Done():
			return FromError(name, time.Since(t0), ctx.Err())
		case <-time.After(5 * time.Second):
			return FromError(name, time.Since(t0), fmt.Errorf("server relay accept timeout"))
		}
		defer serverRelay.Close()

		if err := waitRelayPaths(clientRelay.PacketConn(), serverRelay.PacketConn(), opts.Paths); err != nil {
			return FromError(name, time.Since(t0), err)
		}
	}

	app, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("app listen: %w", err))
	}
	defer app.Close()

	admin := clientRelay.PacketConn().(rendr.AdminPacketConn)
	migrateAt := migrationPoints(opts.Packets, opts.Migrations)
	for i := 0; i < opts.Packets; i++ {
		payload := []byte(fmt.Sprintf("udp-relay-packet-%04d", i))
		if err := relayRoundTrip(app, clientRelay.LocalAddr(), payload); err != nil {
			return FromError(name, time.Since(t0), fmt.Errorf("packet %d: %w", i, err))
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
			"packets":         opts.Packets,
			"paths":           opts.Paths,
			"requested_migs":  opts.Migrations,
			"server":          opts.Server,
			"migration_count": admin.MigrationCount(),
			"elapsed_seconds": elapsed.Seconds(),
			"packets_per_sec": float64(opts.Packets) / elapsed.Seconds(),
		},
	}
}

func migrationPoints(packets, migrations int) map[int]struct{} {
	points := make(map[int]struct{}, migrations)
	for i := 1; i <= migrations; i++ {
		at := (packets * i) / (migrations + 1)
		if at >= packets {
			at = packets - 1
		}
		if at < 0 {
			at = 0
		}
		points[at] = struct{}{}
	}
	return points
}

func startUDPEcho() (net.PacketConn, net.Addr, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc, pc.LocalAddr(), nil
}

func waitRelayPaths(client, server rendr.PacketConn, want int) error {
	ca := client.(rendr.AdminPacketConn)
	sa := server.(rendr.AdminPacketConn)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(ca.Paths()) >= want && len(sa.Paths()) >= want {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("paths did not attach: client=%d server=%d want=%d", len(ca.Paths()), len(sa.Paths()), want)
}

func waitServerRelay(client rendr.PacketConn, server *udprelay.Server, wantPaths int) error {
	ca := client.(rendr.AdminPacketConn)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(ca.Paths()) >= wantPaths && server.Relays() >= 1 {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("server relays=%d client paths=%d want relays>=1 paths>=%d", server.Relays(), len(ca.Paths()), wantPaths)
}

func relayRoundTrip(app net.PacketConn, relayAddr net.Addr, payload []byte) error {
	if _, err := app.WriteTo(payload, relayAddr); err != nil {
		return err
	}
	if err := app.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	buf := make([]byte, len(payload)+16)
	n, _, err := app.ReadFrom(buf)
	if err != nil {
		return err
	}
	if !bytes.Equal(buf[:n], payload) {
		return fmt.Errorf("echo mismatch: got %q want %q", buf[:n], payload)
	}
	return nil
}

func migrateRelay(admin rendr.AdminPacketConn) error {
	cur := admin.ActivePath()
	for _, p := range admin.Paths() {
		if p.ID != cur {
			return admin.Migrate(p.ID)
		}
	}
	return fmt.Errorf("no alternate path from active=%d", cur)
}
