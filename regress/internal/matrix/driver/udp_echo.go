package driver

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/FrankoonG/rendr"
)

// UDPEchoOpts configures one packet-mode case.
type UDPEchoOpts struct {
	CaseName string

	// Paths and Factories follow the same pattern as
	// FileXferOpts: built-in transports come from PathSpec, custom
	// ones from registered factories.
	Paths     []rendr.PathSpec
	Factories []NamedFactory

	// AcceptListen tells the runner how to bind the rendr server:
	// "udpflow" calls rendr.ListenUDPFlowPacket; "quic-datagram"
	// calls rendr.ListenQUICDatagram. The choice MUST match the
	// wire shape produced by the chosen Paths (you cannot bind
	// udpflow on the server and expect a quic-datagram path to
	// reach it — that's C3 of the framework contract).
	AcceptListen string // "udpflow" | "quic-datagram"

	// PPS, Duration, PayloadLen, Migrations follow the same
	// semantics as smoke.G3Opts.
	PPS          int
	Duration     time.Duration
	PayloadLen   int
	Migrations   int
	LossPct      float64 // 0 = strict
	P95CeilingMs int
}

// UDPEchoResult mirrors FileXferResult for packet-mode cases.
type UDPEchoResult struct {
	Name           string
	Elapsed        time.Duration
	Sent           int64
	Received       int64
	LossPct        float64
	MigrationsDone uint64
	P50ms, P95ms   float64
	Failure        string
}

// RunUDPEcho runs one packet-mode case end-to-end.
func RunUDPEcho(ctx context.Context, opts UDPEchoOpts) UDPEchoResult {
	if opts.PPS <= 0 {
		opts.PPS = 5000
	}
	if opts.Duration <= 0 {
		opts.Duration = 5 * time.Second
	}
	if opts.PayloadLen <= 0 {
		opts.PayloadLen = 1024
	}
	if opts.Migrations == 0 {
		opts.Migrations = 3
	}
	if opts.P95CeilingMs <= 0 {
		opts.P95CeilingMs = 100
	}
	if opts.LossPct == 0 {
		opts.LossPct = 1.0
	}
	r := UDPEchoResult{Name: opts.CaseName}
	t0 := time.Now()

	var ln rendr.PacketListener
	var err error
	switch opts.AcceptListen {
	case "udpflow", "":
		ln, err = rendr.ListenUDPFlowPacket("127.0.0.1:0")
	case "quic-datagram":
		ln, err = rendr.ListenQUICDatagram("127.0.0.1:0", nil)
	default:
		r.Failure = "unknown AcceptListen: " + opts.AcceptListen
		return r
	}
	if err != nil {
		r.Failure = "listen: " + err.Error()
		return r
	}
	defer ln.Close()
	listenAddr := ln.Addr().String()
	for i := range opts.Paths {
		if opts.Paths[i].Address == "" {
			opts.Paths[i].Address = listenAddr
		}
	}

	srvAccept := make(chan rendr.PacketConn, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(actx)
		if err != nil {
			return
		}
		srvAccept <- c
	}()

	d := &rendr.Dialer{Mode: rendr.ModePrime, Paths: opts.Paths}
	for _, f := range opts.Factories {
		if f.Stream != nil {
			if err := d.AddStreamPathFactory(f.Name, f.Stream); err != nil {
				r.Failure = "AddStreamPathFactory: " + err.Error()
				return r
			}
		}
		if f.Packet != nil {
			if err := d.AddPacketPathFactory(f.Name, f.Packet); err != nil {
				r.Failure = "AddPacketPathFactory: " + err.Error()
				return r
			}
		}
	}

	client, err := d.DialPacket(ctx)
	if err != nil {
		r.Failure = "DialPacket: " + err.Error()
		return r
	}
	defer client.Close()

	var server rendr.PacketConn
	select {
	case server = <-srvAccept:
	case <-time.After(15 * time.Second):
		r.Failure = "server accept timeout"
		return r
	}
	defer server.Close()

	// Server: echo each datagram back verbatim until read deadline.
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buf := make([]byte, opts.PayloadLen+64)
		_ = server.SetReadDeadline(time.Now().Add(opts.Duration + 5*time.Second))
		for {
			n, _, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = server.WriteTo(buf[:n], nil)
		}
	}()

	admin, ok := client.(rendr.AdminPacketConn)
	if !ok {
		r.Failure = "client conn is not rendr.AdminPacketConn"
		return r
	}
	startMig := admin.MigrationCount()

	// Receiver goroutine on the client side: records (seq, latency).
	var rxMu sync.Mutex
	recvSeqs := map[uint64]struct{}{}
	var latencies []time.Duration
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		buf := make([]byte, opts.PayloadLen+64)
		_ = client.SetReadDeadline(time.Now().Add(opts.Duration + 5*time.Second))
		for {
			n, _, err := client.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 16 {
				continue
			}
			seq := binary.BigEndian.Uint64(buf[:8])
			sentNs := int64(binary.BigEndian.Uint64(buf[8:16]))
			lat := time.Duration(time.Now().UnixNano() - sentNs)
			rxMu.Lock()
			recvSeqs[seq] = struct{}{}
			latencies = append(latencies, lat)
			rxMu.Unlock()
		}
	}()

	// Sender + migration scheduler.
	pktInterval := time.Second / time.Duration(opts.PPS)
	migInterval := opts.Duration / time.Duration(opts.Migrations+1)
	migTicker := time.NewTicker(migInterval)
	defer migTicker.Stop()

	pkt := make([]byte, opts.PayloadLen)
	var sent int64
	endAt := time.Now().Add(opts.Duration)
	nextTick := time.Now()
	for time.Now().Before(endAt) {
		select {
		case <-migTicker.C:
			cur := admin.ActivePath()
			for _, p := range client.Paths() {
				if p.ID != cur {
					_ = admin.Migrate(p.ID)
					break
				}
			}
		default:
		}
		now := time.Now()
		if now.Before(nextTick) {
			time.Sleep(nextTick.Sub(now))
		}
		nextTick = nextTick.Add(pktInterval)
		binary.BigEndian.PutUint64(pkt[:8], uint64(sent))
		binary.BigEndian.PutUint64(pkt[8:16], uint64(time.Now().UnixNano()))
		if _, err := client.WriteTo(pkt, nil); err != nil {
			r.Failure = fmt.Sprintf("WriteTo seq %d: %v", sent, err)
			return r
		}
		sent++
	}

	time.Sleep(500 * time.Millisecond)
	_ = client.SetReadDeadline(time.Now())
	_ = server.SetReadDeadline(time.Now())
	<-recvDone
	<-echoDone

	rxMu.Lock()
	received := int64(len(recvSeqs))
	lats := latencies
	rxMu.Unlock()

	r.Elapsed = time.Since(t0)
	r.Sent = sent
	r.Received = received
	r.MigrationsDone = admin.MigrationCount() - startMig
	if sent > 0 {
		r.LossPct = float64(sent-received) / float64(sent) * 100
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	idx := func(p int) time.Duration {
		if len(lats) == 0 {
			return 0
		}
		i := len(lats) * p / 100
		if i >= len(lats) {
			i = len(lats) - 1
		}
		return lats[i]
	}
	r.P50ms = float64(idx(50)) / float64(time.Millisecond)
	r.P95ms = float64(idx(95)) / float64(time.Millisecond)

	if r.LossPct > opts.LossPct {
		r.Failure = fmt.Sprintf("loss %.3f%% exceeds budget %.3f%%", r.LossPct, opts.LossPct)
		return r
	}
	if int(r.P95ms) > opts.P95CeilingMs {
		r.Failure = fmt.Sprintf("P95 %.1fms exceeds ceiling %dms", r.P95ms, opts.P95CeilingMs)
		return r
	}
	if opts.Migrations > 0 && r.MigrationsDone == 0 {
		r.Failure = "expected migrations; none fired"
		return r
	}
	return r
}
