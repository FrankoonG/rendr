// Package driver implements docs/regression-suite.md §7.3 file-
// transfer case: fixed-content payload travels from a rendr-server's
// HTTP backend to a rendr-client over rendr.Conn, with forced
// migrations at configurable byte offsets, and the receive-side
// SHA-256 must match the source-side SHA-256. Used by both the
// xray-backed T3 matrix and (eventually) the bare-transport T3a
// regression points.
package driver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr"
)

// FixtureSize is the per-case payload size. 30 MiB is enough to make
// forced migrations land mid-stream on loopback (the smaller G1-smoke
// uses 30 MiB too); T4 long-run cases bump this to 100 MiB or more.
const FixtureSize = 30 << 20

// FileXferOpts configures one case.
type FileXferOpts struct {
	// Paths is the rendr-client side path config. At least one path
	// is required; for migration to fire >= 2 are needed.
	Paths []rendr.PathSpec

	// Factories is registered onto the Dialer before Dial. Both
	// stream and packet factories live here; matrix cases that
	// want a custom path source (e.g. an xray-out factory) populate
	// the slice with NamedFactory entries.
	Factories []NamedFactory

	// ListenAddr is the bare-TCP address the rendr-server binds to.
	// Defaults to "127.0.0.1:0" (ephemeral).
	ListenAddr string

	// MigrationFractions: fractions of FixtureSize at which Migrate
	// should fire. Default {0.3, 0.5, 0.7}. Set empty to disable.
	MigrationFractions []float64

	// CaseName is for reports (e.g. "stream.D-1×D-1").
	CaseName string
}

// NamedFactory packages a factory + name for registration. Exactly
// one of Stream or Packet is non-nil per entry.
type NamedFactory struct {
	Name    string
	Stream  rendr.StreamPathFactory
	Packet  rendr.PacketPathFactory
}

// FileXferResult captures the per-case judgment.
type FileXferResult struct {
	Name            string
	Elapsed         time.Duration
	SHA256Match     bool
	BytesReceived   int64
	MigrationsDone  uint64
	MigrationsAsked int
	Failure         string
}

// RunFileXfer executes one case end-to-end.
//
// Setup:
//   1. rendr.ListenTCP on ListenAddr; the accepted Conn becomes the
//      HTTP server side. http.Serve runs on a net.Listener adapter
//      that hands back the single accepted Conn.
//   2. Generate FixtureSize bytes of deterministic payload; SHA-256
//      it both ends.
//   3. rendr.Dialer with Paths + Factories. dial -> rendr.Conn.
//   4. Wrap the client-side rendr.Conn as the sole transport for an
//      http.Client; GET / on the server.
//   5. While reading the response body, count bytes; at each
//      MigrationFraction * FixtureSize, call AdminConn.Migrate to
//      switch to a different path.
//   6. Compare SHA-256 of received bytes against source.
func RunFileXfer(ctx context.Context, opts FileXferOpts) FileXferResult {
	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1:0"
	}
	if opts.MigrationFractions == nil {
		opts.MigrationFractions = []float64{0.3, 0.5, 0.7}
	}
	r := FileXferResult{Name: opts.CaseName, MigrationsAsked: len(opts.MigrationFractions)}

	payload := make([]byte, FixtureSize)
	for i := range payload {
		payload[i] = byte((i*13 + 7) & 0xFF)
	}
	wantHash := sha256.Sum256(payload)

	ln, err := rendr.ListenTCP(opts.ListenAddr)
	if err != nil {
		r.Failure = fmt.Sprintf("listen: %v", err)
		return r
	}
	defer ln.Close()
	listenAddr := ln.Addr().String()

	// Override the address in any path that wants "the rendr server"
	// — bare paths point at the listenAddr; xray-out factory paths
	// already encode an xray-server-mediated dial that ends at this
	// addr. For the simplest "rendr+factory" case both kinds use
	// listenAddr directly.
	for i := range opts.Paths {
		if opts.Paths[i].Address == "" {
			opts.Paths[i].Address = listenAddr
		}
	}

	srvAccept := make(chan rendr.Conn, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c, err := ln.Accept(actx)
		if err != nil {
			return
		}
		srvAccept <- c
	}()

	d := &rendr.Dialer{
		Mode:  rendr.ModePrime,
		Paths: opts.Paths,
	}
	for _, f := range opts.Factories {
		if f.Stream != nil {
			if err := d.AddStreamPathFactory(f.Name, f.Stream); err != nil {
				r.Failure = fmt.Sprintf("AddStreamPathFactory %q: %v", f.Name, err)
				return r
			}
		}
		if f.Packet != nil {
			if err := d.AddPacketPathFactory(f.Name, f.Packet); err != nil {
				r.Failure = fmt.Sprintf("AddPacketPathFactory %q: %v", f.Name, err)
				return r
			}
		}
	}

	t0 := time.Now()
	client, err := d.Dial(ctx)
	if err != nil {
		r.Failure = fmt.Sprintf("dial: %v", err)
		return r
	}
	defer client.Close()

	var server rendr.Conn
	select {
	case server = <-srvAccept:
	case <-time.After(15 * time.Second):
		r.Failure = "server accept timeout"
		return r
	}
	defer server.Close()

	// HTTP server on the accepted rendr.Conn (single connection).
	httpDone := make(chan error, 1)
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
			_, _ = w.Write(payload)
		})
		srv := &http.Server{Handler: mux}
		ln := &singleConnListener{c: server}
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, errSingleExhausted) {
			httpDone <- err
			return
		}
		httpDone <- nil
	}()

	// HTTP client over rendr.Conn — single connection, no keep-alive.
	transport := &http.Transport{
		DialContext:           func(ctx context.Context, _, _ string) (net.Conn, error) { return client, nil },
		MaxIdleConns:          1,
		MaxConnsPerHost:       1,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 15 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
	}
	hc := &http.Client{Transport: transport, Timeout: 90 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://rendr-server/", nil)
	if err != nil {
		r.Failure = fmt.Sprintf("new request: %v", err)
		return r
	}
	resp, err := hc.Do(req)
	if err != nil {
		r.Failure = fmt.Sprintf("http do: %v", err)
		return r
	}
	defer resp.Body.Close()

	admin, ok := client.(rendr.AdminConn)
	if !ok {
		r.Failure = "client conn is not rendr.AdminConn"
		return r
	}
	startMig := admin.MigrationCount()

	// Read response with migration trigger points.
	migTriggers := make([]int64, len(opts.MigrationFractions))
	for i, frac := range opts.MigrationFractions {
		migTriggers[i] = int64(float64(FixtureSize) * frac)
	}

	hash := sha256.New()
	buf := make([]byte, 256*1024)
	var received int64
	var nextMig int
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			hash.Write(buf[:n])
			atomic.AddInt64(&received, int64(n))
			for nextMig < len(migTriggers) && received >= migTriggers[nextMig] {
				triggerMigration(admin, client)
				nextMig++
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			r.Failure = fmt.Sprintf("read body at %d/%d: %v", received, FixtureSize, err)
			return r
		}
	}

	r.Elapsed = time.Since(t0)
	r.BytesReceived = received
	r.MigrationsDone = admin.MigrationCount() - startMig
	gotHash := hash.Sum(nil)
	r.SHA256Match = bytes.Equal(gotHash, wantHash[:])

	if !r.SHA256Match {
		r.Failure = fmt.Sprintf("sha256 mismatch: got %x want %x", gotHash, wantHash[:])
		return r
	}
	if received != FixtureSize {
		r.Failure = fmt.Sprintf("byte count mismatch: got %d want %d", received, FixtureSize)
		return r
	}
	if len(opts.MigrationFractions) > 0 && r.MigrationsDone == 0 {
		r.Failure = "expected at least one migration; MigrationCount unchanged"
		return r
	}

	// Drain server-side http.Serve goroutine. Closing client.body
	// triggers EOF on the server side, but only after all body bytes
	// are written. http.Serve returns once the conn closes.
	_ = server.Close()
	select {
	case <-httpDone:
	case <-time.After(5 * time.Second):
	}

	return r
}

func triggerMigration(admin rendr.AdminConn, client rendr.Conn) {
	cur := admin.ActivePath()
	for _, p := range client.Paths() {
		if p.ID != cur {
			_ = admin.Migrate(p.ID)
			return
		}
	}
}

// singleConnListener satisfies net.Listener but only ever yields a
// single pre-supplied net.Conn. Used to drive http.Serve on a
// rendr.Conn without standing up a real listener loop.
type singleConnListener struct {
	c    net.Conn
	done atomic.Bool
}

var errSingleExhausted = errors.New("driver: singleConnListener exhausted")

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done.CompareAndSwap(false, true) {
		return l.c, nil
	}
	return nil, errSingleExhausted
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.c.LocalAddr() }
