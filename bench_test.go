package rendr

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

// BenchmarkStreamThroughputTCP measures sustained bytes/sec on a
// single-path TCP loopback connection with no migration. It is the
// baseline against which "with-migration" overhead is compared
// (CLAUDE.md hard target G1: <10% regression with migrations).
//
//	go test -bench=BenchmarkStreamThroughputTCP -benchtime=2s
func BenchmarkStreamThroughputTCP(b *testing.B) {
	const chunk = 64 * 1024
	benchStream(b, 1, 0, chunk)
}

// BenchmarkStreamThroughputTCPWithMigration measures the same payload
// throughput with explicit Migrate() calls every migrateEvery bytes.
// Compare with the no-migration baseline to gauge G1 overhead.
//
//	go test -bench=BenchmarkStreamThroughputTCPWithMigration -benchtime=2s
func BenchmarkStreamThroughputTCPWithMigration(b *testing.B) {
	const chunk = 64 * 1024
	// Migrate once per ~512 KiB so a 32 MiB run sees ~64 migrations.
	benchStream(b, 2, 512*1024, chunk)
}

// G3 100k pps long-run benchmark intentionally NOT here:
// QUIC DATAGRAM has no flow-control on loopback, so a one-sender
// one-drainer Go benchmark either runs at sender speed and drops
// frames on the drainer, or runs at drainer speed and starves the
// sender. A proper G3 validation needs a fixed-duration model with
// separate sent/delivered metrics + sender pacing, which doesn't fit
// the testing.B contract. Live in chaos/ on the Linux host instead.

// benchStream drives b.N write/read pairs of `chunk` bytes between
// loopback rendr Conns. nPaths sets how many TCP paths the client
// attaches; migrateEvery==0 disables explicit migration, otherwise
// the client calls Engine.Migrate after every `migrateEvery`
// transferred bytes. b.SetBytes is set to chunk so go test reports
// MB/s; b.ResetTimer skips setup cost from the measurement.
func benchStream(b *testing.B, nPaths int, migrateEvery int, chunk int) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var serverConn Conn
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			b.Errorf("accept: %v", err)
			return
		}
		serverConn = c
	}()

	paths := make([]PathSpec, nPaths)
	for i := range paths {
		paths[i] = PathSpec{Transport: "tcp", Address: ln.Addr().String()}
	}
	client, err := (&Dialer{Mode: ModePrime, Paths: paths}).Dial(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	wg.Wait()
	defer serverConn.Close()

	// Server-side drainer: discard incoming bytes as fast as they
	// arrive so the client's writes are not flow-controlled.
	drainErr := make(chan error, 1)
	go func() {
		buf := make([]byte, chunk)
		var total int64
		want := int64(b.N) * int64(chunk)
		for total < want {
			n, err := serverConn.Read(buf)
			if err != nil {
				drainErr <- err
				return
			}
			total += int64(n)
		}
		drainErr <- nil
	}()

	bc, _ := client.(*engineBackedConn)
	payload := make([]byte, chunk)
	for i := range payload {
		payload[i] = byte(i & 0xFF)
	}

	b.SetBytes(int64(chunk))
	b.ResetTimer()

	var sentSinceMigrate int
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(payload); err != nil {
			b.Fatal(err)
		}
		if migrateEvery > 0 && bc != nil {
			sentSinceMigrate += chunk
			if sentSinceMigrate >= migrateEvery {
				sentSinceMigrate = 0
				cur := bc.Engine().ActivePath()
				for _, p := range bc.Paths() {
					if p.ID != cur {
						_ = bc.Engine().Migrate(p.ID)
						break
					}
				}
			}
		}
	}

	b.StopTimer()
	if err := <-drainErr; err != nil && err != io.EOF {
		b.Fatalf("drainer: %v", err)
	}
}
