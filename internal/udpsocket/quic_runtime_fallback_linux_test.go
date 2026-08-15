//go:build linux

package udpsocket

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/FrankoonG/quic-go"
	"golang.org/x/sys/unix"
)

const runtimeFallbackPayloadBytes = 8 << 20

func TestQUICRuntimeGSOFailureRetriesWithoutConnectionLoss(t *testing.T) {
	serverTLS, clientTLS := runtimeFallbackTLS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	serverSocket := runtimeFallbackSocket(t)
	serverTransport := &quic.Transport{Conn: serverSocket.PacketConn()}
	t.Cleanup(func() { _ = serverTransport.Close() })
	listener, err := serverTransport.Listen(serverTLS, runtimeFallbackQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	clientSocket := runtimeFallbackSocket(t)
	realWrite := clientSocket.writeMsg
	var injected atomic.Bool
	clientSocket.writeMsg = func(payload, oob []byte, address *net.UDPAddr) (int, int, error) {
		segmentSize, _, found, stripErr := stripUDPSegment(oob)
		if stripErr != nil {
			return 0, 0, stripErr
		}
		if found && len(payload) > segmentSize && injected.CompareAndSwap(false, true) {
			return 0, 0, os.NewSyscallError("sendmsg", unix.EIO)
		}
		return realWrite(payload, oob, address)
	}
	clientTransport := &quic.Transport{Conn: clientSocket.PacketConn()}
	t.Cleanup(func() { _ = clientTransport.Close() })

	payload := make([]byte, runtimeFallbackPayloadBytes)
	for index := range payload {
		payload[index] = byte(index*37 + index/251)
	}
	wantDigest := sha256.Sum256(payload)
	type receiveResult struct {
		connection *quic.Conn
		bytes      int64
		digest     [sha256.Size]byte
		err        error
	}
	received := make(chan receiveResult, 1)
	go func() {
		connection, acceptErr := listener.Accept(ctx)
		if acceptErr != nil {
			received <- receiveResult{err: acceptErr}
			return
		}
		stream, acceptErr := connection.AcceptStream(ctx)
		if acceptErr != nil {
			received <- receiveResult{connection: connection, err: acceptErr}
			return
		}
		_ = stream.SetDeadline(time.Now().Add(15 * time.Second))
		hash := sha256.New()
		count, copyErr := io.CopyN(hash, stream, runtimeFallbackPayloadBytes)
		if copyErr == nil {
			var trailing [1]byte
			trailingBytes, trailingErr := stream.Read(trailing[:])
			if trailingBytes != 0 || !errors.Is(trailingErr, io.EOF) {
				copyErr = errors.New("QUIC stream did not end exactly after the qualified payload")
			}
		}
		var digest [sha256.Size]byte
		copy(digest[:], hash.Sum(nil))
		if copyErr == nil {
			_, copyErr = stream.Write(digest[:])
		}
		if closeErr := stream.Close(); copyErr == nil {
			copyErr = closeErr
		}
		received <- receiveResult{connection: connection, bytes: count, digest: digest, err: copyErr}
	}()

	clientConnection, err := clientTransport.Dial(
		ctx, serverSocket.LocalAddr(), clientTLS, runtimeFallbackQUICConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := clientConnection.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(15 * time.Second))
	if written, err := io.Copy(stream, bytes.NewReader(payload)); err != nil || written != int64(len(payload)) {
		t.Fatalf("QUIC payload write=%d/%d err=%v", written, len(payload), err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	var echoedDigest [sha256.Size]byte
	if _, err := io.ReadFull(stream, echoedDigest[:]); err != nil {
		t.Fatal(err)
	}

	var serverResult receiveResult
	select {
	case serverResult = <-received:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	if serverResult.bytes != int64(len(payload)) || serverResult.digest != wantDigest || echoedDigest != wantDigest {
		t.Fatalf(
			"QUIC runtime fallback bytes=%d/%d server_digest=%x echoed_digest=%x want=%x",
			serverResult.bytes, len(payload), serverResult.digest, echoedDigest, wantDigest,
		)
	}
	if !injected.Load() {
		t.Fatal("quic-go never attempted a multi-segment UDP_SEGMENT send")
	}
	status := clientSocket.DatagramAccelerationStatus()
	exactlyOneFailedGSOAttempt := status.GSOAttempts > status.GSOSuperPackets &&
		status.GSOAttempts-status.GSOSuperPackets == 1
	validSuccessfulGSOSegments := status.GSOSuperPackets == 0 && status.GSOSegments == 0 ||
		status.GSOSuperPackets > 0 && status.GSOSegments/status.GSOSuperPackets >= 2
	if status.Mode != "ordinary_fallback" || status.Cause != causePathUnsupported ||
		!exactlyOneFailedGSOAttempt || !validSuccessfulGSOSegments ||
		status.OrdinaryDatagrams == 0 || status.FallbackTransitions != 1 {
		t.Fatalf("runtime fallback status=%+v", status)
	}
	if err := clientConnection.CloseWithError(0, "runtime fallback test complete"); err != nil {
		t.Fatal(err)
	}
	if serverResult.connection != nil {
		_ = serverResult.connection.CloseWithError(0, "runtime fallback test complete")
	}
}

func runtimeFallbackSocket(t testing.TB) *Socket {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	socket := newSocket(conn, policy{treatment: treatmentGSO, cause: causeProbeConfirmed}, DefaultBufferBytes)
	t.Cleanup(func() { _ = socket.Close() })
	return socket
}

func runtimeFallbackQUICConfig() *quic.Config {
	return &quic.Config{MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: time.Second}
}

func runtimeFallbackTLS(t testing.TB) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rendr-udp-gso-test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	const protocol = "rendr-udp-gso-runtime-fallback"
	server := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificateDER}, PrivateKey: privateKey}},
		NextProtos:   []string{protocol}, MinVersion: tls.VersionTLS13,
	}
	client := &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{protocol}, MinVersion: tls.VersionTLS13,
	}
	return server, client
}
