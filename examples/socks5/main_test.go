package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
)

func TestSOCKS5OverRendr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()

	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	rawRendrLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rendrLn, err := serverRuntime.Listen(rendr.ListenConfig{Streams: []rendr.StreamSource{{
		Name:     "tcp",
		Carrier:  rendr.CarrierTCP,
		Listener: rawRendrLn,
	}}})
	if err != nil {
		_ = rawRendrLn.Close()
		t.Fatal(err)
	}
	defer rendrLn.Close()
	rendrDone := make(chan error, 1)
	go func() {
		c, err := rendrLn.AcceptStream(ctx)
		if err != nil {
			rendrDone <- err
			return
		}
		rendrDone <- serveRendrConn(ctx, c)
	}()

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()
	socksDone := make(chan error, 1)
	runtime, err := newRendrRuntime()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		raw, err := socksLn.Accept()
		if err != nil {
			socksDone <- err
			return
		}
		socksDone <- serveSOCKSConn(ctx, raw, func(ctx context.Context) (rendr.Conn, error) {
			return dialRendr(ctx, runtime, rendrLn.Addr().String(), rendrLn.Addr().String())
		})
	}()

	client, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	socksConnect(t, client, echoAddr)

	payload := []byte("hello through rendr socks")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	waitServeDone(t, "socks", socksDone)
	waitServeDone(t, "rendr", rendrDone)
}

func startTCPEcho(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 32*1024)
		n, err := c.Read(buf)
		if n > 0 {
			_, _ = c.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func waitServeDone(t *testing.T, name string, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s serve: %v", name, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s serve did not stop", name)
	}
}

func socksConnect(t *testing.T, c net.Conn, target string) {
	t.Helper()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil {
		t.Fatal(err)
	}
	if method != [2]byte{0x05, 0x00} {
		t.Fatalf("method reply=%#v", method)
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("test target is not IPv4: %s", target)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	req = append(req, portBuf[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("SOCKS reply failure: %#v", reply)
	}
}
