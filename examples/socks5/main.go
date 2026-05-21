// Command socks5 is a small reference embedder for rendr.
//
// It intentionally lives under examples: SOCKS5 is an application
// protocol, while rendr itself stays a generic net.Conn migration
// layer. The client accepts local SOCKS5 CONNECT requests, opens one
// rendr.Conn per CONNECT, and sends the target address to the server
// over that Conn. The server dials the target and proxies bytes.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/FrankoonG/rendr"
)

type config struct {
	mode       string
	listenAddr string
	serverAddr string
	paths      string
}

func main() {
	var cfg config
	flag.StringVar(&cfg.mode, "mode", "client", "client or server")
	flag.StringVar(&cfg.listenAddr, "listen", "127.0.0.1:1080", "client SOCKS5 listen addr or server rendr listen addr")
	flag.StringVar(&cfg.serverAddr, "server", "", "rendr server addr for client mode")
	flag.StringVar(&cfg.paths, "paths", "", "comma-separated rendr path addrs; defaults to -server")
	flag.Parse()

	ctx := context.Background()
	var err error
	switch cfg.mode {
	case "server":
		err = runServer(ctx, cfg.listenAddr)
	case "client":
		if cfg.serverAddr == "" {
			err = errors.New("-server is required in client mode")
		} else {
			err = runClient(ctx, cfg)
		}
	default:
		err = fmt.Errorf("unknown mode %q", cfg.mode)
	}
	if err != nil {
		panic(err)
	}
}

func runServer(ctx context.Context, addr string) error {
	ln, err := rendr.ListenTCP(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		c, err := ln.Accept(ctx)
		if err != nil {
			return err
		}
		go func() {
			_ = serveRendrConn(ctx, c)
		}()
	}
}

func serveRendrConn(ctx context.Context, c rendr.Conn) error {
	defer c.Close()
	br := bufio.NewReader(c)
	target, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return errors.New("empty target")
	}
	dialer := net.Dialer{}
	upstream, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if buffered := br.Buffered(); buffered > 0 {
		if _, err := io.CopyN(upstream, br, int64(buffered)); err != nil {
			return err
		}
	}
	proxy(c, upstream)
	return nil
}

func runClient(ctx context.Context, cfg config) error {
	ln, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			_ = serveSOCKSConn(ctx, raw, func(ctx context.Context) (rendr.Conn, error) {
				return dialRendr(ctx, cfg.serverAddr, cfg.paths)
			})
		}()
	}
}

func serveSOCKSConn(ctx context.Context, raw net.Conn, dial func(context.Context) (rendr.Conn, error)) error {
	defer raw.Close()
	target, err := readSOCKSConnect(raw)
	if err != nil {
		_ = writeSOCKSReply(raw, 0x01)
		return err
	}
	rc, err := dial(ctx)
	if err != nil {
		_ = writeSOCKSReply(raw, 0x05)
		return err
	}
	defer rc.Close()
	if _, err := io.WriteString(rc, target+"\n"); err != nil {
		_ = writeSOCKSReply(raw, 0x05)
		return err
	}
	if err := writeSOCKSReply(raw, 0x00); err != nil {
		return err
	}
	proxy(raw, rc)
	return nil
}

func dialRendr(ctx context.Context, serverAddr, pathList string) (rendr.Conn, error) {
	if pathList == "" {
		pathList = serverAddr
	}
	addrs := strings.Split(pathList, ",")
	paths := make([]rendr.PathSpec, 0, len(addrs))
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		paths = append(paths, rendr.PathSpec{Transport: "tcp", Address: addr})
	}
	if len(paths) == 0 {
		return nil, errors.New("no rendr paths configured")
	}
	d := &rendr.Dialer{
		Mode:  rendr.ModePrime,
		Paths: paths,
	}
	return d.Dial(ctx)
}

func readSOCKSConnect(c net.Conn) (string, error) {
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", err
	}
	defer c.SetDeadline(time.Time{})

	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != 0x05 {
		return "", fmt.Errorf("unsupported SOCKS version %d", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return "", err
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		return "", errors.New("only SOCKS5 CONNECT is supported")
	}

	host, err := readSOCKSAddr(c, req[3])
	if err != nil {
		return "", err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readSOCKSAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	case 0x04:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

func writeSOCKSReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func proxy(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go copyAndClose(done, a, b)
	go copyAndClose(done, b, a)
	<-done
}

func copyAndClose(done chan<- struct{}, dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
	done <- struct{}{}
}
