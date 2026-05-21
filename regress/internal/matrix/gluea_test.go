package matrix

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	rendrxray "github.com/FrankoonG/rendr/xray"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessoutbound "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessinbound "github.com/xtls/xray-core/proxy/vmess/inbound"
	vmessoutbound "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"

	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
	_ "github.com/xtls/xray-core/transport/internet/tls"
)

func TestT3GlueAVMessOverRendrTransport(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	rendrPort := pickFreePort(t)
	transportName := "rendr-gluea-vmess-" + strconv.Itoa(rendrPort)
	rendrAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(rendrPort))
	if err := rendrxray.RegisterRendrTransportListener(transportName, nil); err != nil {
		t.Fatal(err)
	}
	if err := rendrxray.RegisterRendrTransportDialer(transportName, &rendrxray.Config{
		Mode: rendrxray.ModePrime,
		Paths: []rendrxray.PathSpec{
			{Transport: "tcp", Address: rendrAddr},
			{Transport: "tcp", Address: rendrAddr},
		},
	}); err != nil {
		t.Fatal(err)
	}

	userID := protocol.NewID(uuid.New()).String()
	server := startVMessServerOverRendrTransport(t, rendrPort, userID, transportName)
	defer server.Close()
	client := startVMessClientOverRendrTransport(t, rendrPort, userID, transportName)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dest, err := xnet.ParseDestination("tcp:" + echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := core.Dial(ctx, client, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	want := []byte("vmess over xray streamSettings.network=rendr")
	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload got %q want %q", got, want)
	}
}

func TestT3GlueAVLESSTLSOverRendrTransport(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	rendrPort := pickFreePort(t)
	transportName := "rendr-gluea-vless-" + strconv.Itoa(rendrPort)
	rendrAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(rendrPort))
	if err := rendrxray.RegisterRendrTransportListener(transportName, nil); err != nil {
		t.Fatal(err)
	}
	if err := rendrxray.RegisterRendrTransportDialer(transportName, &rendrxray.Config{
		Mode: rendrxray.ModePrime,
		Paths: []rendrxray.PathSpec{
			{Transport: "tcp", Address: rendrAddr},
			{Transport: "tcp", Address: rendrAddr},
		},
	}); err != nil {
		t.Fatal(err)
	}

	userID := protocol.NewID(uuid.New()).String()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	server := startVLESSTLSServerOverRendrTransport(t, rendrPort, userID, transportName, ct)
	defer server.Close()
	client := startVLESSTLSClientOverRendrTransport(t, rendrPort, userID, transportName, ctHash)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dest, err := xnet.ParseDestination("tcp:" + echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := core.Dial(ctx, client, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	want := []byte("vless tls over xray streamSettings.network=rendr")
	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload got %q want %q", got, want)
	}
}

func startVMessServerOverRendrTransport(t *testing.T, port int, userID, transportName string) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(port))}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
					StreamSettings: &internet.StreamConfig{
						ProtocolName: transportName,
					},
				}),
				ProxySettings: serial.ToTypedMessage(&vmessinbound.Config{
					User: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vmess.Account{Id: userID}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}

func startVMessClientOverRendrTransport(t *testing.T, port int, userID, transportName string) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&vmessoutbound.Config{
					Receiver: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(port),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: userID,
								SecuritySettings: &protocol.SecurityConfig{
									Type: protocol.SecurityType_AES128_GCM,
								},
							}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: transportName,
					},
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}

func startVLESSTLSServerOverRendrTransport(t *testing.T, port int, userID, transportName string, srvCert *cert.Certificate) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(port))}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
					StreamSettings: &internet.StreamConfig{
						ProtocolName: transportName,
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								Certificate: []*tls.Certificate{tls.ParseCertificate(srvCert)},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&vlessinbound.Config{
					Users: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID,
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}

func startVLESSTLSClientOverRendrTransport(t *testing.T, port int, userID, transportName string, srvCertHash [32]byte) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&vlessoutbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(port),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id: userID,
							}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: transportName,
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								PinnedPeerCertSha256: [][]byte{srvCertHash[:]},
							}),
						},
					},
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}
