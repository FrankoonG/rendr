# rendr

[![Go](https://github.com/FrankoonG/rendr/actions/workflows/go.yml/badge.svg)](https://github.com/FrankoonG/rendr/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/FrankoonG/rendr.svg)](https://pkg.go.dev/github.com/FrankoonG/rendr)

rendr is a Go framework for lossless connection migration. An embedder
gets a stable `net.Conn` or `net.PacketConn`; rendr manages the
underlying network paths and can move traffic between them without
turning path loss into an application-visible reset or EOF.

The project is intentionally narrow: it is a migration layer, not a
proxy product. Proxy protocols, peer discovery, mesh topology,
configuration management, UI, and routing policy belong to the
embedding program.

## Model

Each application flow has a stable `flow_id`. Multiple underlying
paths can attach to that flow, and rendr decides which path or paths
carry frames at a given moment.

The core policy shapes are:

- `prime` / selector: use the best single path and migrate when
  quality justifies it.
- `race`: duplicate frames across paths and keep the first valid
  arrival.
- `bond`: distribute frames across paths to aggregate throughput.

These policies share the same migration engine and path-quality layer.
They can be used over stream or packet-shaped carriers depending on
the embedder's application protocol.

## Scope

rendr provides:

- Stable stream and packet connection surfaces for Go embedders.
- Path attach, path death classification, failover, recovery, and
  migration control.
- TCP, QUIC, opaque-UDP, and gVisor-backed carrier building blocks.
- Integration surfaces for custom transports and xray-based embedders.
- TUN/L3 identity building blocks for programs that need per-flow
  migration below an OS network stack.

rendr does not provide:

- Built-in proxy protocols such as Shadowsocks, Trojan, VLESS, or
  Hysteria.
- Peer discovery, mesh routing, NAT traversal, or topology control.
- Domain/CIDR policy routing or configuration management.
- A Web UI or operations panel.
- A default guarantee that the final destination server sees the
  original source IP.

## Status

rendr is in active pre-`v1.0` development. The API is usable for
experimentation and internal integration, but policy graph, TUN, and
xray glue surfaces may still evolve as the migration model is hardened.

## License

See [LICENSE](./LICENSE).
