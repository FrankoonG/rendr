# rendr

rendr is a Go library for lossless connection migration and multipath
transport between two rendr instances. An application holds one stable
`net.Conn` (or packet connection) while rendr carries its bytes over any
number of underlying carriers and moves them when a carrier dies, degrades
or is replaced.

**Status: 2.0 is a ground-up rewrite in progress on the `v2` branch.** The
module path is `github.com/FrankoonG/rendr/v2`. It is not compatible with
earlier releases.

## Security model

rendr is a transport layer that is meant to run inside the embedder's own
protocol. It provides **no confidentiality and no authentication**. A rendr
listener must only be reachable through an authenticated, encrypted channel
that the embedder controls. The built-in raw carriers are plaintext and are
intended for tests and trusted networks.

## License

See [LICENSE](./LICENSE).
