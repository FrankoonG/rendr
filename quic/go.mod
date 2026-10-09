module github.com/FrankoonG/rendr/v2/quic

go 1.26.3

require (
	github.com/FrankoonG/rendr/v2 v2.0.0-00010101000000-000000000000
	github.com/quic-go/quic-go v0.63.0
)

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// Development: the root module of the same commit. A release replaces the
// pseudo-version above with the root tag of the same commit (v2.x.y) and
// keeps this directive only for in-tree builds (consumers ignore it).
replace github.com/FrankoonG/rendr/v2 => ../
