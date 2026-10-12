module github.com/FrankoonG/rendr/quic/v2

go 1.26.3

require (
	github.com/FrankoonG/rendr/v2 v2.0.0
	github.com/quic-go/quic-go v0.63.0
)

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// In-tree builds use the root module of the same commit; the release
// requires the root tag of that commit (v2.x.y, tagged with quic/v2.x.y).
// Consumers of the module ignore this directive.
replace github.com/FrankoonG/rendr/v2 => ../
