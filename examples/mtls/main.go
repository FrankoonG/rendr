// Command mtls shows how an embedder wraps rendr carriers in mutually
// authenticated TLS using only the standard library (plan §1.4, ≤ 200
// lines). rendr itself neither encrypts nor authenticates: here every
// carrier is a TLS 1.3 connection over carrier/tcp, the passive side requires
// and verifies a client certificate (tls.RequireAndVerifyClientCert), and
// the dialer's factory completes HandshakeContext before handing the conn
// to rendr. rendr sees only the *tls.Conn, so it uses the coalesced write
// path (one TLS record per batch). A rendr InstanceID is not an identity:
// trust comes from the certificates.
//
// The program builds a throwaway CA and two leaf certificates in memory,
// starts a passive and a dialer Runtime on loopback, dials one selector
// session, echoes a message through it and exits 0. Its test also checks
// that a client without a certificate never reaches rendr.
package main

import (
	"crypto/tls"
	"fmt"
	"os"
)

// pki holds the in-memory CA and the two TLS configurations.
type pki struct {
	server *tls.Config // ClientAuth: RequireAndVerifyClientCert, MinVersion TLS 1.3
	client *tls.Config // RootCAs = the CA, Certificates = client leaf
}

// newPKI generates an ECDSA P-256 CA and server/client leaves valid for
// the IPv4 loopback address and the loopback host name.
func newPKI() (*pki, error) {
	panic("unimplemented: M1b")
}

// run starts both Runtimes, dials, echoes msg and returns what came back.
func run(p *pki, msg []byte) ([]byte, error) {
	panic("unimplemented: M1b")
}

func main() {
	p, err := newPKI()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pki:", err)
		os.Exit(1)
	}
	got, err := run(p, []byte("hello over mutually authenticated carriers"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(1)
	}
	fmt.Printf("echoed %q\n", got)
}
