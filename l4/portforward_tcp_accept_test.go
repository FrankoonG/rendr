//go:build !plan9

package l4

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"testing/synctest"
)

// TestPortForwardTCPResourceAcceptBacksOff (M6 design §A8.7, R1-19): an
// Accept that fails for want of a resource is backed off, never the
// serve's end. Every capacity errno of M4's table (this OS's symbols:
// EMFILE, ENFILE, ENOBUFS, ENOMEM, EADDRNOTAVAIL on Unix; the Windows
// numbers WSAEMFILE, WSAENOBUFS, WSAEADDRNOTAVAIL), each in an accept
// *net.OpError as the net package returns it — which calls ENOBUFS, ENOMEM
// and every Windows number permanent — then one connection: ServeTCP still
// runs, AcceptNoise counts every error, the new connection is echoed, and
// the connection forwarded before the errors still forwards.
func TestPortForwardTCPResourceAcceptBacksOff(t *testing.T) {
	var errs []error
	for _, r := range errnoRows() {
		if r.want == CodeCapacity && !strings.HasSuffix(r.name, " in OpError") {
			errs = append(errs, &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", r.err)})
		}
	}
	if len(errs) < 3 {
		t.Fatalf("stimulus: %d capacity errnos, want at least the three Windows numbers", len(errs))
	}
	synctest.Test(t, func(t *testing.T) {
		w := newPTWorld(t, ptOpts{})
		live := w.pl.dial()
		w.serveTCP()
		ptPing(t, live, 256)
		for _, err := range errs {
			w.pl.q <- ptAccept{err: err}
		}
		ptEcho(t, w.pl.dial(), 16<<10, 5)
		synctest.Wait()
		select {
		case err := <-w.served:
			w.served = nil
			t.Fatalf("ServeTCP returned %v: an out-of-resource Accept error ended the serve", err)
		default:
		}
		ptPing(t, live, 256) // still forwarding
		if st := w.pf.Status().TCP; st.AcceptNoise != uint64(len(errs)) || st.Accepted != 2 || st.Failed != 0 {
			t.Fatalf("status %+v: want AcceptNoise %d, 2 accepted", st, len(errs))
		}
		if err := w.stop(); !errors.Is(err, context.Canceled) {
			t.Fatalf("ServeTCP = %v, want context.Canceled", err)
		}
	})
}
