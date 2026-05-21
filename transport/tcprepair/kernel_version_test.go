package tcprepair

import "testing"

func TestParseLinuxKernelRelease(t *testing.T) {
	cases := []struct {
		release string
		ok      bool
		major   int
		minor   int
		lt45    bool
	}{
		{release: "6.8.0-111-generic", ok: true, major: 6, minor: 8, lt45: false},
		{release: "4.5.0", ok: true, major: 4, minor: 5, lt45: false},
		{release: "4.4.302-custom", ok: true, major: 4, minor: 4, lt45: true},
		{release: "3.10.0-backport", ok: true, major: 3, minor: 10, lt45: true},
		{release: "not-a-kernel", ok: false},
		{release: "6", ok: false},
	}
	for _, c := range cases {
		t.Run(c.release, func(t *testing.T) {
			got, ok := parseLinuxKernelRelease(c.release)
			if ok != c.ok {
				t.Fatalf("ok=%v want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if got.major != c.major || got.minor != c.minor {
				t.Fatalf("version=%d.%d want %d.%d", got.major, got.minor, c.major, c.minor)
			}
			if got.lessThan(4, 5) != c.lt45 {
				t.Fatalf("lessThan(4,5)=%v want %v", got.lessThan(4, 5), c.lt45)
			}
		})
	}
}
