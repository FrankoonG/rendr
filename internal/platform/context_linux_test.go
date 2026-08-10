//go:build linux

package platform

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCurrentSecurityLabelFrom(t *testing.T) {
	const path = "/proc/thread-self/attr/current"
	tests := []struct {
		name    string
		value   []byte
		readErr error
		want    string
		wantErr error
	}{
		{name: "label", value: []byte("unconfined\n"), want: "unconfined"},
		{name: "blank", value: []byte(" \n\t"), want: "unreported"},
		{name: "absent", readErr: unix.ENOENT, want: "unreported"},
		{name: "no getprocattr", readErr: unix.EINVAL, want: "unreported"},
		{name: "unsupported getprocattr", readErr: unix.EOPNOTSUPP, want: "unreported"},
		{name: "permission denied", readErr: unix.EACCES, wantErr: unix.EACCES},
		{name: "operation not permitted", readErr: unix.EPERM, wantErr: unix.EPERM},
		{name: "I/O failure", readErr: unix.EIO, wantErr: unix.EIO},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			label, err := currentSecurityLabelFrom(path, func(gotPath string) ([]byte, error) {
				if gotPath != path {
					t.Fatalf("reader path=%q, want %q", gotPath, path)
				}
				if test.readErr != nil {
					return nil, &os.PathError{Op: "read", Path: gotPath, Err: test.readErr}
				}
				return test.value, nil
			})
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("error=%v, want error matching %v", err, test.wantErr)
				}
				if label != "" {
					t.Fatalf("label=%q on error, want empty", label)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if label != test.want {
				t.Fatalf("label=%q, want %q", label, test.want)
			}
		})
	}
}
