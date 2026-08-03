package smoke

import (
	"strings"
	"testing"
)

func TestValidateG3EffectiveUDPBuffers(t *testing.T) {
	tests := []struct {
		name         string
		receiveBytes int64
		sendBytes    int64
		wantError    string
	}{
		{name: "exact requirement", receiveBytes: g3RequiredLinuxEffectiveUDPBufferBytes, sendBytes: g3RequiredLinuxEffectiveUDPBufferBytes},
		{name: "above requirement", receiveBytes: 2 * g3RequiredLinuxEffectiveUDPBufferBytes, sendBytes: 4 * g3RequiredLinuxEffectiveUDPBufferBytes},
		{name: "receive clamped", receiveBytes: g3RequiredLinuxEffectiveUDPBufferBytes - 1, sendBytes: g3RequiredLinuxEffectiveUDPBufferBytes, wantError: "SO_RCVBUF"},
		{name: "send clamped", receiveBytes: g3RequiredLinuxEffectiveUDPBufferBytes, sendBytes: g3RequiredLinuxEffectiveUDPBufferBytes - 1, wantError: "SO_SNDBUF"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateG3EffectiveUDPBuffers(test.receiveBytes, test.sendBytes)
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error=%v want substring %q", err, test.wantError)
			}
		})
	}
}
