package tun

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func validateKernel5TUNFixedLowerHex(field, value string, encodedBytes int) error {
	if encodedBytes <= 0 || len(value) != encodedBytes*2 {
		return fmt.Errorf("%s must contain exactly %d lowercase hexadecimal characters", field, encodedBytes*2)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != encodedBytes || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("%s must be canonical lowercase hexadecimal", field)
	}
	return nil
}

func validateKernel5TUNNetworkNamespaceFormat(value string) error {
	device, inode, found := strings.Cut(value, ":")
	if !found || device == "" || inode == "" || strings.Contains(inode, ":") {
		return fmt.Errorf("network_namespace %q must contain exactly two decimal components", value)
	}
	for name, component := range map[string]string{"device": device, "inode": inode} {
		parsed, err := strconv.ParseUint(component, 10, 64)
		if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != component {
			return fmt.Errorf("network_namespace %s component %q must be a nonzero canonical decimal uint64", name, component)
		}
	}
	return nil
}

func TestKernel5TUNFixedLowerHexValidation(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError bool
	}{
		{name: "payload hash", value: strings.Repeat("a", 64)},
		{name: "short hash", value: strings.Repeat("a", 63), wantError: true},
		{name: "long hash", value: strings.Repeat("a", 65), wantError: true},
		{name: "uppercase hash", value: strings.Repeat("A", 64), wantError: true},
		{name: "non-hex hash", value: strings.Repeat("g", 64), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateKernel5TUNFixedLowerHex("payload_sha256", test.value, 32)
			if (err != nil) != test.wantError {
				t.Fatalf("validation error=%v wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestKernel5TUNNetworkNamespaceFormatValidation(t *testing.T) {
	tests := []struct {
		value     string
		wantError bool
	}{
		{value: "4:5"},
		{value: "18446744073709551615:18446744073709551615"},
		{value: "", wantError: true},
		{value: "4", wantError: true},
		{value: "4:5:6", wantError: true},
		{value: "0:5", wantError: true},
		{value: "4:0", wantError: true},
		{value: "-4:5", wantError: true},
		{value: "+4:5", wantError: true},
		{value: "04:5", wantError: true},
		{value: "4:05", wantError: true},
		{value: "4:not-decimal", wantError: true},
		{value: "18446744073709551616:5", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			err := validateKernel5TUNNetworkNamespaceFormat(test.value)
			if (err != nil) != test.wantError {
				t.Fatalf("validation error=%v wantError=%t", err, test.wantError)
			}
		})
	}
}
