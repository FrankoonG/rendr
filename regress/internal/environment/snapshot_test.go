package environment

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestCaptureCurrentPlatform(t *testing.T) {
	t.Setenv(VMRoleEnv, "capture-test")
	t.Setenv(CPUGroupEnv, "test-group")
	snapshot, err := Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Runtime.GOOS != runtime.GOOS || snapshot.Runtime.GOARCH != runtime.GOARCH {
		t.Fatalf("runtime provenance = %+v", snapshot.Runtime)
	}
	if snapshot.Metadata.VMRole != "capture-test" || snapshot.Metadata.CPUGroup != "test-group" {
		t.Fatalf("explicit metadata = %+v", snapshot.Metadata)
	}
	if runtime.GOOS == "linux" && (len(snapshot.CPU.Models) == 0 || snapshot.CPU.OnlineSet == "" || snapshot.CPU.ProcessAllowed == "") {
		t.Fatalf("automatic Linux CPU provenance = %+v", snapshot.CPU)
	}
}

func TestSealProducesDeterministicStructuredSnapshot(t *testing.T) {
	first := validSnapshot(t, `[{"kind":"fq_codel","dev":"eth0"},{"dev":"lo","kind":"noqueue"}]`)
	secondInput := baseSnapshot(`[{"kind":"noqueue","dev":"lo"},{"dev":"eth0","kind":"fq_codel"}]`)
	secondInput.Interfaces[0], secondInput.Interfaces[1] = secondInput.Interfaces[1], secondInput.Interfaces[0]
	secondInput.SocketSysctls[0], secondInput.SocketSysctls[1] = secondInput.SocketSysctls[1], secondInput.SocketSysctls[0]
	second, err := Seal(secondInput)
	if err != nil {
		t.Fatal(err)
	}

	firstJSON, err := Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstJSON != secondJSON {
		t.Fatalf("canonical snapshots differ:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
	for _, forbidden := range []string{`"addresses"`, `"ip_address"`, `"hardware_address"`} {
		if strings.Contains(firstJSON, forbidden) {
			t.Fatalf("snapshot contains forbidden interface coordinate %q: %s", forbidden, firstJSON)
		}
	}
}

func TestValidateLinuxSnapshotCompleteness(t *testing.T) {
	snapshot := validSnapshot(t, `[]`)
	if err := Validate(snapshot); err != nil {
		t.Fatalf("complete Linux snapshot failed: %v", err)
	}

	snapshot.Clocksource = ""
	if err := Validate(snapshot); err == nil || !strings.Contains(err.Error(), "clocksource is missing") {
		t.Fatalf("missing clocksource error = %v", err)
	}
	snapshot = validSnapshot(t, `[]`)
	snapshot.CPU.ProcessAllowed = ""
	if err := Validate(snapshot); err == nil || !strings.Contains(err.Error(), "process allowed CPU list is missing") {
		t.Fatalf("missing CPU placement error = %v", err)
	}
	snapshot = validSnapshot(t, `[]`)
	snapshot.SocketSysctls = snapshot.SocketSysctls[1:]
	if err := Validate(snapshot); err == nil || !strings.Contains(err.Error(), "mandatory socket sysctl") {
		t.Fatalf("missing sysctl error = %v", err)
	}
}

func TestParseLinuxCPUProvenance(t *testing.T) {
	models, err := parseCPUModels([]byte("processor: 0\nmodel name: CPU Z\nprocessor: 1\nmodel name : CPU A\nprocessor: 2\nmodel name: CPU Z\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 || models[0] != "CPU A" || models[1] != "CPU Z" {
		t.Fatalf("CPU models = %v", models)
	}
	allowed, err := parseProcessAllowedCPUs([]byte("Name:\ttest\nCpus_allowed:\tff\nCpus_allowed_list:\t0-3,8\n"))
	if err != nil {
		t.Fatal(err)
	}
	if allowed != "0-3,8" {
		t.Fatalf("allowed CPU list = %q", allowed)
	}
	if _, err := parseCPUModels([]byte("processor: 0\n")); err == nil {
		t.Fatal("missing CPU model did not fail")
	}
	if _, err := parseProcessAllowedCPUs([]byte("Name: test\n")); err == nil {
		t.Fatal("missing allowed CPU list did not fail")
	}
}

func TestValidatePairRejectsIdentityDriftAndQDiscLeak(t *testing.T) {
	start := validSnapshot(t, `[{"dev":"eth0","kind":"fq_codel"}]`)
	stableEnd := validSnapshot(t, `[{"kind":"fq_codel","dev":"eth0"}]`)
	if err := ValidatePair(start, stableEnd); err != nil {
		t.Fatalf("stable pair failed: %v", err)
	}

	driftedInput := baseSnapshot(`[{"dev":"eth0","kind":"fq_codel"}]`)
	driftedInput.BootID = "different-boot"
	drifted, err := Seal(driftedInput)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePair(start, drifted); err == nil || !strings.Contains(err.Error(), "stable environment identity changed") {
		t.Fatalf("identity drift error = %v", err)
	}

	leaked := validSnapshot(t, `[{"dev":"eth0","kind":"netem","options":{"delay":100000}}]`)
	if err := ValidatePair(start, leaked); err == nil || !strings.Contains(err.Error(), "qdisc state was not restored") {
		t.Fatalf("qdisc leak error = %v", err)
	}
}

func TestCanonicalQDiscIgnoresEntryAndObjectOrder(t *testing.T) {
	first := validSnapshot(t, `[{"dev":"eth1","kind":"netem","options":{"loss":0.1,"delay":20}},{"kind":"noqueue","dev":"lo"}]`)
	second := validSnapshot(t, `[{"dev":"lo","kind":"noqueue"},{"options":{"delay":20,"loss":0.1},"kind":"netem","dev":"eth1"}]`)
	if first.QDisc.Digest != second.QDisc.Digest || string(first.QDisc.State) != string(second.QDisc.State) {
		t.Fatalf("qdisc canonicalization differs:\nfirst:  %s %s\nsecond: %s %s", first.QDisc.Digest, first.QDisc.State, second.QDisc.Digest, second.QDisc.State)
	}
}

func TestMetadataUsesExplicitEnvironmentVariables(t *testing.T) {
	t.Setenv(VMRoleEnv, " client ")
	t.Setenv(CPUGroupEnv, " CPU1/128-255 ")
	metadata := captureMetadata()
	if metadata.VMRole != " client " || metadata.CPUGroup != " CPU1/128-255 " {
		t.Fatalf("captured metadata = %+v", metadata)
	}
	snapshot := baseSnapshot(`[]`)
	snapshot.Metadata = metadata
	sealed, err := Seal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Metadata.VMRole != "client" || sealed.Metadata.CPUGroup != "CPU1/128-255" {
		t.Fatalf("sealed metadata = %+v", sealed.Metadata)
	}
}

func validSnapshot(t *testing.T, qdisc string) Snapshot {
	t.Helper()
	snapshot, err := Seal(baseSnapshot(qdisc))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func baseSnapshot(qdisc string) Snapshot {
	sysctls := make([]Sysctl, 0, len(mandatoryLinuxSysctls))
	for _, name := range mandatoryLinuxSysctls {
		sysctls = append(sysctls, Sysctl{Name: name, Value: "4096 87380 6291456"})
	}
	return Snapshot{
		SchemaVersion: SnapshotSchemaVersion,
		Runtime: Runtime{
			GoVersion: "go1.26.3",
			GOOS:      "linux",
			GOARCH:    "amd64",
		},
		Hostname:      "regress-vm",
		KernelRelease: "6.8.0-test",
		BootID:        "00000000-0000-4000-8000-000000000001",
		NumCPU:        8,
		CPU: CPU{
			Models:         []string{"Synthetic CPU B", "Synthetic CPU A"},
			OnlineSet:      "0-7",
			ProcessAllowed: "0-3",
		},
		TotalMemoryBytes: 8 << 30,
		Clocksource:      "tsc",
		Interfaces: []Interface{
			{Name: "lo", MTU: 65536},
			{Name: "eth0", MTU: 1500},
		},
		SocketSysctls: sysctls,
		QDisc:         QDisc{Supported: true, State: []byte(qdisc)},
		Metadata:      Metadata{VMRole: "client", CPUGroup: "CPU1/128-255"},
	}
}
