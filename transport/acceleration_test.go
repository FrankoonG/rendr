package transport

import (
	"reflect"
	"testing"
	"time"
)

func TestDatagramAccelerationStatusIsObservationOnly(t *testing.T) {
	observerType := reflect.TypeOf((*DatagramAccelerationObserver)(nil)).Elem()
	if observerType.NumMethod() != 1 || observerType.Method(0).Name != "DatagramAccelerationStatus" {
		t.Fatalf("observer methods=%v", observerType.NumMethod())
	}

	now := time.Unix(10, 20)
	status := DatagramAccelerationStatus{
		Mode: DatagramAccelerationGSO, Cause: "probe_confirmed",
		ProbeGeneration: 7, ProbedAt: now,
		BatchCalls: 2, BatchDatagrams: 7,
		GSOAttempts: 3, GSOSuperPackets: 2, GSOSegments: 8,
		OrdinaryDatagrams: 1, FallbackTransitions: 1,
	}
	copy := status
	if copy != status || copy.Mode != DatagramAccelerationGSO || copy.ProbedAt != now {
		t.Fatalf("status value semantics changed: %+v", copy)
	}
}

func TestDatagramAccelerationModesAreStable(t *testing.T) {
	if DatagramAccelerationUnknown != "unknown" ||
		DatagramAccelerationGSO != "gso_active" ||
		DatagramAccelerationOrdinary != "ordinary_fallback" {
		t.Fatal("datagram acceleration mode values changed")
	}
}
