package tier3

import (
	"fmt"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

type matrixContractMetadata struct {
	purpose      string
	sourceFile   string
	syntheticTUN bool
}

var matrixContracts = map[string]matrixContractMetadata{
	"TestT3GlueAVMessOverRendrTransport":             {"Glue A VMess stream over rendr transport.", "gluea_test.go", false},
	"TestT3GlueAVMessOverRendrTransportMigrates":     {"Glue A VMess stream continuity during migration.", "gluea_test.go", false},
	"TestT3GlueAVLESSTLSOverRendrTransportMigrates":  {"Glue A VLESS plus TLS continuity during migration.", "gluea_test.go", false},
	"TestT3GlueATrojanTLSOverRendrTransportMigrates": {"Glue A Trojan plus TLS continuity during migration.", "gluea_test.go", false},
	"TestT3GlueASS2022OverRendrTransportMigrates":    {"Glue A Shadowsocks 2022 continuity during migration.", "gluea_test.go", false},
	"TestT3GlueAVLESSTLSOverRendrTransport":          {"Glue A VLESS plus TLS stream transport.", "gluea_test.go", false},
	"TestT3GlueAVLESSTLSMLKEMOverRendrTransport":     {"Glue A VLESS plus TLS plus MLKEM stream transport.", "gluea_test.go", false},
	"TestT3GlueATrojanTLSOverRendrTransport":         {"Glue A Trojan plus TLS stream transport.", "gluea_test.go", false},
	"TestT3GlueASS2022OverRendrTransport":            {"Glue A Shadowsocks 2022 stream transport.", "gluea_test.go", false},
	"TestT3VlessTCPxVlessHysteria2Transport":         {"VLESS TCP application path over VLESS Hysteria2-backed transport.", "hysteria_transport_test.go", false},
	"TestT3FreedomXFreedom":                          {"Freedom outbound on both sides through rendr factories.", "matrix_test.go", false},
	"TestT3StreamXrayBalancerFreedom":                {"Stream factory backed by xray balancer and freedom outbounds.", "matrix_test.go", false},
	"TestT3MixedBareTCPxVlessVisionTLS":              {"Mixed bare TCP and VLESS Vision TLS stream leaves.", "mixed_test.go", false},
	"TestT3ThreePath_SS_VMess_Vless":                 {"Three heterogeneous SS2022, VMess and VLESS stream paths.", "mixed_test.go", false},
	"TestT3VlessVisionTLSMLKEM_xItself":              {"VLESS Vision TLS MLKEM end-to-end topology.", "mlkem_test.go", false},
	"TestT3StreamNestedTwoLayer":                     {"Two-layer nested stream outbound topology.", "nested_test.go", false},
	"TestT3StreamReverseOutbound":                    {"Reverse outbound stream topology.", "nested_test.go", false},
	"TestT3PacketBareUDPFlowxUDPFlow":                {"Bare UDP flow packet factories on both sides.", "packet_test.go", false},
	"TestT3PacketQUICDatagramxQUICDatagram":          {"QUIC DATAGRAM packet factories on both sides.", "packet_test.go", false},
	"TestT3PacketXrayFreedomUDPxUDPFlow":             {"xray freedom UDP packet outbound over rendr UDP flow.", "packet_xray_test.go", false},
	"TestT3PacketXrayBalancerUDPxUDPFlow":            {"xray UDP balancer packet outbound over rendr UDP flow.", "packet_xray_test.go", false},
	"TestT3VlessVisionRealityXItself":                {"VLESS Vision REALITY end-to-end topology.", "reality_test.go", false},
	"TestT3StreamDirectXRelay":                       {"Direct stream path combined with relay topology.", "relay_test.go", false},
	"TestT3StreamSS2022ViaRelay":                     {"Shadowsocks 2022 stream through relay topology.", "relay_test.go", false},
	"TestT3SS2022xSS2022":                            {"Shadowsocks 2022 on both sides.", "ss2022_test.go", false},
	"TestT3PacketSS2022UDPxUDPFlow":                  {"Shadowsocks 2022 UDP packet path over rendr UDP flow.", "ss2022_udp_test.go", false},
	"TestT3TrojanxTrojan":                            {"Trojan on both sides.", "trojan_test.go", false},
	"TestTUNT3FreedomStreamOverTUN":                  {"Freedom stream through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3SS2022StreamOverTUN":                   {"Shadowsocks 2022 stream through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3VMessStreamOverTUN":                    {"VMess stream through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3TrojanTLSStreamOverTUN":                {"Trojan TLS stream through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3VLESSVisionTLSStreamOverTUN":           {"VLESS Vision TLS stream through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3VLESSVisionTLSMLKEMStreamOverTUN":      {"VLESS Vision TLS MLKEM stream through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3VLESSVisionRealityStreamOverTUN":       {"VLESS Vision REALITY stream through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3VLESSHysteria2TransportStreamOverTUN":  {"VLESS Hysteria2-backed stream through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3MixedSS2022VMessStreamOverTUN":         {"Mixed SS2022 and VMess paths through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3ThreePathSSVMessVLESSStreamOverTUN":    {"Three heterogeneous stream paths through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3DirectRelayStreamOverTUN":              {"Direct plus relay stream topology through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3NestedTwoLayerStreamOverTUN":           {"Nested two-layer stream through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3PacketXrayFreedomUDPxUDPFlowOverTUN":   {"xray freedom UDP packet flow through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestTUNT3PacketXrayBalancerUDPxUDPFlowOverTUN":  {"xray UDP balancer packet flow through the synthetic matrix TUN wrapper.", "tunfull_test.go", true},
	"TestT3VlessVisionTLSxItself":                    {"VLESS Vision TLS end-to-end topology.", "vless_test.go", false},
	"TestT3VMessxVMess":                              {"VMess on both sides.", "vmess_test.go", false},
	"TestT3SS2022xVMess":                             {"Shadowsocks 2022 and VMess heterogeneous stream topology.", "vmess_test.go", false},
}

func mustMatrixSpec(testName string) manifest.Spec {
	metadata, ok := matrixContracts[testName]
	if !ok {
		panic(fmt.Sprintf("tier3: no manifest contract metadata for %q", testName))
	}

	topologyReason := "The fixture's concrete roles, isolation boundaries, and path count are not frozen or emitted by the current runner."
	if metadata.syntheticTUN {
		topologyReason = "The wrapper uses synthetic stream or packet ingress and does not open /dev/net/tun; its concrete fixture topology and path count are not frozen or emitted."
	}
	contract := manifest.Contract{
		SchemaVersion: manifest.ContractSchemaVersion,
		State:         manifest.ContractStateBlocked,
		MissingDimensions: []manifest.MissingDimension{
			{Dimension: manifest.ContractDimensionTopology, Reason: topologyReason},
			{Dimension: manifest.ContractDimensionRoleCapabilities, Reason: "Fixture dependency and capability prerequisites are not emitted by the current runner."},
			{Dimension: manifest.ContractDimensionPayload, Reason: "The fixture-owned payload size and content profile are not frozen or emitted by the current runner."},
			{Dimension: manifest.ContractDimensionLoad, Reason: "The fixture-owned offered load and operation counts are not frozen or emitted by the current runner."},
			{Dimension: manifest.ContractDimensionSeed, Reason: "Fixture randomness, when present, has no frozen or recorded seed policy."},
			{Dimension: manifest.ContractDimensionStimulus, Reason: "The T3 report row emits no stimulus evidence facts; it records only the exact top-level test outcome."},
			{Dimension: manifest.ContractDimensionOracle, Reason: "The T3 report row emits no oracle evidence facts; fixture assertions are not exported as report evidence."},
			{Dimension: manifest.ContractDimensionNegativeControl, Reason: "No per-topology end-to-end negative control is registered or emitted for this case."},
			{Dimension: manifest.ContractDimensionResources, Reason: "Per-role vCPU, RAM, and disk minima have not been calibrated for the xray fixture."},
		},
		Purpose:    metadata.purpose,
		Entrypoint: fmt.Sprintf("regress/internal/tier3/runner.go::Run -> runCaseDefs -> runMatrixCase -> gotestjson.Executor.Run -> regress/internal/matrix/%s::%s", metadata.sourceFile, testName),
		Payload: manifest.Profile{
			Applicability: manifest.ApplicabilityUnfrozen,
		},
		Load: manifest.Profile{
			Applicability: manifest.ApplicabilityUnfrozen,
		},
		NegativeControl: manifest.NegativeControl{
			Kind: manifest.NegativeControlAbsent,
		},
		Resources: manifest.ResourceBudget{
			State: manifest.ResourceStateUnfrozen,
		},
	}
	spec, err := manifest.NewCompleteSpec(
		manifest.RequiredWithBudget(testName, "T3", matrixTestBudget),
		contract,
	)
	if err != nil {
		panic(fmt.Sprintf("tier3: invalid manifest contract for %q: %v", testName, err))
	}
	return spec
}
