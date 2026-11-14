package mitre

import "edgesight/pkg/protocol"

// ATTACK defines a small curated subset of MITRE ATT&CK mappings used by EdgeSight.
var ATTACK = map[string]protocol.MITREMapping{
	"port_scan": {
		Tactic:      "Reconnaissance",
		TechniqueID: "T1046",
		Name:        "Network Service Discovery",
	},
	"syn_flood": {
		Tactic:      "Impact",
		TechniqueID: "T1498",
		Name:        "Network Denial of Service",
	},
	"dns_tunnel": {
		Tactic:      "Command and Control",
		TechniqueID: "T1071.004",
		Name:        "Application Layer Protocol: DNS",
	},
	"icmp_tunnel": {
		Tactic:      "Command and Control",
		TechniqueID: "T1095",
		Name:        "Non-Application Layer Protocol",
	},
	"data_exfil": {
		Tactic:      "Exfiltration",
		TechniqueID: "T1041",
		Name:        "Exfiltration Over C2 Channel",
	},
	"brute_force": {
		Tactic:      "Credential Access",
		TechniqueID: "T1110",
		Name:        "Brute Force",
	},
	"unusual_protocol": {
		Tactic:      "Defense Evasion",
		TechniqueID: "T1205",
		Name:        "Traffic Signaling",
	},
	"large_payload": {
		Tactic:      "Exfiltration",
		TechniqueID: "T1048",
		Name:        "Exfiltration Over Alternative Protocol",
	},
	"arp_spoof": {
		Tactic:      "Credential Access",
		TechniqueID: "T1557",
		Name:        "Man-in-the-Middle",
	},
	"new_external_conn": {
		Tactic:      "Initial Access",
		TechniqueID: "T1190",
		Name:        "Exploit Public-Facing Application",
	},
}

// Map returns the MITRE mapping for a given signature key, if known.
func Map(key string) (protocol.MITREMapping, bool) {
	m, ok := ATTACK[key]
	return m, ok
}

// Maps returns all known mappings as a slice.
func Maps(keys ...string) []protocol.MITREMapping {
	var out []protocol.MITREMapping
	seen := map[string]struct{}{}
	for _, k := range keys {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		if m, ok := Map(k); ok {
			out = append(out, m)
		}
	}
	return out
}
