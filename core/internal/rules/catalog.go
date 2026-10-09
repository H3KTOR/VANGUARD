// Package rules exposes a read-only inventory of VANGUARD's detection
// rules, built from the code that actually implements them (incident
// types, base severities, evidence kinds, limitations, compiled
// thresholds) plus the effective operator tuning. It performs no
// evaluation and changes nothing.
package rules

import (
	"fmt"
	"sort"

	"vanguard/core/internal/database"
	"vanguard/core/internal/detection"
	"vanguard/core/internal/risk"
	"vanguard/core/internal/thresholds"
	"vanguard/core/internal/tuning"
)

// Setting is one effective configuration value of a rule.
type Setting struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
	Unit  string `json:"unit,omitempty"`
	// Source states where the value comes from: the compiled default, an
	// operator tuning revision, or a startup flag. Never guessed.
	Source  string `json:"source"`
	Tunable bool   `json:"tunable"`
}

// Rule is one inventory entry.
type Rule struct {
	ID            string    `json:"rule_id"`
	Category      string    `json:"category"`
	Description   string    `json:"description"`
	Enabled       bool      `json:"enabled"`
	DisabledBy    string    `json:"disabled_by,omitempty"`
	CanDisable    bool      `json:"can_disable_individually"`
	EvidenceKind  string    `json:"evidence_kind"` // observed | correlated
	RuleRevision  int       `json:"rule_revision"`
	BaseSeverity  int       `json:"base_severity"`
	Settings      []Setting `json:"settings"`
	SettingsNote  string    `json:"settings_note,omitempty"`
	Prerequisites []string  `json:"prerequisites"`
	Limitations   string    `json:"limitations,omitempty"`
	AutoResponse  AutoResp  `json:"automated_response"`
}

// AutoResp describes whether this rule's incidents can reach automatic
// blocking under the current Autopilot policy.
type AutoResp struct {
	Possible bool   `json:"possible"`
	Note     string `json:"note"`
}

// Context carries the runtime facts the inventory reflects.
type Context struct {
	Tuning          tuning.Values
	TuningRevision  uint
	HostSecurity    bool
	SystemPosture   bool
	Intel           bool
	Honeypot        bool
	MinRiskToBan    int  // Autopilot threshold (0 = unknown)
	AutopilotActive bool // Autopilot enabled
}

type def struct {
	id, cat, desc string
	prereq        []string
	hostLocal     bool
	group         string // "", host, posture, intel, honeypot
	settings      func(c Context) []Setting
	note          string
}

func compiled(name string, v any, unit string) Setting {
	return Setting{Name: name, Value: v, Unit: unit, Source: "compiled default", Tunable: false}
}

func tuned(c Context, name string, v int, unit string) Setting {
	src := "compiled default"
	if c.TuningRevision != 0 {
		src = fmt.Sprintf("operator tuning revision %d", c.TuningRevision)
	}
	return Setting{Name: name, Value: v, Unit: unit, Source: src, Tunable: true}
}

func secs(d interface{ Seconds() float64 }) int { return int(d.Seconds()) }

var defs = []def{
	{id: "ssh_bruteforce", cat: "authentication", desc: "Many failed SSH logins from one address in a sliding window.",
		prereq: []string{"auth.log readable"}, settings: func(c Context) []Setting {
			return []Setting{tuned(c, "min_failed_attempts", c.Tuning.SSHBruteForceMinAttempts, "attempts (fires above)"), compiled("window", secs(thresholds.SSHBruteForceWindow), "seconds")}
		}},
	{id: "failed_then_success_login", cat: "authentication", desc: "A successful SSH login shortly after a run of failures from the same address.",
		prereq: []string{"auth.log readable"}, settings: func(c Context) []Setting {
			return []Setting{tuned(c, "min_failures_before_success", c.Tuning.FailedThenSuccessMinFailed, "failures (fires at or above)"), compiled("window", secs(thresholds.FailedThenSuccessWindow), "seconds")}
		}},
	{id: "port_scan", cat: "recon", desc: "One address touching many distinct ports quickly.",
		prereq: []string{"port-touch events (honeypot decoys)"}, settings: func(c Context) []Setting {
			return []Setting{tuned(c, "distinct_ports", c.Tuning.PortScanDistinctPorts, "ports (fires above)"), compiled("window", secs(thresholds.PortScanWindow), "seconds")}
		}},
	{id: "web_directory_scan", cat: "web", desc: "Repeated 404 responses on sensitive paths from one address.",
		prereq: []string{"web access log readable"}, settings: func(c Context) []Setting {
			return []Setting{tuned(c, "min_sensitive_404s", c.Tuning.WebDirScanMin404s, "responses (fires at or above)"), compiled("window", secs(thresholds.WebDirScanWindow), "seconds")}
		}},
	{id: "http_flood", cat: "web", desc: "Very high request rate from one address.",
		prereq: []string{"web access log readable"}, settings: func(c Context) []Setting {
			return []Setting{tuned(c, "max_requests", c.Tuning.HTTPFloodMaxRequests, "requests (fires above)"), compiled("window", secs(thresholds.HTTPFloodWindow), "seconds")}
		}},
	{id: "path_traversal", cat: "web", desc: "Request target contains path-traversal patterns (decoded up to twice).",
		prereq: []string{"web access log readable"}, note: "signature list is compiled in"},
	{id: "sqli_xss_probe", cat: "web", desc: "Request target contains SQL-injection or XSS probe patterns (decoded up to twice).",
		prereq: []string{"web access log readable"}, note: "signature list is compiled in"},
	{id: "web_scanner_behavior", cat: "web", desc: "Burst of 403/404 responses combined with a missing or scanner-like User-Agent.",
		prereq: []string{"web access log with User-Agent"}, settings: func(c Context) []Setting {
			return []Setting{compiled("min_4xx", thresholds.WebScannerMin4xx, "responses"), compiled("window", secs(thresholds.WebScannerWindow), "seconds")}
		}},
	{id: "honeypot_trigger", cat: "deception", desc: "Any connection to a decoy port.", group: "honeypot",
		prereq: []string{"honeypot enabled (-honeypot)"}, note: "no threshold by design"},
	{id: "attack_chain", cat: "correlation", desc: "Recon, web probing and SSH failures from one address in order within a window.",
		prereq: []string{"port-touch, web log and auth log events"}, settings: func(Context) []Setting {
			return []Setting{compiled("window", secs(thresholds.AttackChainWindow), "seconds"), compiled("min_distinct_ports", thresholds.AttackChainMinDistinctPorts, ""), compiled("min_web_probes", thresholds.AttackChainMinWebProbes, ""), compiled("min_auth_failures", thresholds.AttackChainMinAuthFailures, "")}
		}},
	{id: "web_attack_chain", cat: "correlation", desc: "Web probing, SSH failures and an exploitation indicator from one address in order.",
		prereq: []string{"web log and auth log events"}, settings: func(Context) []Setting {
			return []Setting{compiled("window", secs(thresholds.WebAttackChainWindow), "seconds"), compiled("min_web_probes", thresholds.WebAttackChainMinWebProbes, ""), compiled("min_auth_failures", thresholds.WebAttackChainMinAuthFailures, ""), compiled("min_exploit_signals", thresholds.WebAttackChainMinExploitSignals, "")}
		}},
	{id: "password_spraying", cat: "authentication", desc: "Few attempts against many distinct accounts from one address.",
		prereq: []string{"auth.log with usernames"}, settings: func(Context) []Setting {
			return []Setting{compiled("window", secs(thresholds.PasswordSprayingWindow), "seconds"), compiled("min_distinct_usernames", thresholds.PasswordSprayingMinDistinctUsernames, ""), compiled("max_attempts_per_user", thresholds.PasswordSprayingMaxAttemptsPerUser, "")}
		}},
	{id: "credential_stuffing", cat: "authentication", desc: "High-volume, high-failure-ratio logins across many accounts from one address.",
		prereq: []string{"auth.log with usernames"}, settings: func(Context) []Setting {
			return []Setting{compiled("window", secs(thresholds.CredentialStuffingWindow), "seconds"), compiled("min_distinct_usernames", thresholds.CredentialStuffingMinDistinctUsernames, ""), compiled("min_total_attempts", thresholds.CredentialStuffingMinTotalAttempts, ""), compiled("min_failure_ratio", float64(thresholds.CredentialStuffingMinFailureRatioTenths)/10, "ratio")}
		}},
	{id: "web_shell_indicator", cat: "web", desc: "Request shape typical of web shells (script extension, upload path, command-style parameter).",
		prereq: []string{"web access log readable"}, note: "single weak signals produce a low-severity finding; two or more feed the Web Attack Chain"},
	{id: "ssrf_indicator", cat: "web", desc: "Request carries a private/loopback/metadata address as a target.",
		prereq: []string{"web access log readable"}, note: "address classification is compiled in"},
	{id: "oast_indicator", cat: "web", desc: "Request references an out-of-band interaction (OAST) style hostname.",
		prereq: []string{"web access log readable"}, note: "provider suffixes are compiled in"},
	{id: "host_header_anomaly", cat: "web", desc: "Host header is an IP literal/loopback/unexpected, or many distinct Host values from one address.",
		prereq: []string{"web log format that records Host"}, settings: func(Context) []Setting {
			return []Setting{compiled("enumeration_window", secs(thresholds.HostHeaderEnumerationWindow), "seconds"), compiled("min_distinct_hosts", thresholds.HostHeaderEnumerationMinDistinctHosts, "")}
		}},
	{id: "http_protocol_anomaly", cat: "web", desc: "Sustained malformed methods/protocol tokens or protocol-error status codes.",
		prereq: []string{"web access log readable"}, settings: func(Context) []Setting {
			return []Setting{compiled("window", secs(thresholds.HTTPProtocolAnomalyWindow), "seconds"), compiled("min_count", thresholds.HTTPProtocolAnomalyMinCount, "")}
		}},
	{id: "request_smuggling_indicator", cat: "web", desc: "Burst of status codes that are symptoms of request-smuggling probes (not proof).",
		prereq: []string{"web access log readable"}, settings: func(Context) []Setting {
			return []Setting{compiled("window", secs(thresholds.RequestSmugglingWindow), "seconds"), compiled("min_count", thresholds.RequestSmugglingMinCount, "")}
		}},
	{id: "api_abuse", cat: "web", desc: "Many distinct endpoints with a high failure ratio from one address.",
		prereq: []string{"web access log readable"}, settings: func(Context) []Setting {
			return []Setting{compiled("window", secs(thresholds.APIAbuseWindow), "seconds"), compiled("min_distinct_paths", thresholds.APIAbuseMinDistinctPaths, ""), compiled("min_failure_ratio", float64(thresholds.APIAbuseMinFailureRatioTenths)/10, "ratio")}
		}},
	{id: "fim_change", cat: "host", desc: "A monitored sensitive file was created, deleted or changed.", group: "host", hostLocal: true,
		prereq: []string{"read access to monitored files"}, note: "monitored paths via -fim-paths"},
	{id: "persistence_detected", cat: "host", desc: "A new persistence entry (cron, systemd unit, authorized key, shell startup, sudoers).", group: "host", hostLocal: true,
		prereq: []string{"read access to persistence locations"}},
	{id: "privilege_escalation_indicator", cat: "host", desc: "New UID-0 account, privileged group membership, dangerous sudo rule or unexpected root process.", group: "host", hostLocal: true,
		prereq: []string{"/etc and /proc readable"}},
	{id: "account_security_change", cat: "host", desc: "Local user/group created, deleted or changed.", group: "host", hostLocal: true,
		prereq: []string{"/etc/passwd and /etc/group readable"}},
	{id: "suid_sgid_anomaly", cat: "host", desc: "New or removed SUID/SGID binary.", group: "host", hostLocal: true,
		prereq: []string{"read access to scanned directories"}, note: "roots via -suid-roots"},
	{id: "suspicious_process", cat: "host", desc: "Best-effort process heuristics (deleted executable, writable-dir execution, odd parentage, creation burst).", group: "host", hostLocal: true,
		prereq: []string{"/proc readable"}},
	{id: "high_confidence_compromise", cat: "correlation", desc: "A suspicious process corroborated by recent file activity or a listed outbound address.", group: "host", hostLocal: true,
		prereq: []string{"host security scanners enabled"}},
	{id: "system_binary_integrity_violation", cat: "host", desc: "A monitored system binary was replaced, deleted or had its permissions changed.", group: "host", hostLocal: true,
		prereq: []string{"read access to monitored binaries"}, note: "paths via -binary-paths"},
	{id: "configuration_posture", cat: "posture", desc: "A monitored path is world-writable, wrongly owned, or sshd is configured dangerously.", group: "posture", hostLocal: true,
		prereq: []string{"read access to monitored paths"}},
	{id: "configuration_drift", cat: "posture", desc: "A monitored configuration resource changed against its baseline.", group: "posture", hostLocal: true,
		prereq: []string{"read access to monitored paths"}},
	{id: "listening_service_drift", cat: "posture", desc: "The set of listening sockets changed against the baseline.", group: "posture", hostLocal: true,
		prereq: []string{"/proc/net readable"}},
	{id: "package_drift", cat: "posture", desc: "The dpkg package inventory changed against the baseline.", group: "posture", hostLocal: true,
		prereq: []string{"Debian/Ubuntu dpkg status file"}},
	{id: "ioc_match", cat: "threat_intel", desc: "An observed value exactly matched an active local threat indicator.", group: "intel",
		prereq: []string{"indicators imported", "Host logged for domain/URL indicators"}, note: "risk is capped below the auto-response threshold"},
}

// Build returns the inventory sorted by rule id.
func Build(c Context) []Rule {
	out := make([]Rule, 0, len(defs))
	for _, d := range defs {
		id := database.IncidentType(d.id)
		r := Rule{
			ID: d.id, Category: d.cat, Description: d.desc, Enabled: true, CanDisable: false,
			EvidenceKind: "observed", RuleRevision: detection.RuleRevision, BaseSeverity: risk.BaseSeverity[id],
			Prerequisites: d.prereq, Limitations: detection.LimitationFor(id), Settings: []Setting{}, SettingsNote: d.note,
		}
		if database.IsCorrelatedType(id) {
			r.EvidenceKind = "correlated"
		}
		if d.settings != nil {
			r.Settings = d.settings(c)
		} else if r.SettingsNote == "" {
			r.SettingsNote = "no numeric settings"
		}
		switch d.group {
		case "host":
			if !c.HostSecurity {
				r.Enabled, r.DisabledBy = false, "-hostsec=false"
			}
		case "posture":
			if !c.HostSecurity || !c.SystemPosture {
				r.Enabled, r.DisabledBy = false, "-hostsec=false or -system-posture=false"
			}
		case "intel":
			if !c.Intel {
				r.Enabled, r.DisabledBy = false, "-intel=false"
			}
		case "honeypot":
			if !c.Honeypot {
				r.Enabled, r.DisabledBy = false, "-honeypot=false"
			}
		}
		r.AutoResponse = autoResponse(c, id, d.hostLocal, r.BaseSeverity)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// autoResponse states, from the actual scoring bounds and Autopilot
// policy, whether an incident of this type could ever reach automatic
// blocking. It is an upper-bound statement ("possible in principle"), not
// a prediction.
func autoResponse(c Context, id database.IncidentType, hostLocal bool, base int) AutoResp {
	switch {
	case !c.AutopilotActive:
		return AutoResp{false, "Autopilot is disabled: incidents are left for manual review"}
	case id == database.IncidentIOCMatch:
		return AutoResp{false, fmt.Sprintf("risk is capped at %d, below the auto-response threshold", thresholds.MaxIOCOnlyRisk)}
	case hostLocal:
		return AutoResp{false, "host-local finding: the 127.0.0.1 source is always whitelisted and is never blocked"}
	case c.MinRiskToBan <= 0:
		return AutoResp{false, "Autopilot threshold unknown"}
	}
	// base + frequency cap (30) + reputation cap (30) + escalation (25)
	upper := base + 30 + 30 + 25
	if upper > 100 {
		upper = 100
	}
	if upper >= c.MinRiskToBan {
		return AutoResp{true, fmt.Sprintf("possible in principle: maximum attainable score %d >= threshold %d (requires enough frequency, reputation or escalation; whitelisted addresses are never blocked)", upper, c.MinRiskToBan)}
	}
	return AutoResp{false, fmt.Sprintf("maximum attainable score %d is below the threshold %d", upper, c.MinRiskToBan)}
}
