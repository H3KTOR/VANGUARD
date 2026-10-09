package rules

import (
	"fmt"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/tuning"
)

const (
	guidanceWindow    = 30 * 24 * time.Hour
	guidanceMinCount  = 20
	guidanceFPRatioPc = 50
)

// Guidance is a descriptive, non-binding observation about one tunable
// rule. It is NEVER applied automatically.
type Guidance struct {
	RuleID         string `json:"rule_id"`
	Key            string `json:"key"`
	WindowDays     int    `json:"window_days"`
	Incidents      int64  `json:"incidents"`
	FalsePositives int64  `json:"marked_false_positive"`
	Current        int    `json:"current_value"`
	Default        int    `json:"default_value"`
	Recommendation string `json:"recommendation"`
	// Basis explains exactly what the numbers are and are not.
	Basis string `json:"basis"`
}

const guidanceBasis = "Counts are retained incidents and analyst-assigned statuses only. They are not precision, recall or a false-positive rate: incidents an attacker or a misbehaving client causes are counted, unlabelled incidents say nothing, and missed attacks are invisible."

// BuildGuidance summarizes analyst feedback per tunable rule.
func BuildGuidance(db *database.DB, cur tuning.Values, now time.Time) ([]Guidance, error) {
	since := now.Add(-guidanceWindow)
	var out []Guidance
	for _, sp := range tuning.Specs() {
		var n, fp int64
		if err := db.Model(&database.Incident{}).Where("type = ? AND detected_at >= ?", sp.Rule, since).Count(&n).Error; err != nil {
			return nil, err
		}
		if err := db.Model(&database.Incident{}).Where("type = ? AND detected_at >= ? AND status = ?", sp.Rule, since, database.StatusFalsePositive).Count(&fp).Error; err != nil {
			return nil, err
		}
		curV := *valueOf(&cur, sp.Key)
		g := Guidance{RuleID: sp.Rule, Key: sp.Key, WindowDays: int(guidanceWindow.Hours() / 24), Incidents: n, FalsePositives: fp, Current: curV, Default: sp.Default, Basis: guidanceBasis}
		switch {
		case n < guidanceMinCount:
			g.Recommendation = fmt.Sprintf("Insufficient evidence: %d incident(s) in %d days (need at least %d). No change suggested.", n, g.WindowDays, guidanceMinCount)
		case fp*100 >= n*guidanceFPRatioPc:
			g.Recommendation = fmt.Sprintf("Analysts marked %d of %d incidents false positive. If that traffic is expected in your environment, review this threshold (current %d, compiled default %d, allowed up to %d). Suggestion only: raising it makes the rule less sensitive and needs an explicit acknowledgement.", fp, n, curV, sp.Default, sp.Max)
		default:
			g.Recommendation = "No tuning suggested: analyst feedback does not indicate a threshold problem."
		}
		out = append(out, g)
	}
	return out, nil
}

func valueOf(v *tuning.Values, key string) *int {
	switch key {
	case "ssh_bruteforce_min_attempts":
		return &v.SSHBruteForceMinAttempts
	case "failed_then_success_min_failed":
		return &v.FailedThenSuccessMinFailed
	case "port_scan_distinct_ports":
		return &v.PortScanDistinctPorts
	case "web_dir_scan_min_404s":
		return &v.WebDirScanMin404s
	default:
		return &v.HTTPFloodMaxRequests
	}
}
