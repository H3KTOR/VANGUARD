package hostsec

// ---------------------------------------------------------------------------
// Phase 4, Detector A: Configuration Posture
//
// Detection:   a small, bounded set of deterministic checks against an
//              explicit allowlist of security-sensitive paths -- never a
//              filesystem walk:
//                1. dangerous permissions: is a monitored path currently
//                   world-writable?
//                2. sensitive file ownership: does a monitored path's
//                   current uid:gid match an EXPLICITLY configured
//                   expected value? (a path with no configured expected
//                   owner is never ownership-checked -- no "assume
//                   UID 0" default.)
//                3. dangerous service configuration: a bounded, portable
//                   textual check of /etc/ssh/sshd_config for a small set
//                   of known-dangerous directive values (e.g.
//                   PermitRootLogin yes).
// Evidence:    a structured PostureCheckResult (check ID, resource,
//              observed value, expected value, severity, reason,
//              timestamp) -- never free-form-only evidence, per the
//              mega-prompt's explicit "posture result model" requirement.
// Risk:        database.IncidentConfigurationPosture (see
//              risk.BaseSeverity); Critical-escalated for the same
//              highest-value targets FIM/Drift already treat specially
//              (/etc/shadow, /etc/sudoers, /etc/ssh/sshd_config,
//              authorized_keys).
// Correlation: standard Incident pipeline (ReportHostFinding).
// Response:    alert-only (SourceIP=HostLocalIP; see fim.go doc comment).
// False positives: this is NOT a history-based diff (that is
//              Configuration Drift's job) -- it is "is the CURRENT state
//              unsafe", so there is no cold-start/first-scan suppression:
//              an unsafe state present at VANGUARD's very first scan is
//              exactly as reportable as one that appears later. What IS
//              suppressed is re-reporting the IDENTICAL unsafe finding
//              on every subsequent scan tick: each check's last-reported
//              result is itself persisted (BaselineConfigPosture) and a
//              finding is only re-raised when that specific check's
//              observed/expected/severity tuple actually changes (e.g.
//              the mode changes from one unsafe value to a different
//              unsafe value) or it had previously resolved to safe and
//              has now regressed. A path returning to a safe state
//              clears its stored result, so a later regression to the
//              SAME unsafe value is correctly reported again rather than
//              being permanently suppressed by stale state. A missing
//              optional monitored path (os.IsNotExist) is never itself a
//              finding.
// ---------------------------------------------------------------------------

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"vanguard/core/internal/database"
)

// PostureCheckResult is the structured evidence model every Configuration
// Posture check produces, per the mega-prompt's explicit "never
// free-form-only evidence" instruction.
type PostureCheckResult struct {
	CheckID   string    `json:"check_id"`
	Resource  string    `json:"resource"`
	Observed  string    `json:"observed"`
	Expected  string    `json:"expected"`
	Severity  string    `json:"severity"` // descriptive bucket ("low"/"medium"/"high"), not the final risk.Score total
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// fingerprint produces a stable string used to detect whether this exact
// result has already been reported, so an unchanged unsafe condition
// isn't re-raised as a brand-new incident on every scan tick.
func (r PostureCheckResult) fingerprint() string {
	return r.CheckID + "|" + r.Resource + "|" + r.Observed + "|" + r.Expected + "|" + r.Severity
}

// criticalPosturePaths mirrors criticalFIMPaths: any posture violation on
// one of these paths is escalated to Critical=true regardless of which
// specific check fired.
var criticalPosturePaths = map[string]bool{
	"/etc/shadow":                true,
	"/etc/sudoers":               true,
	"/etc/ssh/sshd_config":       true,
	"/root/.ssh/authorized_keys": true,
}

// sshdDangerousDirective describes one bounded, portable sshd_config
// directive check. VANGUARD does not invoke sshd or any service manager
// -- this is a plain textual read of the config file, matching the
// mega-prompt's "no shell command construction" / "deterministic
// portable checks only" constraints.
type sshdDangerousDirective struct {
	name            string          // lowercase directive name
	dangerousValues map[string]bool // lowercase dangerous values
	reason          string
}

var sshdDangerousDirectives = []sshdDangerousDirective{
	{
		name:            "permitrootlogin",
		dangerousValues: map[string]bool{"yes": true},
		reason:          "root login is permitted via SSH (PermitRootLogin yes)",
	},
	{
		name:            "permitemptypasswords",
		dangerousValues: map[string]bool{"yes": true},
		reason:          "accounts with empty passwords are permitted to authenticate via SSH (PermitEmptyPasswords yes)",
	},
}

// PostureConfig controls which checks run and over which targets.
type PostureConfig struct {
	// Paths is the explicit allowlist of files/directories checked for
	// dangerous permissions. Never a recursive filesystem walk.
	Paths []string
	// ExpectedOwners maps a path (that MUST also appear in Paths to be
	// checked at all) to its expected "uid:gid" string. A path absent
	// from this map is never ownership-checked.
	ExpectedOwners map[string]string

	// EnablePermissionCheck/.../EnableServiceConfigCheck let an operator
	// (or a test) disable one specific check without disabling the
	// whole detector.
	EnablePermissionCheck    bool
	EnableOwnershipCheck     bool
	EnableServiceConfigCheck bool

	// SSHDConfigPath overrides the default /etc/ssh/sshd_config location
	// (primarily for tests).
	SSHDConfigPath string
}

// DefaultPostureConfig returns the out-of-the-box Configuration Posture
// configuration.
func DefaultPostureConfig() PostureConfig {
	return PostureConfig{
		EnablePermissionCheck:    true,
		EnableOwnershipCheck:     true,
		EnableServiceConfigCheck: true,
	}
}

// PostureDetector implements Configuration Posture (Phase 4, Detector A).
type PostureDetector struct {
	db       *database.DB
	reporter Reporter
	cfg      PostureConfig

	// root prefixes every checked path. Defaults to "" (the real host
	// filesystem); unit tests set it to a tmpdir via WithRoot.
	root string
	rep  scanReporter
}

// NewPostureDetector constructs a Configuration Posture detector. An
// invalid/empty cfg.Paths list is not an error -- the permission/
// ownership checks simply have nothing to do, which is a fail-safe
// no-op, not a crash.
func NewPostureDetector(db *database.DB, reporter Reporter, cfg PostureConfig) *PostureDetector {
	return &PostureDetector{db: db, reporter: reporter, cfg: cfg}
}

// WithRoot returns a copy of d rooted at root, for tests only.
func (d *PostureDetector) WithRoot(root string) *PostureDetector {
	d2 := *d
	d2.root = root
	return &d2
}

func (d *PostureDetector) path(p string) string { return d.root + p }

// Scan performs one full Configuration Posture pass: every enabled check,
// over every configured path, plus the bounded service-configuration
// check. There is no first-scan concept here (see package doc comment
// above) -- every pass evaluates the CURRENT state against policy.
func (d *PostureDetector) Scan(ctx context.Context) {
	for _, p := range d.cfg.Paths {
		if ctx.Err() != nil {
			logf("posture", "scan cancelled/timed out, stopping early")
			return
		}
		if d.cfg.EnablePermissionCheck {
			d.checkPermissions(p)
		}
		if d.cfg.EnableOwnershipCheck {
			d.checkOwnership(p)
		}
	}

	if d.cfg.EnableServiceConfigCheck {
		d.checkSSHDConfig()
	}
}

// checkPermissions flags a monitored path that is currently
// world-writable (mode bit 0002). A path that doesn't exist right now is
// silently skipped -- a missing OPTIONAL monitored path is never itself
// a finding, per the mega-prompt's explicit false-positive policy.
func (d *PostureDetector) checkPermissions(p string) {
	const checkID = "dangerous_permissions"
	key := checkID + ":" + p

	info, err := os.Lstat(d.path(p))
	if err != nil {
		if os.IsNotExist(err) {
			d.clearResult(key)
			return
		}
		logf("posture", "failed to stat %s for permission check: %v", p, err)
		d.rep.fail("cannot stat " + p + ": " + err.Error())
		return
	}

	mode := info.Mode()
	worldWritable := mode.Perm()&0o002 != 0
	if !worldWritable {
		d.clearResult(key)
		return
	}

	result := PostureCheckResult{
		CheckID:   checkID,
		Resource:  p,
		Observed:  mode.Perm().String(),
		Expected:  "not world-writable (no o+w permission bit)",
		Severity:  "high",
		Reason:    "security-sensitive file/directory is world-writable, allowing any local user to modify it",
		Timestamp: time.Now().UTC(),
	}
	d.reportIfChanged(key, result)
}

// checkOwnership flags a monitored path whose current uid:gid does not
// match an EXPLICITLY configured expected owner. Paths with no entry in
// cfg.ExpectedOwners are never checked -- there is no "assume UID 0"
// default.
func (d *PostureDetector) checkOwnership(p string) {
	expected, ok := d.cfg.ExpectedOwners[p]
	if !ok {
		return
	}
	if !isValidOwnerSpec(expected) {
		logf("posture", "invalid expected-owner spec %q for %s, skipping ownership check (fail-safe)", expected, p)
		return
	}

	const checkID = "unexpected_ownership"
	key := checkID + ":" + p

	info, err := os.Lstat(d.path(p))
	if err != nil {
		if os.IsNotExist(err) {
			d.clearResult(key)
			return
		}
		logf("posture", "failed to stat %s for ownership check: %v", p, err)
		d.rep.fail("cannot stat " + p + ": " + err.Error())
		return
	}
	uid, gid, ok := ownerOf(info)
	if !ok {
		return
	}
	observed := fmt.Sprintf("%d:%d", uid, gid)
	if observed == expected {
		d.clearResult(key)
		return
	}

	result := PostureCheckResult{
		CheckID:   checkID,
		Resource:  p,
		Observed:  observed,
		Expected:  expected,
		Severity:  "medium",
		Reason:    "security-sensitive file's owning user/group does not match the configured expected owner",
		Timestamp: time.Now().UTC(),
	}
	d.reportIfChanged(key, result)
}

// checkSSHDConfig implements the bounded, portable "dangerous service
// configuration" check: a plain textual scan of sshd_config for a small
// set of known-dangerous directive values. Never shells out to sshd or
// any service manager. A missing config file is not a finding (an
// optional check target that simply isn't present on this host).
func (d *PostureDetector) checkSSHDConfig() {
	sshdPath := d.cfg.SSHDConfigPath
	if sshdPath == "" {
		sshdPath = "/etc/ssh/sshd_config"
	}

	directives, err := parseSSHDConfig(d.path(sshdPath))
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		logf("posture", "failed to read sshd config %s: %v", sshdPath, err)
		return
	}

	for _, dd := range sshdDangerousDirectives {
		checkID := "sshd_" + dd.name
		key := checkID + ":" + sshdPath

		value, present := directives[dd.name]
		if !present || !dd.dangerousValues[strings.ToLower(value)] {
			d.clearResult(key)
			continue
		}

		result := PostureCheckResult{
			CheckID:   checkID,
			Resource:  sshdPath,
			Observed:  dd.name + " " + value,
			Expected:  dd.name + " not set to a dangerous value",
			Severity:  "high",
			Reason:    dd.reason,
			Timestamp: time.Now().UTC(),
		}
		d.reportIfChanged(key, result)
	}
}

// reportIfChanged reports result only if it differs from the last result
// stored for key (or none was stored yet), then persists the new
// fingerprint -- the dedup mechanism documented in the package doc
// comment above.
func (d *PostureDetector) reportIfChanged(key string, result PostureCheckResult) {
	row, err := d.db.GetHostBaseline(database.BaselineConfigPosture, key)
	if err == nil {
		var prev PostureCheckResult
		if row.GetContent(&prev) == nil && prev.fingerprint() == result.fingerprint() {
			return // identical unsafe state already reported; suppress
		}
	} else if err != database.ErrNotFound {
		logf("posture", "baseline lookup failed for %s: %v", key, err)
		d.rep.fail("baseline store unavailable: " + err.Error())
		return
	}

	critical := criticalPosturePaths[result.Resource]
	note := ""
	if critical {
		note = "configuration posture violation on a highest-value credential/access-control target (" + result.Resource + ")"
	}

	// Subject deliberately combines check ID + resource (not just the
	// bare resource path): internal/detection's dedupe window keys on
	// (HostLocalIP, Subject, Type) with a cooldown -- using the bare
	// path here would let a SECOND, genuinely distinct check finding on
	// the same resource in the same scan (e.g. both
	// dangerous_permissions and unexpected_ownership on /etc/shadow)
	// be silently swallowed as a false "duplicate" of the first.
	d.reporter.ReportHostFinding(Finding{
		Type:           database.IncidentConfigurationPosture,
		Change:         result.CheckID,
		Subject:        result.CheckID + ":" + result.Resource,
		Critical:       critical,
		EscalationNote: note,
		Details: map[string]any{
			"check_id":  result.CheckID,
			"resource":  result.Resource,
			"observed":  result.Observed,
			"expected":  result.Expected,
			"severity":  result.Severity,
			"reason":    result.Reason,
			"timestamp": result.Timestamp,
		},
	})

	if err := saveJSON(d.db, database.BaselineConfigPosture, key, result); err != nil {
		logf("posture", "failed to save posture result for %s: %v", key, err)
	}
}

// clearResult removes a stored posture result once the underlying
// condition resolves back to safe, so a later regression to the exact
// same unsafe value is reported again rather than permanently
// suppressed by stale state.
func (d *PostureDetector) clearResult(key string) {
	_ = d.db.DeleteHostBaseline(database.BaselineConfigPosture, key)
}

// isValidOwnerSpec reports whether s looks like a "uid:gid" pair of
// non-negative integers. Used as a fail-safe guard against operator
// misconfiguration (Section 24's "invalid configuration must not
// silently create dangerous behavior" -- here, that means skipping the
// check entirely rather than comparing against a garbage value that
// could never match, which would effectively always-alert).
func isValidOwnerSpec(s string) bool {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// parseSSHDConfig reads path into a lowercase-directive-name -> value
// map, honoring sshd's own "first occurrence wins" semantics. Comments
// and blank lines are skipped via the shared nonComment helper.
func parseSSHDConfig(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !nonComment(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, exists := out[name]; exists {
			continue // sshd uses the first occurrence of a directive
		}
		out[name] = fields[1]
	}
	return out, nil
}
