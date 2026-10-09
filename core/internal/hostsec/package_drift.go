package hostsec

// ---------------------------------------------------------------------------
// Phase 4, Detector D: Package Drift
//
// Detection:   /var/lib/dpkg/status (Debian/Ubuntu) is parsed directly --
//              apt/dpkg are never executed. The inventory is a bounded,
//              structured map keyed by "<name>:<architecture>" holding
//              version and install state.
// Baseline:    one atomic JSON snapshot row (BaselinePackage, key
//              "snapshot"). The first successful scan establishes it
//              silently; the full inventory is never an incident.
// Drift:       installed, removed, version_changed (classified as
//              upgrade or downgrade with dpkg version ordering),
//              state_changed, architecture_changed.
// Policy:      IgnoredPackages are excluded in both directions.
//              WatchedPackages (security-sensitive: sshd, sudo, firewall,
//              TLS) escalate on removal/downgrade; HighRiskPatterns
//              (glob) weight fresh installs of dual-use tooling higher.
// Fail-safe:   a missing/unreadable/unparseable package database
//              disables the detector for that tick (logged once per
//              outage) and NEVER fabricates "all packages removed"; the
//              previous baseline is untouched.
// ---------------------------------------------------------------------------

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

const (
	packageSnapshotKey  = "snapshot"
	defaultDpkgStatus   = "/var/lib/dpkg/status"
	maxPackageLineBytes = 1024 * 1024
)

// PackageConfig controls the Package Drift detector.
type PackageConfig struct {
	// StatusPath overrides /var/lib/dpkg/status (tests).
	StatusPath string
	// Ignored package names are excluded from drift detection.
	Ignored []string
	// Watched package names escalate on removal/downgrade.
	Watched []string
	// HighRiskPatterns are path.Match globs weighting fresh installs.
	HighRiskPatterns []string
}

// DefaultPackageConfig returns the out-of-the-box configuration.
func DefaultPackageConfig() PackageConfig {
	return PackageConfig{
		StatusPath:       defaultDpkgStatus,
		Ignored:          thresholds.DefaultIgnoredPackages,
		Watched:          thresholds.DefaultWatchedSecurityPackages,
		HighRiskPatterns: thresholds.DefaultHighRiskPackagePatterns,
	}
}

// Package is one installed-package record (and the persisted shape).
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	State   string `json:"state"` // dpkg "Status" third word, e.g. installed
}

// Key is the stable identity "<name>:<arch>".
func (p Package) Key() string { return p.Name + ":" + p.Arch }

type packageSnapshot struct {
	Packages  map[string]Package `json:"packages"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// PackageChange is one detected drift.
type PackageChange struct {
	Kind string // installed, removed, upgraded, downgraded, state_changed, architecture_changed
	Prev *Package
	Curr *Package
}

// PackageDetector implements Package Drift.
type PackageDetector struct {
	db       *database.DB
	reporter Reporter
	cfg      PackageConfig

	ignored map[string]bool
	watched map[string]bool

	// unavailable tracks an ongoing outage so it is logged once, not
	// on every tick.
	unavailable atomic.Bool
}

// NewPackageDetector constructs the detector.
func NewPackageDetector(db *database.DB, reporter Reporter, cfg PackageConfig) *PackageDetector {
	if cfg.StatusPath == "" {
		cfg.StatusPath = defaultDpkgStatus
	}
	d := &PackageDetector{db: db, reporter: reporter, cfg: cfg,
		ignored: map[string]bool{}, watched: map[string]bool{}}
	for _, n := range cfg.Ignored {
		d.ignored[strings.TrimSpace(n)] = true
	}
	for _, n := range cfg.Watched {
		d.watched[strings.TrimSpace(n)] = true
	}
	return d
}

// Scan performs one full Package Drift pass.
func (d *PackageDetector) Scan(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	inv, err := readDpkgStatus(d.cfg.StatusPath)
	if err != nil {
		if d.unavailable.CompareAndSwap(false, true) {
			logf("package_drift", "package database unavailable (%v): detector idle until it is readable; baseline preserved", err)
		}
		return
	}
	if d.unavailable.CompareAndSwap(true, false) {
		logf("package_drift", "package database available again")
	}

	curr := make(map[string]Package, len(inv))
	for k, p := range inv {
		if d.ignored[p.Name] {
			continue
		}
		curr[k] = p
	}

	var prev packageSnapshot
	have, err := loadSnapshot(d.db, database.BaselinePackage, packageSnapshotKey, &prev)
	if err != nil {
		logf("package_drift", "baseline unavailable: %v (not replacing it)", err)
		return
	}
	save := func() {
		snap := packageSnapshot{Packages: curr, UpdatedAt: time.Now().UTC()}
		if err := saveJSON(d.db, database.BaselinePackage, packageSnapshotKey, snap); err != nil {
			logf("package_drift", "failed to store baseline: %v", err)
		}
	}
	if !have {
		save()
		logf("package_drift", "baseline created (%d packages)", len(curr))
		return
	}

	prevFiltered := make(map[string]Package, len(prev.Packages))
	for k, p := range prev.Packages {
		if !d.ignored[p.Name] {
			prevFiltered[k] = p
		}
	}

	changes := diffPackages(prevFiltered, curr)
	if len(changes) == 0 {
		if len(prevFiltered) != len(prev.Packages) {
			save()
		}
		return
	}
	for _, c := range changes {
		d.report(c, prev.UpdatedAt)
	}
	save()
	logf("package_drift", "baseline changed (%d change(s))", len(changes))
}

// readDpkgStatus parses a dpkg status file into name:arch -> Package.
// Only fully-qualified stanzas (Package, Version, Architecture, Status)
// are kept; malformed stanzas are skipped. Packages in the
// not-installed / config-files states are treated as absent. An
// unreadable file, an oversized one, or a non-empty file yielding zero
// packages is an error (the caller must not treat that as "empty").
func readDpkgStatus(statusPath string) (map[string]Package, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > thresholds.MaxPackageStatusBytes {
		return nil, fmt.Errorf("status file too large (%d bytes)", st.Size())
	}
	pkgs, nonEmpty, err := parseDpkgStatus(io.LimitReader(f, thresholds.MaxPackageStatusBytes))
	if err != nil {
		return nil, err
	}
	if nonEmpty && len(pkgs) == 0 {
		return nil, errors.New("package database parsed to zero packages (malformed?)")
	}
	return pkgs, nil
}

// parseDpkgStatus is the reader-based pure parser. nonEmpty reports
// whether any non-blank input was seen.
func parseDpkgStatus(r io.Reader) (pkgs map[string]Package, nonEmpty bool, err error) {
	pkgs = make(map[string]Package)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxPackageLineBytes)

	var cur Package
	var status string
	flush := func() {
		defer func() { cur, status = Package{}, "" }()
		if cur.Name == "" || cur.Version == "" || cur.Arch == "" || status == "" {
			return
		}
		words := strings.Fields(status)
		if len(words) < 3 {
			return
		}
		state := words[len(words)-1]
		if state == "not-installed" || state == "config-files" {
			return
		}
		cur.State = state
		if len(pkgs) >= thresholds.MaxPackages {
			return
		}
		pkgs[cur.Key()] = cur
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		nonEmpty = true
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation of a multi-line field (e.g. Description)
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			cur.Name = v
		case "Version":
			cur.Version = v
		case "Architecture":
			cur.Arch = v
		case "Status":
			status = v
		}
	}
	flush()
	return pkgs, nonEmpty, sc.Err()
}

// diffPackages computes drift between two inventories. Pure function;
// output is deterministically sorted.
func diffPackages(prev, curr map[string]Package) []PackageChange {
	var changes []PackageChange
	var added, removed []Package
	for k, c := range curr {
		p, ok := prev[k]
		if !ok {
			added = append(added, c)
			continue
		}
		cc, pp := c, p
		switch {
		case p.Version != c.Version:
			kind := "upgraded"
			if compareDebVersions(c.Version, p.Version) < 0 {
				kind = "downgraded"
			}
			changes = append(changes, PackageChange{Kind: kind, Prev: &pp, Curr: &cc})
		case p.State != c.State:
			changes = append(changes, PackageChange{Kind: "state_changed", Prev: &pp, Curr: &cc})
		}
	}
	for k, p := range prev {
		if _, ok := curr[k]; !ok {
			removed = append(removed, p)
		}
	}

	// Architecture change: a name with exactly one removed and one added
	// identity and no surviving identity of the same name.
	byNameAdded := map[string][]int{}
	byNameRemoved := map[string][]int{}
	for i, a := range added {
		byNameAdded[a.Name] = append(byNameAdded[a.Name], i)
	}
	for i, r := range removed {
		byNameRemoved[r.Name] = append(byNameRemoved[r.Name], i)
	}
	survives := func(name string) bool {
		for _, c := range curr {
			if c.Name == name {
				if _, was := prev[c.Key()]; was {
					return true
				}
			}
		}
		return false
	}
	usedAdd, usedRem := map[int]bool{}, map[int]bool{}
	for name, ai := range byNameAdded {
		ri := byNameRemoved[name]
		if len(ai) == 1 && len(ri) == 1 && !survives(name) {
			a, r := added[ai[0]], removed[ri[0]]
			usedAdd[ai[0]], usedRem[ri[0]] = true, true
			changes = append(changes, PackageChange{Kind: "architecture_changed", Prev: &r, Curr: &a})
		}
	}
	for i, a := range added {
		if !usedAdd[i] {
			aa := a
			changes = append(changes, PackageChange{Kind: "installed", Curr: &aa})
		}
	}
	for i, r := range removed {
		if !usedRem[i] {
			rr := r
			changes = append(changes, PackageChange{Kind: "removed", Prev: &rr})
		}
	}
	sort.SliceStable(changes, func(i, j int) bool {
		return pkgChangeKey(changes[i]) < pkgChangeKey(changes[j])
	})
	return changes
}

func pkgChangeKey(c PackageChange) string {
	p := c.Curr
	if p == nil {
		p = c.Prev
	}
	return p.Key() + "|" + c.Kind
}

// suspiciousStates are dpkg states that indicate an interrupted or
// unusual package operation.
var suspiciousStates = map[string]bool{
	"half-installed": true, "half-configured": true, "unpacked": true,
	"triggers-awaited": true, "triggers-pending": true,
}

// classifyPackageChange maps a change to a contextual risk adjustment and
// an optional hard escalation. Pure function.
func (d *PackageDetector) classifyPackageChange(c PackageChange) (adjust int, critical bool, note string) {
	name := ""
	if c.Curr != nil {
		name = c.Curr.Name
	} else {
		name = c.Prev.Name
	}
	watched := d.watched[name]
	switch c.Kind {
	case "upgraded":
		adjust, note = -10, "ordinary package update"
		if watched {
			adjust, note = -5, "update of a security-sensitive package"
		}
	case "installed":
		adjust, note = 5, "unexpected package installation"
		for _, pat := range d.cfg.HighRiskPatterns {
			if ok, _ := path.Match(pat, name); ok {
				adjust, note = 20, "installation of a high-risk (dual-use tooling) package"
				break
			}
		}
	case "downgraded":
		adjust, note = 20, "package version downgrade"
		if watched {
			critical, note = true, "downgrade of a security-sensitive package"
		}
	case "removed":
		adjust, note = 0, "package removed"
		if watched {
			critical, note = true, "removal of a security-sensitive package"
		}
	case "state_changed":
		adjust, note = 0, "package install state changed"
		if c.Curr != nil && suspiciousStates[c.Curr.State] {
			adjust, note = 15, "package left in an interrupted/unusual state ("+c.Curr.State+")"
		}
	case "architecture_changed":
		adjust, note = 10, "package architecture changed"
	}
	return adjust, critical, note
}

func (d *PackageDetector) report(c PackageChange, baselineAt time.Time) {
	adjust, critical, note := d.classifyPackageChange(c)
	cur := c.Curr
	if cur == nil {
		cur = c.Prev
	}
	details := map[string]any{
		"change":           c.Kind,
		"package":          cur.Name,
		"architecture":     cur.Arch,
		"package_state":    cur.State,
		"new_version":      "",
		"old_version":      "",
		"risk_context":     note,
		"watched_package":  d.watched[cur.Name],
		"baseline_age_sec": ageSeconds(baselineAt),
		"detected_at":      time.Now().UTC(),
	}
	if c.Prev != nil {
		details["old_version"] = c.Prev.Version
		details["previous_state"] = c.Prev
	}
	if c.Curr != nil {
		details["new_version"] = c.Curr.Version
		details["current_state"] = c.Curr
	}
	f := Finding{
		Type:       database.IncidentPackageDrift,
		Change:     c.Kind,
		Subject:    "package_drift:" + c.Kind + ":" + cur.Key() + ":" + details["new_version"].(string),
		RiskAdjust: adjust,
		Details:    details,
	}
	if critical {
		f.Critical = true
		f.EscalationNote = note + " (" + cur.Name + ")"
	}
	d.reporter.ReportHostFinding(f)
}

// ---------------------------------------------------------------------------
// dpkg version ordering (Debian Policy 5.6.12)
// ---------------------------------------------------------------------------

// compareDebVersions returns <0, 0, >0 as a is older than, equal to, or
// newer than b under dpkg's epoch:upstream-revision ordering.
func compareDebVersions(a, b string) int {
	ea, ua, ra := splitDebVersion(a)
	eb, ub, rb := splitDebVersion(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := compareDebPart(ua, ub); c != 0 {
		return c
	}
	return compareDebPart(ra, rb)
}

func splitDebVersion(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		for _, c := range v[:i] {
			if c < '0' || c > '9' {
				epoch = 0
				goto noEpoch
			}
			epoch = epoch*10 + int(c-'0')
			if epoch > 1<<30 {
				break
			}
		}
		v = v[i+1:]
	}
noEpoch:
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func debOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	default:
		return int(c) + 256
	}
}

func compareDebPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// compare the non-digit prefix
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ca, cb int
			if i < len(a) && !isDigit(a[i]) {
				ca = debOrder(a[i])
			}
			if j < len(b) && !isDigit(b[j]) {
				cb = debOrder(b[j])
			}
			if ca != cb {
				if ca < cb {
					return -1
				}
				return 1
			}
			if i < len(a) && !isDigit(a[i]) {
				i++
			}
			if j < len(b) && !isDigit(b[j]) {
				j++
			}
		}
		// compare the digit run numerically
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		si, sj := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		la, lb := i-si, j-sj
		if la != lb {
			if la < lb {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
