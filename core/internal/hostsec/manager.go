package hostsec

// manager.go bundles every Host Security scanner -- the five Phase 1
// scanners (FIM, Persistence, Account, PrivEsc, SUID/SGID) plus Phase 2's
// Process Anomaly Detection and System Binary Integrity -- behind a
// single Run(ctx) entry point, mirroring internal/metrics.Collector's own
// Run(ctx)-on-ticker shape so cmd/vanguard/serve.go can wire this in with
// the exact same goTracked(...) pattern used for every other background
// subsystem (see serve.go's startBackgroundTasks).
//
// Each scanner keeps its own ticker (their intervals genuinely differ --
// see thresholds.go's *ScanInterval constants) rather than sharing one,
// so a slow SUID/SGID filesystem walk can never delay the much cheaper,
// more time-sensitive FIM/Persistence/Account/PrivEsc scans.

import (
	"context"
	"sync"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/thresholds"
)

// Config controls which Host Security scanners run and where.
type Config struct {
	// FIMPaths overrides thresholds.DefaultFIMPaths when non-empty.
	FIMPaths []string
	// SUIDRoots overrides thresholds.DefaultSUIDScanRoots when non-empty
	// (thresholds.WritableScanRoots is always additionally scanned,
	// regardless of this override, since the writable-dir escalation
	// check depends on it).
	SUIDRoots []string
	// BinaryPaths overrides thresholds.DefaultSystemBinaryPaths when
	// non-empty (Phase 2, Feature 8: System Binary Integrity). Kept as an
	// explicit small allowlist, never a filesystem walk of /bin, /sbin,
	// /usr/bin, /usr/sbin wholesale, per the mega-prompt's own "do not
	// hash the entire filesystem by default" constraint.
	BinaryPaths []string

	// SystemPosture configures the four Phase 4 System Posture detectors
	// (Configuration Posture, Configuration Drift, Listening Service
	// Drift, Package Drift). Its zero value leaves them all disabled.
	SystemPosture SystemPostureConfig

	// Enabled toggles the whole Host Security subsystem. Defaults to
	// true; operators on a non-Linux dev sandbox or a container without
	// access to /etc, /proc etc. can disable it entirely.
	Enabled bool
}

// SystemPostureConfig groups the Phase 4 detector configurations and
// their scan cadence.
type SystemPostureConfig struct {
	Enabled bool

	Posture  PostureConfig
	Drift    ConfigDriftConfig
	Listen   ListeningConfig
	Packages PackageConfig

	EnablePosture, EnableDrift, EnableListening, EnablePackages bool

	// ScanInterval, when >0, overrides every Phase 4 detector's default
	// interval (floored at thresholds.MinPhase4ScanInterval). 0 keeps
	// the per-detector defaults from internal/thresholds.
	ScanInterval time.Duration
}

// DefaultSystemPostureConfig enables all four detectors with defaults.
func DefaultSystemPostureConfig() SystemPostureConfig {
	posture := DefaultPostureConfig()
	posture.Paths = thresholds.DefaultConfigPosturePaths
	posture.ExpectedOwners = thresholds.DefaultConfigPostureExpectedOwners
	return SystemPostureConfig{
		Enabled: true, EnablePosture: true, EnableDrift: true, EnableListening: true, EnablePackages: true,
		Posture:  posture,
		Drift:    DefaultConfigDriftConfig(),
		Listen:   DefaultListeningConfig(),
		Packages: DefaultPackageConfig(),
	}
}

// interval resolves a detector's effective scan interval.
func (c SystemPostureConfig) interval(def time.Duration) time.Duration {
	if c.ScanInterval <= 0 {
		return def
	}
	if c.ScanInterval < thresholds.MinPhase4ScanInterval {
		return thresholds.MinPhase4ScanInterval
	}
	return c.ScanInterval
}

// DefaultConfig returns the out-of-the-box scan target lists.
func DefaultConfig() Config {
	return Config{
		FIMPaths:      thresholds.DefaultFIMPaths,
		SUIDRoots:     thresholds.DefaultSUIDScanRoots,
		BinaryPaths:   thresholds.DefaultSystemBinaryPaths,
		SystemPosture: DefaultSystemPostureConfig(),
		Enabled:       true,
	}
}

// Manager owns every Host Security scanner and their independent
// scan-interval tickers.
type Manager struct {
	cfg Config

	fim         *FIMWatcher
	persistence *PersistenceDetector
	account     *AccountDetector
	privesc     *PrivEscDetector
	suid        *SUIDMonitor
	process     *ProcessDetector        // Phase 2, Feature 6
	binaries    *BinaryIntegrityWatcher // Phase 2, Feature 8

	// Phase 4 System Posture (nil when disabled).
	posture   *PostureDetector
	drift     *ConfigDriftDetector
	listening *ListeningDetector
	packages  *PackageDetector
}

// NewManager constructs every scanner, wiring reporter as the sink for
// every finding (in production, this is the detection.Engine itself --
// see engine_hostsec.go).
func NewManager(db *database.DB, reporter Reporter, cfg Config) *Manager {
	fimPaths := cfg.FIMPaths
	if len(fimPaths) == 0 {
		fimPaths = thresholds.DefaultFIMPaths
	}
	suidRoots := cfg.SUIDRoots
	if len(suidRoots) == 0 {
		suidRoots = thresholds.DefaultSUIDScanRoots
	}
	// The writable/temp directories are always scanned for SUID
	// binaries too, independent of any operator override, since the
	// CRITICAL escalation rule depends on having actually looked there.
	suidRoots = append(append([]string{}, suidRoots...), thresholds.WritableScanRoots...)

	binaryPaths := cfg.BinaryPaths
	if len(binaryPaths) == 0 {
		binaryPaths = thresholds.DefaultSystemBinaryPaths
	}

	m := &Manager{
		cfg:         cfg,
		fim:         NewFIMWatcher(db, reporter, fimPaths),
		persistence: NewPersistenceDetector(db, reporter),
		account:     NewAccountDetector(db, reporter),
		privesc:     NewPrivEscDetector(db, reporter),
		suid:        NewSUIDMonitor(db, reporter, suidRoots),
		process:     NewProcessDetector(db, reporter),
		binaries:    NewBinaryIntegrityWatcher(db, reporter, binaryPaths),
	}
	if sp := cfg.SystemPosture; sp.Enabled {
		if sp.EnablePosture {
			m.posture = NewPostureDetector(db, reporter, sp.Posture)
		}
		if sp.EnableDrift {
			m.drift = NewConfigDriftDetector(db, reporter, sp.Drift)
		}
		if sp.EnableListening {
			m.listening = NewListeningDetector(db, reporter, sp.Listen)
		}
		if sp.EnablePackages {
			m.packages = NewPackageDetector(db, reporter, sp.Packages)
		}
	}
	return m
}

// Run starts every scanner on its own ticker and blocks until ctx is
// cancelled, at which point every scanner goroutine has returned. Each
// scanner runs once immediately (matching serve.go's runMaintenanceLoop
// convention) so VANGUARD establishes its host-security baseline as soon
// as it starts, rather than waiting a full interval for the first pass.
func (m *Manager) Run(ctx context.Context) {
	if !m.cfg.Enabled {
		logf("manager", "Host Security scanning disabled (-hostsec=false)")
		return
	}

	var wg sync.WaitGroup
	loop := func(name string, interval time.Duration, scan func(context.Context)) {
		defer wg.Done()
		runOnce(ctx, name, scan)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runOnce(ctx, name, scan)
			}
		}
	}

	scanners := []struct {
		name     string
		interval time.Duration
		scan     func(context.Context)
	}{
		{"fim", thresholds.FIMScanInterval, m.fim.Scan},
		{"persistence", thresholds.PersistenceScanInterval, m.persistence.Scan},
		{"account", thresholds.AccountScanInterval, m.account.Scan},
		{"privesc", thresholds.PrivEscScanInterval, m.privesc.Scan},
		{"suid", thresholds.SUIDScanInterval, m.suid.Scan},
		{"process", thresholds.ProcessScanInterval, m.process.Scan},
		{"binary_integrity", thresholds.BinaryIntegrityScanInterval, m.binaries.Scan},
	}
	sp := m.cfg.SystemPosture
	if m.posture != nil {
		scanners = append(scanners, struct {
			name     string
			interval time.Duration
			scan     func(context.Context)
		}{"config_posture", sp.interval(thresholds.ConfigPostureScanInterval), m.posture.Scan})
	}
	if m.drift != nil {
		scanners = append(scanners, struct {
			name     string
			interval time.Duration
			scan     func(context.Context)
		}{"config_drift", sp.interval(thresholds.ConfigDriftScanInterval), m.drift.Scan})
	}
	if m.listening != nil {
		scanners = append(scanners, struct {
			name     string
			interval time.Duration
			scan     func(context.Context)
		}{"listening", sp.interval(thresholds.ListeningServiceScanInterval), m.listening.Scan})
	}
	if m.packages != nil {
		scanners = append(scanners, struct {
			name     string
			interval time.Duration
			scan     func(context.Context)
		}{"package_drift", sp.interval(thresholds.PackageDriftScanInterval), m.packages.Scan})
	}
	for _, s := range scanners {
		wg.Add(1)
		go loop(s.name, s.interval, s.scan)
	}
	wg.Wait()
}

// runOnce bounds a single scan tick with thresholds.HostScanTimeout, per
// Phase 13's requirement that every periodic scanner have a configurable
// interval + context cancellation + timeout, so a pathological filesystem
// (e.g. a stuck network mount) can never wedge a scanner goroutine
// forever.
func runOnce(parent context.Context, name string, scan func(context.Context)) {
	ctx, cancel := context.WithTimeout(parent, thresholds.HostScanTimeout)
	defer cancel()
	start := time.Now()
	scan(ctx)
	if elapsed := time.Since(start); elapsed > thresholds.HostScanTimeout/2 {
		logf(name, "scan took %s (approaching the %s timeout)", elapsed, thresholds.HostScanTimeout)
	}
}
