// serve.go wires every VANGUARD subsystem (database, detection engine,
// Autopilot/firewall, honeypot, metrics collector, and REST API) into a
// single long-running daemon process, and owns its full lifecycle:
// construction order, concurrent startup, and coordinated graceful
// shutdown on SIGINT/SIGTERM.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/api"
	"vanguard/core/internal/auth"
	"vanguard/core/internal/backup"
	"vanguard/core/internal/database"
	"vanguard/core/internal/detection"
	"vanguard/core/internal/firewall"
	"vanguard/core/internal/health"
	"vanguard/core/internal/honeypot"
	"vanguard/core/internal/hostsec"
	"vanguard/core/internal/intel"
	"vanguard/core/internal/metrics"
	"vanguard/core/internal/notify"
	"vanguard/core/internal/pipeline"
	"vanguard/core/internal/retention"
	"vanguard/core/internal/rules"
	"vanguard/core/internal/simulator"
	"vanguard/core/internal/tuning"
)

// runServeCmd is the entry point for `vanguard serve`. It parses flags,
// builds every component, starts them concurrently, then blocks until an
// OS signal (or an unrecoverable component failure) triggers an orderly
// shutdown.
func runServeCmd(args []string) {
	cfg := parseServeFlags(args)

	log.Printf("[serve] VANGUARD Core starting (db=%s http=%s)", cfg.DBPath, cfg.HTTPAddr)

	app, err := buildApp(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanguard serve: %v\n", err)
		os.Exit(1)
	}

	app.run()
}

// app holds every long-lived component `serve` orchestrates, plus the
// primitives needed to coordinate a clean shutdown: a single root context
// cancelled on signal, and a WaitGroup every background goroutine joins so
// Run() can block until they've *all* actually stopped -- not just been
// asked to -- before the database is closed.
type app struct {
	cfg serveConfig

	db         *database.DB
	engine     *detection.Engine
	autopilot  *firewall.Autopilot
	executor   firewall.Executor
	collector  *metrics.Collector
	honeypotS  *honeypot.Server
	hostsecM   *hostsec.Manager
	intelM     *intel.Matcher
	echoSrv    *api.Server
	echoHandle *echo.Echo // set once startHTTPServer runs; used by shutdown()
	health     *health.Registry
	queues     []*pipeline.Queue // index 0 is auth when enabled, then web sources in order
	retention  *retention.Runner

	shutdownOnce sync.Once

	wg sync.WaitGroup
}

// buildApp constructs every component in dependency order but starts
// nothing yet. Keeping construction (buildApp) and execution (app.run)
// separate makes the wiring easy to reason about and, in principle, easy
// to unit test independently of actually binding sockets/tailing files.
func buildApp(cfg serveConfig) (*app, error) {
	// --- 1. Database: everything else depends on this, so it must be
	// fully migrated and ready before any other component touches it. ---
	db, err := database.Open(database.Config{Path: cfg.DBPath, Verbose: cfg.Verbose})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// --- 2. Firewall executor + Autopilot. Built before the detection
	// Engine because the Engine needs Autopilot as its Notifier. ---
	var executor firewall.Executor
	if cfg.UseUFW {
		executor = firewall.NewUFWExecutor(cfg.UFWSudo)
		log.Println("[serve] firewall executor: real UFW (production mode)")
	} else {
		executor = firewall.NewMockExecutor()
		log.Println("[serve] firewall executor: in-memory mock (no -ufw flag set; safe for sandbox/dev, " +
			"bans are tracked in the database but NOT enforced at the OS level)")
	}

	fwCfg := firewall.DefaultConfig()
	fwCfg.AdminWhitelistIPs = cfg.AdminIPs
	autopilot := firewall.NewAutopilot(db, executor, fwCfg)

	// --- Telegram alerts (optional). A nil notifier (either env var
	// unset) makes SetAlertNotifier's callee-side nil-check a total
	// no-op, so this is always safe to call unconditionally. ---
	telegram := notify.NewTelegramNotifier(cfg.TelegramBotToken, cfg.TelegramChatID)
	if telegram != nil {
		autopilot.SetAlertNotifier(telegram)
		log.Println("[serve] Telegram alerts: ENABLED (TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID configured)")
	} else {
		log.Println("[serve] Telegram alerts: disabled (set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID env vars to enable)")
	}

	// --- 3. Detection Engine, wired to Autopilot as its Notifier so every
	// newly created Incident is evaluated for an automatic ban in real
	// time, with zero coupling between the detection and firewall
	// packages beyond the small Notifier interface. ---
	// Phase 6: local, offline threat intelligence. The matcher is also the
	// engine's ThreatIntelChecker, which activates the (previously
	// dormant) reputation bonus for medium/high-confidence IP indicators.
	var iocMatcher *intel.Matcher
	detCfg := detection.Config{DB: db, MaxIdle: cfg.StateMaxIdle, Notifier: autopilot}
	tuningStore := tuning.Load(db)
	detCfg.Tuning = tuningStore
	if e := tuningStore.LoadError(); e != "" {
		log.Printf("[serve] WARNING: %s", e)
	}
	if cfg.EnableIntel {
		iocMatcher = intel.NewMatcher(db)
		detCfg.IOC = iocMatcher
		detCfg.ThreatIntel = iocMatcher
	} else {
		log.Println("[serve] local threat intelligence disabled (-intel=false)")
	}
	engine := detection.NewEngine(detCfg)

	// --- 4. Metrics collector. ---
	collector := metrics.NewCollector(db, cfg.MetricsInterval, cfg.DiskPath, cfg.MetricsRetention)

	// --- 5. Honeypot server. Every accepted decoy connection is adapted
	// into a detection.Engine.IngestHoneypotHit call, so a honeypot trigger
	// flows through the exact same Incident -> risk-score -> Autopilot
	// pipeline as every other detection rule. ---
	var honeypotSrv *honeypot.Server
	if cfg.EnableHoneypot {
		honeypotSrv = honeypot.NewServer(honeypot.DefaultDecoys(), func(hit honeypot.Hit) {
			engine.IngestHoneypotHit(hit.SourceIP, hit.Port, hit.Service, hit.Timestamp, hit.Received)
		})
	}

	// --- 5b. Host Security scanners (Mega Expansion, Phase 1: FIM,
	// Persistence, Account, Privilege Escalation, SUID/SGID; Phase 2:
	// Process Anomaly Detection, System Binary Integrity). The Engine
	// itself implements hostsec.Reporter (see engine_hostsec.go), so
	// every finding flows into the exact same Incident/risk pipeline as
	// every log-driven rule. ---
	hostsecMgr := hostsec.NewManager(db, engine, hostsec.Config{
		FIMPaths:      cfg.FIMPaths,
		SUIDRoots:     cfg.SUIDScanRoots,
		BinaryPaths:   cfg.BinaryPaths,
		SystemPosture: cfg.SystemPosture,
		Enabled:       cfg.EnableHostSecurity,
	})

	// --- 6. Auth manager + REST API. ---
	authMgr, err := auth.NewManager(cfg.JWTSecret, cfg.JWTTTL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to build auth manager: %w", err)
	}

	echoSrv := &api.Server{
		DB:        db,
		Engine:    engine,
		Autopilot: autopilot,
		Auth:      authMgr,
		Registry:  simulator.NewRegistry(),
		StartedAt: time.Now(),
	}
	if cfg.EnableHostSecurity {
		echoSrv.Detectors = hostsecMgr
	}
	echoSrv.Intel = iocMatcher
	echoSrv.Tuning = tuningStore
	echoSrv.BackupDir = cfg.BackupDir
	if echoSrv.BackupDir == "" {
		echoSrv.BackupDir = filepath.Join(filepath.Dir(cfg.DBPath), "backups")
	}
	// A database written by a NEWER VANGUARD is not refused (that would turn
	// a harmless extra index into an outage) but it is called out loudly:
	// downgrade is unsupported.
	if w := backup.SchemaWarnings(db); len(w) > 0 {
		log.Printf("[serve] WARNING: the database contains schema elements this version does not know (%v); it was probably written by a newer VANGUARD and downgrading is unsupported", w)
	}
	echoSrv.RuleCtx = rules.Context{
		HostSecurity: cfg.EnableHostSecurity, SystemPosture: cfg.SystemPosture.Enabled, Intel: cfg.EnableIntel,
		Honeypot: cfg.EnableHoneypot, MinRiskToBan: fwCfg.MinRiskScoreToBan, AutopilotActive: fwCfg.Enabled,
	}
	reg := newRuntimeRegistry(cfg)
	echoSrv.Runtime = api.RuntimeSources{Registry: reg, MetricsInterval: cfg.MetricsInterval}

	// Phase 12: one bounded, ordered ingest queue per log source, and a
	// guard that contains slow or numerous expensive API reads.
	var queues []*pipeline.Queue
	if cfg.AuthLogPath != "" {
		queues = append(queues, pipeline.New(pipeline.Config{Name: "auth", Size: cfg.IngestQueueSize}, engine.IngestAuthLogLine))
	}
	for i := range cfg.WebLogPaths {
		queues = append(queues, pipeline.New(pipeline.Config{Name: fmt.Sprintf("web%d", i+1), Size: cfg.IngestQueueSize}, engine.IngestWebLogLine))
	}
	echoSrv.QueueStats = func() []pipeline.Stats {
		out := make([]pipeline.Stats, 0, len(queues))
		for _, q := range queues {
			out = append(out, q.Stats())
		}
		return out
	}
	echoSrv.Guard = database.NewQueryGuard(cfg.QueryLimit, 250*time.Millisecond, cfg.QueryTimeout)
	echoSrv.Security = api.SecurityConfig{
		AllowedOrigins: cfg.AllowedOrigins, AllowedHosts: cfg.AllowedHosts, AllowRemoteBootstrap: cfg.AllowRemoteBootstrap,
	}
	echoSrv.BackupMinGap = 30 * time.Second
	echoSrv.SimulateMinGap = time.Second
	if w := bindWarning(cfg.HTTPAddr); w != "" {
		log.Printf("[serve] WARNING: %s", w)
	}
	if honeypotSrv != nil {
		echoSrv.Runtime.HoneypotStats = honeypotSrv.Stats
	}

	return &app{
		cfg:       cfg,
		db:        db,
		engine:    engine,
		autopilot: autopilot,
		executor:  executor,
		collector: collector,
		honeypotS: honeypotSrv,
		hostsecM:  hostsecMgr,
		intelM:    iocMatcher,
		echoSrv:   echoSrv,
		health:    reg,
		queues:    queues,
		retention: retention.New(db),
	}, nil
}

// run starts every component concurrently, then blocks until a shutdown
// signal is received, at which point it drives an ordered, best-effort
// graceful shutdown of each one before returning.
func (a *app) run() {
	// Root context for every background goroutine (tailers, metrics
	// collector, honeypot listeners, Autopilot maintenance loop). Cancelled
	// exactly once, when a shutdown signal arrives.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- Startup reconciliation: re-apply every currently-active DB ban to
	// the live OS firewall *before* accepting new traffic or incidents, so
	// a restart never has a window where a supposedly-banned IP is
	// actually let through at the OS level. ---
	if err := a.autopilot.ReconcileOnStartup(ctx); err != nil {
		log.Printf("[serve] WARNING: startup firewall reconciliation failed: %v", err)
	}

	a.startBackgroundTasks(ctx)
	a.startHTTPServer()

	log.Println("[serve] VANGUARD Core is up. Press Ctrl+C (or send SIGTERM) to stop.")

	// Block here until the signal context is cancelled.
	<-ctx.Done()
	log.Println("[serve] shutdown signal received, beginning graceful shutdown...")

	a.shutdown()
}

// startBackgroundTasks launches every monitoring/maintenance goroutine.
// Each one is added to a.wg so shutdown() can wait for a full, clean stop
// before the database handle is closed underneath them.
func (a *app) startBackgroundTasks(ctx context.Context) {
	// --- Log tailers feed the detection Engine directly. A missing log
	// file is non-fatal (TailFile logs a warning and returns), so one
	// absent source never blocks VANGUARD from protecting the rest of the
	// host. ---
	// Each tailer submits into its own bounded queue; one worker per queue
	// applies lines in arrival order (see internal/pipeline).
	qi := 0
	if a.cfg.AuthLogPath != "" {
		q := a.queues[qi]
		qi++
		a.goTracked(func() { q.Run(ctx) })
		a.goTracked(func() {
			if err := detection.TailFileObserved(ctx, a.cfg.AuthLogPath, func(l string) { q.Submit(l) }, newTailHealth(a.health, "log:auth")); err != nil {
				log.Printf("[serve] auth log tailer exited with error: %v", err)
			}
		})
	} else {
		log.Println("[serve] auth log tailing disabled (-auth-log \"\")")
	}

	for i, path := range a.cfg.WebLogPaths {
		p := path // capture for the closure
		hname := fmt.Sprintf("log:web%d", i+1)
		q := a.queues[qi]
		qi++
		a.goTracked(func() { q.Run(ctx) })
		a.goTracked(func() {
			if err := detection.TailFileObserved(ctx, p, func(l string) { q.Submit(l) }, newTailHealth(a.health, hname)); err != nil {
				log.Printf("[serve] web log tailer for %s exited with error: %v", p, err)
			}
		})
	}
	if len(a.cfg.WebLogPaths) == 0 {
		log.Println("[serve] web log tailing disabled (-web-log \"\")")
	}

	// --- Metrics collector: samples on its own ticker until ctx is done. ---
	a.goTracked(func() {
		a.collector.Run(ctx)
	})

	// --- Honeypot: every decoy listener runs its own accept-loop
	// goroutine internally; Server.Wait() blocks until all of them (and
	// any in-flight connection handlers) have returned. We track that as
	// a single unit of work in a.wg. ---
	if a.honeypotS != nil {
		a.honeypotS.Start(ctx)
		a.goTracked(func() {
			a.honeypotS.Wait()
		})
	} else {
		log.Println("[serve] honeypot listeners disabled (-honeypot=false)")
	}

	// --- Host Security scanners: each of the five (FIM, Persistence,
	// Account, Privilege Escalation, SUID/SGID) runs on its own ticker
	// inside Manager.Run, which blocks until ctx is cancelled -- tracked
	// here as a single unit of work, exactly like the honeypot server
	// above. ---
	if a.cfg.EnableHostSecurity {
		a.goTracked(func() {
			a.hostsecM.Run(ctx)
		})
	} else {
		log.Println("[serve] Host Security scanners disabled (-hostsec=false)")
	}

	// --- Local IOC snapshot refresh (bounded staleness; imports and
	// operator changes also reload immediately via the API). ---
	if a.intelM != nil {
		a.goTracked(func() {
			a.intelM.Run(ctx, 5*time.Minute)
		})
	}

	// --- Data-lifecycle job (Phase 12). Does nothing unless the operator set
	// a retention policy with `vanguard retention set -confirm`. ---
	a.goTracked(func() { a.runRetentionLoop(ctx) })

	// --- Autopilot maintenance loop: periodically reaps expired TTL bans
	// (lifting them at the OS level + marking inactive in the DB) and
	// prunes idle in-memory detection state, on the same ticker so both
	// housekeeping tasks share one predictable cadence. ---
	a.goTracked(func() {
		a.runMaintenanceLoop(ctx)
	})
}

// runMaintenanceLoop is the Autopilot's periodic housekeeping: TTL ban
// expiry and detection-state reaping. Runs once immediately (so a
// short-lived TTL ban created just before a restart doesn't linger for a
// full interval) and then on cfg.ReapInterval thereafter.
func (a *app) runMaintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.ReapInterval)
	defer ticker.Stop()

	a.runMaintenanceTick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runMaintenanceTick(ctx)
		}
	}
}

func (a *app) runMaintenanceTick(ctx context.Context) {
	if n, err := a.autopilot.ReapExpiredBans(ctx); err != nil {
		log.Printf("[serve] maintenance: failed to reap expired bans: %v", err)
		a.health.Failure("maintenance", health.Failed, "ban expiry sweep failed: "+err.Error())
	} else {
		a.health.Success("maintenance")
		if n > 0 {
			log.Printf("[serve] maintenance: reaped %d expired ban(s)", n)
		}
	}

	now := time.Now().UTC()
	a.engine.ReapDedupe(now)
	if n := a.engine.State().Reap(now); n > 0 {
		log.Printf("[serve] maintenance: reaped %d idle in-memory IP tracker(s)", n)
	}
	if n := a.engine.ChainTracker().Reap(now); n > 0 {
		log.Printf("[serve] maintenance: reaped %d idle attack-chain tracker(s)", n)
	}
	if n := a.engine.ScannerTracker().Reap(now); n > 0 {
		log.Printf("[serve] maintenance: reaped %d idle web-scanner tracker(s)", n)
	}
	if n := a.engine.AuthAbuseTracker().Reap(now); n > 0 {
		log.Printf("[serve] maintenance: reaped %d idle auth-abuse tracker(s)", n)
	}
	if n := a.engine.APIAbuseTracker().Reap(now); n > 0 {
		log.Printf("[serve] maintenance: reaped %d idle api-abuse tracker(s)", n)
	}
	if n := a.engine.ProtocolAnomalyTracker().Reap(now); n > 0 {
		log.Printf("[serve] maintenance: reaped %d idle protocol-anomaly tracker(s)", n)
	}
	if n := a.engine.SmugglingTracker().Reap(now); n > 0 {
		log.Printf("[serve] maintenance: reaped %d idle request-smuggling tracker(s)", n)
	}
	if n := a.engine.HostHeaderTracker().Reap(now); n > 0 {
		log.Printf("[serve] maintenance: reaped %d idle host-header tracker(s)", n)
	}
	if n := a.engine.OASTTracker().Reap(now); n > 0 {
		log.Printf("[serve] maintenance: reaped %d idle OAST-callback tracker(s)", n)
	}
}

// startHTTPServer builds the Echo instance and starts it listening in its
// own goroutine (echo.Start blocks for the server's entire lifetime, so it
// can never run on the main goroutine alongside signal handling).
func (a *app) startHTTPServer() {
	e := a.echoSrv.NewEcho()

	// Attach the embedded React dashboard (core/frontend's Vite build,
	// embedded via cmd/vanguard/frontend.go's go:embed) after every
	// /api/* route is already registered, so its catch-all "/*" route
	// never shadows an API endpoint.
	if err := mountFrontend(e); err != nil {
		log.Printf("[serve] WARNING: failed to mount embedded frontend: %v", err)
	}

	a.echoHandle = e

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		log.Printf("[serve] REST API + dashboard listening on %s", a.cfg.HTTPAddr)
		if err := e.Start(a.cfg.HTTPAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[serve] HTTP server stopped unexpectedly: %v", err)
		}
	}()
}

// goTracked launches fn in its own goroutine, registered on a.wg so
// shutdown() can wait for it to actually finish before closing the
// database.
func (a *app) goTracked(fn func()) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		fn()
	}()
}

// shutdown drives an ordered, best-effort graceful stop: first the HTTP
// server (so it stops accepting new requests and drains in-flight ones
// within the configured timeout), then waits for every background
// goroutine (tailers, metrics, honeypot, maintenance loop -- all already
// unblocked by the cancelled root context passed into run()) to fully
// return, and only then closes the database. This ordering is what
// prevents SQLite WAL corruption: no goroutine can still be mid-write when
// Close() runs, because we've proven every one of them has already exited.
func (a *app) shutdown() {
	// Repeated shutdown requests (signal + error path) must be harmless.
	a.shutdownOnce.Do(a.doShutdown)
}

func (a *app) doShutdown() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.ShutdownTimeout)
	defer cancel()

	if a.echoHandle != nil {
		log.Printf("[serve] shutting down HTTP server (timeout %s)...", a.cfg.ShutdownTimeout)
		if err := a.echoHandle.Shutdown(shutdownCtx); err != nil {
			log.Printf("[serve] HTTP server did not shut down cleanly: %v", err)
		} else {
			log.Println("[serve] HTTP server stopped")
		}
	}

	log.Println("[serve] waiting for background tasks (tailers, metrics, honeypot, maintenance loop) to stop...")
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Println("[serve] all background tasks stopped cleanly")
	case <-time.After(a.cfg.ShutdownTimeout):
		log.Println("[serve] WARNING: timed out waiting for background tasks to stop; closing database anyway")
	}

	log.Println("[serve] closing database...")
	if err := a.db.Close(); err != nil {
		log.Printf("[serve] error closing database: %v", err)
	} else {
		log.Println("[serve] database closed cleanly")
	}

	log.Println("[serve] shutdown complete")
}
