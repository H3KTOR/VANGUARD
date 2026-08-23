// Package simulator implements VANGUARD's Attack Simulation Mode: safe,
// synthetic attack scenarios that exercise the exact same data path a real
// attack would (Incident + FirewallRule rows in SQLite) without touching
// any real network socket, log file, or firewall rule on the host.
//
// This lets `vanguard simulate <scenario>` produce a fully populated,
// demo-able dashboard (incidents, risk scores, auto-bans) in a locked-down
// sandbox or CI environment with zero risk.
//
// Step 1 scope: the Simulator interface, a registry, and a complete
// ssh-bruteforce implementation. Honeypot and port-scan are registered as
// stubs (see honeypot.go / port_scan.go) and will be fleshed out once the
// real detection engine (internal/detection) exists in a later step, so
// both paths can share one risk-scoring implementation instead of
// duplicating logic.
package simulator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"vanguard/core/internal/database"
)

// ErrNotImplemented is returned by simulators that are registered (so they
// show up in CLI help / `vanguard simulate --list`) but not yet built out.
var ErrNotImplemented = errors.New("simulator: scenario not implemented yet")

// Options controls how a simulation run behaves. Not every field is used by
// every simulator; each implementation documents which ones it honors.
type Options struct {
	// SourceIP is the attacker IP to attribute events to. If empty, the
	// simulator generates a random, non-routable-looking public IP so
	// repeated runs don't collide with real whitelisted/banned entries.
	SourceIP string

	// AttemptCount overrides the default number of attack events generated
	// (e.g. failed SSH logins). 0 means "use the simulator's default".
	AttemptCount int

	// WindowSeconds spreads the generated events across this many seconds
	// of synthetic timestamps ending at "now", to mimic a realistic burst.
	// 0 means "use the simulator's default".
	WindowSeconds int

	// AutoBan, when true (default), makes the simulator also create a TTL
	// FirewallRule row to represent the Autopilot's automated response --
	// mirroring the real "detect -> score -> incident -> auto-ban" flow.
	AutoBan bool

	// BanDuration is the TTL applied to the simulated ban when AutoBan is
	// true. 0 means "use the simulator's default".
	BanDuration time.Duration

	// DryRun, when true, computes and returns the result WITHOUT writing
	// anything to the database. Useful for previewing a scenario (mirrors
	// the mandatory dry-run requirement for the real Autopilot).
	DryRun bool
}

// withDefaults fills zero-valued fields with the given fallbacks and
// returns a copy, leaving the caller's Options untouched.
func (o Options) withDefaults(attemptCount, windowSeconds int, banDuration time.Duration) Options {
	out := o
	if out.AttemptCount <= 0 {
		out.AttemptCount = attemptCount
	}
	if out.WindowSeconds <= 0 {
		out.WindowSeconds = windowSeconds
	}
	if out.BanDuration <= 0 {
		out.BanDuration = banDuration
	}
	return out
}

// Result summarizes what a simulation run produced, for CLI output and for
// API callers that trigger simulations from the dashboard.
type Result struct {
	Scenario     string                 `json:"scenario"`
	SourceIP     string                 `json:"source_ip"`
	AttemptCount int                    `json:"attempt_count"`
	RiskScore    int                    `json:"risk_score"`
	Severity     database.Severity      `json:"severity"`
	Incident     *database.Incident     `json:"incident,omitempty"`
	FirewallRule *database.FirewallRule `json:"firewall_rule,omitempty"`
	DryRun       bool                   `json:"dry_run"`
	Narrative    []string               `json:"narrative"` // human-readable step log, mirrors the "Flow" in the spec
}

// Simulator is implemented by every attack scenario the demo mode supports.
type Simulator interface {
	// Name is the CLI/API identifier, e.g. "ssh-bruteforce".
	Name() string
	// Description is a one-line human-readable summary for CLI help.
	Description() string
	// Run executes the scenario against db (unless opts.DryRun is set) and
	// returns a Result describing what happened.
	Run(ctx context.Context, db *database.DB, opts Options) (*Result, error)
}

// Registry holds all known simulators keyed by Name().
type Registry struct {
	simulators map[string]Simulator
}

// NewRegistry builds a Registry pre-populated with every scenario VANGUARD
// ships, in the order they appear in the product spec.
func NewRegistry() *Registry {
	r := &Registry{simulators: make(map[string]Simulator)}
	r.register(NewSSHBruteForceSimulator())
	r.register(NewHoneypotSimulator())
	r.register(NewPortScanSimulator())
	return r
}

func (r *Registry) register(s Simulator) {
	r.simulators[s.Name()] = s
}

// Get returns the simulator registered under name, or (nil, false).
func (r *Registry) Get(name string) (Simulator, bool) {
	s, ok := r.simulators[name]
	return s, ok
}

// List returns every registered simulator's Name()+Description(), sorted
// for stable CLI output.
func (r *Registry) List() []Simulator {
	out := make([]Simulator, 0, len(r.simulators))
	for _, s := range r.simulators {
		out = append(out, s)
	}
	return out
}

// Run is a convenience that looks up name in the registry and executes it,
// wrapping the "unknown scenario" error with the list of valid names.
func (r *Registry) Run(ctx context.Context, db *database.DB, name string, opts Options) (*Result, error) {
	s, ok := r.Get(name)
	if !ok {
		return nil, fmt.Errorf("simulator: unknown scenario %q (known: %s)", name, r.namesJoined())
	}
	return s.Run(ctx, db, opts)
}

func (r *Registry) namesJoined() string {
	out := ""
	for i, s := range r.List() {
		if i > 0 {
			out += ", "
		}
		out += s.Name()
	}
	return out
}
