package simulator

import (
	"context"

	"vanguard/core/internal/database"
)

// honeypotSimulator will implement `vanguard simulate honeypot`: simulating
// a connection attempt to a decoy port (e.g. fake SSH on 2222, fake MySQL
// on 33060) which the real Honeypot Engine treats as an instant CRITICAL
// trigger (ANY connection = malicious intent, no threshold needed).
//
// Deferred to a later step: this scenario shares its scoring/ban plumbing
// with ssh_bruteforce.go and the real internal/detection package, so it is
// best implemented once that shared risk-scoring helper exists, to avoid
// duplicating the Incident/FirewallRule creation logic.
type honeypotSimulator struct{}

// NewHoneypotSimulator constructs the (currently stubbed) honeypot scenario.
func NewHoneypotSimulator() Simulator { return &honeypotSimulator{} }

func (s *honeypotSimulator) Name() string { return "honeypot" }

func (s *honeypotSimulator) Description() string {
	return "Simulates a connection to a decoy port to trigger an instant CRITICAL honeypot incident. (coming in a later step)"
}

func (s *honeypotSimulator) Run(ctx context.Context, db *database.DB, opts Options) (*Result, error) {
	return nil, ErrNotImplemented
}
