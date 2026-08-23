package simulator

import (
	"context"

	"vanguard/core/internal/database"
)

// portScanSimulator will implement `vanguard simulate port-scan`: simulating
// one source IP touching many distinct destination ports in a short window,
// which the real Reconnaissance detector flags once the distinct-port count
// crosses its threshold.
//
// Deferred to a later step alongside honeypot.go (see comment there).
type portScanSimulator struct{}

// NewPortScanSimulator constructs the (currently stubbed) port-scan scenario.
func NewPortScanSimulator() Simulator { return &portScanSimulator{} }

func (s *portScanSimulator) Name() string { return "port-scan" }

func (s *portScanSimulator) Description() string {
	return "Simulates one IP rapidly touching multiple ports to trigger port-scan reconnaissance detection. (coming in a later step)"
}

func (s *portScanSimulator) Run(ctx context.Context, db *database.DB, opts Options) (*Result, error) {
	return nil, ErrNotImplemented
}
