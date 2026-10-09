package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/health"
)

const (
	auditSealInterval   = time.Minute
	auditVerifyInterval = time.Hour
	auditComponent      = "audit_integrity"
)

// runAuditLoop seals new audit records every minute and verifies the ledger
// every hour, reporting through runtime health. An integrity discrepancy is a
// FAILED component (never a quiet log line); an inability to seal or verify is
// degraded/failed too - it is not reported as a clean audit state.
func (a *app) runAuditLoop(ctx context.Context) {
	seal := time.NewTicker(auditSealInterval)
	verify := time.NewTicker(auditVerifyInterval)
	defer seal.Stop()
	defer verify.Stop()
	a.auditSealOnce()
	a.auditVerifyOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-seal.C:
			a.auditSealOnce()
			a.purgeSessions()
		case <-verify.C:
			a.auditVerifyOnce()
		}
	}
}

// purgeSessions removes expired sessions and sessions of vanished accounts (bounded).
func (a *app) purgeSessions() {
	if n, err := a.db.PurgeSessions(time.Now().UTC(), 1000); err != nil {
		log.Printf("[auth] session purge failed: %v", err)
	} else if n > 0 {
		log.Printf("[auth] purged %d expired session(s)", n)
	}
}

func (a *app) auditSealOnce() {
	for i := 0; i < 10; i++ { // at most 10 batches per tick
		r, err := a.db.SealPending(time.Now().UTC())
		if err != nil {
			log.Printf("[audit] sealing failed: %v", err)
			a.health.Failure(auditComponent, health.Degraded, "could not seal new audit records into the ledger: "+err.Error())
			return
		}
		if !r.Remaining {
			return
		}
	}
}

func (a *app) auditVerifyOnce() {
	rep, err := a.db.VerifyLedger(database.VerifyOptions{})
	switch {
	case err != nil:
		a.health.Failure(auditComponent, health.Failed, "audit ledger verification could not run: "+err.Error())
	case !rep.OK:
		first := rep.Findings[0]
		log.Printf("[audit] INTEGRITY FINDING: %s (entry %d, %s #%d); %d finding(s) in total", first.Kind, first.Seq, first.Table, first.RecordID, len(rep.Findings))
		a.health.Failure(auditComponent, health.Failed, fmt.Sprintf("audit integrity check found %d inconsistenc(ies); first: %s at ledger entry %d. Run `vanguard audit verify`", len(rep.Findings), first.Kind, first.Seq))
	case rep.Partial:
		a.health.Degrade(auditComponent, "the ledger is larger than one verification pass; part of it was not examined this time")
	default:
		a.health.Success(auditComponent)
	}
}
