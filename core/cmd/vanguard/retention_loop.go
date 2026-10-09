package main

import (
	"context"
	"log"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/health"
)

const (
	retentionInterval     = 6 * time.Hour
	retentionInitialDelay = 2 * time.Minute
	retentionComponent    = "retention"
)

// runRetentionLoop applies the stored retention policy periodically. With the
// default policy (0 days) every tick is a no-op that deletes nothing.
func (a *app) runRetentionLoop(ctx context.Context) {
	a.retention.Skip = func() string {
		if a.autopilot != nil && a.autopilot.PanicModeStatus().Active {
			return "Panic Mode is active; retention does not run during an emergency"
		}
		return ""
	}
	timer := time.NewTimer(retentionInitialDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			a.retentionTick(ctx)
			timer.Reset(retentionInterval)
		}
	}
}

func (a *app) retentionTick(ctx context.Context) {
	res, err := a.retention.Execute(ctx, "system:retention")
	switch {
	case err != nil && res == nil:
		log.Printf("[retention] run not started: %v", err)
		a.health.Failure(retentionComponent, health.Failed, "retention run could not start: "+err.Error())
	case res == nil:
	case res.Run.Status == database.RetentionStatusDisabled:
		a.health.Disable(retentionComponent, "no incident retention policy is set; nothing is ever deleted")
	case err != nil || res.Run.Status == database.RetentionStatusFailed:
		log.Printf("[retention] run failed: %s", res.Run.Detail)
		a.health.Failure(retentionComponent, health.Failed, res.Run.Detail)
	case res.Run.Status == database.RetentionStatusSkipped:
		a.health.Degrade(retentionComponent, res.Run.Detail)
	case res.Run.Status == database.RetentionStatusPartial:
		log.Printf("[retention] partial: %s", res.Run.Detail)
		a.health.Degrade(retentionComponent, "more eligible incidents remain: "+res.Run.Detail)
	default:
		if res.Run.IncidentsDeleted > 0 {
			log.Printf("[retention] %s", res.Run.Detail)
		}
		a.health.Success(retentionComponent)
	}
}
