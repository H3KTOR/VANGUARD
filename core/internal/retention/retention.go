// Package retention deletes old operational records under an explicit,
// operator-set, auditable policy (Phase 12).
//
// What it will and will not delete:
//
//	incidents            only resolved / false_positive / auto_blocked ones older
//	                     than the policy, never open or investigating ones, never
//	                     one that an ACTIVE firewall rule still points at, and (by
//	                     default) never one with a live analyst note.
//	incident_events      deleted together with their incident (they are that
//	                     incident's audit trail; enabling incident retention is
//	                     the explicit policy that permits this).
//	incident_notes       deleted together with their incident (soft-deleted notes
//	                     only, unless the operator turned "keep with notes" off).
//	ioc_matches          NOT deleted: their incident link is cleared, the match
//	                     history keeps its own age/row bounds.
//	firewall_rules       NOT deleted: only the (inactive) rule's incident link is
//	                     cleared; ban history is kept.
//	rule_tuning_revisions, backup_audits, retention_runs, users, iocs,
//	ioc_imports, host baselines: never touched.
//
// A deleted incident leaves no tombstone row. The audit row in retention_runs
// records the count and the ID range of each run. A missing incident is NOT
// evidence that nothing happened: retention only removes records older than the
// operator's window, and the audit rows say that it ran.
package retention

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"vanguard/core/internal/database"
)

// Policy bounds (enforced on every write and again on every run).
const (
	MinRetentionDays = 30
	MaxRetentionDays = 3650
	MinBatchSize     = 10
	MaxBatchSize     = 1000
	MaxBatches       = 100
	// maxAttempts is how many times one batch is retried after a transient
	// database error (for example SQLITE_BUSY on lock upgrade).
	maxAttempts = 3
)

// ErrAlreadyRunning: another run in this process is in progress.
var ErrAlreadyRunning = errors.New("a retention run is already in progress")

// Validate checks a policy against the fixed bounds.
func Validate(p database.RetentionPolicy) error {
	if p.IncidentRetentionDays != 0 && (p.IncidentRetentionDays < MinRetentionDays || p.IncidentRetentionDays > MaxRetentionDays) {
		return fmt.Errorf("incident_retention_days must be 0 (keep forever) or between %d and %d", MinRetentionDays, MaxRetentionDays)
	}
	if p.BatchSize < MinBatchSize || p.BatchSize > MaxBatchSize {
		return fmt.Errorf("batch_size must be between %d and %d", MinBatchSize, MaxBatchSize)
	}
	if p.MaxBatchesPerRun < 1 || p.MaxBatchesPerRun > MaxBatches {
		return fmt.Errorf("max_batches_per_run must be between 1 and %d", MaxBatches)
	}
	return nil
}

// Runner executes retention runs.
type Runner struct {
	DB *database.DB
	// Skip, when set, is asked before an Execute run; a non-empty answer skips
	// the run and is recorded (for example "panic mode is active").
	Skip func() string

	running atomic.Bool
	now     func() time.Time
	// afterBatch is a test hook called after each committed batch.
	afterBatch func(batch int)
}

// New returns a Runner.
func New(db *database.DB) *Runner {
	return &Runner{DB: db, now: func() time.Time { return time.Now().UTC() }}
}

// Result is what one Preview/Execute reports.
type Result struct {
	Run    database.RetentionRun    `json:"run"`
	Policy database.RetentionPolicy `json:"policy"`
	// More is true when eligible incidents remain after this run (the batch
	// cap was reached, the run was cancelled, or an error stopped it).
	More bool `json:"more_pending"`
}

// eligibleSQL selects incident IDs that retention may delete. All values are
// bound parameters.
func eligibleSQL(keepWithNotes bool) string {
	q := `incidents.status IN ('resolved','false_positive','auto_blocked')
 AND COALESCE(incidents.resolved_at, incidents.detected_at) < ?
 AND NOT EXISTS (SELECT 1 FROM firewall_rules fr WHERE fr.incident_id = incidents.id AND fr.is_active = 1)`
	if keepWithNotes {
		q += `
 AND NOT EXISTS (SELECT 1 FROM incident_notes n WHERE n.incident_id = incidents.id AND n.deleted = 0)`
	}
	return q
}

// Preview computes what Execute would do without modifying incidents, events,
// notes, matches or rules. It records a dry_run audit row.
func (r *Runner) Preview(ctx context.Context, actor string) (*Result, error) {
	return r.run(ctx, actor, true)
}

// Execute performs a bounded retention run.
func (r *Runner) Execute(ctx context.Context, actor string) (*Result, error) {
	return r.run(ctx, actor, false)
}

func (r *Runner) run(ctx context.Context, actor string, dry bool) (*Result, error) {
	if !r.running.CompareAndSwap(false, true) {
		return nil, ErrAlreadyRunning
	}
	defer r.running.Store(false)

	pol, err := r.DB.GetRetentionPolicy()
	if err != nil {
		return nil, fmt.Errorf("cannot read retention policy: %w", err)
	}
	now := r.now()
	run := database.RetentionRun{
		StartedAt: now, Actor: actor, Mode: database.RetentionModeExecute, Status: database.RetentionStatusCompleted,
		PolicyRevision: pol.Revision, PolicyDays: pol.IncidentRetentionDays,
	}
	if dry {
		run.Mode = database.RetentionModeDryRun
	}
	res := &Result{Policy: pol}

	finish := func(status, detail string) (*Result, error) {
		fin := r.now()
		run.FinishedAt, run.Status, run.Detail = &fin, status, detail
		res.Run = run
		// Disabled/skipped daemon runs are not worth a row; everything else is audited.
		if status == database.RetentionStatusDisabled && !dry {
			return res, nil
		}
		if err := r.DB.RecordRetentionRun(&run); err != nil {
			return res, fmt.Errorf("retention finished but its audit row could not be written: %w", err)
		}
		res.Run = run
		return res, nil
	}

	if err := Validate(pol); err != nil {
		return finish(database.RetentionStatusFailed, "stored policy is invalid: "+err.Error())
	}
	if pol.IncidentRetentionDays == 0 {
		return finish(database.RetentionStatusDisabled, "incident retention is disabled (incident_retention_days = 0); nothing is ever deleted")
	}
	if !dry && r.Skip != nil {
		if why := r.Skip(); why != "" {
			return finish(database.RetentionStatusSkipped, why)
		}
	}

	cutoff := now.AddDate(0, 0, -pol.IncidentRetentionDays)
	run.Cutoff = cutoff
	where := eligibleSQL(pol.KeepWithNotes)

	// Counts that explain what was NOT deleted and why.
	base := r.DB.WithContext(ctx).Model(&database.Incident{}).
		Where("status IN ('resolved','false_positive','auto_blocked') AND COALESCE(resolved_at, detected_at) < ?", cutoff)
	var old int64
	if err := base.Count(&old).Error; err != nil {
		return finish(database.RetentionStatusFailed, "count failed: "+err.Error())
	}
	if err := r.DB.WithContext(ctx).Model(&database.Incident{}).Where(where, cutoff).Count(&run.EligibleTotal).Error; err != nil {
		return finish(database.RetentionStatusFailed, "count failed: "+err.Error())
	}
	_ = r.DB.WithContext(ctx).Model(&database.Incident{}).
		Where("status IN ('resolved','false_positive','auto_blocked') AND COALESCE(resolved_at, detected_at) < ?", cutoff).
		Where("EXISTS (SELECT 1 FROM firewall_rules fr WHERE fr.incident_id = incidents.id AND fr.is_active = 1)").
		Count(&run.SkippedActive).Error
	if pol.KeepWithNotes {
		_ = r.DB.WithContext(ctx).Model(&database.Incident{}).
			Where("status IN ('resolved','false_positive','auto_blocked') AND COALESCE(resolved_at, detected_at) < ?", cutoff).
			Where("EXISTS (SELECT 1 FROM incident_notes n WHERE n.incident_id = incidents.id AND n.deleted = 0)").
			Count(&run.SkippedNotes).Error
	}

	if dry {
		// Examine at most what a real run could touch, so a preview is as
		// bounded as an execution.
		limit := pol.BatchSize * pol.MaxBatchesPerRun
		var ids []uint
		if err := r.DB.WithContext(ctx).Model(&database.Incident{}).Where(where, cutoff).
			Order("id ASC").Limit(limit).Pluck("id", &ids).Error; err != nil {
			return finish(database.RetentionStatusFailed, "preview failed: "+err.Error())
		}
		run.IncidentsDeleted = 0
		if len(ids) > 0 {
			run.MinID, run.MaxID = ids[0], ids[len(ids)-1]
			r.countDependents(ctx, ids, pol.KeepWithNotes, &run)
		}
		res.More = run.EligibleTotal > int64(len(ids))
		return finish(database.RetentionStatusPreview, fmt.Sprintf(
			"dry run: %d incident(s) eligible (%d examined for dependents); nothing was modified", run.EligibleTotal, len(ids)))
	}

	for batch := 0; batch < pol.MaxBatchesPerRun; batch++ {
		if err := ctx.Err(); err != nil {
			res.More = true
			return finish(database.RetentionStatusPartial, "cancelled: "+err.Error())
		}
		stats, err := r.deleteBatch(ctx, pol, cutoff)
		if err != nil {
			res.More = true
			return finish(database.RetentionStatusFailed, "batch failed after retries; earlier batches were committed: "+err.Error())
		}
		if stats.incidents == 0 {
			return finish(database.RetentionStatusCompleted, fmt.Sprintf("deleted %d incident(s) in %d batch(es)", run.IncidentsDeleted, run.Batches))
		}
		run.Batches++
		run.IncidentsDeleted += stats.incidents
		run.EventsDeleted += stats.events
		run.NotesDeleted += stats.notes
		run.MatchesUnlinked += stats.matches
		run.RulesUnlinked += stats.rules
		if run.MinID == 0 || stats.minID < run.MinID {
			run.MinID = stats.minID
		}
		if stats.maxID > run.MaxID {
			run.MaxID = stats.maxID
		}
		if r.afterBatch != nil {
			r.afterBatch(run.Batches)
		}
	}
	// Batch cap reached: say whether more remain.
	var left int64
	_ = r.DB.WithContext(ctx).Model(&database.Incident{}).Where(where, cutoff).Count(&left).Error
	if left > 0 {
		res.More = true
		return finish(database.RetentionStatusPartial, fmt.Sprintf("batch cap reached; deleted %d, about %d still eligible (run again)", run.IncidentsDeleted, left))
	}
	return finish(database.RetentionStatusCompleted, fmt.Sprintf("deleted %d incident(s) in %d batch(es)", run.IncidentsDeleted, run.Batches))
}

type batchStats struct {
	incidents, events, notes, matches, rules int64
	minID, maxID                             uint
}

// deleteBatch removes up to BatchSize eligible incidents and their dependents
// in ONE transaction (all or nothing), re-checking eligibility inside it so a
// ban or note added since the preview protects the incident.
func (r *Runner) deleteBatch(ctx context.Context, pol database.RetentionPolicy, cutoff time.Time) (batchStats, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return batchStats{}, ctx.Err()
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
		}
		var st batchStats
		err := r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			st = batchStats{}
			var ids []uint
			if err := tx.Model(&database.Incident{}).Where(eligibleSQL(pol.KeepWithNotes), cutoff).
				Order("id ASC").Limit(pol.BatchSize).Pluck("id", &ids).Error; err != nil {
				return err
			}
			if len(ids) == 0 {
				return nil
			}
			st.minID, st.maxID = ids[0], ids[len(ids)-1]
			// Dependents first, then the incident rows. Every statement is
			// parameterized and bounded by len(ids) <= BatchSize <= 1000.
			ev := tx.Where("incident_id IN ?", ids).Delete(&database.IncidentEvent{})
			if ev.Error != nil {
				return ev.Error
			}
			nt := tx.Where("incident_id IN ?", ids).Delete(&database.IncidentNote{})
			if nt.Error != nil {
				return nt.Error
			}
			mt := tx.Model(&database.IOCMatch{}).Where("incident_id IN ?", ids).Update("incident_id", 0)
			if mt.Error != nil {
				return mt.Error
			}
			fr := tx.Model(&database.FirewallRule{}).Where("incident_id IN ? AND is_active = 0", ids).Update("incident_id", nil)
			if fr.Error != nil {
				return fr.Error
			}
			in := tx.Where("id IN ?", ids).Delete(&database.Incident{})
			if in.Error != nil {
				return in.Error
			}
			st.incidents, st.events, st.notes, st.matches, st.rules = in.RowsAffected, ev.RowsAffected, nt.RowsAffected, mt.RowsAffected, fr.RowsAffected
			return nil
		})
		if err == nil {
			return st, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return batchStats{}, ctx.Err()
		}
	}
	return batchStats{}, lastErr
}

// countDependents fills the dependent counts for a dry run.
func (r *Runner) countDependents(ctx context.Context, ids []uint, keepWithNotes bool, run *database.RetentionRun) {
	for start := 0; start < len(ids); start += MaxBatchSize {
		end := start + MaxBatchSize
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		var n int64
		r.DB.WithContext(ctx).Model(&database.IncidentEvent{}).Where("incident_id IN ?", chunk).Count(&n)
		run.EventsDeleted += n
		r.DB.WithContext(ctx).Model(&database.IncidentNote{}).Where("incident_id IN ?", chunk).Count(&n)
		run.NotesDeleted += n
		r.DB.WithContext(ctx).Model(&database.IOCMatch{}).Where("incident_id IN ?", chunk).Count(&n)
		run.MatchesUnlinked += n
		r.DB.WithContext(ctx).Model(&database.FirewallRule{}).Where("incident_id IN ?", chunk).Count(&n)
		run.RulesUnlinked += n
	}
}
