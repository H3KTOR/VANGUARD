package detection

import (
	"fmt"
	"time"

	"vanguard/core/internal/thresholds"
	"vanguard/core/internal/tuning"
)

// TuningSource supplies the effective tunable thresholds (Phase 10).
// *tuning.Store satisfies it. Implementations must be cheap and
// concurrency-safe: it is consulted on every relevant event.
type TuningSource interface {
	Values() tuning.Values
	Revision() uint
}

type defaultTuning struct{}

func (defaultTuning) Values() tuning.Values { return tuning.Defaults() }
func (defaultTuning) Revision() uint        { return 0 }

func tuningOrDefault(t TuningSource) TuningSource {
	if t == nil {
		return defaultTuning{}
	}
	return t
}

// explain builds the structured "why did this fire" block stored in an
// incident's evidence for the tunable rules: the condition, the observed
// value, the threshold actually applied, and where that threshold came
// from. It states only facts the rule evaluated; it makes no claim about
// intent or about what the detector could not see.
func (e *Engine) explain(condition string, observed int, cmp string, threshold int, window time.Duration) map[string]any {
	rev := e.tuning.Revision()
	src := "compiled default"
	if rev != 0 {
		src = fmt.Sprintf("operator tuning revision %d", rev)
	}
	return map[string]any{
		"condition":        condition,
		"comparison":       cmp,
		"observed":         observed,
		"threshold":        threshold,
		"window_seconds":   int(window.Seconds()),
		"threshold_source": src,
		"tuning_revision":  rev,
	}
}

var _ = thresholds.SSHBruteForceWindow // keep import grouping stable
