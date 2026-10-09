package api

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"github.com/labstack/echo/v4"

	"vanguard/core/internal/database"
	"vanguard/core/internal/detection"
	"vanguard/core/internal/health"
	"vanguard/core/internal/honeypot"
	"vanguard/core/internal/hostsec"
	"vanguard/core/internal/intel"
	"vanguard/core/internal/investigate"
)

// RuntimeSources are optional inputs to GET /api/health/runtime. A nil
// source is reported as "disabled", never as healthy.
type RuntimeSources struct {
	// Registry holds components that report themselves (log tailers,
	// maintenance loop).
	Registry *health.Registry
	// HoneypotStats is nil when the honeypot is disabled.
	HoneypotStats func() honeypot.Stats
	// MetricsInterval is the metrics collector's sampling period (0 = unknown).
	MetricsInterval time.Duration
}

const dbProbeTimeout = 2 * time.Second

// detectorState maps a scanner's last recorded result to a health state.
// A scanner that has not finished a scan within 3x its interval is
// reported unknown (missing telemetry) even if its last result was ok.
func detectorState(s hostsec.ScanStatus, now time.Time) health.State {
	switch s.LastResult {
	case hostsec.ResultOK:
		if s.IntervalSeconds > 0 && s.LastFinished != nil &&
			now.Sub(*s.LastFinished) > time.Duration(health.StaleFactor*s.IntervalSeconds)*time.Second {
			return health.Unknown
		}
		return health.Healthy
	case hostsec.ResultSkipped:
		return health.Degraded
	case hostsec.ResultFailed:
		return health.Failed
	case hostsec.ResultTimeout:
		return health.TimedOut
	}
	return health.NotYetObserved
}

func (s *Server) dbComponent(ctx context.Context, now time.Time) health.Component {
	c := health.Component{Name: "database"}
	ctx, cancel := context.WithTimeout(ctx, dbProbeTimeout)
	defer cancel()
	sqlDB, err := s.DB.DB.DB()
	start := time.Now()
	if err == nil {
		err = sqlDB.PingContext(ctx)
	}
	c.LastAttempt = &now
	c.Attempts = 1
	if err != nil {
		c.State, c.Failures, c.Detail = health.Failed, 1, health.Sanitize("database probe failed: "+err.Error())
		return c
	}
	c.State, c.LastSuccess = health.Healthy, &now
	c.Counters = map[string]uint64{"probe_latency_ms": uint64(time.Since(start).Milliseconds())}
	return c
}

// runtimeComponents assembles every component's current state.
func (s *Server) runtimeComponents(ctx context.Context, now time.Time) []health.Component {
	var out []health.Component
	out = append(out, s.dbComponent(ctx, now))

	if s.Runtime.Registry != nil {
		out = append(out, s.Runtime.Registry.Snapshot()...)
	}

	if s.Detectors == nil {
		out = append(out, health.Component{Name: "detectors", State: health.Disabled, Detail: "host security scanning is disabled"})
	} else {
		list := s.Detectors.Status()
		if len(list) == 0 {
			out = append(out, health.Component{Name: "detectors", State: health.NotYetObserved, Detail: "no scanner has registered yet"})
		}
		for _, d := range list {
			c := health.Component{
				Name: "detector:" + d.Name, State: detectorState(d, now), Detail: health.Sanitize(d.LastNote),
				LastAttempt: d.LastStarted, LastSuccess: d.LastCleanScan, Attempts: d.Runs, Failures: d.Failures + d.Timeouts,
				Counters: map[string]uint64{"skips": d.Skips, "timeouts": d.Timeouts},
			}
			if c.State == health.Unknown {
				c.Detail = "no scan finished within the expected interval (missing telemetry, not a clean result)"
			}
			out = append(out, c)
		}
	}

	if s.Intel == nil {
		out = append(out, health.Component{Name: "intel_matcher", State: health.Disabled, Detail: "local threat intelligence is disabled"})
	} else {
		st := s.Intel.Status()
		c := health.Component{Name: "intel_matcher", LastAttempt: st.LastReloadAt, LastSuccess: st.LoadedAt,
			Counters: map[string]uint64{"indicators_loaded": uint64(st.Indicators)}}
		switch {
		case !st.Loaded:
			c.State, c.Detail = health.Failed, health.Sanitize("indicator snapshot never loaded: "+st.LastError)
		case st.LastError != "":
			c.State, c.Detail = health.Degraded, health.Sanitize("last reload failed, previous snapshot kept: "+st.LastError)
		case st.Truncated:
			c.State, c.Detail = health.Degraded, "more active indicators exist than the snapshot cap"
		case st.LoadedAt != nil && now.Sub(*st.LoadedAt) > 3*intelReloadEvery:
			c.State, c.Detail = health.Unknown, "snapshot not refreshed within the expected interval"
		default:
			c.State = health.Healthy
		}
		out = append(out, c)
	}

	if s.Runtime.HoneypotStats == nil {
		out = append(out, health.Component{Name: "honeypot", State: health.Disabled, Detail: "honeypot is disabled"})
	} else {
		st := s.Runtime.HoneypotStats()
		c := health.Component{Name: "honeypot", State: health.Healthy, Counters: map[string]uint64{
			"accepted": st.Accepted, "shed": st.Shed, "accept_errors": st.AcceptErrors,
			"bound_ports": st.BoundPorts, "bind_failures": st.BindFailures,
		}}
		switch {
		case st.BoundPorts == 0:
			c.State, c.Detail = health.Failed, "no decoy port is bound"
		case st.BindFailures > 0:
			c.State, c.Detail = health.Degraded, "some decoy ports could not be bound"
		case st.Shed > 0:
			c.State, c.Detail = health.Degraded, "connections exceeded the concurrency bound since start (still reported as hits; banner capture skipped)"
		}
		out = append(out, c)
	}

	if s.Tuning != nil {
		c := health.Component{Name: "rule_tuning", State: health.Healthy, Counters: map[string]uint64{"revision": uint64(s.Tuning.Revision())}}
		if e := s.Tuning.LoadError(); e != "" {
			c.State, c.Detail = health.Degraded, health.Sanitize("stored tuning ignored, compiled defaults in effect: "+e)
		}
		out = append(out, c)
	}

	if s.Engine != nil {
		out = append(out, engineComponent(s.Engine.Stats(), s.Engine.DedupeLen(), now))
	}
	if s.QueueStats != nil {
		for _, q := range s.QueueStats() {
			out = append(out, queueComponent(q, now))
		}
	}
	if s.Guard != nil {
		out = append(out, guardComponent(s.Guard.Stats()))
	}

	if lm, err := s.DB.LatestMetric(); err != nil || lm == nil {
		out = append(out, health.Component{Name: "metrics_collector", State: health.NotYetObserved, Detail: "no metric sample recorded"})
	} else {
		c := health.Component{Name: "metrics_collector", State: health.Healthy, LastSuccess: &lm.Timestamp}
		if s.Runtime.MetricsInterval > 0 && now.Sub(lm.Timestamp) > health.StaleFactor*s.Runtime.MetricsInterval {
			c.State, c.Detail = health.Unknown, "no recent metric sample (missing telemetry)"
		}
		out = append(out, c)
	}
	return out
}

const intelReloadEvery = 5 * time.Minute

type runtimeBounds struct {
	HoneypotMaxConcurrentConns int `json:"honeypot_max_concurrent_connections"`
	DedupeMaxKeys              int `json:"incident_dedupe_max_keys"`
	HealthMaxComponents        int `json:"health_max_components"`
	InvestigatePageMax         int `json:"investigation_query_page_max"`
	TimelinePageMax            int `json:"timeline_page_max"`
	ExportMaxBytes             int `json:"export_max_bytes"`
	IOCImportMaxBytes          int `json:"ioc_import_max_bytes"`
	IOCImportMaxRecords        int `json:"ioc_import_max_records"`
	EvidenceMaxBytes           int `json:"incident_evidence_max_bytes"`
	EventsPerIncidentMax       int `json:"audit_events_per_incident_max"`
}

// GET /api/health/runtime -- authenticated, read-only, bounded.
//
// Describes whether VANGUARD's own machinery is working. It does not
// describe whether the monitored host is secure, and a "healthy" overall
// state is only reported when every running component recorded a real,
// recent success.
func (s *Server) handleRuntimeHealth(c echo.Context) error {
	now := time.Now().UTC()
	comps := s.runtimeComponents(c.Request().Context(), now)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return c.JSON(http.StatusOK, echo.Map{
		"generated_at": now.Format(time.RFC3339),
		"overall":      health.Overall(comps),
		"components":   comps,
		"resources": echo.Map{
			"goroutines":    runtime.NumGoroutine(),
			"heap_alloc_mb": mem.HeapAlloc / (1024 * 1024),
			"uptime_sec":    int(time.Since(s.StartedAt).Seconds()),
		},
		"bounds": runtimeBounds{
			HoneypotMaxConcurrentConns: honeypot.MaxConcurrentConns,
			DedupeMaxKeys:              detection.MaxDedupeEntries,
			HealthMaxComponents:        health.MaxComponents,
			InvestigatePageMax:         investigate.MaxQueryLimit,
			TimelinePageMax:            investigate.MaxTimelinePage,
			ExportMaxBytes:             investigate.MaxExportBytes,
			IOCImportMaxBytes:          intel.MaxImportBytes,
			IOCImportMaxRecords:        intel.MaxImportRecords,
			EvidenceMaxBytes:           detection.MaxEvidenceBytes,
			EventsPerIncidentMax:       database.MaxEventsPerIncident,
		},
		"notes": []string{
			"Health describes VANGUARD's own components, not the security of the host.",
			"unknown = a component stopped reporting; not_yet_observed = nothing recorded yet; neither is a clean result.",
		},
	})
}
