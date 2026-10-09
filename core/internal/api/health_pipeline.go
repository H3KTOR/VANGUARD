package api

import (
	"fmt"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/detection"
	"vanguard/core/internal/health"
	"vanguard/core/internal/pipeline"
)

// lossWindow: a loss event keeps its component degraded for this long. The
// monotonic counters never reset, so the loss stays visible after recovery.
const lossWindow = 15 * time.Minute

// queueSaturation: depth/capacity at or above this is reported as degraded
// (ingestion is being delayed by backpressure; nothing is lost yet).
const queueSaturation = 0.9

func queueComponent(q pipeline.Stats, now time.Time) health.Component {
	c := health.Component{
		Name: "ingest_queue:" + q.Name, State: health.Healthy,
		Counters: map[string]uint64{
			"depth": uint64(q.Depth), "capacity": uint64(q.Capacity), "high_water": q.HighWater,
			"enqueued": q.Enqueued, "processed": q.Processed, "backpressure_waits": q.Waits,
			"processing_failures": q.Failed, "oversize_dropped": q.Oversize,
			"rejected_at_shutdown": q.RejectedShutdown, "abandoned_at_shutdown": q.Abandoned,
		},
	}
	c.Failures = q.Failed
	c.Attempts = q.Processed + q.Failed
	switch {
	case !q.Running:
		c.State, c.Detail = health.Failed, "ingest worker is not running; lines from this source are not being analysed"
	case !q.LastLoss.IsZero() && now.Sub(q.LastLoss) < lossWindow:
		c.State = health.Degraded
		c.Detail = health.Sanitize(fmt.Sprintf("%d line(s) were NOT analysed since start; most recent cause: %s", q.Lost(), q.LastLossKind))
	case q.Capacity > 0 && float64(q.Depth) >= queueSaturation*float64(q.Capacity):
		c.State, c.Detail = health.Degraded, "queue is nearly full: analysis is falling behind ingestion (backpressure, no loss yet)"
	}
	return c
}

func engineComponent(st detection.PersistStats, dedupeKeys int, now time.Time) health.Component {
	c := health.Component{
		Name: "detection_engine", State: health.Healthy,
		Attempts: st.Created + st.Failed, Failures: st.Failed,
		Counters: map[string]uint64{"dedupe_keys": uint64(dedupeKeys), "incidents_created": st.Created, "incidents_lost": st.Failed},
	}
	if st.Failed > 0 && now.Sub(st.LastFailureAt) < lossWindow {
		c.State = health.Failed
		c.Detail = health.Sanitize(fmt.Sprintf("%d detected incident(s) could not be stored and were not sent to response: %s", st.Failed, st.LastError))
	} else if st.Failed > 0 {
		c.State = health.Degraded
		c.Detail = fmt.Sprintf("%d detected incident(s) were lost earlier (persistence has since recovered)", st.Failed)
	}
	return c
}

func guardComponent(g database.GuardStats) health.Component {
	c := health.Component{
		Name: "query_guard", State: health.Healthy,
		Counters: map[string]uint64{
			"limit": uint64(g.Limit), "in_flight": uint64(g.InFlight), "abandoned_running": uint64(g.Abandoned),
			"started": g.Started, "rejected_busy": g.Rejected, "timed_out": g.TimedOut,
		},
	}
	switch {
	case g.Abandoned > 0:
		c.State, c.Detail = health.Degraded, "timed-out queries are still executing inside SQLite (they cannot be interrupted) and hold guard slots"
	case g.InFlight >= g.Limit && g.Limit > 0:
		c.State, c.Detail = health.Degraded, "every expensive-query slot is in use"
	}
	return c
}

// securityComponent reports the abuse-resistance counters. It is informational:
// refusing hostile requests is the control working, so the state stays healthy,
// but recent login throttling is stated in the detail so an operator can see
// that someone is guessing credentials.
func (s *Server) securityComponent(now time.Time) health.Component {
	c := health.Component{
		Name: "api_security", State: health.Healthy,
		Counters: map[string]uint64{
			"login_failures": s.sec.loginFailed.Load(), "login_throttled": s.sec.loginThrottled.Load(),
			"host_rejected": s.sec.hostRejected.Load(), "origin_rejected": s.sec.originRejected.Load(),
			"body_rejected": s.sec.bodyRejected.Load(), "operations_rate_limited": s.sec.opLimited.Load(),
		},
	}
	if last := s.sec.lastThrottle.Load(); last > 0 && now.Sub(time.Unix(last, 0)) < lossWindow {
		c.Detail = "login throttling engaged in the last 15 minutes (repeated failed sign-ins from one address)"
	}
	return c
}
