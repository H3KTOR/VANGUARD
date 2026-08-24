package firewall

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// PanicModeState is the current lockdown status, returned to the dashboard
// so the UI can render the countdown-to-rollback and require confirmation
// before re-arming.
type PanicModeState struct {
	Active        bool       `json:"active"`
	ActivatedAt   *time.Time `json:"activated_at,omitempty"`
	AutoDisableAt *time.Time `json:"auto_disable_at,omitempty"`
	KeepIPs       []string   `json:"keep_ips,omitempty"`
	KeepPorts     []int      `json:"keep_ports,omitempty"`
	Reason        string     `json:"reason,omitempty"`
}

// PanicPreview is what a dry-run of Panic Mode would do, per the spec's
// "Mandatory Dry-Run: Shows exactly which IPs will be blocked and allowed
// before execution."
type PanicPreview struct {
	WillAllowIPs       []string `json:"will_allow_ips"`
	WillAllowPorts     []int    `json:"will_allow_ports"`
	WillBlockAllOthers bool     `json:"will_block_all_others"`
	Warning            string   `json:"warning"`
}

// panicController tracks live lockdown state and owns the auto-rollback
// timer. Embedded in Autopilot rather than a separate exported type so
// callers only ever interact with one object (Autopilot).
type panicController struct {
	mu    sync.Mutex
	state PanicModeState
	timer *time.Timer
}

// PreviewPanicMode computes (without executing anything) exactly what
// EnterPanicMode would do: which IPs/ports stay open, and a plain-English
// warning. This satisfies the spec's mandatory-dry-run requirement -- the
// dashboard MUST call this and show the result before allowing the
// two-step confirmation to proceed.
func (a *Autopilot) PreviewPanicMode(adminIP string) PanicPreview {
	keepIPs := append([]string{}, a.cfg.AdminWhitelistIPs...)
	if adminIP != "" {
		keepIPs = appendIfMissing(keepIPs, adminIP)
	}
	return PanicPreview{
		WillAllowIPs:       keepIPs,
		WillAllowPorts:     a.cfg.EssentialPorts,
		WillBlockAllOthers: true,
		Warning: fmt.Sprintf(
			"Panic Mode will drop ALL inbound connections except from %v and to ports %v. "+
				"It will automatically disable itself after %s if not manually lifted first.",
			keepIPs, a.cfg.EssentialPorts, a.cfg.PanicModeAutoRollback),
	}
}

// EnterPanicMode activates the site-wide lockdown. Per spec this requires
// the caller (the REST API handler) to have already obtained explicit
// two-step "Are you sure?" confirmation from the operator -- this method
// itself performs no additional confirmation gating, it just executes.
// confirmed must be true or the call is rejected, as a final safety
// backstop against a caller wiring this up without the confirmation step.
func (a *Autopilot) EnterPanicMode(ctx context.Context, adminIP, reason string, confirmed bool) error {
	if !confirmed {
		return fmt.Errorf("panic mode requires explicit confirmation (confirmed=true)")
	}

	keepIPs := append([]string{}, a.cfg.AdminWhitelistIPs...)
	if adminIP != "" {
		keepIPs = appendIfMissing(keepIPs, adminIP)
	}

	if err := a.exec.EnableLockdown(ctx, keepIPs, a.cfg.EssentialPorts); err != nil {
		return fmt.Errorf("failed to enable lockdown: %w", err)
	}

	now := time.Now().UTC()
	rollbackAt := now.Add(a.cfg.PanicModeAutoRollback)

	a.panicCtl.mu.Lock()
	a.panicCtl.state = PanicModeState{
		Active:        true,
		ActivatedAt:   &now,
		AutoDisableAt: &rollbackAt,
		KeepIPs:       keepIPs,
		KeepPorts:     a.cfg.EssentialPorts,
		Reason:        reason,
	}
	if a.panicCtl.timer != nil {
		a.panicCtl.timer.Stop()
	}
	a.panicCtl.timer = time.AfterFunc(a.cfg.PanicModeAutoRollback, func() {
		log.Printf("[autopilot] PANIC MODE emergency rollback firing after %s with no manual exit", a.cfg.PanicModeAutoRollback)
		if err := a.ExitPanicMode(context.Background(), "emergency auto-rollback (30-minute safety timer)"); err != nil {
			log.Printf("[autopilot] CRITICAL: emergency rollback failed: %v", err)
		}
	})
	a.panicCtl.mu.Unlock()

	log.Printf("[autopilot] PANIC MODE ENABLED (reason: %q). Keeping %v / ports %v open. Auto-rollback at %s.",
		reason, keepIPs, a.cfg.EssentialPorts, rollbackAt.Format(time.RFC3339))
	return nil
}

// ExitPanicMode manually (or automatically, via the emergency rollback
// timer) disables Panic Mode, restoring the default-allow-incoming posture
// used before lockdown. Individual IP bans are untouched.
func (a *Autopilot) ExitPanicMode(ctx context.Context, reason string) error {
	if err := a.exec.DisableLockdown(ctx); err != nil {
		return fmt.Errorf("failed to disable lockdown: %w", err)
	}

	a.panicCtl.mu.Lock()
	wasActive := a.panicCtl.state.Active
	if a.panicCtl.timer != nil {
		a.panicCtl.timer.Stop()
		a.panicCtl.timer = nil
	}
	a.panicCtl.state = PanicModeState{Active: false}
	a.panicCtl.mu.Unlock()

	if wasActive {
		log.Printf("[autopilot] PANIC MODE DISABLED (%s)", reason)
	}
	return nil
}

// PanicModeStatus returns the current lockdown state for the dashboard.
func (a *Autopilot) PanicModeStatus() PanicModeState {
	a.panicCtl.mu.Lock()
	defer a.panicCtl.mu.Unlock()
	return a.panicCtl.state
}

func appendIfMissing(list []string, v string) []string {
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
}
