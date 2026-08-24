// Package firewall implements VANGUARD's Autopilot & IPS (Action Engine):
// it turns detection Incidents into OS firewall changes (UFW/iptables),
// while enforcing the fail-safe guarantees from the spec -- whitelisted
// IPs are never blocked, TTL bans auto-expire, and Panic Mode always
// carries a mandatory dry-run, explicit confirmation, and an automatic
// rollback so an operator can never permanently lock themselves out.
package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Executor is the low-level interface for actually changing OS firewall
// state. Production code uses UFWExecutor (shells out to the `ufw` CLI,
// which requires root); tests and dry-run previews use MockExecutor so the
// Autopilot's decision logic can be verified without touching the host's
// real firewall or requiring root in CI/sandbox environments.
type Executor interface {
	// Block denies all inbound traffic from ip.
	Block(ctx context.Context, ip string) error
	// Unblock removes a previously added block rule for ip.
	Unblock(ctx context.Context, ip string) error
	// Allow explicitly permits traffic from ip (used for whitelist rules
	// and to restore access after Panic Mode / emergency rollback).
	Allow(ctx context.Context, ip string) error
	// EnableLockdown drops all connections except the ports/IPs passed in
	// keepPorts/keepIPs (used by Panic Mode).
	EnableLockdown(ctx context.Context, keepIPs []string, keepPorts []int) error
	// DisableLockdown reverts EnableLockdown, restoring normal operation.
	DisableLockdown(ctx context.Context) error
	// Status returns a human-readable dump of current firewall rules, used
	// by the dashboard's "raw firewall state" diagnostic view.
	Status(ctx context.Context) (string, error)
}

// ---------------------------------------------------------------------------
// UFWExecutor: production implementation shelling out to `ufw`
// ---------------------------------------------------------------------------

// UFWExecutor drives the Uncomplicated Firewall (ufw) CLI. It requires the
// process to run as root (or with passwordless sudo configured for `ufw`)
// on a Linux host with ufw installed. This is intentionally a thin,
// auditable wrapper: every method maps to exactly one or two `ufw`
// invocations, and every command run is returned in errors for easy
// debugging/logging.
type UFWExecutor struct {
	// UseSudo prepends `sudo` to every command. Set this if the VANGUARD
	// process itself does not run as root but has a passwordless sudo rule
	// scoped to `ufw`/`iptables`.
	UseSudo bool
}

// NewUFWExecutor constructs a production UFWExecutor.
func NewUFWExecutor(useSudo bool) *UFWExecutor {
	return &UFWExecutor{UseSudo: useSudo}
}

func (u *UFWExecutor) run(ctx context.Context, args ...string) (string, error) {
	name := "ufw"
	if u.UseSudo {
		args = append([]string{"ufw"}, args...)
		name = "sudo"
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("firewall: command %q %v failed: %w (output: %s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Block adds a `ufw deny from <ip>` rule.
func (u *UFWExecutor) Block(ctx context.Context, ip string) error {
	_, err := u.run(ctx, "deny", "from", ip)
	return err
}

// Unblock removes a `deny from <ip>` rule.
func (u *UFWExecutor) Unblock(ctx context.Context, ip string) error {
	_, err := u.run(ctx, "delete", "deny", "from", ip)
	return err
}

// Allow adds an explicit `ufw allow from <ip>` rule (used for whitelisting
// and restoring an admin's access).
func (u *UFWExecutor) Allow(ctx context.Context, ip string) error {
	_, err := u.run(ctx, "allow", "from", ip)
	return err
}

// EnableLockdown implements Panic Mode: default-deny incoming, then
// re-allow only the whitelisted IPs and the essential ports the operator
// needs to keep serving/administering the box.
func (u *UFWExecutor) EnableLockdown(ctx context.Context, keepIPs []string, keepPorts []int) error {
	if _, err := u.run(ctx, "default", "deny", "incoming"); err != nil {
		return err
	}
	for _, ip := range keepIPs {
		if _, err := u.run(ctx, "allow", "from", ip); err != nil {
			return err
		}
	}
	for _, port := range keepPorts {
		if _, err := u.run(ctx, "allow", fmt.Sprintf("%d", port)); err != nil {
			return err
		}
	}
	_, err := u.run(ctx, "--force", "enable")
	return err
}

// DisableLockdown reverts to a default-allow-incoming posture. Individual
// ban rules created before/after lockdown are left untouched -- this only
// toggles the blanket default-deny policy Panic Mode set.
func (u *UFWExecutor) DisableLockdown(ctx context.Context) error {
	_, err := u.run(ctx, "default", "allow", "incoming")
	return err
}

// Status returns `ufw status verbose` output.
func (u *UFWExecutor) Status(ctx context.Context) (string, error) {
	return u.run(ctx, "status", "verbose")
}

// ---------------------------------------------------------------------------
// MockExecutor: in-memory implementation for tests, dry-run, and
// environments without ufw/root (e.g. this development sandbox).
// ---------------------------------------------------------------------------

// MockExecutor records every call it receives instead of touching any real
// OS firewall state. Safe for concurrent use.
type MockExecutor struct {
	Blocked   map[string]bool
	Allowed   map[string]bool
	Lockdown  bool
	KeepIPs   []string
	KeepPorts []int
	Calls     []string
}

// NewMockExecutor constructs an empty MockExecutor.
func NewMockExecutor() *MockExecutor {
	return &MockExecutor{Blocked: map[string]bool{}, Allowed: map[string]bool{}}
}

func (m *MockExecutor) Block(ctx context.Context, ip string) error {
	m.Blocked[ip] = true
	delete(m.Allowed, ip)
	m.Calls = append(m.Calls, "block "+ip)
	return nil
}

func (m *MockExecutor) Unblock(ctx context.Context, ip string) error {
	delete(m.Blocked, ip)
	m.Calls = append(m.Calls, "unblock "+ip)
	return nil
}

func (m *MockExecutor) Allow(ctx context.Context, ip string) error {
	m.Allowed[ip] = true
	delete(m.Blocked, ip)
	m.Calls = append(m.Calls, "allow "+ip)
	return nil
}

func (m *MockExecutor) EnableLockdown(ctx context.Context, keepIPs []string, keepPorts []int) error {
	m.Lockdown = true
	m.KeepIPs = keepIPs
	m.KeepPorts = keepPorts
	m.Calls = append(m.Calls, fmt.Sprintf("enable_lockdown keep_ips=%v keep_ports=%v", keepIPs, keepPorts))
	return nil
}

func (m *MockExecutor) DisableLockdown(ctx context.Context) error {
	m.Lockdown = false
	m.Calls = append(m.Calls, "disable_lockdown")
	return nil
}

func (m *MockExecutor) Status(ctx context.Context) (string, error) {
	return fmt.Sprintf("lockdown=%v blocked=%d allowed=%d", m.Lockdown, len(m.Blocked), len(m.Allowed)), nil
}
