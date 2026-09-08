package hostsec

// ---------------------------------------------------------------------------
// Feature 4: Account Manipulation Detection
//
// Detection:   periodic parse of /etc/passwd and /etc/group, diffed
//              against the last-known baseline to find: user
//              created/deleted, group created/deleted, a user's UID/GID
//              changed, or a group's member list changed.
// Evidence:    the account/group name and the specific field that changed.
// Risk:        database.IncidentAccountChange.
// Correlation: standard Incident pipeline.
// Response:    alert-only (SourceIP=HostLocalIP; see fim.go doc comment).
// False positives: routine account lifecycle (e.g. a legitimate new
//              service account created by a package installer) still
//              raises a finding by design -- account creation/deletion is
//              inherently worth an analyst's attention, not something
//              this detector can safely auto-suppress. What it does avoid
//              is re-alerting on the SAME already-known account/group
//              every single scan tick, since the baseline is only ever
//              updated to the new state after reporting a change.
// ---------------------------------------------------------------------------

import (
	"bufio"
	"context"
	"os"
	"strings"

	"vanguard/core/internal/database"
)

// passwdEntry is the subset of /etc/passwd fields this detector tracks.
type passwdEntry struct {
	UID  string `json:"uid"`
	GID  string `json:"gid"`
	Home string `json:"home,omitempty"`
	Shell string `json:"shell,omitempty"`
}

// groupEntry is the subset of /etc/group fields this detector tracks.
type groupEntry struct {
	GID     string   `json:"gid"`
	Members []string `json:"members"`
}

// AccountDetector implements Account Manipulation Detection.
type AccountDetector struct {
	db       *database.DB
	reporter Reporter
}

// NewAccountDetector constructs an Account Manipulation Detector.
func NewAccountDetector(db *database.DB, reporter Reporter) *AccountDetector {
	return &AccountDetector{db: db, reporter: reporter}
}

// Scan performs one full pass over /etc/passwd and /etc/group.
func (a *AccountDetector) Scan(ctx context.Context) {
	first, err := isFirstScan(a.db, database.BaselineAccount)
	if err != nil {
		logf("account", "failed to check first-scan marker: %v", err)
		return
	}

	users := parsePasswd()
	if len(users) == 0 {
		// /etc/passwd was unreadable or genuinely empty (should never
		// happen on a real Linux host). Bail out WITHOUT calling
		// diffDeletedUsers, which would otherwise misinterpret a read
		// failure as every single known account having been deleted --
		// a textbook false-positive trap this detector must not fall
		// into (Phase 16: False Positive Protection).
		logf("account", "skipping user diff: /etc/passwd read returned zero entries")
	} else {
		for name, entry := range users {
			if ctx.Err() != nil {
				return
			}
			a.diffUser(name, entry, first)
		}
		a.diffDeletedUsers(users, first)
	}

	groups := parseGroup()
	if len(groups) == 0 {
		logf("account", "skipping group diff: /etc/group read returned zero entries")
	} else {
		for name, entry := range groups {
			if ctx.Err() != nil {
				return
			}
			a.diffGroup(name, entry, first)
		}
		a.diffDeletedGroups(groups, first)
	}

	if first {
		if err := markSeeded(a.db, database.BaselineAccount); err != nil {
			logf("account", "failed to mark category seeded: %v", err)
		}
	}
}

func (a *AccountDetector) diffUser(name string, curr passwdEntry, firstScan bool) {
	key := "user:" + name
	row, err := a.db.GetHostBaseline(database.BaselineAccount, key)
	if err != nil {
		if err != database.ErrNotFound {
			logf("account", "baseline lookup failed for %s: %v", key, err)
			return
		}
		if !firstScan {
			a.reporter.ReportHostFinding(Finding{
				Type:    database.IncidentAccountChange,
				Change:  "user_created",
				Subject: name,
				Details: map[string]any{"user": name, "uid": curr.UID, "gid": curr.GID},
			})
		}
		a.saveUser(key, curr)
		return
	}

	var prev passwdEntry
	_ = row.GetContent(&prev)
	switch {
	case prev.UID != curr.UID:
		a.reporter.ReportHostFinding(Finding{
			Type: database.IncidentAccountChange, Change: "uid_changed", Subject: name,
			Details: map[string]any{"user": name, "previous_uid": prev.UID, "current_uid": curr.UID},
		})
	case prev.GID != curr.GID:
		a.reporter.ReportHostFinding(Finding{
			Type: database.IncidentAccountChange, Change: "gid_changed", Subject: name,
			Details: map[string]any{"user": name, "previous_gid": prev.GID, "current_gid": curr.GID},
		})
	case prev.Shell != curr.Shell:
		a.reporter.ReportHostFinding(Finding{
			Type: database.IncidentAccountChange, Change: "shell_changed", Subject: name,
			Details: map[string]any{"user": name, "previous_shell": prev.Shell, "current_shell": curr.Shell},
		})
	}
	a.saveUser(key, curr)
}

func (a *AccountDetector) saveUser(key string, e passwdEntry) {
	if err := saveJSON(a.db, database.BaselineAccount, key, e); err != nil {
		logf("account", "failed to save baseline for %s: %v", key, err)
	}
}

func (a *AccountDetector) diffDeletedUsers(current map[string]passwdEntry, firstScan bool) {
	rows, err := a.db.ListHostBaseline(database.BaselineAccount)
	if err != nil {
		logf("account", "failed to list baseline: %v", err)
		return
	}
	for _, row := range rows {
		name, ok := strings.CutPrefix(row.Key, "user:")
		if !ok {
			continue
		}
		if _, stillExists := current[name]; stillExists {
			continue
		}
		if !firstScan {
			a.reporter.ReportHostFinding(Finding{
				Type: database.IncidentAccountChange, Change: "user_deleted", Subject: name,
				Details: map[string]any{"user": name},
			})
		}
		if err := a.db.DeleteHostBaseline(database.BaselineAccount, row.Key); err != nil {
			logf("account", "failed to delete stale baseline for %s: %v", row.Key, err)
		}
	}
}

func (a *AccountDetector) diffGroup(name string, curr groupEntry, firstScan bool) {
	key := "group:" + name
	row, err := a.db.GetHostBaseline(database.BaselineAccount, key)
	if err != nil {
		if err != database.ErrNotFound {
			logf("account", "baseline lookup failed for %s: %v", key, err)
			return
		}
		if !firstScan {
			a.reporter.ReportHostFinding(Finding{
				Type: database.IncidentAccountChange, Change: "group_created", Subject: name,
				Details: map[string]any{"group": name, "gid": curr.GID, "members": curr.Members},
			})
		}
		a.saveGroup(key, curr)
		return
	}

	var prev groupEntry
	_ = row.GetContent(&prev)
	added, removed := diffMembers(prev.Members, curr.Members)
	if len(added) > 0 {
		a.reporter.ReportHostFinding(Finding{
			Type: database.IncidentAccountChange, Change: "group_member_added", Subject: name,
			Details: map[string]any{"group": name, "added_members": added},
		})
	}
	if len(removed) > 0 {
		a.reporter.ReportHostFinding(Finding{
			Type: database.IncidentAccountChange, Change: "group_member_removed", Subject: name,
			Details: map[string]any{"group": name, "removed_members": removed},
		})
	}
	if prev.GID != curr.GID {
		a.reporter.ReportHostFinding(Finding{
			Type: database.IncidentAccountChange, Change: "gid_changed", Subject: name,
			Details: map[string]any{"group": name, "previous_gid": prev.GID, "current_gid": curr.GID},
		})
	}
	a.saveGroup(key, curr)
}

func (a *AccountDetector) saveGroup(key string, e groupEntry) {
	if err := saveJSON(a.db, database.BaselineAccount, key, e); err != nil {
		logf("account", "failed to save baseline for %s: %v", key, err)
	}
}

func (a *AccountDetector) diffDeletedGroups(current map[string]groupEntry, firstScan bool) {
	rows, err := a.db.ListHostBaseline(database.BaselineAccount)
	if err != nil {
		return
	}
	for _, row := range rows {
		name, ok := strings.CutPrefix(row.Key, "group:")
		if !ok {
			continue
		}
		if _, stillExists := current[name]; stillExists {
			continue
		}
		if !firstScan {
			a.reporter.ReportHostFinding(Finding{
				Type: database.IncidentAccountChange, Change: "group_deleted", Subject: name,
				Details: map[string]any{"group": name},
			})
		}
		if err := a.db.DeleteHostBaseline(database.BaselineAccount, row.Key); err != nil {
			logf("account", "failed to delete stale baseline for %s: %v", row.Key, err)
		}
	}
}

func diffMembers(prev, curr []string) (added, removed []string) {
	prevSet := make(map[string]bool, len(prev))
	for _, m := range prev {
		prevSet[m] = true
	}
	currSet := make(map[string]bool, len(curr))
	for _, m := range curr {
		currSet[m] = true
	}
	for _, m := range curr {
		if !prevSet[m] {
			added = append(added, m)
		}
	}
	for _, m := range prev {
		if !currSet[m] {
			removed = append(removed, m)
		}
	}
	return added, removed
}

// parsePasswd reads /etc/passwd into name -> passwdEntry. Never returns an
// error to callers: an unreadable /etc/passwd (should never happen on a
// real Linux host) simply yields an empty map, which -- combined with
// diffDeletedUsers -- would spuriously report every known user as deleted.
// To guard against exactly that, an empty parse result on a NON-first
// scan is treated as a read failure and skipped entirely by Scan's
// caller-visible behavior: see the empty-map guard below.
func parsePasswd() map[string]passwdEntry {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()

	out := make(map[string]passwdEntry)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !nonComment(line) {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		out[fields[0]] = passwdEntry{UID: fields[2], GID: fields[3], Home: fields[5], Shell: fields[6]}
	}
	return out
}

// parseGroup reads /etc/group into name -> groupEntry.
func parseGroup() map[string]groupEntry {
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil
	}
	defer f.Close()

	out := make(map[string]groupEntry)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !nonComment(line) {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		var members []string
		if fields[3] != "" {
			members = strings.Split(fields[3], ",")
		}
		out[fields[0]] = groupEntry{GID: fields[2], Members: members}
	}
	return out
}
