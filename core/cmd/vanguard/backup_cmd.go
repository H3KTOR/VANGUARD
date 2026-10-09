package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"vanguard/core/internal/backup"
	"vanguard/core/internal/database"
)

// runBackupCmd implements the offline backup/recovery workflow:
//
//	vanguard backup create  [-db F] [-dir D] [-label L] [-exclude-users]
//	vanguard backup list    [-dir D]
//	vanguard backup verify  -name N [-dir D]
//	vanguard backup restore -name N [-db F] [-dir D] [-confirm]
//
// create/list/verify are safe to run while the daemon is up. restore is
// OFFLINE ONLY: stop `vanguard serve` first. Without -confirm it only
// validates and prints what would change.
func runBackupCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: vanguard backup create|list|verify|restore [flags]")
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		backupCreate(args[1:])
	case "list":
		backupList(args[1:])
	case "verify":
		backupVerify(args[1:])
	case "restore":
		backupRestore(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "vanguard backup: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func defaultBackupDir(dbPath string) string { return filepath.Join(filepath.Dir(dbPath), "backups") }

func osActor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli"
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "vanguard backup: %v\n", err)
	os.Exit(1)
}

func backupCreate(args []string) {
	fs := flag.NewFlagSet("backup create", flag.ExitOnError)
	dbPath := fs.String("db", envOr("VANGUARD_DB_PATH", "vanguard.db"), "SQLite database path")
	dir := fs.String("dir", "", "backups directory (default: <db dir>/backups)")
	label := fs.String("label", "", "optional label [a-z0-9]{1,16}")
	excl := fs.Bool("exclude-users", false, "leave user accounts (password hashes) out of the backup")
	_ = fs.Parse(args)
	if *dir == "" {
		*dir = defaultBackupDir(*dbPath)
	}
	db, err := database.Open(database.Config{Path: *dbPath})
	if err != nil {
		fail(err)
	}
	name, m, err := backup.Create(db, backup.CreateOptions{Dir: *dir, Label: *label, ExcludeUsers: *excl, Actor: osActor()})
	res, detail := "ok", ""
	if err != nil {
		res, detail = "failed", err.Error()
	}
	_ = db.RecordBackupAudit(&database.BackupAudit{Kind: "create", Actor: osActor(), BackupName: name, Result: res, Detail: detail,
		DBSHA256: func() string {
			if m != nil {
				return m.DBSHA256
			}
			return ""
		}()})
	if err != nil {
		fail(err)
	}
	printJSON(map[string]any{"name": name, "manifest": m})
}

func backupList(args []string) {
	fs := flag.NewFlagSet("backup list", flag.ExitOnError)
	dbPath := fs.String("db", envOr("VANGUARD_DB_PATH", "vanguard.db"), "used only to derive the default directory")
	dir := fs.String("dir", "", "backups directory")
	_ = fs.Parse(args)
	if *dir == "" {
		*dir = defaultBackupDir(*dbPath)
	}
	l, err := backup.List(*dir)
	if err != nil {
		fail(err)
	}
	printJSON(l)
}

func backupVerify(args []string) {
	fs := flag.NewFlagSet("backup verify", flag.ExitOnError)
	dbPath := fs.String("db", envOr("VANGUARD_DB_PATH", "vanguard.db"), "used only to derive the default directory")
	dir := fs.String("dir", "", "backups directory")
	name := fs.String("name", "", "backup name")
	_ = fs.Parse(args)
	if *dir == "" {
		*dir = defaultBackupDir(*dbPath)
	}
	rep, err := backup.Verify(*dir, *name)
	if err != nil {
		fail(err)
	}
	printJSON(rep)
	if !rep.Valid {
		os.Exit(1)
	}
}

func backupRestore(args []string) {
	fs := flag.NewFlagSet("backup restore", flag.ExitOnError)
	dbPath := fs.String("db", envOr("VANGUARD_DB_PATH", "vanguard.db"), "the live SQLite database to replace")
	dir := fs.String("dir", "", "backups directory")
	name := fs.String("name", "", "backup name")
	confirm := fs.Bool("confirm", false, "actually replace the live database (default: preview only)")
	_ = fs.Parse(args)
	if *dir == "" {
		*dir = defaultBackupDir(*dbPath)
	}
	plan, err := backup.Restore(backup.RestoreOptions{Root: *dir, Name: *name, LivePath: *dbPath, Confirm: *confirm, Actor: osActor()})
	if plan != nil {
		printJSON(plan)
	}
	if err != nil {
		if errors.Is(err, backup.ErrInUse) {
			fmt.Fprintln(os.Stderr, "stop the VANGUARD daemon first, then re-run this command")
		}
		fail(err)
	}
	if !*confirm {
		fmt.Fprintln(os.Stderr, "preview only: nothing was changed. Re-run with -confirm to restore.")
	}
}
