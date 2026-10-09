package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/retention"
)

// runRetentionCmd implements the operator workflow for the data-lifecycle
// policy (Phase 12):
//
//	vanguard retention show    [-db F]
//	vanguard retention set     [-db F] -days N [-batch N] [-max-batches N] [-keep-with-notes=true] [-expected-revision R] [-confirm]
//	vanguard retention run     [-db F] [-confirm]     (without -confirm: dry run, deletes nothing)
//	vanguard retention history [-db F] [-limit N]
//
// Everything here needs write access to the database file, which is the
// authorization boundary; there is no HTTP route that changes or runs it.
// `set` and `run` only act with -confirm.
func runRetentionCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: vanguard retention show|set|run|history [flags]")
		os.Exit(2)
	}
	switch args[0] {
	case "show":
		retentionShow(args[1:])
	case "set":
		retentionSet(args[1:])
	case "run":
		retentionRun(args[1:])
	case "history":
		retentionHistory(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "vanguard retention: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func retFail(err error) {
	fmt.Fprintf(os.Stderr, "vanguard retention: %v\n", err)
	os.Exit(1)
}

func openRetentionDB(fs *flag.FlagSet, args []string) (*database.DB, *flag.FlagSet) {
	dbPath := fs.String("db", envOr("VANGUARD_DB_PATH", "vanguard.db"), "SQLite database path")
	_ = fs.Parse(args)
	db, err := database.Open(database.Config{Path: *dbPath})
	if err != nil {
		retFail(err)
	}
	return db, fs
}

func retentionShow(args []string) {
	db, _ := openRetentionDB(flag.NewFlagSet("retention show", flag.ExitOnError), args)
	defer db.Close()
	p, err := db.GetRetentionPolicy()
	if err != nil {
		retFail(err)
	}
	printJSON(map[string]any{"policy": p, "enabled": p.IncidentRetentionDays > 0,
		"note": "incident_retention_days 0 = nothing is ever deleted"})
}

func retentionSet(args []string) {
	fs := flag.NewFlagSet("retention set", flag.ExitOnError)
	days := fs.Int("days", -1, "delete eligible incidents older than N days (0 = keep forever, else 30-3650)")
	batch := fs.Int("batch", 0, "incidents per transaction (10-1000; default: keep current)")
	maxBatches := fs.Int("max-batches", 0, "batches per run (1-100; default: keep current)")
	keep := fs.Bool("keep-with-notes", true, "never delete an incident that has a live analyst note")
	rev := fs.Int("expected-revision", -1, "refuse unless the stored policy is at this revision (default: the current one)")
	confirm := fs.Bool("confirm", false, "actually store the policy (without it, only validates and prints)")
	db, _ := openRetentionDB(fs, args)
	defer db.Close()

	cur, err := db.GetRetentionPolicy()
	if err != nil {
		retFail(err)
	}
	if *days < 0 {
		retFail(fmt.Errorf("-days is required (0 disables deletion)"))
	}
	next := cur
	next.IncidentRetentionDays, next.KeepWithNotes = *days, *keep
	if *batch != 0 {
		next.BatchSize = *batch
	}
	if *maxBatches != 0 {
		next.MaxBatchesPerRun = *maxBatches
	}
	if err := retention.Validate(next); err != nil {
		retFail(err)
	}
	if *rev < 0 {
		*rev = cur.Revision
	}
	if !*confirm {
		printJSON(map[string]any{"preview": true, "current": cur, "proposed": next,
			"note": "nothing was changed; add -confirm to store this policy. Run `vanguard retention run` (dry run) to see what it would delete."})
		return
	}
	saved, err := db.SetRetentionPolicy(next, *rev, osActor(), time.Now().UTC())
	if err != nil {
		retFail(err)
	}
	printJSON(map[string]any{"stored": true, "policy": saved})
}

func retentionRun(args []string) {
	fs := flag.NewFlagSet("retention run", flag.ExitOnError)
	confirm := fs.Bool("confirm", false, "actually delete (without it: dry run)")
	db, _ := openRetentionDB(fs, args)
	defer db.Close()
	r := retention.New(db)
	ctx := context.Background()
	var res *retention.Result
	var err error
	if *confirm {
		res, err = r.Execute(ctx, osActor())
	} else {
		res, err = r.Preview(ctx, osActor())
	}
	if res != nil {
		printJSON(res)
	}
	if err != nil {
		retFail(err)
	}
	if res != nil && res.Run.Status == database.RetentionStatusFailed {
		os.Exit(1)
	}
}

func retentionHistory(args []string) {
	fs := flag.NewFlagSet("retention history", flag.ExitOnError)
	limit := fs.Int("limit", 20, "number of audit rows (max 100)")
	db, _ := openRetentionDB(fs, args)
	defer db.Close()
	rows, err := db.ListRetentionRuns(*limit)
	if err != nil {
		retFail(err)
	}
	printJSON(rows)
}
