package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/intel"
)

// runIntelCmd implements `vanguard intel import|list`: offline, local-file
// management of the IOC store (no network access of any kind).
//
//	vanguard intel import [-db vanguard.db] [-source name] [-strict]
//	                      [-replace-source] [-allow-shrink] <feed.json|feed.jsonl|->
//	vanguard intel list   [-db vanguard.db] [-type ip|domain|url|sha256] [-limit N]
//
// A running daemon reloads its snapshot every 5 minutes (or immediately
// when you import through the API instead).
func runIntelCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: vanguard intel import|list [flags] ...")
		os.Exit(2)
	}
	switch args[0] {
	case "import":
		intelImport(args[1:])
	case "list":
		intelList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "vanguard intel: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func openIntelDB(path string) *database.DB {
	db, err := database.Open(database.Config{Path: path})
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanguard intel: cannot open database: %v\n", err)
		os.Exit(1)
	}
	return db
}

func intelImport(args []string) {
	fs := flag.NewFlagSet("intel import", flag.ExitOnError)
	dbPath := fs.String("db", envOr("VANGUARD_DB_PATH", "vanguard.db"), "SQLite database path")
	source := fs.String("source", "", "feed source name (used if the feed header has none)")
	strict := fs.Bool("strict", false, "reject the whole import if any record is invalid")
	replace := fs.Bool("replace-source", false, "remove this source's indicators that are absent from the feed (guarded)")
	shrink := fs.Bool("allow-shrink", false, "with -replace-source, allow a >50% reduction")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: vanguard intel import [flags] <file|->")
		os.Exit(2)
	}
	var r io.Reader = os.Stdin
	if p := fs.Arg(0); p != "-" {
		f, err := os.Open(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vanguard intel: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		r = f
	}
	db := openIntelDB(*dbPath)
	rep, err := intel.Import(db, r, intel.ImportOptions{Source: *source, Strict: *strict, ReplaceSource: *replace, AllowShrink: *shrink})
	out, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(out))
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanguard intel: %v\n", err)
		os.Exit(1)
	}
}

func intelList(args []string) {
	fs := flag.NewFlagSet("intel list", flag.ExitOnError)
	dbPath := fs.String("db", envOr("VANGUARD_DB_PATH", "vanguard.db"), "SQLite database path")
	typ := fs.String("type", "", "filter by type")
	limit := fs.Int("limit", 50, "max rows (<=500)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	db := openIntelDB(*dbPath)
	rows, err := db.ListIOCs(database.IOCFilter{Type: database.IOCType(*typ), Limit: *limit})
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanguard intel: %v\n", err)
		os.Exit(1)
	}
	now := time.Now().UTC()
	for _, r := range rows {
		state := "active"
		if !r.Enabled {
			state = "disabled"
		} else if r.ExpiresAt != nil && !now.Before(*r.ExpiresAt) {
			state = "expired"
		}
		fmt.Printf("%-6d %-7s %-8s %-18s %s\n", r.ID, r.Type, state, r.Source, r.Value)
	}
}
