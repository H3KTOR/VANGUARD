// Command vanguard is the entrypoint for the VANGUARD Core binary.
//
// Step 1 wires up only the database layer and the attack Simulation Engine
// behind a minimal CLI (`vanguard simulate <scenario>`), so both can be
// exercised end-to-end before the log tailer, detection engine, REST API,
// and embedded frontend are layered on in later steps.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"vanguard/core/internal/database"
	"vanguard/core/internal/simulator"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "simulate":
		runSimulateCmd(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "vanguard: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`VANGUARD - Lightweight AI-Assisted Linux IDS/IPS

Usage:
  vanguard simulate <scenario> [flags]   Run a safe, synthetic attack simulation
  vanguard help                          Show this message

Simulate scenarios:
  ssh-bruteforce   Simulate a brute-force SSH login attack (implemented)
  honeypot         Simulate a honeypot trigger (coming soon)
  port-scan        Simulate a port scan (coming soon)

Simulate flags:
  -db string        Path to the SQLite database file (default "vanguard.db")
  -ip string        Source IP to attribute the simulated attack to (default: random)
  -attempts int     Number of attack events to generate (default: scenario-specific)
  -window int       Seconds to spread synthetic events across (default: scenario-specific)
  -ban-minutes int  TTL, in minutes, for the simulated Autopilot ban (default: scenario-specific)
  -no-autoban       Disable the simulated Autopilot ban (incident is created but left open)
  -dry-run          Compute and print the result without writing to the database
  -list             List available simulation scenarios and exit`)
}

func runSimulateCmd(args []string) {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	dbPath := fs.String("db", "vanguard.db", "Path to the SQLite database file")
	ip := fs.String("ip", "", "Source IP to attribute the simulated attack to")
	attempts := fs.Int("attempts", 0, "Number of attack events to generate")
	window := fs.Int("window", 0, "Seconds to spread synthetic events across")
	banMinutes := fs.Int("ban-minutes", 0, "TTL, in minutes, for the simulated Autopilot ban")
	noAutoban := fs.Bool("no-autoban", false, "Disable the simulated Autopilot ban")
	dryRun := fs.Bool("dry-run", false, "Compute and print the result without writing to the database")
	list := fs.Bool("list", false, "List available simulation scenarios and exit")

	registry := simulator.NewRegistry()

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "vanguard simulate: missing scenario name")
		printScenarios(registry)
		os.Exit(1)
	}

	scenario := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		os.Exit(1)
	}

	if *list {
		printScenarios(registry)
		return
	}

	opts := simulator.Options{
		SourceIP:      *ip,
		AttemptCount:  *attempts,
		WindowSeconds: *window,
		AutoBan:       !*noAutoban,
		DryRun:        *dryRun,
	}
	if *banMinutes > 0 {
		opts.BanDuration = time.Duration(*banMinutes) * time.Minute
	}

	var db *database.DB
	if !*dryRun {
		var err error
		db, err = database.Open(database.Config{Path: *dbPath})
		if err != nil {
			fmt.Fprintf(os.Stderr, "vanguard: failed to open database: %v\n", err)
			os.Exit(1)
		}
		defer db.Close()
	}

	result, err := registry.Run(context.Background(), db, scenario, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vanguard simulate: %v\n", err)
		os.Exit(1)
	}

	printResult(result)
}

func printScenarios(r *simulator.Registry) {
	fmt.Println("Available scenarios:")
	for _, s := range r.List() {
		fmt.Printf("  %-16s %s\n", s.Name(), s.Description())
	}
}

func printResult(res *simulator.Result) {
	fmt.Println("──────────────────────────────────────────────────────")
	fmt.Printf(" VANGUARD SIMULATION: %s\n", res.Scenario)
	fmt.Println("──────────────────────────────────────────────────────")
	for _, line := range res.Narrative {
		fmt.Println(" " + line)
	}
	fmt.Println("──────────────────────────────────────────────────────")
	fmt.Printf(" Source IP     : %s\n", res.SourceIP)
	fmt.Printf(" Attempts      : %d\n", res.AttemptCount)
	fmt.Printf(" Risk Score    : %d/100 (%s)\n", res.RiskScore, res.Severity)
	if res.Incident != nil {
		fmt.Printf(" Incident ID   : #%d (status: %s)\n", res.Incident.ID, res.Incident.Status)
	}
	if res.FirewallRule != nil {
		fmt.Printf(" Firewall Rule : #%d banned until %s\n", res.FirewallRule.ID, res.FirewallRule.UnbanAt.Format(time.RFC3339))
	}
	if res.DryRun {
		fmt.Println(" (dry run -- nothing was written to the database)")
	}
	fmt.Println("──────────────────────────────────────────────────────")
}
