// Command valreport turns REAL test output into a reproducible validation
// report. It never invents results: every number is a count of events found
// in the supplied files, and anything not supplied is reported as "not run"
// (with the reason you pass via -blocked), never as passing.
//
//	go test -json ./... > gotest.json
//	valreport -gotest gotest.json -lab lab/results/summary.json \
//	          -baseline old-gotest.json \
//	          -blocked "race=no CGO toolchain,docker lab=no Docker" \
//	          -out docs/reports/validation
//
// Metric definitions (no coverage or accuracy percentages are produced):
//
//	test events  = go test -json events with Action pass|fail|skip and a
//	               non-empty Test (subtests included, each counted once)
//	passed/failed/skipped = count of those events by Action
//	"not run" suites = capabilities listed in -blocked
//
// A synthetic test or lab pass says the scenario behaved as specified in an
// isolated fixture; it does not measure real-world detection efficacy.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

type goEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
}

// Results summarizes one go test -json stream.
type Results struct {
	Passed, Failed, Skipped int
	Status                  map[string]string // "pkg/Test" -> pass|fail|skip
	PackageFailed           map[string]bool   // build failures / package-level fail without a test
}

func parseGoTest(path string) (*Results, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := &Results{Status: map[string]string{}, PackageFailed: map[string]bool{}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var e goEvent
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		switch e.Action {
		case "pass", "fail", "skip":
		default:
			continue
		}
		if e.Test == "" {
			if e.Action == "fail" {
				r.PackageFailed[e.Package] = true
			}
			continue
		}
		k := e.Package + "/" + e.Test
		r.Status[k] = e.Action
	}
	for _, s := range r.Status {
		switch s {
		case "pass":
			r.Passed++
		case "fail":
			r.Failed++
		case "skip":
			r.Skipped++
		}
	}
	return r, sc.Err()
}

// Report is the machine-readable output.
type Report struct {
	GeneratedAt string            `json:"generated_at"`
	Environment map[string]string `json:"environment"`
	GoTest      *struct {
		Passed      int      `json:"passed"`
		Failed      int      `json:"failed"`
		Skipped     int      `json:"skipped"`
		Failing     []string `json:"failing_tests"`
		Skips       []string `json:"skipped_tests"`
		BuildFailed []string `json:"failed_packages_without_test_result"`
	} `json:"go_tests,omitempty"`
	Baseline *struct {
		Regressions []string `json:"regressions_vs_baseline"`
		Persistent  []string `json:"failing_in_both"`
		Fixed       []string `json:"fixed_since_baseline"`
		Note        string   `json:"note"`
	} `json:"baseline_comparison,omitempty"`
	Lab     json.RawMessage   `json:"lab,omitempty"`
	LabNote string            `json:"lab_note"`
	NotRun  map[string]string `json:"not_run"`
	Caveats []string          `json:"caveats"`
}

func sorted(m map[string]string, want string) []string {
	var out []string
	for k, v := range m {
		if v == want {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func build(gotest, baseline, lab, blocked string, now time.Time) (*Report, error) {
	rep := &Report{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Environment: map[string]string{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version()},
		NotRun:      map[string]string{},
		Caveats: []string{
			"Counts are test events found in the supplied files; nothing is extrapolated.",
			"Passing synthetic tests/lab scenarios show behaviour on isolated fixtures, not real-world detection efficacy, false-negative or false-positive rates.",
			"A report generated on one OS says nothing about another: Linux-specific behaviour is only verified by a Linux run.",
		},
	}
	for _, kv := range strings.Split(blocked, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name, reason, _ := strings.Cut(kv, "=")
		rep.NotRun[strings.TrimSpace(name)] = strings.TrimSpace(reason)
	}
	if gotest != "" {
		r, err := parseGoTest(gotest)
		if err != nil {
			return nil, err
		}
		g := &struct {
			Passed      int      `json:"passed"`
			Failed      int      `json:"failed"`
			Skipped     int      `json:"skipped"`
			Failing     []string `json:"failing_tests"`
			Skips       []string `json:"skipped_tests"`
			BuildFailed []string `json:"failed_packages_without_test_result"`
		}{Passed: r.Passed, Failed: r.Failed, Skipped: r.Skipped, Failing: sorted(r.Status, "fail"), Skips: sorted(r.Status, "skip")}
		for p := range r.PackageFailed {
			hasTest := false
			for k := range r.Status {
				if strings.HasPrefix(k, p+"/") {
					hasTest = true
					break
				}
			}
			if !hasTest {
				g.BuildFailed = append(g.BuildFailed, p)
			}
		}
		sort.Strings(g.BuildFailed)
		rep.GoTest = g
		if baseline != "" {
			b, err := parseGoTest(baseline)
			if err != nil {
				return nil, err
			}
			cmp := &struct {
				Regressions []string `json:"regressions_vs_baseline"`
				Persistent  []string `json:"failing_in_both"`
				Fixed       []string `json:"fixed_since_baseline"`
				Note        string   `json:"note"`
			}{Note: "compares only tests present in both runs; tests absent from the baseline are new, not regressions"}
			for k, s := range r.Status {
				bs, ok := b.Status[k]
				if !ok {
					continue
				}
				switch {
				case s == "fail" && bs == "pass":
					cmp.Regressions = append(cmp.Regressions, k)
				case s == "fail" && bs == "fail":
					cmp.Persistent = append(cmp.Persistent, k)
				case s == "pass" && bs == "fail":
					cmp.Fixed = append(cmp.Fixed, k)
				}
			}
			sort.Strings(cmp.Regressions)
			sort.Strings(cmp.Persistent)
			sort.Strings(cmp.Fixed)
			rep.Baseline = cmp
		}
	} else {
		if _, ok := rep.NotRun["go tests"]; !ok {
			rep.NotRun["go tests"] = "no go test -json file supplied"
		}
	}
	if lab != "" {
		b, err := os.ReadFile(lab)
		if err != nil {
			return nil, err
		}
		if !json.Valid(b) {
			return nil, fmt.Errorf("lab summary %s is not valid JSON", lab)
		}
		rep.Lab = b
		rep.LabNote = "suite status comes from lab/run-all.sh: only assertions the scripts printed count; blocked/skipped suites did not run"
	} else {
		if _, ok := rep.NotRun["docker lab"]; !ok {
			rep.NotRun["docker lab"] = "no lab summary supplied"
		}
		rep.LabNote = "lab not run: no scenario outcome is claimed"
	}
	return rep, nil
}

func markdown(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# VANGUARD validation report\n\nGenerated %s on %s/%s (%s).\n\n", r.GeneratedAt, r.Environment["goos"], r.Environment["goarch"], r.Environment["go"])
	if g := r.GoTest; g != nil {
		fmt.Fprintf(&b, "## Go tests\n\n%d passed, %d failed, %d skipped (test events incl. subtests).\n\n", g.Passed, g.Failed, g.Skipped)
		if len(g.Failing) > 0 {
			b.WriteString("Failing:\n")
			for _, t := range g.Failing {
				fmt.Fprintf(&b, "- %s\n", t)
			}
			b.WriteString("\n")
		}
		if len(g.BuildFailed) > 0 {
			b.WriteString("Packages that failed without reporting a test (build/setup failure):\n")
			for _, p := range g.BuildFailed {
				fmt.Fprintf(&b, "- %s\n", p)
			}
			b.WriteString("\n")
		}
		if len(g.Skips) > 0 {
			fmt.Fprintf(&b, "Skipped tests (**not** passes): %d\n\n", len(g.Skips))
		}
	}
	if c := r.Baseline; c != nil {
		fmt.Fprintf(&b, "## Baseline comparison\n\n%d regression(s), %d failing in both, %d fixed. %s.\n\n", len(c.Regressions), len(c.Persistent), len(c.Fixed), c.Note)
		for _, t := range c.Regressions {
			fmt.Fprintf(&b, "- REGRESSION %s\n", t)
		}
	}
	fmt.Fprintf(&b, "## Lab\n\n%s\n\n", r.LabNote)
	if len(r.NotRun) > 0 {
		b.WriteString("## Not run (unverified)\n\n")
		keys := make([]string, 0, len(r.NotRun))
		for k := range r.NotRun {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "- **%s** — %s\n", k, r.NotRun[k])
		}
		b.WriteString("\n")
	}
	b.WriteString("## Caveats\n\n")
	for _, c := range r.Caveats {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	return b.String()
}

func main() {
	gotest := flag.String("gotest", "", "go test -json output file")
	baseline := flag.String("baseline", "", "earlier go test -json output to compare against")
	lab := flag.String("lab", "", "lab/results/summary.json from lab/run-all.sh")
	blocked := flag.String("blocked", "", "comma list of name=reason for checks that could not run")
	out := flag.String("out", "", "output path prefix (writes <out>.json and <out>.md); stdout if empty")
	flag.Parse()
	rep, err := build(*gotest, *baseline, *lab, *blocked, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "valreport:", err)
		os.Exit(1)
	}
	js, _ := json.MarshalIndent(rep, "", "  ")
	md := markdown(rep)
	if *out == "" {
		fmt.Println(md)
		return
	}
	if err := os.WriteFile(*out+".json", js, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "valreport:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out+".md", []byte(md), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "valreport:", err)
		os.Exit(1)
	}
	if rep.GoTest != nil && (rep.GoTest.Failed > 0 || len(rep.GoTest.BuildFailed) > 0 || (rep.Baseline != nil && len(rep.Baseline.Regressions) > 0)) {
		os.Exit(1)
	}
}
