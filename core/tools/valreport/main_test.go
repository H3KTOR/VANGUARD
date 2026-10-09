package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, name, body string) string {
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const run1 = `{"Action":"run","Package":"p","Test":"A"}
{"Action":"pass","Package":"p","Test":"A"}
{"Action":"fail","Package":"p","Test":"B"}
{"Action":"skip","Package":"p","Test":"C"}
{"Action":"fail","Package":"p"}
{"Action":"fail","Package":"broken"}
not json at all
`

func TestParseAndCounts(t *testing.T) {
	r, err := parseGoTest(write(t, "a.json", run1))
	if err != nil {
		t.Fatal(err)
	}
	if r.Passed != 1 || r.Failed != 1 || r.Skipped != 1 {
		t.Fatalf("%+v", r)
	}
	if !r.PackageFailed["broken"] {
		t.Fatal("package-level failure must be kept")
	}
}

func TestReportNeverClaimsWhatDidNotRun(t *testing.T) {
	rep, err := build(write(t, "a.json", run1), "", "", "race=no CGO, docker lab=no Docker", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if rep.NotRun["race"] != "no CGO" || rep.NotRun["docker lab"] != "no Docker" {
		t.Fatalf("%v", rep.NotRun)
	}
	if rep.GoTest.BuildFailed[0] != "broken" {
		t.Fatalf("a package that failed with no test result must be surfaced: %v", rep.GoTest.BuildFailed)
	}
	md := markdown(rep)
	for _, want := range []string{"1 passed, 1 failed, 1 skipped", "Skipped tests (**not** passes)", "Not run (unverified)", "not real-world detection efficacy"} {
		if !strings.Contains(md, want) && !strings.Contains(strings.ToLower(md), strings.ToLower(want)) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	noLab, _ := build("", "", "", "", time.Unix(0, 0))
	if noLab.NotRun["docker lab"] == "" || noLab.NotRun["go tests"] == "" {
		t.Fatal("missing inputs must be reported as not run")
	}
}

func TestBaselineComparison(t *testing.T) {
	base := write(t, "b.json", `{"Action":"pass","Package":"p","Test":"A"}
{"Action":"fail","Package":"p","Test":"B"}
{"Action":"fail","Package":"p","Test":"D"}
`)
	cur := write(t, "c.json", `{"Action":"fail","Package":"p","Test":"A"}
{"Action":"pass","Package":"p","Test":"B"}
{"Action":"fail","Package":"p","Test":"D"}
{"Action":"fail","Package":"p","Test":"NEW"}
`)
	rep, err := build(cur, base, "", "", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	c := rep.Baseline
	if len(c.Regressions) != 1 || c.Regressions[0] != "p/A" || len(c.Fixed) != 1 || c.Fixed[0] != "p/B" || len(c.Persistent) != 1 || c.Persistent[0] != "p/D" {
		t.Fatalf("%+v", c)
	}
	for _, x := range append(append([]string{}, c.Regressions...), c.Persistent...) {
		if x == "p/NEW" {
			t.Fatal("a test absent from the baseline is new, not a regression")
		}
	}
}

func TestLabSummaryMustBeValidJSON(t *testing.T) {
	if _, err := build("", "", write(t, "l.json", "{broken"), "", time.Unix(0, 0)); err == nil {
		t.Fatal("invalid lab summary must be an error, not silently ignored")
	}
	rep, err := build("", "", write(t, "l.json", `{"suites":[{"suite":"x","status":"blocked"}]}`), "", time.Unix(0, 0))
	if err != nil || len(rep.Lab) == 0 {
		t.Fatalf("%v", err)
	}
}
