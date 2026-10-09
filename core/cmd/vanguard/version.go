package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set at build time by deploy/release.sh and the Makefile:
//
//	-ldflags "-X main.version=v1.2.3 -X main.buildDate=2026-10-10T12:00:00Z"
//
// An un-stamped build reports "dev". These strings are labels an operator can
// compare; they are not signatures and prove nothing about who built the file.
var (
	version   = "dev"
	buildDate = ""
)

type buildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`   // VCS revision recorded by the Go toolchain, if any
	Modified  string `json:"modified,omitempty"` // "true" when the tree had uncommitted changes
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	CGO       string `json:"cgo,omitempty"`
	Modules   int    `json:"dependency_modules"`
}

func currentBuildInfo() buildInfo {
	b := buildInfo{Version: version, BuildDate: buildDate, GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	if bi, ok := debug.ReadBuildInfo(); ok {
		b.Modules = len(bi.Deps)
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				b.Commit = s.Value
			case "vcs.modified":
				b.Modified = s.Value
			case "CGO_ENABLED":
				b.CGO = s.Value
			}
		}
	}
	return b
}

func runVersionCmd(args []string) {
	b := currentBuildInfo()
	if len(args) > 0 && (args[0] == "-json" || args[0] == "--json") {
		printJSON(b)
		return
	}
	fmt.Printf("vanguard %s (%s/%s, %s", b.Version, b.OS, b.Arch, b.GoVersion)
	if b.Commit != "" {
		c := b.Commit
		if len(c) > 12 {
			c = c[:12]
		}
		fmt.Printf(", commit %s", c)
		if b.Modified == "true" {
			fmt.Print("+dirty")
		}
	}
	if b.CGO != "" {
		fmt.Printf(", CGO_ENABLED=%s", b.CGO)
	}
	fmt.Println(")")
}
