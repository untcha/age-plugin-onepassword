package appmeta

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	want := "dev (commit unknown, built unknown)"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestResolveVersion(t *testing.T) {
	withVersion := func(v string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: v}}
	}
	tests := []struct {
		name    string
		stamped string
		info    *debug.BuildInfo
		want    string
	}{
		{"stamped wins", "v0.2.0", withVersion("v0.1.0"), "v0.2.0"},
		{"go install", "dev", withVersion("v0.1.0"), "v0.1.0"},
		{"local checkout", "dev", withVersion("(devel)"), "dev"},
		{"empty module version", "dev", withVersion(""), "dev"},
		{"no build info", "dev", nil, "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.stamped, tt.info); got != tt.want {
				t.Fatalf("resolveVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveName(t *testing.T) {
	withPath := func(p string) *debug.BuildInfo {
		return &debug.BuildInfo{Path: p}
	}
	tests := []struct {
		name    string
		stamped string
		info    *debug.BuildInfo
		want    string
	}{
		{"stamped wins", "app", withPath("example.com/repo/cmd/other"), "app"},
		{"go install", "", withPath("example.com/repo/cmd/app"), "app"},
		{"empty path", "", withPath(""), ""},
		{"no build info", "", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveName(tt.stamped, tt.info); got != tt.want {
				t.Fatalf("resolveName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStringIncludesAllFields(t *testing.T) {
	origVersion, origCommit, origBuildDate := Version, Commit, BuildDate
	t.Cleanup(func() { Version, Commit, BuildDate = origVersion, origCommit, origBuildDate })

	Version, Commit, BuildDate = "1.2.3", "abc1234", "2026-01-02T00:00:00Z"
	got := String()
	for _, want := range []string{"1.2.3", "abc1234", "2026-01-02T00:00:00Z"} {
		if !strings.Contains(got, want) {
			t.Fatalf("String() = %q, missing %q", got, want)
		}
	}
}
