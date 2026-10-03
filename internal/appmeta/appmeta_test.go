package appmeta

import (
	"runtime/debug"
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
