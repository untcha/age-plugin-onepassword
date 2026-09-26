package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/log"

	"github.com/untcha/age-plugin-onepassword/internal/config"
)

var envKeys = []string{"VAULT", "ACCOUNT", "OP", "TIMEOUT", "LOG_FILE", "LOG_LEVEL"}

// isolate clears plugin env vars and points XDG_CONFIG_HOME at a temp dir.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	for _, k := range envKeys {
		t.Setenv(config.EnvPrefix+"_"+k, "")
	}
	return home
}

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	defaults := config.Config{OpPath: "op", Timeout: 2 * time.Minute, LogLevel: log.InfoLevel}
	tests := []struct {
		name string
		env  map[string]string
		file string
		want config.Config
	}{
		{name: "defaults", want: defaults},
		{
			name: "file",
			file: "vault: Private\naccount: acme\nop: /opt/op\ntimeout: 30s\nlog_file: /tmp/x.log\nlog_level: debug\n",
			want: config.Config{
				Vault: "Private", Account: "acme", OpPath: "/opt/op", Timeout: 30 * time.Second,
				LogFile: "/tmp/x.log", LogLevel: log.DebugLevel,
			},
		},
		{
			name: "env",
			env:  map[string]string{"VAULT": "Work", "TIMEOUT": "10s", "LOG_LEVEL": "warn"},
			want: config.Config{Vault: "Work", OpPath: "op", Timeout: 10 * time.Second, LogLevel: log.WarnLevel},
		},
		{
			name: "env beats file",
			env:  map[string]string{"VAULT": "Work"},
			file: "vault: Private\n",
			want: config.Config{Vault: "Work", OpPath: "op", Timeout: 2 * time.Minute, LogLevel: log.InfoLevel},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := isolate(t)
			for k, v := range tt.env {
				t.Setenv(config.EnvPrefix+"_"+k, v)
			}
			if tt.file != "" {
				writeConfig(t, filepath.Join(home, "age-plugin-onepassword", "config.yaml"), tt.file)
			}
			got, err := config.Load("")
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLoadExplicitPath(t *testing.T) {
	isolate(t)
	path := filepath.Join(t.TempDir(), "custom.yaml")
	writeConfig(t, path, "vault: Custom\n")
	got, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Vault != "Custom" {
		t.Fatalf("vault = %q, want Custom", got.Vault)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		file string
		path string // explicit path; "missing" = nonexistent
	}{
		{name: "explicit missing file", path: "missing"},
		{name: "malformed yaml", file: "vault: [unclosed\n"},
		{name: "invalid timeout", env: map[string]string{"TIMEOUT": "soon"}},
		{name: "zero timeout", env: map[string]string{"TIMEOUT": "0s"}},
		{name: "negative timeout", env: map[string]string{"TIMEOUT": "-1s"}},
		{name: "invalid log level", env: map[string]string{"LOG_LEVEL": "loud"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := isolate(t)
			for k, v := range tt.env {
				t.Setenv(config.EnvPrefix+"_"+k, v)
			}
			if tt.file != "" {
				writeConfig(t, filepath.Join(home, "age-plugin-onepassword", "config.yaml"), tt.file)
			}
			path := ""
			if tt.path == "missing" {
				path = filepath.Join(t.TempDir(), "nope.yaml")
			}
			if _, err := config.Load(path); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLoadPaths(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantOp  string
		wantLog string
		wantErr bool
	}{
		{name: "bare op", env: map[string]string{"OP": "op"}, wantOp: "op"},
		{name: "absolute op", env: map[string]string{"OP": "/opt/bin/op"}, wantOp: "/opt/bin/op"},
		{name: "tilde op", env: map[string]string{"OP": "~/bin/op"}, wantOp: "HOME/bin/op"},
		{name: "tilde log", env: map[string]string{"LOG_FILE": "~/aop.log"}, wantOp: "op", wantLog: "HOME/aop.log"},
		{name: "relative op", env: map[string]string{"OP": "./op"}, wantErr: true},
		{name: "relative op dir", env: map[string]string{"OP": "bin/op"}, wantErr: true},
		{name: "relative log", env: map[string]string{"LOG_FILE": "logs/aop.log"}, wantErr: true},
		{name: "bare log", env: map[string]string{"LOG_FILE": "aop.log"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolate(t)
			home := t.TempDir()
			t.Setenv("HOME", home)
			for k, v := range tt.env {
				t.Setenv(config.EnvPrefix+"_"+k, v)
			}
			got, err := config.Load("")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			wantOp := strings.Replace(tt.wantOp, "HOME", home, 1)
			wantLog := strings.Replace(tt.wantLog, "HOME", home, 1)
			if got.OpPath != wantOp || got.LogFile != wantLog {
				t.Fatalf("op = %q, log = %q; want %q, %q", got.OpPath, got.LogFile, wantOp, wantLog)
			}
		})
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if got, _ := config.DefaultPath(); got != "/xdg/age-plugin-onepassword/config.yaml" {
		t.Fatalf("with XDG: %q", got)
	}
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)
	want := filepath.Join(home, ".config", "age-plugin-onepassword", "config.yaml")
	if got, _ := config.DefaultPath(); got != want {
		t.Fatalf("without XDG: %q, want %q", got, want)
	}
}
