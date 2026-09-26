//go:build integration

// Package e2e runs the plugin through the real age CLI with a fake op.
package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

const module = "github.com/untcha/age-plugin-onepassword"

func TestIntegrationRoundTrip(t *testing.T) {
	bin := t.TempDir()
	build(t, bin, "age-plugin-onepassword", module+"/cmd/age-plugin-onepassword")
	build(t, bin, "age", "filippo.io/age/cmd/age")
	if _, err := testutil.BuildFakeOp(bin); err != nil {
		t.Fatal(err)
	}
	age := filepath.Join(bin, "age")

	target, other, absent := testutil.Ed25519(t), testutil.Ed25519(t), testutil.Ed25519(t)
	fixtures := testutil.WriteFakeOpDir(t,
		testutil.OpItem{Key: other, VaultID: "v1", VaultName: "Private", ItemID: "other", Title: "other"},
		testutil.OpItem{Key: target, VaultID: "v1", VaultName: "Private", ItemID: "target", Title: "target"},
	)
	logPath := filepath.Join(t.TempDir(), "op.log")
	env := append(baseEnv(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"XDG_CONFIG_HOME="+t.TempDir(),
		"AGE_PLUGIN_ONEPASSWORD_OP="+filepath.Join(bin, "op"),
		"FAKEOP_DIR="+fixtures,
		"FAKEOP_LOG="+logPath,
	)
	const plaintext = "hello from 1Password\n"
	const readTarget = "read op://v1/target/private key?ssh-format=openssh"
	ciphertext := mustRun(t, env, plaintext, age, "-r", target.AuthorizedKey)

	t.Run("default identity", func(t *testing.T) {
		resetLog(t, logPath)
		if got := mustRun(t, env, ciphertext, age, "-d", "-j", "onepassword"); got != plaintext {
			t.Fatalf("plaintext = %q", got)
		}
		want := []string{"item list --categories SSH Key --format json", readTarget}
		if got := readLog(t, logPath); !slices.Equal(got, want) {
			t.Fatalf("op calls = %q, want %q", got, want)
		}
	})

	t.Run("pinned identity", func(t *testing.T) {
		idFile := filepath.Join(t.TempDir(), "pinned.id")
		mustRun(t, env, "", filepath.Join(bin, "age-plugin-onepassword"),
			"identity", "--key", "op://Private/target", "-o", idFile)
		resetLog(t, logPath)
		if got := mustRun(t, env, ciphertext, age, "-d", "-i", idFile); got != plaintext {
			t.Fatalf("plaintext = %q", got)
		}
		if got := readLog(t, logPath); !slices.Equal(got, []string{readTarget}) {
			t.Fatalf("op calls = %q, want only %q", got, readTarget)
		}
	})

	t.Run("plugin-mode setup error surfaces through age", func(t *testing.T) {
		// F1: a config error must reach age's own stderr without AGEDEBUG=plugin,
		// via the identity-v1 protocol, not just the plugin's own stderr (which
		// age discards unless AGEDEBUG=plugin).
		badEnv := append(baseEnv(),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"XDG_CONFIG_HOME="+t.TempDir(),
			"AGE_PLUGIN_ONEPASSWORD_OP="+filepath.Join(bin, "op"),
			"AGE_PLUGIN_ONEPASSWORD_TIMEOUT=bogus",
			"FAKEOP_DIR="+fixtures,
			"FAKEOP_LOG="+logPath,
		)
		resetLog(t, logPath)
		cmd := exec.Command(age, "-d", "-j", "onepassword") //nolint:gosec // G204: test binary.
		var stderr bytes.Buffer
		cmd.Env, cmd.Stdin, cmd.Stderr = badEnv, strings.NewReader(ciphertext), &stderr
		if err := cmd.Run(); err == nil {
			t.Fatal("decrypt succeeded, want failure")
		}
		if !strings.Contains(stderr.String(), "invalid timeout") {
			t.Fatalf("age stderr = %q, want mention of the config error", stderr.String())
		}
	})

	t.Run("file for a key not in 1Password", func(t *testing.T) {
		foreign := mustRun(t, env, plaintext, age, "-r", absent.AuthorizedKey)
		resetLog(t, logPath)
		cmd := exec.Command(age, "-d", "-j", "onepassword") //nolint:gosec // G204: test binary.
		cmd.Env, cmd.Stdin = env, strings.NewReader(foreign)
		if err := cmd.Run(); err == nil {
			t.Fatal("decrypt succeeded, want failure")
		}
		for _, call := range readLog(t, logPath) {
			if strings.HasPrefix(call, "read ") {
				t.Fatalf("unexpected private key read: %q", call)
			}
		}
	})
}

func build(t *testing.T, dir, name, pkg string) {
	t.Helper()
	if _, err := testutil.Build(dir, name, pkg); err != nil {
		t.Fatal(err)
	}
}

// baseEnv drops variables the test controls, so user settings cannot leak in.
func baseEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "AGE_PLUGIN_ONEPASSWORD_") || strings.HasPrefix(kv, "FAKEOP_") ||
			strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=") ||
			strings.HasPrefix(kv, "AGEDEBUG=") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func mustRun(t *testing.T, env []string, stdin, name string, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(name, args...) //nolint:gosec // G204: test binaries.
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, strings.NewReader(stdin), &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v: %v\n%s", filepath.Base(name), args, err, stderr.String())
	}
	return stdout.String()
}

func resetLog(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readLog(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test log path.
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.TrimSpace(string(b)); s != "" {
		return strings.Split(s, "\n")
	}
	return nil
}
