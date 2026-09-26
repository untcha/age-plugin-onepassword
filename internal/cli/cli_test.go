package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	ageplugin "filippo.io/age/plugin"
	"github.com/charmbracelet/log"

	"github.com/untcha/age-plugin-onepassword/internal/appmeta"
	"github.com/untcha/age-plugin-onepassword/internal/cli"
	"github.com/untcha/age-plugin-onepassword/internal/config"
	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword/fake"
	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

func run(t *testing.T, c *fake.Client, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var out, errb bytes.Buffer
	code = cli.Execute(t.Context(), args, cli.Options{
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errb,
		NewClient: func(config.Config, *log.Logger) onepassword.Client {
			return c
		},
	})
	return code, out.String(), errb.String()
}

// identityLines returns the AGE-PLUGIN-… lines of an identity file.
func identityLines(t *testing.T, text string) []string {
	t.Helper()
	var ids []string
	for line := range strings.Lines(text) {
		if strings.HasPrefix(line, "AGE-PLUGIN-ONEPASSWORD-1") {
			ids = append(ids, strings.TrimSpace(line))
		}
	}
	if len(ids) == 0 {
		t.Fatalf("no identity line in:\n%s", text)
	}
	return ids
}

// identityLine returns the only AGE-PLUGIN-… line of an identity file.
func identityLine(t *testing.T, text string) string {
	t.Helper()
	ids := identityLines(t, text)
	if len(ids) != 1 {
		t.Fatalf("identity lines = %d, want 1", len(ids))
	}
	return ids[0]
}

func decodePin(t *testing.T, line string) *identity.Pin {
	t.Helper()
	_, data, err := ageplugin.ParseIdentity(line)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := identity.DecodePayload(data)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func TestDefaultIdentityCommand(t *testing.T) {
	c := &fake.Client{}
	code, out, errOut := run(t, c, "identity")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, errOut)
	}
	if got := identityLine(t, out); got != identity.EncodeDefault() {
		t.Fatalf("identity = %q", got)
	}
	if !strings.Contains(out, "# age-plugin-onepassword default identity (contains no key material)") {
		t.Fatalf("missing header:\n%s", out)
	}
	if len(c.Calls()) != 0 {
		t.Fatalf("calls = %v, want none", c.Calls())
	}
}

func TestPinnedIdentityCommand(t *testing.T) {
	k := testutil.Ed25519(t)
	c := &fake.Client{Keys: []fake.Key{k.FakeKey("v1", "Private", "i1", "target")}}
	code, out, errOut := run(t, c, "identity", "--key", "op://Private/target")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, errOut)
	}
	pin := decodePin(t, identityLine(t, out))
	if pin.VaultID != "v1" || pin.ItemID != "i1" || !bytes.Equal(pin.PubKey.Marshal(), k.PublicKey.Marshal()) {
		t.Fatalf("pin = %+v", pin)
	}
	for _, want := range []string{"# Item: Private/target", "# Recipient: " + k.AuthorizedKey} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if want := []string{"resolve Private/target", "public v1/i1"}; !slices.Equal(c.Calls(), want) {
		t.Fatalf("calls = %v, want %v", c.Calls(), want)
	}
}

func TestPinnedIdentityMultipleKeys(t *testing.T) {
	laptop, backup := testutil.Ed25519(t), testutil.RSA(t)
	c := &fake.Client{Keys: []fake.Key{
		laptop.FakeKey("v1", "Private", "il", "laptop"),
		backup.FakeKey("v1", "Private", "ib", "backup"),
	}}
	code, out, errOut := run(t, c, "identity", "--key", "op://Private/laptop", "--key", "op://Private/backup")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, errOut)
	}
	ids := identityLines(t, out)
	if len(ids) != 2 || decodePin(t, ids[0]).ItemID != "il" || decodePin(t, ids[1]).ItemID != "ib" {
		t.Fatalf("identities = %v", ids)
	}
	if strings.Count(out, "# age-plugin-onepassword pinned identity file") != 1 ||
		strings.Count(out, "# Item: ") != 2 {
		t.Fatalf("unexpected layout:\n%s", out)
	}
}

func TestPinnedIdentityAllOrNothing(t *testing.T) {
	k := testutil.Ed25519(t)
	c := &fake.Client{Keys: []fake.Key{k.FakeKey("v1", "Private", "i1", "target")}}
	tests := []struct {
		name    string
		keys    []string
		wantErr string
	}{
		{"duplicate item", []string{"op://Private/target", "op://v1/i1"}, "same 1Password item"},
		{"second missing", []string{"op://Private/target", "op://Private/missing"}, "resolve op://Private/missing"},
		{"second malformed", []string{"op://Private/target", "Private/x"}, "op://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "op.id")
			args := []string{"identity", "-o", path}
			for _, k := range tt.keys {
				args = append(args, "--key", k)
			}
			code, _, errOut := run(t, c, args...)
			if code != 1 || !strings.Contains(errOut, tt.wantErr) {
				t.Fatalf("code = %d, stderr = %s", code, errOut)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("output file written despite error (stat err = %v)", err)
			}
		})
	}
}

func TestPluginModeLogging(t *testing.T) {
	tests := []struct {
		name       string
		ageDebug   string
		logFile    bool
		wantStderr bool
	}{
		{name: "silent by default"},
		{name: "AGEDEBUG=plugin logs to stderr", ageDebug: "plugin", wantStderr: true},
		{name: "log file only", logFile: true},
		{name: "both", ageDebug: "plugin", logFile: true, wantStderr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AGEDEBUG", tt.ageDebug)
			logPath := ""
			if tt.logFile {
				logPath = filepath.Join(t.TempDir(), "aop.log")
			}
			t.Setenv(config.EnvPrefix+"_LOG_FILE", logPath)
			// recipient-v1 fails fast after logging, without running the protocol.
			_, _, errOut := run(t, &fake.Client{}, "--age-plugin=recipient-v1")
			if got := strings.Contains(errOut, "age plugin session"); got != tt.wantStderr {
				t.Fatalf("debug line on stderr = %v, want %v; stderr:\n%s", got, tt.wantStderr, errOut)
			}
			if tt.logFile {
				//nolint:gosec // G304: logPath is built from t.TempDir() in this test.
				b, err := os.ReadFile(logPath)
				if err != nil || !strings.Contains(string(b), "age plugin failed") {
					t.Fatalf("log file = %q, err = %v", b, err)
				}
			}
		})
	}
}

func TestPinnedIdentityBadRef(t *testing.T) {
	code, _, errOut := run(t, &fake.Client{}, "identity", "--key", "Private/target")
	if code != 1 || !strings.Contains(errOut, "op://") {
		t.Fatalf("code = %d, stderr = %s", code, errOut)
	}
}

func TestIdentityOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "op.id")
	if code, _, errOut := run(t, &fake.Client{}, "identity", "-o", path); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, errOut)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %o, want 600", perm)
	}
	if code, _, _ := run(t, &fake.Client{}, "identity", "-o", path); code != 1 {
		t.Fatalf("overwrite: code = %d, want 1", code)
	}
}

func TestRecipientsCommand(t *testing.T) {
	work, private := testutil.Ed25519(t), testutil.RSA(t)
	c := &fake.Client{Keys: []fake.Key{
		work.FakeKey("vw", "Work", "iw", "deploy"),
		private.FakeKey("vp", "Private", "ip", "chezmoi-age"),
	}}
	code, out, errOut := run(t, c, "recipients")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, errOut)
	}
	want := "op://Private/chezmoi-age: " + private.AuthorizedKey + "\n" +
		"op://Work/deploy: " + work.AuthorizedKey + "\n"
	if out != want {
		t.Fatalf("out =\n%s\nwant\n%s", out, want)
	}
	if n := c.Count("private"); n != 0 {
		t.Fatalf("private key reads = %d, want 0", n)
	}

	_, out, _ = run(t, c, "recipients", "--json")
	var got []map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0]["vault"] != "Private" || got[0]["item_id"] != "ip" ||
		got[1]["public_key"] != work.AuthorizedKey {
		t.Fatalf("json = %v", got)
	}
}

func TestUnsupportedStateMachine(t *testing.T) {
	code, _, errOut := run(t, &fake.Client{}, "--age-plugin=recipient-v1")
	if code != 1 || !strings.Contains(errOut, "unsupported") {
		t.Fatalf("code = %d, stderr = %s", code, errOut)
	}
}

func TestVersionCommand(t *testing.T) {
	code, out, _ := run(t, &fake.Client{}, "version")
	if code != 0 || !strings.Contains(out, appmeta.String()) {
		t.Fatalf("code = %d, out = %q", code, out)
	}
}

func TestNoArgsShowsHelp(t *testing.T) {
	code, out, _ := run(t, &fake.Client{})
	if code != 0 || !strings.Contains(out, "Usage:") {
		t.Fatalf("code = %d, out = %q", code, out)
	}
}
