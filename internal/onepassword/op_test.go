package onepassword_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

var fakeOp string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "fakeop")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fakeOp, err = testutil.BuildFakeOp(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// setup points fakeop at fixtures and returns the call-log path.
func setup(t *testing.T, fixtures string) string {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "op.log")
	t.Setenv("FAKEOP_DIR", fixtures)
	t.Setenv("FAKEOP_LOG", logPath)
	t.Setenv("FAKEOP_FAIL", "")
	t.Setenv("FAKEOP_SLEEP", "")
	return logPath
}

func calls(t *testing.T, logPath string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath) //nolint:gosec // G304: test log path built by setup().
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func newClient(opts onepassword.OpOptions) *onepassword.OpClient {
	opts.Bin = fakeOp
	return onepassword.NewOpClient(opts)
}

func twoVaults(t *testing.T) (dir string, work, private testutil.Key) {
	t.Helper()
	work, private = testutil.Ed25519(t), testutil.Ed25519(t)
	dir = testutil.WriteFakeOpDir(t,
		testutil.OpItem{Key: work, VaultID: "vwork", VaultName: "Work", ItemID: "iwork", Title: "work-key"},
		testutil.OpItem{Key: private, VaultID: "vpriv", VaultName: "Private", ItemID: "ipriv", Title: "private-key"},
	)
	return dir, work, private
}

func TestOpListSSHKeys(t *testing.T) {
	dir, work, private := twoVaults(t)
	const base = "item list --categories SSH Key --format json"
	tests := []struct {
		name     string
		opts     onepassword.OpOptions
		wantIDs  []string
		wantCall string
	}{
		{"all vaults", onepassword.OpOptions{}, []string{"iwork", "ipriv"}, base},
		{"vault scope", onepassword.OpOptions{Vault: "Work"}, []string{"iwork"}, base + " --vault Work"},
		{"account", onepassword.OpOptions{Account: "acme"}, []string{"iwork", "ipriv"}, base + " --account acme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := setup(t, dir)
			items, err := newClient(tt.opts).ListSSHKeys(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, it := range items {
				ids = append(ids, it.ID)
			}
			if !slices.Equal(ids, tt.wantIDs) {
				t.Fatalf("ids = %v, want %v", ids, tt.wantIDs)
			}
			if got := calls(t, logPath); !slices.Equal(got, []string{tt.wantCall}) {
				t.Fatalf("calls = %q, want %q", got, tt.wantCall)
			}
		})
	}
	t.Run("field mapping", func(t *testing.T) {
		setup(t, dir)
		items, err := newClient(onepassword.OpOptions{}).ListSSHKeys(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		want := []onepassword.SSHKeyItem{
			{ID: "iwork", Title: "work-key", VaultID: "vwork", VaultName: "Work", Fingerprint: work.Fingerprint()},
			{
				ID:          "ipriv",
				Title:       "private-key",
				VaultID:     "vpriv",
				VaultName:   "Private",
				Fingerprint: private.Fingerprint(),
			},
		}
		if !slices.Equal(items, want) {
			t.Fatalf("items = %+v, want %+v", items, want)
		}
	})
}

func TestOpListSSHKeysBadJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantIDs []string
		wantErr string
	}{
		{
			name:    "invalid items dropped",
			json:    `[{"id":"","title":"broken","vault":{"id":"v"}},{"id":"ok1","title":"ok","vault":{"id":"v1","name":"V"}}]`,
			wantIDs: []string{"ok1"},
		},
		{name: "malformed", json: "not json", wantErr: "decode op item list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "items.json"), []byte(tt.json), 0o600); err != nil {
				t.Fatal(err)
			}
			setup(t, dir)
			items, err := newClient(onepassword.OpOptions{}).ListSSHKeys(t.Context())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(items) != len(tt.wantIDs) || items[0].ID != tt.wantIDs[0] {
				t.Fatalf("items = %+v, want IDs %v", items, tt.wantIDs)
			}
		})
	}
}

func TestOpResolveSSHKey(t *testing.T) {
	dir, _, _ := twoVaults(t)
	setup(t, dir)
	c := newClient(onepassword.OpOptions{})
	for _, ref := range [][2]string{{"Work", "work-key"}, {"vwork", "iwork"}} {
		it, err := c.ResolveSSHKey(t.Context(), ref[0], ref[1])
		if err != nil {
			t.Fatal(err)
		}
		if it.ID != "iwork" || it.VaultID != "vwork" || it.VaultName != "Work" {
			t.Fatalf("resolve %v = %+v", ref, it)
		}
	}
	if _, err := c.ResolveSSHKey(t.Context(), "Work", "nope"); !errors.Is(err, onepassword.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestOpResolveSSHKeyWrongCategory(t *testing.T) {
	dir := t.TempDir()
	login := `[{"id":"i1","title":"login","category":"LOGIN","vault":{"id":"v1","name":"V"}}]`
	if err := os.WriteFile(filepath.Join(dir, "items.json"), []byte(login), 0o600); err != nil {
		t.Fatal(err)
	}
	setup(t, dir)
	_, err := newClient(onepassword.OpOptions{}).ResolveSSHKey(t.Context(), "V", "login")
	if err == nil || !strings.Contains(err.Error(), "not an SSH key") {
		t.Fatalf("err = %v, want 'not an SSH key'", err)
	}
}

func TestOpReadKeys(t *testing.T) {
	dir, work, _ := twoVaults(t)
	logPath := setup(t, dir)
	c := newClient(onepassword.OpOptions{})
	pub, err := c.PublicKey(t.Context(), "vwork", "iwork")
	if err != nil {
		t.Fatal(err)
	}
	if string(pub) != work.AuthorizedKey {
		t.Fatalf("public key = %q, want %q", pub, work.AuthorizedKey)
	}
	priv, err := c.PrivateKey(t.Context(), "vwork", "iwork")
	if err != nil {
		t.Fatal(err)
	}
	if string(priv) != string(work.PrivatePEM) {
		t.Fatal("private key differs from fixture")
	}
	want := []string{
		"read op://vwork/iwork/public key",
		"read op://vwork/iwork/private key?ssh-format=openssh",
	}
	if got := calls(t, logPath); !slices.Equal(got, want) {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if _, err := c.PrivateKey(t.Context(), "vwork", "missing"); !errors.Is(err, onepassword.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestOpRejectsInvalidIDsWithoutExec(t *testing.T) {
	dir, _, _ := twoVaults(t)
	logPath := setup(t, dir)
	if _, err := newClient(onepassword.OpOptions{}).PrivateKey(t.Context(), "../x", "y"); err == nil {
		t.Fatal("expected error")
	}
	if got := calls(t, logPath); got != nil {
		t.Fatalf("calls = %q, want none", got)
	}
}

func TestOpErrorIncludesStderr(t *testing.T) {
	dir, _, _ := twoVaults(t)
	setup(t, dir)
	t.Setenv("FAKEOP_FAIL", "account is not signed in")
	_, err := newClient(onepassword.OpOptions{}).ListSSHKeys(t.Context())
	if err == nil || !strings.Contains(err.Error(), "account is not signed in") ||
		errors.Is(err, onepassword.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpTimeout(t *testing.T) {
	dir, _, _ := twoVaults(t)
	setup(t, dir)
	t.Setenv("FAKEOP_SLEEP", "5s")
	_, err := newClient(onepassword.OpOptions{Timeout: 200 * time.Millisecond}).ListSSHKeys(t.Context())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}
