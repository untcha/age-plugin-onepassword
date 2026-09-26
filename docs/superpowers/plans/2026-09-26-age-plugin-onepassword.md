# age-plugin-onepassword Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an age plugin (`age-plugin-onepassword`) that decrypts SSH-key age files by reading only the matching private key from 1Password via the `op` CLI.

**Architecture:** `cli → plugin → identity → onepassword(Client interface)`. `identity` matches age stanza tags against 1Password fingerprints and fetches one key lazily; `onepassword.OpClient` wraps the `op` CLI behind a typed interface so an SDK backend can be added later. Settings come from env/XDG config file because age starts the plugin without user flags.

**Tech Stack:** Go 1.26, filippo.io/age v1.3.2 (plugin framework, agessh), golang.org/x/crypto/ssh, spf13/cobra, spf13/viper, charmbracelet/log, Taskfile (untcha/meta cli template), golangci-lint v2.

**Spec:** `docs/superpowers/specs/2026-09-26-age-plugin-onepassword-design.md`

## Global Constraints

- Module `github.com/untcha/age-plugin-onepassword`; binary `age-plugin-onepassword`; plugin name `onepassword`; env prefix `AGE_PLUGIN_ONEPASSWORD_`.
- `go.mod`: `go 1.26`. Pinned deps: `filippo.io/age v1.3.2`, `golang.org/x/crypto v0.57.0`, `github.com/spf13/cobra v1.10.2`, `github.com/spf13/viper v1.21.0`, `github.com/charmbracelet/log v1.0.0`.
- No fang. No Nix. No references to other implementations in code, comments or docs.
- `CGO_ENABLED=0` builds (Taskfile default).
- **Never run `git init/add/commit`.** Each task ends by proposing a commit message per `docs/COMMIT_GUIDE.md`; the user commits.
- Unit test function names must NOT start with `TestI` (common.yml `test:unit` runs `-run '^Test[^I]*$'`). Integration tests are `TestIntegration*` behind `//go:build integration`.
- Lint config is `untcha/meta` `.golangci.yml` (gosec, funcorder, revive, gocritic, modernize, golines 120). Justify every `//nolint` inline. funcorder: constructor right after its type; exported methods before unexported.
- Never log private keys or `op read` output. `op` must never inherit stdin/stderr (in plugin mode they carry the age protocol).
- Every `op` call takes a `context.Context`.
- If `task lint` reports golines/gofmt/goimports issues, run `task lint:fmt` first, then re-run `task lint`.

**Deviations from spec (intentional, minor):**
- E2E uses build tag `integration` and the shared `task test:integration` instead of a new `e2e` tag / `test:e2e` task — reuses `taskfiles/common.yml`.
- Test SSH keys are generated at test time (`internal/testutil`) instead of committed fixture files — nothing secret-looking in the repo, same determinism of behavior.

## File Map

```text
go.mod, go.sum
Taskfile.yml                          # from meta taskfiles/cli, vars set
taskfiles/common.yml                  # from meta, unchanged
taskfiles/Taskfile.project.yml        # from meta stub, header retitled
.golangci.yml, .gitignore, LICENSE    # from meta, unchanged
README.md
cmd/age-plugin-onepassword/main.go    # signal ctx → cli.Execute → os.Exit
internal/appmeta/appmeta.go           # Version, Commit, BuildDate, String()
internal/config/config.go             # Config, Load, DefaultPath
internal/onepassword/client.go        # Client, SSHKeyItem, ErrNotFound, ValidID, ParseItemRef
internal/onepassword/op.go            # OpClient (op CLI)
internal/onepassword/fake/fake.go     # in-memory Client, records calls
internal/onepassword/fakeop/main.go   # fake `op` binary (tests only)
internal/identity/tag.go              # TagFromFingerprint, TagFromPubKey, StanzaTags
internal/identity/encoding.go         # PluginName, Pin, EncodeDefault, EncodePinned, DecodePayload
internal/identity/decoder.go          # Decoder (shared cache), Decode
internal/identity/default.go          # defaultIdentity.Unwrap
internal/identity/pinned.go           # pinnedIdentity.Unwrap
internal/plugin/plugin.go             # Run(identity-v1)
internal/cli/root.go                  # Execute, Options, root cmd, plugin mode, setup
internal/cli/identity.go              # `identity` command
internal/cli/recipients.go            # `recipients` command
internal/cli/version.go               # `version` command
internal/cli/output.go                # writeOutput (-o, O_EXCL, 0600)
internal/testutil/keys.go             # test key generation, Wrap, FileKey
internal/testutil/fakeop.go           # WriteFakeOpDir, Build, BuildFakeOp
e2e/roundtrip_test.go                 # //go:build integration
```

---

### Task 1: Project scaffold and build metadata

**Files:**
- Create: `go.mod`, `Taskfile.yml`, `taskfiles/common.yml`, `taskfiles/Taskfile.project.yml`, `.golangci.yml`, `.gitignore`, `LICENSE`
- Create: `internal/appmeta/appmeta.go`
- Test: `internal/appmeta/appmeta_test.go`

**Interfaces:**
- Produces: `appmeta.Version`, `appmeta.Commit`, `appmeta.BuildDate` (string vars), `appmeta.String() string`.

- [ ] **Step 1: Init module and copy templates**

```bash
cd /Users/untcha/Development/repositories/golang/age-plugin-onepassword
go mod init github.com/untcha/age-plugin-onepassword
go mod edit -go=1.26
rm -rf /tmp/meta && git clone --depth 1 https://github.com/untcha/meta /tmp/meta
mkdir -p taskfiles
cp /tmp/meta/.gitignore /tmp/meta/.golangci.yml /tmp/meta/LICENSE .
cp /tmp/meta/taskfiles/common.yml /tmp/meta/taskfiles/Taskfile.project.yml taskfiles/
cp /tmp/meta/taskfiles/cli/Taskfile.yml Taskfile.yml
```

(`git clone` of the template into `/tmp` is fine; it does not touch this repo.)

- [ ] **Step 2: Set Taskfile vars and verify include path**

In `Taskfile.yml` set:

```yaml
  REPO: age-plugin-onepassword
  APP_NAME: age-plugin-onepassword
```

Confirm the include reads `taskfile: ./taskfiles/common.yml` and the project include reads `taskfile: ./taskfiles/Taskfile.project.yml` (both already so in the cli template; do not change to `../`).

In `taskfiles/Taskfile.project.yml` replace the first comment block (lines starting `# Source:` … up to `tasks: {}`) header line with:

```yaml
# Project tasks for age-plugin-onepassword (run as `task project:<name>`).
```

Keep `tasks: {}`.

Check `LICENSE` copyright line names the user; if it names a different holder/year, ask the user before editing.

- [ ] **Step 3: Write the failing test**

`internal/appmeta/appmeta_test.go`:

```go
package appmeta

import "testing"

func TestString(t *testing.T) {
	want := "dev (commit unknown, built unknown)"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `go test ./internal/appmeta/`
Expected: FAIL — `undefined: String`

- [ ] **Step 5: Implement**

`internal/appmeta/appmeta.go`:

```go
// Package appmeta holds build metadata, stamped via -ldflags by the Taskfile.
package appmeta

import "fmt"

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// String returns a one-line version description.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildDate)
}
```

- [ ] **Step 6: Verify**

Run: `go test ./internal/appmeta/ && task lint && task --list-all`
Expected: `ok`, lint clean, task list includes `build`, `test:integration`, `lint`.

- [ ] **Step 7: Propose commit**

```
build 🏗(scaffold): init module, tooling and build metadata

Initialise the Go module and vendor the shared tooling from the meta
templates: CLI Taskfile, common tasks, project task stub, golangci
config, gitignore and license. Add internal/appmeta as the single
source of version, commit and build date, stamped via ldflags.
```

---

### Task 2: Test key helpers and stanza tags

**Files:**
- Create: `internal/testutil/keys.go`
- Create: `internal/identity/tag.go`
- Test: `internal/identity/tag_test.go`

**Interfaces:**
- Produces (testutil): `type Key struct{ PublicKey ssh.PublicKey; PrivatePEM []byte; AuthorizedKey string; Recipient age.Recipient }`, `Ed25519(t testing.TB) Key`, `RSA(t testing.TB) Key`, `(Key) Fingerprint() string`, `Wrap(t testing.TB, fileKey []byte, rs ...age.Recipient) []*age.Stanza`, `FileKey() []byte`.
- Produces (identity): `TagFromFingerprint(fp string) (string, error)`, `TagFromPubKey(pk ssh.PublicKey) string`, `StanzaTags(stanzas []*age.Stanza) map[string]bool`.

- [ ] **Step 1: Add dependencies**

```bash
go get filippo.io/age@v1.3.2 golang.org/x/crypto@v0.57.0
```

- [ ] **Step 2: Write test helpers**

`internal/testutil/keys.go`:

```go
// Package testutil holds test-only helpers. Never import it from non-test code.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// Key is a generated SSH key pair in the formats 1Password returns.
type Key struct {
	PublicKey     ssh.PublicKey
	PrivatePEM    []byte // OpenSSH private key PEM
	AuthorizedKey string // "ssh-ed25519 AAAA…", no comment, no newline
	Recipient     age.Recipient
}

// Ed25519 generates an Ed25519 key.
func Ed25519(t testing.TB) Key {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newKey(t, priv)
}

// RSA generates a 2048-bit RSA key.
func RSA(t testing.TB) Key {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return newKey(t, priv)
}

// Fingerprint returns the fingerprint as 1Password reports it ("SHA256:…").
func (k Key) Fingerprint() string {
	return ssh.FingerprintSHA256(k.PublicKey)
}

// FileKey returns a fixed 16-byte age file key.
func FileKey() []byte {
	return []byte("0123456789abcdef")
}

// Wrap wraps fileKey for every recipient and returns all stanzas in order.
func Wrap(t testing.TB, fileKey []byte, rs ...age.Recipient) []*age.Stanza {
	t.Helper()
	var out []*age.Stanza
	for _, r := range rs {
		ss, err := r.Wrap(fileKey)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ss...)
	}
	return out
}

func newKey(t testing.TB, priv any) Key {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	var r age.Recipient
	if pub.Type() == ssh.KeyAlgoED25519 {
		r, err = agessh.NewEd25519Recipient(pub)
	} else {
		r, err = agessh.NewRSARecipient(pub)
	}
	if err != nil {
		t.Fatal(err)
	}
	return Key{
		PublicKey:     pub,
		PrivatePEM:    pem.EncodeToMemory(block),
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Recipient:     r,
	}
}
```

- [ ] **Step 3: Write the failing tests**

`internal/identity/tag_test.go`:

```go
package identity_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

// stanzaTag returns the tag age itself writes for k.
func stanzaTag(t *testing.T, k testutil.Key) string {
	t.Helper()
	return testutil.Wrap(t, testutil.FileKey(), k.Recipient)[0].Args[0]
}

func TestTagFromFingerprint(t *testing.T) {
	ed := testutil.Ed25519(t)
	rsaKey := testutil.RSA(t)
	tests := []struct {
		name    string
		fp      string
		want    string
		wantErr bool
	}{
		{name: "ed25519", fp: ed.Fingerprint(), want: stanzaTag(t, ed)},
		{name: "rsa", fp: rsaKey.Fingerprint(), want: stanzaTag(t, rsaKey)},
		{name: "missing prefix", fp: strings.TrimPrefix(ed.Fingerprint(), "SHA256:"), wantErr: true},
		{name: "bad base64", fp: "SHA256:!!!!", wantErr: true},
		{name: "wrong length", fp: "SHA256:" + base64.RawStdEncoding.EncodeToString([]byte("short")), wantErr: true},
		{name: "empty", fp: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identity.TagFromFingerprint(tt.fp)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("tag = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTagFromPubKey(t *testing.T) {
	for _, k := range []testutil.Key{testutil.Ed25519(t), testutil.RSA(t)} {
		if got, want := identity.TagFromPubKey(k.PublicKey), stanzaTag(t, k); got != want {
			t.Errorf("%s: tag = %q, want %q", k.PublicKey.Type(), got, want)
		}
	}
}

func TestStanzaTags(t *testing.T) {
	ed := testutil.Ed25519(t)
	rsaKey := testutil.RSA(t)
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	fk := testutil.FileKey()
	tests := []struct {
		name    string
		stanzas []*age.Stanza
		want    []string
	}{
		{"ed25519", testutil.Wrap(t, fk, ed.Recipient), []string{stanzaTag(t, ed)}},
		{"rsa", testutil.Wrap(t, fk, rsaKey.Recipient), []string{stanzaTag(t, rsaKey)}},
		{
			"mixed",
			testutil.Wrap(t, fk, x.Recipient(), ed.Recipient, rsaKey.Recipient),
			[]string{stanzaTag(t, ed), stanzaTag(t, rsaKey)},
		},
		{"x25519 only", testutil.Wrap(t, fk, x.Recipient()), nil},
		{"grease", []*age.Stanza{{Type: "x-grease", Args: []string{"abc"}}}, nil},
		{"ssh without args", []*age.Stanza{{Type: "ssh-ed25519"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identity.StanzaTags(tt.stanzas)
			if len(got) != len(tt.want) {
				t.Fatalf("tags = %v, want %v", got, tt.want)
			}
			for _, w := range tt.want {
				if !got[w] {
					t.Errorf("missing tag %q in %v", w, got)
				}
			}
		})
	}
}
```

- [ ] **Step 4: Run to verify failure**

Run: `go test ./internal/identity/`
Expected: FAIL — `undefined: identity.TagFromFingerprint` (package has no non-test files yet).

- [ ] **Step 5: Implement**

`internal/identity/tag.go`:

```go
// Package identity implements age identities backed by SSH keys in 1Password.
package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

// tagSize is the number of SHA-256 bytes age puts in an SSH stanza tag.
const tagSize = 4

// TagFromFingerprint converts a 1Password fingerprint ("SHA256:<base64>") into
// the stanza tag age writes for the same SSH public key.
func TagFromFingerprint(fp string) (string, error) {
	b64, ok := strings.CutPrefix(fp, "SHA256:")
	if !ok {
		return "", fmt.Errorf("fingerprint %q: missing SHA256: prefix", fp)
	}
	sum, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("fingerprint %q: %w", fp, err)
	}
	if len(sum) != sha256.Size {
		return "", fmt.Errorf("fingerprint %q: got %d bytes, want %d", fp, len(sum), sha256.Size)
	}
	return base64.RawStdEncoding.EncodeToString(sum[:tagSize]), nil
}

// TagFromPubKey returns the stanza tag age writes for pk.
func TagFromPubKey(pk ssh.PublicKey) string {
	sum := sha256.Sum256(pk.Marshal())
	return base64.RawStdEncoding.EncodeToString(sum[:tagSize])
}

// StanzaTags collects the tags of all ssh-ed25519 and ssh-rsa stanzas.
func StanzaTags(stanzas []*age.Stanza) map[string]bool {
	tags := make(map[string]bool)
	for _, s := range stanzas {
		if (s.Type == ssh.KeyAlgoED25519 || s.Type == ssh.KeyAlgoRSA) && len(s.Args) > 0 {
			tags[s.Args[0]] = true
		}
	}
	return tags
}
```

- [ ] **Step 6: Verify**

Run: `go test ./internal/identity/ && task lint`
Expected: `ok`, lint clean.

- [ ] **Step 7: Propose commit**

```
feat ✨(identity): derive age stanza tags from 1Password fingerprints

Add tag helpers that map a 1Password "SHA256:" fingerprint and an SSH
public key to the 4-byte tag age writes into ssh-ed25519 and ssh-rsa
stanzas, plus stanza tag collection. Add test helpers that generate
Ed25519 and RSA keys and wrap file keys for recipients.
```

---

### Task 3: 1Password boundary types and in-memory fake

**Files:**
- Create: `internal/onepassword/client.go`
- Create: `internal/onepassword/fake/fake.go`
- Modify: `internal/testutil/keys.go` (append `FakeKey` method)
- Test: `internal/onepassword/client_test.go`

**Interfaces:**
- Produces (onepassword):
  ```go
  type SSHKeyItem struct{ ID, Title, VaultID, VaultName, Fingerprint string }
  var ErrNotFound error
  type Client interface {
      ListSSHKeys(ctx context.Context) ([]SSHKeyItem, error)
      ResolveSSHKey(ctx context.Context, vault, item string) (SSHKeyItem, error)
      PublicKey(ctx context.Context, vaultID, itemID string) ([]byte, error)
      PrivateKey(ctx context.Context, vaultID, itemID string) ([]byte, error)
  }
  func ValidID(s string) bool
  func ParseItemRef(ref string) (vault, item string, err error)
  ```
- Produces (fake): `type Key struct{ Item onepassword.SSHKeyItem; PublicKey, PrivateKey []byte }`, `type Client struct{ Keys []Key; Err error }` implementing `onepassword.Client`, `(*Client) Calls() []string`, `(*Client) Count(prefix string) int`. Call records: `"list"`, `"resolve <vault>/<item>"`, `"public <vaultID>/<itemID>"`, `"private <vaultID>/<itemID>"`.
- Produces (testutil): `(Key) FakeKey(vaultID, vaultName, itemID, title string) fake.Key`.

- [ ] **Step 1: Write the failing tests**

`internal/onepassword/client_test.go`:

```go
package onepassword_test

import (
	"strings"
	"testing"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

func TestValidID(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"abcdefghijklmnopqrstuvwxyz", true},
		{"ABC123", true},
		{strings.Repeat("a", 255), true},
		{"", false},
		{strings.Repeat("a", 256), false},
		{"a/b", false},
		{"a b", false},
		{"..", false},
		{"a?b", false},
	}
	for _, tt := range tests {
		if got := onepassword.ValidID(tt.in); got != tt.want {
			t.Errorf("ValidID(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseItemRef(t *testing.T) {
	tests := []struct {
		ref       string
		vault     string
		item      string
		wantError bool
	}{
		{ref: "op://Private/chezmoi-age", vault: "Private", item: "chezmoi-age"},
		{ref: "op://Private/My Key", vault: "Private", item: "My Key"},
		{ref: "Private/chezmoi-age", wantError: true},
		{ref: "op://Private", wantError: true},
		{ref: "op://Private/item/private key", wantError: true},
		{ref: "op:///item", wantError: true},
		{ref: "op://Private/", wantError: true},
	}
	for _, tt := range tests {
		vault, item, err := onepassword.ParseItemRef(tt.ref)
		if (err != nil) != tt.wantError {
			t.Fatalf("ParseItemRef(%q) err = %v, wantError %v", tt.ref, err, tt.wantError)
		}
		if vault != tt.vault || item != tt.item {
			t.Errorf("ParseItemRef(%q) = %q, %q; want %q, %q", tt.ref, vault, item, tt.vault, tt.item)
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/onepassword/`
Expected: FAIL — `undefined: onepassword.ValidID`

- [ ] **Step 3: Implement the boundary**

`internal/onepassword/client.go`:

```go
// Package onepassword is the boundary to 1Password. Callers depend on Client;
// OpClient implements it with the op CLI.
package onepassword

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// maxIDLength bounds vault and item IDs (1Password IDs are 26 characters).
const maxIDLength = 255

// ErrNotFound reports a vault or item that does not exist.
var ErrNotFound = errors.New("1password: item not found")

// SSHKeyItem is the metadata of an SSH Key item. It never holds secrets.
type SSHKeyItem struct {
	ID          string
	Title       string
	VaultID     string
	VaultName   string
	Fingerprint string // "SHA256:<base64>", as reported by 1Password
}

// Client is the subset of 1Password the plugin needs.
type Client interface {
	// ListSSHKeys returns metadata of SSH Key items. No secrets.
	ListSSHKeys(ctx context.Context) ([]SSHKeyItem, error)
	// ResolveSSHKey looks up one SSH Key item by vault and item (name or ID).
	ResolveSSHKey(ctx context.Context, vault, item string) (SSHKeyItem, error)
	// PublicKey returns the item's public key in authorized_keys format.
	PublicKey(ctx context.Context, vaultID, itemID string) ([]byte, error)
	// PrivateKey returns the item's private key in OpenSSH format.
	PrivateKey(ctx context.Context, vaultID, itemID string) ([]byte, error)
}

// ValidID reports whether s is a plausible 1Password vault or item ID:
// 1..255 ASCII letters or digits. It keeps untrusted IDs out of op:// references.
func ValidID(s string) bool {
	if s == "" || len(s) > maxIDLength {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// ParseItemRef parses "op://<vault>/<item>" into vault and item (names or IDs).
func ParseItemRef(ref string) (vault, item string, err error) {
	rest, ok := strings.CutPrefix(ref, "op://")
	if !ok {
		return "", "", fmt.Errorf("item reference %q: must start with op://", ref)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("item reference %q: want op://<vault>/<item>", ref)
	}
	return parts[0], parts[1], nil
}
```

- [ ] **Step 4: Implement the fake**

`internal/onepassword/fake/fake.go`:

```go
// Package fake provides an in-memory onepassword.Client for tests.
package fake

import (
	"context"
	"fmt"
	"strings"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

var _ onepassword.Client = (*Client)(nil)

// Key is one SSH Key item with its key material.
type Key struct {
	Item       onepassword.SSHKeyItem
	PublicKey  []byte
	PrivateKey []byte
}

// Client serves Keys and records every call. Not safe for concurrent use.
type Client struct {
	Keys  []Key
	Err   error // when set, every call fails with it
	calls []string
}

func (c *Client) ListSSHKeys(_ context.Context) ([]onepassword.SSHKeyItem, error) {
	c.calls = append(c.calls, "list")
	if c.Err != nil {
		return nil, c.Err
	}
	items := make([]onepassword.SSHKeyItem, 0, len(c.Keys))
	for _, k := range c.Keys {
		items = append(items, k.Item)
	}
	return items, nil
}

func (c *Client) ResolveSSHKey(_ context.Context, vault, item string) (onepassword.SSHKeyItem, error) {
	c.calls = append(c.calls, "resolve "+vault+"/"+item)
	if c.Err != nil {
		return onepassword.SSHKeyItem{}, c.Err
	}
	for _, k := range c.Keys {
		it := k.Item
		if (it.VaultID == vault || it.VaultName == vault) && (it.ID == item || it.Title == item) {
			return it, nil
		}
	}
	return onepassword.SSHKeyItem{}, fmt.Errorf("resolve %s/%s: %w", vault, item, onepassword.ErrNotFound)
}

func (c *Client) PublicKey(_ context.Context, vaultID, itemID string) ([]byte, error) {
	c.calls = append(c.calls, "public "+vaultID+"/"+itemID)
	k, err := c.find(vaultID, itemID)
	if err != nil {
		return nil, err
	}
	return k.PublicKey, nil
}

func (c *Client) PrivateKey(_ context.Context, vaultID, itemID string) ([]byte, error) {
	c.calls = append(c.calls, "private "+vaultID+"/"+itemID)
	k, err := c.find(vaultID, itemID)
	if err != nil {
		return nil, err
	}
	return k.PrivateKey, nil
}

// Calls returns the recorded calls in order.
func (c *Client) Calls() []string {
	return append([]string(nil), c.calls...)
}

// Count returns how many recorded calls start with prefix.
func (c *Client) Count(prefix string) int {
	n := 0
	for _, call := range c.calls {
		if strings.HasPrefix(call, prefix) {
			n++
		}
	}
	return n
}

func (c *Client) find(vaultID, itemID string) (Key, error) {
	if c.Err != nil {
		return Key{}, c.Err
	}
	for _, k := range c.Keys {
		if k.Item.VaultID == vaultID && k.Item.ID == itemID {
			return k, nil
		}
	}
	return Key{}, fmt.Errorf("%s/%s: %w", vaultID, itemID, onepassword.ErrNotFound)
}
```

- [ ] **Step 5: Add testutil bridge**

Append to `internal/testutil/keys.go` (add imports `github.com/untcha/age-plugin-onepassword/internal/onepassword` and `.../internal/onepassword/fake`; place the method directly after `Fingerprint`):

```go
// FakeKey returns k as an item for fake.Client.
func (k Key) FakeKey(vaultID, vaultName, itemID, title string) fake.Key {
	return fake.Key{
		Item: onepassword.SSHKeyItem{
			ID:          itemID,
			Title:       title,
			VaultID:     vaultID,
			VaultName:   vaultName,
			Fingerprint: k.Fingerprint(),
		},
		PublicKey:  []byte(k.AuthorizedKey),
		PrivateKey: k.PrivatePEM,
	}
}
```

- [ ] **Step 6: Verify**

Run: `go test ./internal/... && task lint`
Expected: `ok` for onepassword and identity, lint clean.

- [ ] **Step 7: Propose commit**

```
feat ✨(onepassword): add 1Password client boundary and fake

Define the Client interface the plugin depends on (list SSH key
metadata, resolve an item, read public and private key), item
metadata, ErrNotFound, ID validation and op://vault/item parsing.
Add an in-memory fake that records calls for tests.
```

---

### Task 4: Identity encoding (default + pinned payload v1)

**Files:**
- Create: `internal/identity/encoding.go`
- Test: `internal/identity/encoding_test.go`

**Interfaces:**
- Consumes: `onepassword.ValidID`.
- Produces: `const PluginName = "onepassword"`, `type Pin struct{ VaultID, ItemID string; PubKey ssh.PublicKey }`, `EncodeDefault() string`, `EncodePinned(p Pin) (string, error)`, `DecodePayload(data []byte) (*Pin, error)` (nil, nil for empty payload).

- [ ] **Step 1: Write the failing tests**

`internal/identity/encoding_test.go`:

```go
package identity_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"testing"

	ageplugin "filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"

	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

func TestEncodeDefault(t *testing.T) {
	const want = "AGE-PLUGIN-ONEPASSWORD-10K6MQ2"
	if got := identity.EncodeDefault(); got != want {
		t.Fatalf("EncodeDefault() = %q, want %q", got, want)
	}
	name, data, err := ageplugin.ParseIdentity(want)
	if err != nil || name != identity.PluginName {
		t.Fatalf("ParseIdentity = %q, %v", name, err)
	}
	pin, err := identity.DecodePayload(data)
	if err != nil || pin != nil {
		t.Fatalf("DecodePayload(default) = %v, %v; want nil, nil", pin, err)
	}
}

func TestPinnedRoundTrip(t *testing.T) {
	for _, k := range []testutil.Key{testutil.Ed25519(t), testutil.RSA(t)} {
		in := identity.Pin{VaultID: "vault1", ItemID: "item1", PubKey: k.PublicKey}
		s, err := identity.EncodePinned(in)
		if err != nil {
			t.Fatal(err)
		}
		_, data, err := ageplugin.ParseIdentity(s)
		if err != nil {
			t.Fatal(err)
		}
		out, err := identity.DecodePayload(data)
		if err != nil {
			t.Fatal(err)
		}
		if out.VaultID != in.VaultID || out.ItemID != in.ItemID ||
			!bytes.Equal(out.PubKey.Marshal(), in.PubKey.Marshal()) {
			t.Fatalf("round trip = %+v, want %+v", out, in)
		}
	}
}

func TestEncodePinnedRejectsInvalid(t *testing.T) {
	pub := testutil.Ed25519(t).PublicKey
	tests := map[string]identity.Pin{
		"empty vault ID":    {VaultID: "", ItemID: "i", PubKey: pub},
		"slash in item ID":  {VaultID: "v", ItemID: "a/b", PubKey: pub},
		"missing publickey": {VaultID: "v", ItemID: "i"},
	}
	for name, p := range tests {
		if _, err := identity.EncodePinned(p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDecodePayloadErrors(t *testing.T) {
	pub := testutil.Ed25519(t).PublicKey.Marshal()
	tests := []struct {
		name string
		data []byte
	}{
		{"unknown version", payload(2, []byte("v"), []byte("i"), pub)},
		{"missing fields", payload(1, []byte("v"))},
		{"truncated length", []byte{1, 0}},
		{"truncated field", []byte{1, 0, 5, 'a'}},
		{"empty field", payload(1, []byte{}, []byte("i"), pub)},
		{"trailing bytes", append(payload(1, []byte("v"), []byte("i"), pub), 0xff)},
		{"invalid vault ID", payload(1, []byte("../x"), []byte("i"), pub)},
		{"oversized item ID", payload(1, []byte("v"), bytes.Repeat([]byte("a"), 300), pub)},
		{"garbage public key", payload(1, []byte("v"), []byte("i"), []byte("nope"))},
		{"unsupported key type", payload(1, []byte("v"), []byte("i"), ecdsaPub(t))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := identity.DecodePayload(tt.data); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// payload builds a raw pinned payload: version, then uint16-length-prefixed fields.
func payload(version byte, fields ...[]byte) []byte {
	out := []byte{version}
	for _, f := range fields {
		out = binary.BigEndian.AppendUint16(out, uint16(len(f))) //nolint:gosec // G115: test fields are < 64 KiB.
		out = append(out, f...)
	}
	return out
}

func ecdsaPub(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub.Marshal()
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/identity/`
Expected: FAIL — `undefined: identity.EncodeDefault`

- [ ] **Step 3: Implement**

`internal/identity/encoding.go`:

```go
package identity

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	ageplugin "filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

// PluginName is the age plugin name: binary age-plugin-onepassword, `age -j onepassword`.
const PluginName = "onepassword"

// payloadV1 is the version byte of the pinned identity payload.
const payloadV1 byte = 0x01

// Pin identifies exactly one SSH Key item in 1Password. It holds no secrets.
type Pin struct {
	VaultID string
	ItemID  string
	PubKey  ssh.PublicKey
}

// EncodeDefault returns the default identity (empty payload). It matches any
// SSH key in 1Password and is equivalent to `age -j onepassword`.
func EncodeDefault() string {
	return ageplugin.EncodeIdentity(PluginName, nil)
}

// EncodePinned returns the identity string for p.
//
// Payload v1: version byte, then vault ID, item ID and SSH wire-format public
// key, each prefixed with a big-endian uint16 length.
func EncodePinned(p Pin) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	b := []byte{payloadV1}
	for _, f := range [][]byte{[]byte(p.VaultID), []byte(p.ItemID), p.PubKey.Marshal()} {
		if len(f) > math.MaxUint16 {
			return "", fmt.Errorf("pin: field of %d bytes too long", len(f))
		}
		b = binary.BigEndian.AppendUint16(b, uint16(len(f)))
		b = append(b, f...)
	}
	return ageplugin.EncodeIdentity(PluginName, b), nil
}

// DecodePayload parses an identity payload. An empty payload is the default
// identity and returns (nil, nil).
func DecodePayload(data []byte) (*Pin, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if data[0] != payloadV1 {
		return nil, fmt.Errorf("identity payload: unsupported version %d", data[0])
	}
	rest := data[1:]
	var fields [3][]byte
	for i := range fields {
		var err error
		if fields[i], rest, err = readField(rest); err != nil {
			return nil, fmt.Errorf("identity payload: %w", err)
		}
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("identity payload: %d trailing bytes", len(rest))
	}
	pk, err := ssh.ParsePublicKey(fields[2])
	if err != nil {
		return nil, fmt.Errorf("identity payload: public key: %w", err)
	}
	p := &Pin{VaultID: string(fields[0]), ItemID: string(fields[1]), PubKey: pk}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("identity payload: %w", err)
	}
	return p, nil
}

func (p Pin) validate() error {
	if !onepassword.ValidID(p.VaultID) {
		return fmt.Errorf("pin: invalid vault ID %q", p.VaultID)
	}
	if !onepassword.ValidID(p.ItemID) {
		return fmt.Errorf("pin: invalid item ID %q", p.ItemID)
	}
	if p.PubKey == nil {
		return errors.New("pin: missing public key")
	}
	if t := p.PubKey.Type(); t != ssh.KeyAlgoED25519 && t != ssh.KeyAlgoRSA {
		return fmt.Errorf("pin: unsupported key type %s", t)
	}
	return nil
}

func readField(b []byte) (field, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, errors.New("truncated field length")
	}
	n := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if n == 0 {
		return nil, nil, errors.New("empty field")
	}
	if len(b) < n {
		return nil, nil, errors.New("truncated field")
	}
	return b[:n], b[n:], nil
}
```

If gosec still reports G115 on `uint16(len(f))` despite the guard, add `//nolint:gosec // G115: bounded by the MaxUint16 check above.` on that line.

- [ ] **Step 4: Verify**

Run: `go test ./internal/identity/ && task lint`
Expected: `ok`, lint clean.

- [ ] **Step 5: Propose commit**

```
feat ✨(identity): encode default and pinned identities

Add the plugin name, the default identity (empty payload) and a
versioned pinned payload holding vault ID, item ID and SSH public
key. Decoding validates version, field lengths, IDs, trailing bytes
and key type, so untrusted identity files cannot inject references.
```

---

### Task 5: Decoder and default identity (targeted lookup)

**Files:**
- Create: `internal/identity/decoder.go`
- Create: `internal/identity/default.go`
- Test: `internal/identity/default_test.go`

**Interfaces:**
- Consumes: `onepassword.Client`, `fake.Client`, `testutil.*`, `DecodePayload`, `StanzaTags`, `TagFromFingerprint`.
- Produces: `NewDecoder(ctx context.Context, client onepassword.Client, logger *log.Logger) *Decoder`, `(*Decoder) Decode(data []byte) (age.Identity, error)`. Unexported for Task 6: `(*Decoder) privateKey(vaultID, itemID string) ([]byte, error)` (cached), `unwrapWithKey(key []byte, stanzas []*age.Stanza) ([]byte, error)`, fields `ctx`, `client`, `logger`.

- [ ] **Step 1: Add dependency**

```bash
go get github.com/charmbracelet/log@v1.0.0
```

- [ ] **Step 2: Write the failing tests**

`internal/identity/default_test.go`:

```go
package identity_test

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/charmbracelet/log"

	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword/fake"
	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

func newDecoder(t *testing.T, c *fake.Client) *identity.Decoder {
	t.Helper()
	return identity.NewDecoder(t.Context(), c, log.New(io.Discard))
}

func defaultIdentity(t *testing.T, d *identity.Decoder) age.Identity {
	t.Helper()
	id, err := d.Decode(nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDefaultTargeted(t *testing.T) {
	for _, target := range []testutil.Key{testutil.Ed25519(t), testutil.RSA(t)} {
		t.Run(target.PublicKey.Type(), func(t *testing.T) {
			c := &fake.Client{Keys: []fake.Key{
				testutil.Ed25519(t).FakeKey("v1", "Private", "other1", "other ed25519"),
				target.FakeKey("v1", "Private", "target", "target"),
				testutil.RSA(t).FakeKey("v2", "Work", "other2", "other rsa"),
			}}
			stanzas := testutil.Wrap(t, testutil.FileKey(), target.Recipient)
			got, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, testutil.FileKey()) {
				t.Fatalf("file key = %x", got)
			}
			if want := []string{"list", "private v1/target"}; !slices.Equal(c.Calls(), want) {
				t.Fatalf("calls = %v, want %v", c.Calls(), want)
			}
		})
	}
}

func TestDefaultNoSSHStanza(t *testing.T) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	c := &fake.Client{}
	_, err = defaultIdentity(t, newDecoder(t, c)).Unwrap(testutil.Wrap(t, testutil.FileKey(), x.Recipient()))
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("err = %v, want ErrIncorrectIdentity", err)
	}
	if len(c.Calls()) != 0 {
		t.Fatalf("calls = %v, want none", c.Calls())
	}
}

func TestDefaultNoMatch(t *testing.T) {
	c := &fake.Client{Keys: []fake.Key{testutil.Ed25519(t).FakeKey("v1", "Private", "other", "other")}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), testutil.Ed25519(t).Recipient)
	_, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas)
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("err = %v, want ErrIncorrectIdentity", err)
	}
	if n := c.Count("private"); n != 0 {
		t.Fatalf("private key reads = %d, want 0", n)
	}
}

func TestDefaultCollision(t *testing.T) {
	target := testutil.Ed25519(t)
	impostor := testutil.Ed25519(t).FakeKey("v1", "Private", "impostor", "impostor")
	impostor.Item.Fingerprint = target.Fingerprint() // same tag, different key
	c := &fake.Client{Keys: []fake.Key{impostor, target.FakeKey("v1", "Private", "target", "target")}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), target.Recipient)
	if _, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas); err != nil {
		t.Fatal(err)
	}
	want := []string{"list", "private v1/impostor", "private v1/target"}
	if !slices.Equal(c.Calls(), want) {
		t.Fatalf("calls = %v, want %v", c.Calls(), want)
	}
}

func TestDefaultBadItemsSkipped(t *testing.T) {
	target := testutil.Ed25519(t)
	var bad []fake.Key
	for i, fp := range []string{"", "garbage", "SHA256:xx"} {
		k := testutil.Ed25519(t).FakeKey("v1", "Private", "bad"+string(rune('a'+i)), "bad")
		k.Item.Fingerprint = fp
		bad = append(bad, k)
	}
	c := &fake.Client{Keys: append(bad, target.FakeKey("v1", "Private", "target", "target"))}
	stanzas := testutil.Wrap(t, testutil.FileKey(), target.Recipient)
	if _, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas); err != nil {
		t.Fatal(err)
	}
	if n := c.Count("private"); n != 1 {
		t.Fatalf("private key reads = %d, want 1", n)
	}
}

func TestDefaultLocked(t *testing.T) {
	c := &fake.Client{Err: errors.New("account is not signed in")}
	stanzas := testutil.Wrap(t, testutil.FileKey(), testutil.Ed25519(t).Recipient)
	_, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas)
	if err == nil || errors.Is(err, age.ErrIncorrectIdentity) || !strings.Contains(err.Error(), "not signed in") {
		t.Fatalf("err = %v, want fatal error mentioning 'not signed in'", err)
	}
}

func TestDefaultMultiRecipient(t *testing.T) {
	target := testutil.Ed25519(t)
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	c := &fake.Client{Keys: []fake.Key{target.FakeKey("v1", "Private", "target", "target")}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), x.Recipient(), target.Recipient)
	if _, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas); err != nil {
		t.Fatal(err)
	}
	if n := c.Count("private"); n != 1 {
		t.Fatalf("private key reads = %d, want 1", n)
	}
}

func TestDefaultCachePerDecoder(t *testing.T) {
	target := testutil.Ed25519(t)
	c := &fake.Client{Keys: []fake.Key{target.FakeKey("v1", "Private", "target", "target")}}
	d := newDecoder(t, c)
	for range 2 {
		stanzas := testutil.Wrap(t, testutil.FileKey(), target.Recipient)
		if _, err := defaultIdentity(t, d).Unwrap(stanzas); err != nil {
			t.Fatal(err)
		}
	}
	if n := c.Count("private"); n != 1 {
		t.Fatalf("private key reads = %d, want 1", n)
	}
}

func TestDefaultUnparseableMatchedKey(t *testing.T) {
	target := testutil.Ed25519(t)
	k := target.FakeKey("v1", "Private", "target", "target")
	k.PrivateKey = []byte("not a key")
	c := &fake.Client{Keys: []fake.Key{k}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), target.Recipient)
	_, err := defaultIdentity(t, newDecoder(t, c)).Unwrap(stanzas)
	if err == nil || errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("err = %v, want fatal parse error", err)
	}
}

func TestDecodeInvalidPayload(t *testing.T) {
	if _, err := newDecoder(t, &fake.Client{}).Decode([]byte{9}); err == nil {
		t.Fatal("expected error")
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/identity/`
Expected: FAIL — `undefined: identity.NewDecoder`

- [ ] **Step 4: Implement the decoder**

`internal/identity/decoder.go`:

```go
package identity

import (
	"context"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/charmbracelet/log"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

// Decoder turns identity payloads into age identities backed by 1Password.
// All identities it returns share one in-memory private-key cache, so each
// key is fetched at most once per process. Not safe for concurrent use; age
// calls Unwrap sequentially.
type Decoder struct {
	// ctx bounds 1Password calls; age.Identity.Unwrap has no context parameter.
	ctx    context.Context
	client onepassword.Client
	logger *log.Logger
	cache  map[string][]byte
}

// NewDecoder returns a Decoder using client for all 1Password access.
func NewDecoder(ctx context.Context, client onepassword.Client, logger *log.Logger) *Decoder {
	return &Decoder{ctx: ctx, client: client, logger: logger, cache: make(map[string][]byte)}
}

// Decode parses an identity payload as passed by the age plugin framework.
// An empty payload yields the default identity.
func (d *Decoder) Decode(data []byte) (age.Identity, error) {
	pin, err := DecodePayload(data)
	if err != nil {
		return nil, err
	}
	if pin == nil {
		return &defaultIdentity{d: d}, nil
	}
	return &pinnedIdentity{d: d, pin: *pin}, nil
}

// privateKey returns the item's private key, fetching it at most once.
func (d *Decoder) privateKey(vaultID, itemID string) ([]byte, error) {
	k := vaultID + "/" + itemID
	if key, ok := d.cache[k]; ok {
		return key, nil
	}
	key, err := d.client.PrivateKey(d.ctx, vaultID, itemID)
	if err != nil {
		return nil, err
	}
	d.cache[k] = key
	return key, nil
}

// unwrapWithKey unwraps stanzas with an OpenSSH private key. The error wraps
// age.ErrIncorrectIdentity when the key does not match any stanza.
func unwrapWithKey(key []byte, stanzas []*age.Stanza) ([]byte, error) {
	id, err := agessh.ParseIdentity(key)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return id.Unwrap(stanzas)
}
```

`pinnedIdentity` is added in Task 6. To compile now, create a minimal placeholder **in `pinned.go`** that Task 6 replaces entirely:

```go
package identity

import (
	"errors"

	"filippo.io/age"
)

type pinnedIdentity struct {
	d   *Decoder
	pin Pin
}

func (i *pinnedIdentity) Unwrap(_ []*age.Stanza) ([]byte, error) {
	return nil, errors.New("pinned identity: not implemented")
}
```

- [ ] **Step 5: Implement the default identity**

`internal/identity/default.go`:

```go
package identity

import (
	"errors"
	"fmt"

	"filippo.io/age"
)

// defaultIdentity finds the key a file was encrypted to by matching stanza
// tags against 1Password fingerprints, then reads only matching keys.
type defaultIdentity struct {
	d *Decoder
}

func (i *defaultIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	tags := StanzaTags(stanzas)
	if len(tags) == 0 {
		return nil, age.ErrIncorrectIdentity
	}
	items, err := i.d.client.ListSSHKeys(i.d.ctx)
	if err != nil {
		return nil, fmt.Errorf("list SSH keys in 1Password: %w", err)
	}
	for _, it := range items {
		tag, err := TagFromFingerprint(it.Fingerprint)
		if err != nil {
			i.d.logger.Warn("skipping 1Password item", "item", it.Title, "vault", it.VaultID, "err", err)
			continue
		}
		if !tags[tag] {
			continue
		}
		i.d.logger.Debug("stanza tag matches 1Password item", "item", it.Title, "vault", it.VaultID, "tag", tag)
		key, err := i.d.privateKey(it.VaultID, it.ID)
		if err != nil {
			return nil, fmt.Errorf("read private key of 1Password item %q: %w", it.Title, err)
		}
		fileKey, err := unwrapWithKey(key, stanzas)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			i.d.logger.Debug("tag collision, trying next item", "item", it.Title)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("1Password item %q: %w", it.Title, err)
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}
```

- [ ] **Step 6: Verify**

Run: `go test ./internal/identity/ && task lint`
Expected: `ok`, lint clean.

- [ ] **Step 7: Propose commit**

```
feat ✨(identity): decrypt with only the matching 1Password key

Add the Decoder and the default identity. Unwrap collects SSH stanza
tags, lists 1Password SSH key metadata, and reads only items whose
fingerprint yields a matching tag. Files without SSH stanzas make no
1Password calls, bad items are skipped, tag collisions fall through
to the next match, and keys are cached per process.
```

---

### Task 6: Pinned identity

**Files:**
- Modify (replace entirely): `internal/identity/pinned.go`
- Test: `internal/identity/pinned_test.go`

**Interfaces:**
- Consumes: `Decoder.privateKey`, `Decoder.client/ctx/logger`, `unwrapWithKey`, `TagFromPubKey`, `StanzaTags`, `onepassword.ErrNotFound`, `EncodePinned`.
- Produces: `pinnedIdentity.Unwrap` behaviour (via `Decoder.Decode` with a pinned payload).

- [ ] **Step 1: Write the failing tests**

`internal/identity/pinned_test.go`:

```go
package identity_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
	ageplugin "filippo.io/age/plugin"

	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword/fake"
	"github.com/untcha/age-plugin-onepassword/internal/testutil"
)

func pinnedIdentity(t *testing.T, d *identity.Decoder, k testutil.Key, vaultID, itemID string) age.Identity {
	t.Helper()
	s, err := identity.EncodePinned(identity.Pin{VaultID: vaultID, ItemID: itemID, PubKey: k.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	_, data, err := ageplugin.ParseIdentity(s)
	if err != nil {
		t.Fatal(err)
	}
	id, err := d.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPinnedTagMismatch(t *testing.T) {
	pinned, other := testutil.Ed25519(t), testutil.Ed25519(t)
	c := &fake.Client{Keys: []fake.Key{pinned.FakeKey("v1", "Private", "a", "a")}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), other.Recipient)
	_, err := pinnedIdentity(t, newDecoder(t, c), pinned, "v1", "a").Unwrap(stanzas)
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("err = %v, want ErrIncorrectIdentity", err)
	}
	if len(c.Calls()) != 0 {
		t.Fatalf("calls = %v, want none", c.Calls())
	}
}

func TestPinnedByID(t *testing.T) {
	for _, k := range []testutil.Key{testutil.Ed25519(t), testutil.RSA(t)} {
		c := &fake.Client{Keys: []fake.Key{k.FakeKey("v1", "Private", "a", "a")}}
		stanzas := testutil.Wrap(t, testutil.FileKey(), k.Recipient)
		got, err := pinnedIdentity(t, newDecoder(t, c), k, "v1", "a").Unwrap(stanzas)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, testutil.FileKey()) {
			t.Fatalf("file key = %x", got)
		}
		if want := []string{"private v1/a"}; !slices.Equal(c.Calls(), want) {
			t.Fatalf("calls = %v, want %v", c.Calls(), want)
		}
	}
}

func TestPinnedFallbackByFingerprint(t *testing.T) {
	k := testutil.Ed25519(t)
	c := &fake.Client{Keys: []fake.Key{k.FakeKey("v2", "Work", "fresh", "moved")}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), k.Recipient)
	if _, err := pinnedIdentity(t, newDecoder(t, c), k, "v1", "stale").Unwrap(stanzas); err != nil {
		t.Fatal(err)
	}
	want := []string{"private v1/stale", "list", "private v2/fresh"}
	if !slices.Equal(c.Calls(), want) {
		t.Fatalf("calls = %v, want %v", c.Calls(), want)
	}
}

func TestPinnedFallbackMissing(t *testing.T) {
	k := testutil.Ed25519(t)
	c := &fake.Client{}
	stanzas := testutil.Wrap(t, testutil.FileKey(), k.Recipient)
	_, err := pinnedIdentity(t, newDecoder(t, c), k, "v1", "gone").Unwrap(stanzas)
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("err = %v, want ErrIncorrectIdentity", err)
	}
}

func TestPinnedPubKeyMismatch(t *testing.T) {
	pinned, other := testutil.Ed25519(t), testutil.Ed25519(t)
	k := pinned.FakeKey("v1", "Private", "a", "a")
	k.PrivateKey = other.PrivatePEM // item now holds a different key
	c := &fake.Client{Keys: []fake.Key{k}}
	stanzas := testutil.Wrap(t, testutil.FileKey(), pinned.Recipient)
	_, err := pinnedIdentity(t, newDecoder(t, c), pinned, "v1", "a").Unwrap(stanzas)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v, want pubkey mismatch", err)
	}
}

func TestPinnedReadError(t *testing.T) {
	k := testutil.Ed25519(t)
	c := &fake.Client{Err: errors.New("account is not signed in")}
	stanzas := testutil.Wrap(t, testutil.FileKey(), k.Recipient)
	_, err := pinnedIdentity(t, newDecoder(t, c), k, "v1", "a").Unwrap(stanzas)
	if err == nil || errors.Is(err, age.ErrIncorrectIdentity) || !strings.Contains(err.Error(), "not signed in") {
		t.Fatalf("err = %v, want fatal error mentioning 'not signed in'", err)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/identity/ -run Pinned`
Expected: FAIL — `pinned identity: not implemented`

- [ ] **Step 3: Implement**

Replace `internal/identity/pinned.go`:

```go
package identity

import (
	"bytes"
	"errors"
	"fmt"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

// pinnedIdentity reads one known item. It needs a single 1Password call and
// falls back to a fingerprint search if the item was moved or recreated.
type pinnedIdentity struct {
	d   *Decoder
	pin Pin
}

func (i *pinnedIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if !StanzaTags(stanzas)[TagFromPubKey(i.pin.PubKey)] {
		return nil, age.ErrIncorrectIdentity
	}
	key, err := i.d.privateKey(i.pin.VaultID, i.pin.ItemID)
	switch {
	case errors.Is(err, onepassword.ErrNotFound):
		i.d.logger.Warn("pinned 1Password item not found, searching by fingerprint; regenerate the identity",
			"vault", i.pin.VaultID, "item", i.pin.ItemID)
		if key, err = i.findByFingerprint(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("read pinned private key: %w", err)
	}
	if err := matchesPubKey(key, i.pin.PubKey); err != nil {
		return nil, err
	}
	fileKey, err := unwrapWithKey(key, stanzas)
	if err != nil {
		return nil, fmt.Errorf("pinned identity: %w", err)
	}
	return fileKey, nil
}

func (i *pinnedIdentity) findByFingerprint() ([]byte, error) {
	fp := ssh.FingerprintSHA256(i.pin.PubKey)
	items, err := i.d.client.ListSSHKeys(i.d.ctx)
	if err != nil {
		return nil, fmt.Errorf("list SSH keys in 1Password: %w", err)
	}
	for _, it := range items {
		if it.Fingerprint != fp {
			continue
		}
		key, err := i.d.privateKey(it.VaultID, it.ID)
		if err != nil {
			return nil, fmt.Errorf("read private key of 1Password item %q: %w", it.Title, err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("pinned SSH key %s not found in 1Password: %w", fp, age.ErrIncorrectIdentity)
}

// matchesPubKey ensures the key read from 1Password is the pinned key.
func matchesPubKey(key []byte, want ssh.PublicKey) error {
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("pinned identity: parse private key: %w", err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), want.Marshal()) {
		return fmt.Errorf("pinned identity: 1Password key %s does not match pinned key %s",
			ssh.FingerprintSHA256(signer.PublicKey()), ssh.FingerprintSHA256(want))
	}
	return nil
}
```

- [ ] **Step 4: Verify**

Run: `go test ./internal/identity/ && task lint`
Expected: `ok`, lint clean.

- [ ] **Step 5: Propose commit**

```
feat ✨(identity): add pinned identity with one 1Password call

A pinned identity stores vault ID, item ID and public key. Unwrap
skips 1Password entirely when the file is for another key, reads the
pinned item directly otherwise, falls back to a fingerprint search if
the item was moved or recreated, and refuses a key that does not
match the pinned public key.
```

---

### Task 7: op CLI client and fake op binary

**Files:**
- Create: `internal/onepassword/op.go`
- Create: `internal/onepassword/fakeop/main.go`
- Create: `internal/testutil/fakeop.go`
- Test: `internal/onepassword/op_test.go`

**Interfaces:**
- Consumes: `SSHKeyItem`, `ErrNotFound`, `ValidID`, `testutil.Key`.
- Produces (onepassword): `type OpOptions struct{ Bin, Vault, Account string; Timeout time.Duration; Logger *log.Logger }`, `NewOpClient(opts OpOptions) *OpClient` implementing `Client`.
- Produces (testutil): `type OpItem struct{ Key Key; VaultID, VaultName, ItemID, Title, Fingerprint string }` (empty Fingerprint = derived), `WriteFakeOpDir(t testing.TB, items ...OpItem) string`, `Build(dir, name, pkg string) (string, error)`, `BuildFakeOp(dir string) (string, error)`.
- fakeop env contract: `FAKEOP_DIR` (fixtures: `items.json`, `keys/<vaultID>/<itemID>/{private,public}`), `FAKEOP_LOG` (append args joined by space, one line per call), `FAKEOP_FAIL` (stderr message, exit 1), `FAKEOP_SLEEP` (duration before responding).

- [ ] **Step 1: Write the fake op binary**

`internal/onepassword/fakeop/main.go`:

```go
// Command fakeop imitates the subset of the 1Password CLI used by OpClient.
// Test-only.
//
// Environment:
//
//	FAKEOP_DIR    fixtures: items.json and keys/<vaultID>/<itemID>/{private,public}
//	FAKEOP_LOG    append each invocation's arguments (space-joined) to this file
//	FAKEOP_FAIL   print this to stderr and exit 1
//	FAKEOP_SLEEP  sleep this duration before responding
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type item struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Vault    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
	AdditionalInformation string `json:"additional_information,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if err := logCall(args); err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	if d, err := time.ParseDuration(os.Getenv("FAKEOP_SLEEP")); err == nil {
		time.Sleep(d)
	}
	if msg := os.Getenv("FAKEOP_FAIL"); msg != "" {
		fmt.Fprintf(stderr, "[ERROR] 2026/01/01 00:00:00 %s\n", msg)
		return 1
	}
	pos, flags := parseArgs(args)
	dir := os.Getenv("FAKEOP_DIR")
	switch {
	case len(pos) == 2 && pos[0] == "item" && pos[1] == "list":
		return itemList(dir, flags, stdout, stderr)
	case len(pos) == 3 && pos[0] == "item" && pos[1] == "get":
		return itemGet(dir, pos[2], flags["--vault"], stdout, stderr)
	case len(pos) == 2 && pos[0] == "read":
		return read(dir, pos[1], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "fakeop: unsupported command %q\n", args)
		return 2
	}
}

func logCall(args []string) error {
	p := os.Getenv("FAKEOP_LOG")
	if p == "" {
		return nil
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: test log path.
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, strings.Join(args, " "))
	return err
}

// parseArgs splits args into positionals and "--flag value" / "--flag=value" pairs.
func parseArgs(args []string) (pos []string, flags map[string]string) {
	flags = make(map[string]string)
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			if name, val, ok := strings.Cut(a, "="); ok {
				flags[name] = val
				continue
			}
			if i+1 < len(args) {
				flags[a] = args[i+1]
				i++
				continue
			}
		}
		pos = append(pos, a)
	}
	return pos, flags
}

func itemList(dir string, flags map[string]string, stdout, stderr io.Writer) int {
	if flags["--categories"] != "SSH Key" || flags["--format"] != "json" {
		fmt.Fprintln(stderr, `fakeop: item list needs --categories "SSH Key" --format json`)
		return 2
	}
	raw, err := os.ReadFile(filepath.Join(dir, "items.json")) //nolint:gosec // G304: test fixture path.
	if err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	vault := flags["--vault"]
	if vault == "" {
		_, _ = stdout.Write(raw) // raw, so tests can serve malformed JSON
		return 0
	}
	var items, out []item
	if err := json.Unmarshal(raw, &items); err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	for _, it := range items {
		if it.Vault.ID == vault || it.Vault.Name == vault {
			out = append(out, it)
		}
	}
	if out == nil {
		out = []item{}
	}
	_ = json.NewEncoder(stdout).Encode(out)
	return 0
}

func itemGet(dir, ref, vault string, stdout, stderr io.Writer) int {
	raw, err := os.ReadFile(filepath.Join(dir, "items.json")) //nolint:gosec // G304: test fixture path.
	if err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	var items []item
	if err := json.Unmarshal(raw, &items); err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	for _, it := range items {
		if (it.Vault.ID == vault || it.Vault.Name == vault) && (it.ID == ref || it.Title == ref) {
			_ = json.NewEncoder(stdout).Encode(it)
			return 0
		}
	}
	fmt.Fprintf(stderr, "[ERROR] 2026/01/01 00:00:00 %q isn't an item in the %q vault. "+
		"Specify the item with its UUID, name, or domain.\n", ref, vault)
	return 1
}

func read(dir, ref string, stdout, stderr io.Writer) int {
	rest, ok := strings.CutPrefix(ref, "op://")
	path, query, _ := strings.Cut(rest, "?")
	parts := strings.Split(path, "/")
	if !ok || len(parts) != 3 {
		fmt.Fprintf(stderr, "fakeop: bad reference %q\n", ref)
		return 2
	}
	var file string
	switch parts[2] {
	case "private key":
		if query != "ssh-format=openssh" {
			fmt.Fprintln(stderr, "fakeop: private key read without ?ssh-format=openssh")
			return 2
		}
		file = "private"
	case "public key":
		file = "public"
	default:
		fmt.Fprintf(stderr, "fakeop: unsupported field %q\n", parts[2])
		return 2
	}
	b, err := os.ReadFile(filepath.Join(dir, "keys", parts[0], parts[1], file)) //nolint:gosec // G304: test fixture path.
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "[ERROR] 2026/01/01 00:00:00 could not read secret '%s': %q isn't an item in the %q vault\n",
			ref, parts[1], parts[0])
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "fakeop:", err)
		return 2
	}
	fmt.Fprintln(stdout, strings.TrimRight(string(b), "\n"))
	return 0
}
```

- [ ] **Step 2: Write fixture helpers**

`internal/testutil/fakeop.go`:

```go
package testutil

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// FakeOpPackage is the import path of the fake op binary.
const FakeOpPackage = "github.com/untcha/age-plugin-onepassword/internal/onepassword/fakeop"

// OpItem is one SSH Key item in a fake op fixture directory.
type OpItem struct {
	Key         Key
	VaultID     string
	VaultName   string
	ItemID      string
	Title       string
	Fingerprint string // empty: derived from Key
}

// WriteFakeOpDir writes items.json and key files for fakeop and returns the directory.
func WriteFakeOpDir(t testing.TB, items ...OpItem) string {
	t.Helper()
	dir := t.TempDir()
	list := make([]map[string]any, 0, len(items))
	for _, it := range items {
		fp := it.Fingerprint
		if fp == "" {
			fp = it.Key.Fingerprint()
		}
		list = append(list, map[string]any{
			"id":                     it.ItemID,
			"title":                  it.Title,
			"category":               "SSH_KEY",
			"vault":                  map[string]string{"id": it.VaultID, "name": it.VaultName},
			"additional_information": fp,
		})
		keyDir := filepath.Join(dir, "keys", it.VaultID, it.ItemID)
		if err := os.MkdirAll(keyDir, 0o750); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(keyDir, "private"), it.Key.PrivatePEM)
		writeFile(t, filepath.Join(keyDir, "public"), []byte(it.Key.AuthorizedKey))
	}
	b, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "items.json"), b)
	return dir
}

// Build compiles the Go package pkg into dir/name and returns the binary path.
func Build(dir, name, pkg string) (string, error) {
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", out, pkg) //nolint:gosec // G204: test helper building known packages.
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build %s: %w\n%s", pkg, err, b)
	}
	return out, nil
}

// BuildFakeOp compiles fakeop into dir/op.
func BuildFakeOp(dir string) (string, error) {
	return Build(dir, "op", FakeOpPackage)
}

func writeFile(t testing.TB, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 3: Write the failing tests**

`internal/onepassword/op_test.go`:

```go
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
	b, err := os.ReadFile(logPath)
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
			{ID: "ipriv", Title: "private-key", VaultID: "vpriv", VaultName: "Private", Fingerprint: private.Fingerprint()},
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
	if err == nil || !strings.Contains(err.Error(), "account is not signed in") || errors.Is(err, onepassword.ErrNotFound) {
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
```

- [ ] **Step 4: Run to verify failure**

Run: `go test ./internal/onepassword/`
Expected: FAIL — `undefined: onepassword.OpOptions`

- [ ] **Step 5: Implement OpClient**

`internal/onepassword/op.go`:

```go
package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

var _ Client = (*OpClient)(nil)

// OpOptions configures OpClient.
type OpOptions struct {
	Bin     string        // op binary; "op" resolves via PATH
	Vault   string        // optional: limit ListSSHKeys to this vault
	Account string        // optional: --account for every call
	Timeout time.Duration // per call; 0 means none
	Logger  *log.Logger
}

// OpClient implements Client with the 1Password CLI.
type OpClient struct {
	opts OpOptions
}

// NewOpClient returns a Client that shells out to op.
func NewOpClient(opts OpOptions) *OpClient {
	if opts.Bin == "" {
		opts.Bin = "op"
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard)
	}
	return &OpClient{opts: opts}
}

// opItem is the subset of op's item JSON the plugin uses.
type opItem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Vault    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
	AdditionalInformation string `json:"additional_information"`
}

func (c *OpClient) ListSSHKeys(ctx context.Context) ([]SSHKeyItem, error) {
	args := []string{"item", "list", "--categories", "SSH Key", "--format", "json"}
	if c.opts.Vault != "" {
		args = append(args, "--vault", c.opts.Vault)
	}
	out, err := c.run(ctx, "item list", args...)
	if err != nil {
		return nil, err
	}
	var raw []opItem
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("decode op item list: %w", err)
	}
	items := make([]SSHKeyItem, 0, len(raw))
	for _, r := range raw {
		if !ValidID(r.ID) || !ValidID(r.Vault.ID) {
			c.opts.Logger.Warn("skipping 1Password item with invalid ID", "item", r.Title)
			continue
		}
		items = append(items, r.sshKeyItem())
	}
	return items, nil
}

func (c *OpClient) ResolveSSHKey(ctx context.Context, vault, item string) (SSHKeyItem, error) {
	out, err := c.run(ctx, "item get", "item", "get", item, "--vault", vault, "--format", "json")
	if err != nil {
		return SSHKeyItem{}, err
	}
	var r opItem
	if err := json.Unmarshal(out, &r); err != nil {
		return SSHKeyItem{}, fmt.Errorf("decode op item get: %w", err)
	}
	if r.Category != "SSH_KEY" {
		return SSHKeyItem{}, fmt.Errorf("1Password item %q is a %s item, not an SSH key", r.Title, r.Category)
	}
	if !ValidID(r.ID) || !ValidID(r.Vault.ID) {
		return SSHKeyItem{}, fmt.Errorf("1Password item %q: invalid ID", r.Title)
	}
	return r.sshKeyItem(), nil
}

func (c *OpClient) PublicKey(ctx context.Context, vaultID, itemID string) ([]byte, error) {
	ref, err := secretRef(vaultID, itemID, "public key")
	if err != nil {
		return nil, err
	}
	out, err := c.run(ctx, "read", "read", ref)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(out), nil
}

func (c *OpClient) PrivateKey(ctx context.Context, vaultID, itemID string) ([]byte, error) {
	ref, err := secretRef(vaultID, itemID, "private key?ssh-format=openssh")
	if err != nil {
		return nil, err
	}
	return c.run(ctx, "read", "read", ref)
}

// run executes op and returns stdout. stdin and stderr are never inherited:
// in plugin mode they carry the age protocol. stdout is never logged.
func (c *OpClient) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if c.opts.Account != "" {
		args = append(args, "--account", c.opts.Account)
	}
	if c.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.Timeout)
		defer cancel()
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, c.opts.Bin, args...) //nolint:gosec // G204: op path is user config; args built here.
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
	c.opts.Logger.Debug("op call", "cmd", name, "duration", time.Since(start), "ok", err == nil)
	if err == nil {
		return stdout.Bytes(), nil
	}
	msg := strings.TrimSpace(stderr.String())
	switch {
	case ctx.Err() != nil:
		return nil, fmt.Errorf("op %s: %w", name, ctx.Err())
	case isNotFound(msg):
		return nil, fmt.Errorf("op %s: %w: %s", name, ErrNotFound, msg)
	default:
		return nil, fmt.Errorf("op %s: %w: %s", name, err, msg)
	}
}

func (r opItem) sshKeyItem() SSHKeyItem {
	return SSHKeyItem{
		ID:          r.ID,
		Title:       r.Title,
		VaultID:     r.Vault.ID,
		VaultName:   r.Vault.Name,
		Fingerprint: r.AdditionalInformation,
	}
}

func secretRef(vaultID, itemID, field string) (string, error) {
	if !ValidID(vaultID) || !ValidID(itemID) {
		return "", fmt.Errorf("invalid 1Password IDs %q/%q", vaultID, itemID)
	}
	return "op://" + vaultID + "/" + itemID + "/" + field, nil
}

// isNotFound matches op's messages for missing items and vaults.
// Verified against op 2.x in Task 11; keep fakeop messages in sync.
func isNotFound(stderr string) bool {
	return strings.Contains(stderr, "isn't an item") || strings.Contains(stderr, "isn't a vault")
}
```

(funcorder: `opItem.sshKeyItem` is an unexported method of a different type; if funcorder complains about placement, move `opItem` and its method below `OpClient`'s methods.)

- [ ] **Step 6: Verify**

Run: `go test ./internal/... && task lint`
Expected: all `ok`, lint clean.

- [ ] **Step 7: Propose commit**

```
feat ✨(onepassword): implement Client with the op CLI

OpClient lists SSH key metadata, resolves items and reads public and
private keys via op, with typed JSON, per-call timeout, optional
vault and account scoping, stderr surfaced in errors and not-found
mapped to ErrNotFound. IDs are validated before building op://
references. Add a fake op binary and fixture helpers for tests.
```

---

### Task 8: Configuration

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `const EnvPrefix = "AGE_PLUGIN_ONEPASSWORD"`, `type Config struct{ Vault, Account, OpPath string; Timeout time.Duration; LogFile string; LogLevel log.Level }`, `Load(path string) (Config, error)`, `DefaultPath() (string, error)`.

- [ ] **Step 1: Add dependency**

```bash
go get github.com/spf13/viper@v1.21.0
```

- [ ] **Step 2: Write the failing tests**

`internal/config/config_test.go`:

```go
package config_test

import (
	"os"
	"path/filepath"
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
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/config/`
Expected: FAIL — `undefined: config.Load`

- [ ] **Step 4: Implement**

`internal/config/config.go`:

```go
// Package config resolves runtime settings from env vars and an optional YAML
// file. age starts the plugin without user flags, so plugin-mode settings can
// only come from here.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/spf13/viper"
)

// EnvPrefix prefixes every env var, e.g. AGE_PLUGIN_ONEPASSWORD_VAULT.
const EnvPrefix = "AGE_PLUGIN_ONEPASSWORD"

// Config is the resolved configuration.
type Config struct {
	Vault    string        // limit key search to this vault
	Account  string        // op --account
	OpPath   string        // op binary
	Timeout  time.Duration // per op call
	LogFile  string        // log destination; empty = default for the mode
	LogLevel log.Level
}

// DefaultPath returns $XDG_CONFIG_HOME/age-plugin-onepassword/config.yaml,
// falling back to ~/.config when XDG_CONFIG_HOME is unset.
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("config: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "age-plugin-onepassword", "config.yaml"), nil
}

// Load resolves env > file > defaults. A non-empty path must exist; the
// default path is optional.
func Load(path string) (Config, error) {
	v := viper.New()
	v.SetDefault("vault", "")
	v.SetDefault("account", "")
	v.SetDefault("op", "op")
	v.SetDefault("timeout", "2m")
	v.SetDefault("log_file", "")
	v.SetDefault("log_level", "info")
	v.SetEnvPrefix(EnvPrefix)
	v.AutomaticEnv()

	if err := readFile(v, path); err != nil {
		return Config{}, err
	}

	timeout, err := time.ParseDuration(v.GetString("timeout"))
	if err != nil || timeout <= 0 {
		return Config{}, fmt.Errorf("config: invalid timeout %q (want a positive duration like 2m)", v.GetString("timeout"))
	}
	level, err := parseLevel(v.GetString("log_level"))
	if err != nil {
		return Config{}, err
	}
	return Config{
		Vault:    v.GetString("vault"),
		Account:  v.GetString("account"),
		OpPath:   v.GetString("op"),
		Timeout:  timeout,
		LogFile:  v.GetString("log_file"),
		LogLevel: level,
	}, nil
}

func readFile(v *viper.Viper, path string) error {
	explicit := path != ""
	if !explicit {
		p, err := DefaultPath()
		if err != nil {
			return nil // no home directory: run without a config file
		}
		path = p
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) && !explicit {
			return nil
		}
		return fmt.Errorf("config: %w", err)
	}
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	return nil
}

func parseLevel(s string) (log.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return log.DebugLevel, nil
	case "info":
		return log.InfoLevel, nil
	case "warn":
		return log.WarnLevel, nil
	case "error":
		return log.ErrorLevel, nil
	default:
		return 0, fmt.Errorf("config: invalid log_level %q (want debug, info, warn or error)", s)
	}
}
```

- [ ] **Step 5: Verify**

Run: `go test ./internal/config/ && task lint`
Expected: `ok`, lint clean.

- [ ] **Step 6: Propose commit**

```
feat ✨(config): resolve settings from env and XDG config file

age starts plugins without user flags, so vault, account, op path,
timeout and logging come from AGE_PLUGIN_ONEPASSWORD_* env vars or
an optional YAML file under XDG_CONFIG_HOME. Env overrides the file;
invalid timeouts, log levels, malformed files and a missing explicit
path are errors.
```

---

### Task 9: Plugin wiring, CLI commands and entrypoint

**Files:**
- Create: `internal/plugin/plugin.go`, `internal/plugin/plugin_test.go`
- Create: `internal/cli/root.go`, `internal/cli/identity.go`, `internal/cli/recipients.go`, `internal/cli/version.go`, `internal/cli/output.go`
- Create: `cmd/age-plugin-onepassword/main.go`
- Test: `internal/cli/cli_test.go`

**Interfaces:**
- Consumes: `identity.NewDecoder`, `identity.PluginName`, `identity.EncodeDefault`, `identity.EncodePinned`, `identity.Pin`, `identity.DecodePayload`, `onepassword.Client`, `onepassword.NewOpClient`, `onepassword.OpOptions`, `onepassword.ParseItemRef`, `config.Load`, `config.Config`, `appmeta.*`.
- Produces (plugin): `type IdentityDecoder func(data []byte) (age.Identity, error)`, `Run(name, stateMachine string, decode IdentityDecoder, stdin io.Reader, stdout, stderr io.Writer) (int, error)`.
- Produces (cli): `type Options struct{ Stdin io.Reader; Stdout, Stderr io.Writer; NewClient func(config.Config, *log.Logger) onepassword.Client }`, `Execute(ctx context.Context, args []string, opts Options) int`.

- [ ] **Step 1: Add dependency**

```bash
go get github.com/spf13/cobra@v1.10.2
```

- [ ] **Step 2: Write the failing plugin test**

`internal/plugin/plugin_test.go`:

```go
package plugin_test

import (
	"io"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/untcha/age-plugin-onepassword/internal/plugin"
)

func TestRunUnsupportedStateMachine(t *testing.T) {
	decode := func([]byte) (age.Identity, error) { return nil, nil }
	code, err := plugin.Run("onepassword", "recipient-v1", decode, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || code == 0 || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("code = %d, err = %v", code, err)
	}
}
```

- [ ] **Step 3: Implement plugin**

`internal/plugin/plugin.go`:

```go
// Package plugin runs the age plugin protocol for this binary.
package plugin

import (
	"fmt"
	"io"

	"filippo.io/age"
	ageplugin "filippo.io/age/plugin"
)

// IdentityDecoder turns an identity payload into an age.Identity.
type IdentityDecoder func(data []byte) (age.Identity, error)

// Run executes the age plugin state machine and returns the process exit code.
// Only identity-v1 is supported: encryption uses plain SSH recipients.
func Run(name, stateMachine string, decode IdentityDecoder, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if stateMachine != "identity-v1" {
		return 1, fmt.Errorf("unsupported age plugin state machine %q: "+
			"encrypt with an ssh-ed25519 or ssh-rsa recipient (age -r) instead", stateMachine)
	}
	p, err := ageplugin.New(name)
	if err != nil {
		return 1, fmt.Errorf("init age plugin: %w", err)
	}
	p.SetIO(stdin, stdout, stderr)
	p.HandleIdentity(decode)
	return p.IdentityV1(), nil
}
```

Run: `go test ./internal/plugin/`
Expected: `ok`

- [ ] **Step 4: Write the failing CLI tests**

`internal/cli/cli_test.go`:

```go
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

// identityLine returns the AGE-PLUGIN-… line of an identity file.
func identityLine(t *testing.T, text string) string {
	t.Helper()
	for line := range strings.Lines(text) {
		if strings.HasPrefix(line, "AGE-PLUGIN-ONEPASSWORD-1") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("no identity line in:\n%s", text)
	return ""
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
	_, data, err := ageplugin.ParseIdentity(identityLine(t, out))
	if err != nil {
		t.Fatal(err)
	}
	pin, err := identity.DecodePayload(data)
	if err != nil {
		t.Fatal(err)
	}
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
	if len(got) != 2 || got[0]["vault"] != "Private" || got[0]["item_id"] != "ip" || got[1]["public_key"] != work.AuthorizedKey {
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
```

- [ ] **Step 5: Run to verify failure**

Run: `go test ./internal/cli/`
Expected: FAIL — `undefined: cli.Execute`

- [ ] **Step 6: Implement root and plugin mode**

`internal/cli/root.go`:

```go
// Package cli implements the age-plugin-onepassword command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"

	"github.com/untcha/age-plugin-onepassword/internal/appmeta"
	"github.com/untcha/age-plugin-onepassword/internal/config"
	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
	"github.com/untcha/age-plugin-onepassword/internal/plugin"
)

const long = `age-plugin-onepassword decrypts age files encrypted to SSH keys stored in 1Password.
It reads only the one private key a file was encrypted to.

Encrypt with plain age and an SSH public key (no plugin needed):
  age -r "ssh-ed25519 AAAA…" -o secret.age secret.txt

Decrypt:
  age -d -j onepassword secret.age
  age -d -i op.id secret.age          # identity file from "identity"

Settings (env or $XDG_CONFIG_HOME/age-plugin-onepassword/config.yaml):
  AGE_PLUGIN_ONEPASSWORD_VAULT, _ACCOUNT, _OP, _TIMEOUT, _LOG_FILE, _LOG_LEVEL`

// Options are the process-level dependencies. Zero values use os.Std* and the op CLI.
type Options struct {
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	NewClient func(cfg config.Config, logger *log.Logger) onepassword.Client
}

// exitCodeError carries a non-zero exit code from the age plugin protocol.
type exitCodeError int

func (e exitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", int(e))
}

type app struct {
	opts       Options
	configPath string
	debug      bool
	agePlugin  string
}

// Execute runs the CLI with args and returns the process exit code.
func Execute(ctx context.Context, args []string, opts Options) int {
	opts = opts.withDefaults()
	if args == nil {
		args = []string{} // cobra falls back to os.Args on nil
	}
	root := newRootCmd(opts)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	var code exitCodeError
	switch {
	case errors.As(err, &code):
		return int(code)
	case err != nil:
		fmt.Fprintf(opts.Stderr, "age-plugin-onepassword: %v\n", err)
		return 1
	default:
		return 0
	}
}

func (o Options) withDefaults() Options {
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.NewClient == nil {
		o.NewClient = newOpClient
	}
	return o
}

func newRootCmd(opts Options) *cobra.Command {
	a := &app{opts: opts}
	cmd := &cobra.Command{
		Use:           "age-plugin-onepassword",
		Short:         "age plugin for SSH keys stored in 1Password",
		Long:          long,
		Version:       appmeta.String(),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          a.runRoot,
	}
	cmd.SetIn(opts.Stdin)
	cmd.SetOut(opts.Stdout)
	cmd.SetErr(opts.Stderr)
	cmd.SetVersionTemplate("age-plugin-onepassword {{.Version}}\n")
	pf := cmd.PersistentFlags()
	pf.StringVar(&a.configPath, "config", "", "config file (default $XDG_CONFIG_HOME/age-plugin-onepassword/config.yaml)")
	pf.BoolVar(&a.debug, "debug", false, "enable debug logging")
	cmd.Flags().StringVar(&a.agePlugin, "age-plugin", "", "age plugin state machine (set by age)")
	_ = cmd.Flags().MarkHidden("age-plugin")
	cmd.AddCommand(newIdentityCmd(a), newRecipientsCmd(a), newVersionCmd())
	return cmd
}

// runRoot is plugin mode when age passes --age-plugin, help otherwise.
func (a *app) runRoot(cmd *cobra.Command, _ []string) error {
	if a.agePlugin == "" {
		return cmd.Help()
	}
	cfg, logger, closeLog, err := a.setup(true)
	if err != nil {
		return err
	}
	defer closeLog()
	logger.Debug("age plugin session", "state_machine", a.agePlugin, "version", appmeta.Version)
	dec := identity.NewDecoder(cmd.Context(), a.opts.NewClient(cfg, logger), logger)
	code, err := plugin.Run(identity.PluginName, a.agePlugin, dec.Decode, a.opts.Stdin, a.opts.Stdout, a.opts.Stderr)
	if err != nil {
		logger.Error("age plugin failed", "err", err)
		return err
	}
	if code != 0 {
		logger.Error("age plugin exited", "code", code)
		return exitCodeError(code)
	}
	return nil
}

// setup loads config and builds the logger. In plugin mode stderr belongs to
// the age session, so logs go only to log_file (or nowhere).
func (a *app) setup(pluginMode bool) (config.Config, *log.Logger, func(), error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	if a.debug {
		cfg.LogLevel = log.DebugLevel
	}
	var w io.Writer = a.opts.Stderr
	closeLog := func() {}
	if pluginMode {
		w = io.Discard
	}
	if cfg.LogFile != "" {
		//nolint:gosec // G304: log path is user configuration.
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return config.Config{}, nil, nil, fmt.Errorf("open log file: %w", err)
		}
		w, closeLog = f, func() { _ = f.Close() }
	}
	logger := log.NewWithOptions(w, log.Options{
		Level:           cfg.LogLevel,
		ReportTimestamp: true,
		Prefix:          "age-plugin-onepassword",
	})
	return cfg, logger, closeLog, nil
}

func newOpClient(cfg config.Config, logger *log.Logger) onepassword.Client {
	return onepassword.NewOpClient(onepassword.OpOptions{
		Bin:     cfg.OpPath,
		Vault:   cfg.Vault,
		Account: cfg.Account,
		Timeout: cfg.Timeout,
		Logger:  logger,
	})
}
```

- [ ] **Step 7: Implement output helper**

`internal/cli/output.go`:

```go
package cli

import (
	"fmt"
	"io"
	"os"
)

// writeOutput writes text to stdout, or to a new file (never overwritten) with mode 0600.
func writeOutput(path string, stdout io.Writer, text string) error {
	if path == "" || path == "-" {
		_, err := io.WriteString(stdout, text)
		return err
	}
	//nolint:gosec // G304: output path is the user's -o argument.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	if _, err := io.WriteString(f, text); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}
```

- [ ] **Step 8: Implement `identity` command**

`internal/cli/identity.go`:

```go
package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/untcha/age-plugin-onepassword/internal/identity"
	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

func newIdentityCmd(a *app) *cobra.Command {
	var key, output string
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Write an age identity file (contains no key material)",
		Long: `Without --key, writes the default identity. At decrypt time the plugin finds the SSH key
matching the file in 1Password. Equivalent to "age -d -j onepassword"; makes no 1Password calls.

With --key "op://<vault>/<item>", writes a pinned identity for exactly that SSH Key item.
Decrypting then needs a single 1Password call. Reads only the public key.`,
		Example: `  age-plugin-onepassword identity -o ~/.config/chezmoi/op.id
  age-plugin-onepassword identity --key "op://Private/chezmoi-age" -o op.id`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			text := defaultIdentityText()
			if key != "" {
				var err error
				if text, err = a.pinnedIdentityText(cmd.Context(), key); err != nil {
					return err
				}
			}
			return writeOutput(output, a.opts.Stdout, text)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", `pin to the SSH Key item at "op://<vault>/<item>"`)
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to FILE (must not exist) instead of stdout")
	return cmd
}

func (a *app) pinnedIdentityText(ctx context.Context, ref string) (string, error) {
	vault, item, err := onepassword.ParseItemRef(ref)
	if err != nil {
		return "", err
	}
	cfg, logger, closeLog, err := a.setup(false)
	if err != nil {
		return "", err
	}
	defer closeLog()
	client := a.opts.NewClient(cfg, logger)
	it, err := client.ResolveSSHKey(ctx, vault, item)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	raw, err := client.PublicKey(ctx, it.VaultID, it.ID)
	if err != nil {
		return "", fmt.Errorf("read public key of %s: %w", ref, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return "", fmt.Errorf("parse public key of %s: %w", ref, err)
	}
	enc, err := identity.EncodePinned(identity.Pin{VaultID: it.VaultID, ItemID: it.ID, PubKey: pub})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("# age-plugin-onepassword pinned identity (contains no key material)\n"+
		"# Item: %s/%s\n# Recipient: %s\n%s\n", it.VaultName, it.Title, authorizedKey(pub), enc), nil
}

func defaultIdentityText() string {
	return "# age-plugin-onepassword default identity (contains no key material)\n" +
		"# Finds the matching SSH key in 1Password at decrypt time.\n" +
		identity.EncodeDefault() + "\n"
}

func authorizedKey(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}
```

- [ ] **Step 9: Implement `recipients` and `version`**

`internal/cli/recipients.go`:

```go
package cli

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"

	"github.com/untcha/age-plugin-onepassword/internal/onepassword"
)

type recipient struct {
	Vault     string `json:"vault"`
	Item      string `json:"item"`
	VaultID   string `json:"vault_id"`
	ItemID    string `json:"item_id"`
	PublicKey string `json:"public_key"`
}

func newRecipientsCmd(a *app) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "recipients",
		Short: "List SSH public keys in 1Password, usable with age -r",
		Long:  "Lists every SSH Key item's public key. Never reads private keys.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, logger, closeLog, err := a.setup(false)
			if err != nil {
				return err
			}
			defer closeLog()
			rs, err := listRecipients(cmd.Context(), a.opts.NewClient(cfg, logger), logger)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(a.opts.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rs)
			}
			for _, r := range rs {
				fmt.Fprintf(a.opts.Stdout, "op://%s/%s: %s\n", r.Vault, r.Item, r.PublicKey)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}

// listRecipients returns public keys sorted by vault, item title and item ID.
func listRecipients(ctx context.Context, client onepassword.Client, logger *log.Logger) ([]recipient, error) {
	items, err := client.ListSSHKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list SSH keys in 1Password: %w", err)
	}
	rs := make([]recipient, 0, len(items))
	for _, it := range items {
		pub, err := client.PublicKey(ctx, it.VaultID, it.ID)
		if err != nil {
			logger.Warn("skipping item: cannot read public key", "item", it.Title, "vault", it.VaultName, "err", err)
			continue
		}
		rs = append(rs, recipient{
			Vault:     it.VaultName,
			Item:      it.Title,
			VaultID:   it.VaultID,
			ItemID:    it.ID,
			PublicKey: string(bytes.TrimSpace(pub)),
		})
	}
	slices.SortFunc(rs, func(x, y recipient) int {
		return cmp.Or(cmp.Compare(x.Vault, y.Vault), cmp.Compare(x.Item, y.Item), cmp.Compare(x.ItemID, y.ItemID))
	})
	return rs, nil
}
```

`internal/cli/version.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/untcha/age-plugin-onepassword/internal/appmeta"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "age-plugin-onepassword %s\n", appmeta.String())
			return err
		},
	}
}
```

- [ ] **Step 10: Implement entrypoint**

`cmd/age-plugin-onepassword/main.go`:

```go
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/untcha/age-plugin-onepassword/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Execute(ctx, os.Args[1:], cli.Options{})
	stop()
	os.Exit(code)
}
```

- [ ] **Step 11: Verify**

Run:
```bash
go mod tidy
go test ./... && task lint && task build
./bin/$(go env GOOS)-$(go env GOARCH)/age-plugin-onepassword identity
./bin/$(go env GOOS)-$(go env GOARCH)/age-plugin-onepassword --version
```
Expected: all tests `ok`, lint clean; `identity` prints the two comment lines and `AGE-PLUGIN-ONEPASSWORD-10K6MQ2`; `--version` prints `age-plugin-onepassword dev (commit …, built …)`.

- [ ] **Step 12: Propose commit**

```
feat ✨(cli): add identity, recipients, version and plugin mode

Wire the age identity-v1 state machine to the 1Password-backed
decoder when age passes --age-plugin. Add the identity command for
default and pinned identity files (O_EXCL, 0600), recipients with
text and JSON output (public keys only), and version. In plugin mode
logs go only to the configured log file.
```

---

### Task 10: End-to-end round trip with the real age CLI

**Files:**
- Modify: `go.mod` (add `tool filippo.io/age/cmd/age`)
- Create: `e2e/roundtrip_test.go`

**Interfaces:**
- Consumes: `testutil.Build`, `testutil.BuildFakeOp`, `testutil.WriteFakeOpDir`, `testutil.OpItem`, `testutil.Ed25519`.

- [ ] **Step 1: Pin the age CLI as a tool**

```bash
go get -tool filippo.io/age/cmd/age@v1.3.2
```

Expected: `go.mod` gains `tool filippo.io/age/cmd/age`.

- [ ] **Step 2: Write the integration test**

`e2e/roundtrip_test.go`:

```go
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
			strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
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
```

- [ ] **Step 3: Run it**

Run: `task test:integration`
Expected: `--- PASS: TestIntegrationRoundTrip` with 3 passing subtests.

If `default identity` fails, run with `AGE_PLUGIN_ONEPASSWORD_LOG_FILE=/tmp/aop.log AGE_PLUGIN_ONEPASSWORD_LOG_LEVEL=debug` added to `env` and inspect `/tmp/aop.log` (use superpowers:systematic-debugging).

- [ ] **Step 4: Verify the full suite**

Run: `task check && task test:unit`
Expected: fmt, lint and tests clean; `test:unit` runs all unit tests (none start with `TestI`).

- [ ] **Step 5: Propose commit**

```
test 🧪(e2e): round trip through the real age CLI

Build the plugin, a pinned age CLI (Go tool dependency) and the fake
op, then encrypt to an SSH recipient and decrypt via -j onepassword
and via a pinned identity file. Assert the exact op calls: one list
plus one read for the default identity, a single read when pinned,
and no private key read for files addressed to other keys.
```

---

### Task 11: README and real 1Password verification

**Files:**
- Modify: `README.md` (replace the existing stub)
- Possibly modify: `internal/onepassword/op.go` (`isNotFound`), `internal/onepassword/fakeop/main.go` (messages), `internal/onepassword/op_test.go` — only if real `op` output differs.

- [ ] **Step 1: Write README**

Replace the stub `README.md` with:

````markdown
# age-plugin-onepassword

An [age](https://age-encryption.org) plugin that decrypts files encrypted to SSH keys stored in
1Password. It reads **only the one private key** a file was encrypted to.

- Encryption is plain age with an SSH public key: no plugin, no 1Password needed.
- Output files are standard age files.
- Ed25519 and RSA keys (the SSH key types both 1Password and age support).

## Requirements

- [1Password CLI](https://developer.1password.com/docs/cli/) (`op`), signed in or with desktop app integration
- [age](https://github.com/FiloSottile/age) v1.1+ (plugin support)

## Install

```sh
go install github.com/untcha/age-plugin-onepassword/cmd/age-plugin-onepassword@latest
```

The binary must be on `PATH` so age can find it.

## Usage

List SSH public keys in 1Password:

```sh
age-plugin-onepassword recipients
# op://Private/chezmoi-age: ssh-ed25519 AAAAC3Nz…
```

Encrypt (plain age):

```sh
age -r "ssh-ed25519 AAAAC3Nz…" -o secret.age secret.txt
```

Decrypt:

```sh
age -d -j onepassword secret.age
```

### Identity files

For tools that need an identity file instead of `-j`:

```sh
# Default identity: finds the matching key at decrypt time. Same on every machine.
age-plugin-onepassword identity -o ~/.config/age/op.id

# Pinned identity: exactly one item, one 1Password call per decrypt.
age-plugin-onepassword identity --key "op://Private/chezmoi-age" -o ~/.config/age/op.id
```

Neither contains key material. A pinned identity survives the item being moved or recreated
(it falls back to a fingerprint search and logs a warning to regenerate it).

## How it finds the key

age writes a tag into each SSH stanza: the first 4 bytes of the SHA-256 of the public key.
1Password lists the full SHA-256 fingerprint of every SSH key as metadata. The plugin
compares the two, then reads only the matching private key. Files without SSH stanzas
cause no 1Password calls at all.

## Configuration

age starts the plugin without user flags, so settings come from env vars or
`$XDG_CONFIG_HOME/age-plugin-onepassword/config.yaml` (env wins).

| Key | Env | Default | Purpose |
|---|---|---|---|
| `vault` | `AGE_PLUGIN_ONEPASSWORD_VAULT` | all vaults | only search this vault |
| `account` | `AGE_PLUGIN_ONEPASSWORD_ACCOUNT` | op default | `op --account` |
| `op` | `AGE_PLUGIN_ONEPASSWORD_OP` | `op` | path to the op binary |
| `timeout` | `AGE_PLUGIN_ONEPASSWORD_TIMEOUT` | `2m` | per op call |
| `log_file` | `AGE_PLUGIN_ONEPASSWORD_LOG_FILE` | none | debug log destination |
| `log_level` | `AGE_PLUGIN_ONEPASSWORD_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

```yaml
vault: Private
log_file: /Users/you/.local/state/age-plugin-onepassword.log  # absolute path, ~ is not expanded
log_level: debug
```

## chezmoi

```toml
encryption = "age"
[age]
  command    = "age"
  identity   = "~/.config/chezmoi/op.id"
  recipient  = "ssh-ed25519 AAAAC3Nz… chezmoi-age"
```

Create the identity with `age-plugin-onepassword identity [--key op://…] -o ~/.config/chezmoi/op.id`.

## Security notes

- Private keys are read only after a tag match, kept in memory for one process, never logged
  or written to disk.
- Identity files hold no secrets; pinned identities hold vault ID, item ID and public key.
- The stanza tag reveals which SSH key a file is for to anyone who has that public key
  (standard age behaviour).

## Development

```sh
task check             # fmt, lint, tests
task test:integration  # round trip through the real age CLI with a fake op
task build
```

## License

MIT, see [LICENSE](LICENSE).
````

- [ ] **Step 2: Real 1Password checks (user runs these — they touch the user's vault)**

Ask the user to run and paste output (values redacted as they like):

```sh
op --version
op item list --categories "SSH Key" --format json | jq '.[0] | {id, category, vault, additional_information}'
op item get "<an SSH item title>" --vault "<vault>" --format json | jq '{id, category, vault}'
op read "op://<vaultID>/doesnotexist/private key?ssh-format=openssh"; echo "exit=$?"
op item get doesnotexist --vault "<vault>" --format json; echo "exit=$?"
```

Check:
- `additional_information` looks like `SHA256:<43 base64 chars>`.
- `category` is `SSH_KEY`; `vault` has `id` and `name`.
- The two not-found commands' stderr contains `isn't an item` (or `isn't a vault`). If the wording differs, update `isNotFound` in `op.go`, the matching messages in `fakeop/main.go`, and re-run `go test ./...`.

- [ ] **Step 3: Manual round trip (user runs)**

```sh
task dev:install
op item create --category ssh --title age-test --vault Private --ssh-generate-key ed25519
echo hi | age -r "$(op read 'op://Private/age-test/public key')" -o /tmp/t.age
AGE_PLUGIN_ONEPASSWORD_LOG_FILE=/tmp/aop.log AGE_PLUGIN_ONEPASSWORD_LOG_LEVEL=debug age -d -j onepassword /tmp/t.age
cat /tmp/aop.log
age-plugin-onepassword identity --key "op://Private/age-test" -o /tmp/t.id && age -d -i /tmp/t.id /tmp/t.age
```

(Check `op item create --help` for the exact `--ssh-generate-key` values on the installed op version.)

Expected: `hi` twice; one 1Password approval prompt; the log names only `age-test`. Then lock the 1Password app and repeat the decrypt: a clear error mentioning op's message, no panic. Delete the `age-test` item afterwards.

- [ ] **Step 4: Final verification**

Run: `task check && task test:integration && task build:all`
Expected: all green; binaries for linux/amd64, darwin/arm64, darwin/amd64 under `bin/`.

- [ ] **Step 5: Propose commit**

```
docs 📚(readme): document usage, configuration and security

Describe install, encrypting with SSH recipients, decrypting via
-j onepassword and identity files, how tag matching avoids reading
unrelated keys, env and config file settings, a chezmoi example,
security notes and development tasks.
```
