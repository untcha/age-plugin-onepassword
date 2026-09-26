# age-plugin-onepassword — Design

Date: 2026-09-26 · Status: approved design, pre-implementation

## 1. Goal

An age plugin that decrypts files encrypted to SSH keys stored in
1Password, reading **only the one private key** the file was encrypted to.
Follows the Go standards in `AGENTS.md`. Output files stay 100% standard age.

Encryption is plain age and needs neither plugin nor 1Password:

```sh
age -r "ssh-ed25519 AAAA… chezmoi-age" -o secret.age secret.txt
```

### Non-goals

- `recipient-v1` state machine / encrypting via identity file
- 1Password Go SDK backend (boundary prepared, not implemented)
- Native age X25519 keys in 1Password
- Disk caching of any kind

## 2. Naming

| Thing | Value |
|---|---|
| Module | `github.com/untcha/age-plugin-onepassword` |
| Binary | `age-plugin-onepassword` |
| Plugin name | `onepassword` (`age -d -j onepassword`) |
| Identity HRP | `AGE-PLUGIN-ONEPASSWORD-` |
| Env prefix | `AGE_PLUGIN_ONEPASSWORD_` |

Any age file encrypted to an SSH recipient can be decrypted; no re-encryption
needed.

## 3. Background: how targeting works

- age SSH stanzas carry a tag as first argument:
  `-> ssh-ed25519 <tag> <ephemeral>` and `-> ssh-rsa <tag>`.
- `tag = base64.RawStdEncoding(sha256(pubkey.Marshal())[:4])` (age `agessh`).
- `op item list --categories "SSH Key" --format json` returns per item
  `additional_information = "SHA256:<base64 raw std of the full sha256>"`.
- Therefore `tag == base64(decode(fingerprint)[:4])`, computable from metadata
  only. No secret is read until a match is found.

## 4. Architecture

```text
cmd/age-plugin-onepassword/main.go  # builds root cmd, Execute, exit code. No logic.
internal/appmeta/                   # Version, Commit, BuildDate (ldflags)
internal/config/                    # Config struct, Load (Viper), Validate
internal/cli/                       # Cobra commands; wires config, logger, client
internal/onepassword/               # 1Password boundary
    client.go        # Client interface, SSHKeyItem, ErrNotFound
    op.go            # OpClient: `op` subprocess implementation
    fake/            # in-memory Client for tests (records calls)
    fakeop/          # package main: fake `op` binary for OpClient + e2e tests
internal/identity/                  # age.Identity implementations, no `op` knowledge
    tag.go           # TagFromFingerprint, TagFromPubKey, StanzaTags
    encoding.go      # identity string + pinned payload v1 encode/decode
    default.go       # DefaultIdentity
    pinned.go        # PinnedIdentity
internal/plugin/                    # identity-v1 wiring to filippo.io/age/plugin
internal/testutil/                  # test-only: key generation, fake op fixtures
e2e/                                # //go:build integration — real age round trip
taskfiles/common.yml                # vendored from untcha/meta
taskfiles/Taskfile.project.yml      # project tasks (install, vuln)
Taskfile.yml                        # from meta cli template, include ./taskfiles/common.yml
```

Dependency direction: `cli → plugin → identity → onepassword` (interface only).
`config`, `appmeta` are leaves. No cycles.

Go: `go 1.27.1` in `go.mod` (the local toolchain is selected from it).

Dependencies (latest stable at implementation time, pinned in `go.mod`):
`filippo.io/age` (v1.3.x), `golang.org/x/crypto`, `github.com/spf13/cobra`,
`github.com/spf13/viper`, `github.com/charmbracelet/log`. Pinned Go `tool`
dependencies: the `age` CLI (e2e tests) and `govulncheck`. No fang.

## 5. 1Password boundary (`internal/onepassword`)

```go
type SSHKeyItem struct {
	ID          string
	Title       string
	VaultID     string
	VaultName   string
	Fingerprint string // "SHA256:<b64>", as reported by 1Password
}

var ErrNotFound = errors.New("1password: item not found")

type Client interface {
	// ListSSHKeys returns metadata of SSH Key items. No secrets.
	ListSSHKeys(ctx context.Context) ([]SSHKeyItem, error)
	// ResolveSSHKey looks up one item by vault and item (name or ID).
	ResolveSSHKey(ctx context.Context, vault, item string) (SSHKeyItem, error)
	// PublicKey returns the item's public key (authorized_keys format).
	PublicKey(ctx context.Context, vaultID, itemID string) ([]byte, error)
	// PrivateKey returns the item's private key in OpenSSH format.
	PrivateKey(ctx context.Context, vaultID, itemID string) ([]byte, error)
}
```

`OpClient` (only implementation now):

| Method | `op` invocation |
|---|---|
| `ListSSHKeys` | `op item list --categories "SSH Key" --format json [--vault V]` |
| `ResolveSSHKey` | `op item get <item> --vault <vault> --format json` |
| `PublicKey` | `op read "op://<vaultID>/<itemID>/public key"` |
| `PrivateKey` | `op read "op://<vaultID>/<itemID>/private key?ssh-format=openssh"` |

- Global `--account A` appended when configured.
- Binary path from config (`op` default, resolved via `PATH`).
- One runner: `exec.CommandContext`, stdout captured, stderr captured into a
  buffer; on failure: `fmt.Errorf("op %s: %w: %s", subcmd, err, trimmedStderr)`.
- Stderr indicating a missing item maps to `ErrNotFound` (wrapped). Exact `op`
  phrases are verified against a real `op` during implementation and covered by
  fake-op fixtures.
- JSON decoded into typed structs; unknown fields ignored; items with empty ID
  or vault ID are dropped with a warn log.
- Logs never contain command stdout of `read` calls.

A future SDK backend implements the same interface; selection via a `backend`
config key. Not built now.

## 6. Identities (`internal/identity`)

### 6.1 Default identity

- String: bech32 of HRP `age-plugin-onepassword-` with **empty payload**,
  uppercased: `AGE-PLUGIN-ONEPASSWORD-1<checksum>`. Equivalent to
  `-j onepassword`. Contains no key material; identical everywhere.
- `Unwrap(stanzas)`:
  1. `tags := StanzaTags(stanzas)` (only `ssh-ed25519`/`ssh-rsa` with ≥1 arg).
     Empty → `age.ErrIncorrectIdentity`, zero `op` calls.
  2. `ListSSHKeys`. Per item: `TagFromFingerprint`; parse error → warn log,
     skip. Keep items whose tag ∈ tags, in list order.
  3. For each match: `PrivateKey` (via cache) → `agessh.ParseIdentity` →
     `Unwrap`. `ErrIncorrectIdentity` → next match (tag collision). Parse
     error of a matched key → hard error naming the item. Other errors → return.
  4. No match / all collisions → `age.ErrIncorrectIdentity`.
- Search scope controlled by config `vault` / `account`.

### 6.2 Pinned identity

- Created by `identity --key "op://<vault>/<item>"`. Contains vault ID, item ID
  and public key — no secrets.
- Payload v1 (binary, big-endian):

  ```text
  byte     version = 0x01
  uint16   len | vaultID  (UTF-8, 1..255 bytes)
  uint16   len | itemID   (UTF-8, 1..255 bytes)
  uint16   len | pubkey   (SSH wire format, ssh.PublicKey.Marshal())
  ```

  Decode rejects: unknown version, empty or oversized fields, trailing bytes,
  pubkey types other than `ssh-ed25519` / `ssh-rsa`.
- `Unwrap(stanzas)`:
  1. `TagFromPubKey(pinned) ∉ StanzaTags(stanzas)` → `ErrIncorrectIdentity`,
     zero `op` calls.
  2. `PrivateKey(vaultID, itemID)` → 1 `op` call.
  3. On `ErrNotFound` (item moved/recreated): fallback — `ListSSHKeys`, find
     item whose fingerprint equals `ssh.FingerprintSHA256(pinned)`, read it;
     warn log "pinned item not found, regenerate identity".
  4. Derive the public key of the read private key; must equal the pinned
     pubkey byte-for-byte, else hard error. Never silently use another key.
  5. `agessh.ParseIdentity(key).Unwrap(stanzas)`.

### 6.3 Shared

- Per-process cache `map[vaultID/itemID][]byte`, in memory only.
- `DecodeIdentity(data []byte) (age.Identity, error)`: empty → default,
  otherwise pinned payload.

## 7. Plugin wiring (`internal/plugin`)

- `filippo.io/age/plugin`: `New("onepassword")`, `HandleIdentity(DecodeIdentity…)`,
  run the identity-v1 state machine; return its exit code.
- `--age-plugin=identity-v1` is the only supported state machine. Any other
  value → clear error ("recipient-v1 not supported: encrypt with `age -r
  ssh-…`"), non-zero exit.
- Exact API of age v1.3.x (`IdentityV1`/`Main`, flag registration) verified
  with `go doc` at implementation time.

## 8. CLI (`internal/cli`)

```sh
age-plugin-onepassword identity [-o FILE]                    # default identity
age-plugin-onepassword identity --key "op://V/I" [--key …] [-o FILE]  # pinned identity/identities
age-plugin-onepassword recipients [--json]                   # SSH pubkeys in 1Password
age-plugin-onepassword version
age-plugin-onepassword --age-plugin=identity-v1              # hidden; called by age
```

Global flags: `--debug` (= `log_level=debug`), `--config FILE`.

- `identity` (default): no 1Password calls. Output:

  ```text
  # age-plugin-onepassword default identity (contains no key material)
  # Finds the matching SSH key in 1Password at decrypt time.
  AGE-PLUGIN-ONEPASSWORD-1…
  ```

- `identity --key`: `ResolveSSHKey` + `PublicKey` per key; never reads a
  private key. `--key` is repeatable; each must match `op://<vault>/<item>`
  (exactly two non-empty segments). Output: one shared header line, then per
  key a block `# Item: <vault>/<title>`, `# Recipient: ssh-… …` and its
  identity line. Two refs resolving to the same item are an error. Any failure
  aborts before anything is written (all or nothing).

  ```text
  # age-plugin-onepassword pinned identity file (contains no key material)

  # Item: Private/laptop
  # Recipient: ssh-ed25519 AAAA…
  AGE-PLUGIN-ONEPASSWORD-1…

  # Item: Private/backup
  # Recipient: ssh-ed25519 AAAA…
  AGE-PLUGIN-ONEPASSWORD-1…
  ```
- `-o FILE`: `O_WRONLY|O_CREATE|O_EXCL`, mode `0600`; `-` or unset → stdout.
- `recipients`: `ListSSHKeys` + `PublicKey` per item. Text:
  `op://<vault name>/<item title>: ssh-ed25519 AAAA…`, sorted by vault then
  title. `--json`: array of `{vault, item, vault_id, item_id, public_key}`.
  Items whose public key read fails → warn log, skipped.
- `version`: `Version`, `Commit`, `BuildDate` from `appmeta`.
- Exit codes: 0 success, 1 error. Errors printed once to stderr.

## 9. Configuration (`internal/config`)

age launches the plugin with only `--age-plugin=identity-v1`, so plugin-mode
settings come from env vars or the config file — never flags.

| Key | Env | Default | Purpose |
|---|---|---|---|
| `vault` | `AGE_PLUGIN_ONEPASSWORD_VAULT` | — | `--vault` on list |
| `account` | `AGE_PLUGIN_ONEPASSWORD_ACCOUNT` | — | `--account` on every call |
| `op` | `AGE_PLUGIN_ONEPASSWORD_OP` | `op` | op binary path |
| `timeout` | `AGE_PLUGIN_ONEPASSWORD_TIMEOUT` | `2m` | per `op` call (covers approval prompt) |
| `log_file` | `AGE_PLUGIN_ONEPASSWORD_LOG_FILE` | — | log destination (plugin mode) |
| `log_level` | `AGE_PLUGIN_ONEPASSWORD_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |

- File: `$XDG_CONFIG_HOME/age-plugin-onepassword/config.yaml`
  (fallback `~/.config/…`), or `--config`. Missing file is fine; malformed file
  or unknown `log_level` / invalid `timeout` is an error.
- Precedence: flag > env > file > default.
- Paths: age starts the plugin with the system temp dir as working directory,
  so relative paths would silently resolve there. `log_file` and `op` expand a
  leading `~/`; `op` may be a bare command name (looked up via `PATH`); any
  other relative path is an error.

## 10. Logging

- `charmbracelet/log`, structured key/value.
- CLI mode: stderr, or `log_file` if set.
- Plugin mode: `log_file` if set (append, create, `0600`). Additionally, when
  `AGEDEBUG=plugin` is set (age then forwards plugin stderr), logs go to
  stderr at debug level. Both set → both destinations. Neither → discarded.
  Note: with `AGEDEBUG=plugin` age itself prints the protocol, including the
  file key — documented in the README.
- Never logged: private keys, `op read` output. Logged: item title, vault ID,
  tags, `op` subcommand, durations, errors.

## 11. Error handling

- All errors wrapped with context (`fmt.Errorf("…: %w", err)`), no panics on
  external input.
- `op` errors include trimmed stderr (e.g. "account is not signed in").
- Unparseable unmatched items: skipped, never fetched. Unparseable matched
  key: hard error.
- `context.Context` on every `op` call, bounded by `timeout`.

## 12. Testing

Table-driven unit tests:

| Test | Asserts |
|---|---|
| Tag | `TagFromFingerprint` equals age tag for ed25519 + RSA fixtures; rejects missing prefix, bad base64, wrong length |
| StanzaTags | ssh-ed25519 / ssh-rsa tags collected; X25519, grease, empty args ignored |
| Encoding | default string round trip; pinned v1 round trip; rejects bad version, trailing bytes, oversized fields, unsupported key type |
| Config | precedence, defaults, invalid values, path rules (`~/` expansion, bare `op`, relative rejected) |

`identity` tests with `onepassword/fake` (records calls):

| Test | Asserts |
|---|---|
| DefaultTargeted | decrypt ok; 1 `ListSSHKeys`, 1 `PrivateKey` for target only |
| DefaultNoSSHStanza | X25519-only file → `ErrIncorrectIdentity`, 0 calls |
| DefaultNoMatch | unknown tag → `ErrIncorrectIdentity`, 0 `PrivateKey` |
| DefaultCollision | two items same tag → wrong skipped, right unwraps |
| DefaultBadItems | garbled/missing fingerprint → skipped, no panic |
| DefaultLocked | client error propagated with message |
| DefaultMultiRecipient | target + X25519 recipient → 1 `PrivateKey` |
| DefaultCache | two unwraps same process → 1 `PrivateKey` |
| PinnedTagMismatch | 0 calls |
| PinnedByID | 1 `PrivateKey`, 0 `ListSSHKeys` |
| PinnedFallback | `ErrNotFound` → list + read by fingerprint, success |
| PinnedPubKeyMismatch | read key ≠ pinned → error |

`OpClient` tests against `fakeop` (Go binary built in `TestMain`): argument
construction (`--vault`, `--account`, refs), stderr surfaced in error,
`ErrNotFound` mapping, JSON decode incl. malformed items, timeout.

E2E (`//go:build integration`, `task test:integration` from common.yml): builds the plugin,
`fakeop` and the pinned `age` tool into a temp dir on `PATH`; runs
`age -r <fixture pub> | age -d -j onepassword` and with a pinned identity
file; asserts plaintext and fake-op call log.

Test SSH keys (Ed25519, RSA 2048) are generated at test time by
`internal/testutil`; no key files are committed. Unit test names must not
start with `TestI` (common.yml `test:unit` filter); integration tests are
`TestIntegration*`.

Manual check with real 1Password (documented in README): scratch vault item,
one approval prompt, debug log names only that item, locked app → clear error.

## 13. Tooling

- `Taskfile.yml` from `untcha/meta` `taskfiles/cli`, vars set (`REPO`,
  `APP_NAME`), include path `./taskfiles/common.yml`, `CGO_ENABLED=0`.
- `taskfiles/Taskfile.project.yml`:
  - `install`: `VERSION=$(git describe --tags --always --dirty) task install`
    (stamps the version; templates stay unchanged).
  - `vuln`: runs the pinned `govulncheck` tool on `./...` (manual, pre-release).
- `.golangci.yml`, `.gitignore`, `LICENSE` from `untcha/meta`. `.envrc` is not
  committed.
- No CI. No Windows target (template `RELEASE_TARGETS`).
- Install: clone + `task project:install` (binary in `~/.local/bin`).
- `README.md`: install, usage (encrypt, `-j onepassword`, default + pinned
  identity files), config table incl. path rules, debugging with
  `AGEDEBUG=plugin`, chezmoi example, security notes.

## 14. Risks / open checks during implementation

| Item | Check |
|---|---|
| `additional_information` format of `op item list` | verify with real `op`; parsing is defensive |
| `op` "not found" stderr phrasing | verify with real `op`; encode in fakeop fixtures |
| age v1.3.x plugin API | `go doc filippo.io/age/plugin` |
| `?ssh-format=openssh` for RSA keys | verify with real `op`; `agessh.ParseIdentity` also accepts PKCS#8 |
| `op` overhead per file (chezmoi) | acceptable; pinned identity halves calls; SDK later |
| Key in process memory during unwrap | unavoidable; not logged, not persisted |
