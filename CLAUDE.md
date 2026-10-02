# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

Working style, Go standards and commit rules live in AGENTS.md (imported above) and
`docs/COMMIT_GUIDE.md`. This file covers only what is specific to this repository.

## Commands

```sh
task check                 # fmt, lint (golangci-lint), unit tests
task test                  # go test ./...
task test:integration      # e2e round trip: builds the plugin, real age CLI and fakeop
task vuln                  # govulncheck (pinned in taskfiles/common.yml)
task build                 # bin/<os>-<arch>/age-plugin-onepassword, version-stamped
task project:install       # install to ~/.local/bin with version from git describe

go test ./internal/identity -run TestName       # single test
go test -tags=integration -run Integration ./e2e # integration only
```

`taskfiles/common.yml` and the root `Taskfile.yml` are vendored from the `untcha/meta`
templates; repo-specific tasks go in `taskfiles/Taskfile.project.yml` (`project:` namespace).

## Architecture

One binary with two roles, dispatched in `internal/cli`:

- **age plugin**: age runs it as `age-plugin-onepassword --age-plugin=identity-v1`.
  `internal/plugin` drives the `filippo.io/age/plugin` state machine. Only
  `identity-v1` exists; encryption is plain age with an SSH recipient, so there is
  no recipient-v1 side.
- **User CLI** (Cobra): `recipients` (list SSH public keys), `identity` (write
  identity files), `version`.

Flow of a decrypt:

1. `internal/identity.Decoder` turns the identity payload into an `age.Identity`.
   Empty payload = **default** identity (`default.go`, matches any key); payload v1 =
   **pinned** identity (`pinned.go`, vault ID + item ID + public key, see
   `encoding.go`). Pinned falls back to a fingerprint search if the item moved.
2. `tag.go` matches age's 4-byte SSH stanza tag (SHA-256 prefix of the public key)
   against the SHA-256 fingerprints 1Password lists as metadata.
3. Only the matching item's private key is fetched, then unwrapped via `agessh`.
   Private keys are cached in memory per process; never logged or written to disk.
   Files without SSH stanzas must cause zero 1Password calls.

`internal/onepassword` is the only 1Password boundary: the `Client` interface,
implemented by `OpClient` (shells out to `op`, per-call timeout, error hints in
`hints.go`). Untrusted vault/item IDs are checked with `ValidID` before building
`op://` references.

`internal/config`: age starts the plugin without user flags, so config comes from
`AGE_PLUGIN_ONEPASSWORD_*` env vars or `$XDG_CONFIG_HOME/age-plugin-onepassword/config.yaml`
(env wins). Relative paths are rejected because age runs plugins with the temp dir as
working directory.

## Testing

- `onepassword/fake`: in-memory `Client` for unit tests; inject via `cli.Options.NewClient`.
- `onepassword/fakeop`: test-only binary imitating the `op` CLI (fixtures via
  `FAKEOP_DIR`; `FAKEOP_LOG`, `FAKEOP_FAIL`, `FAKEOP_SLEEP` for call logging and
  failure injection). Built by `internal/testutil`, used by `OpClient` tests and `e2e/`.
- `e2e/` has the `integration` build tag.
- The real `op` CLI is never used in automated tests; verify against it with the manual
  checklist in `docs/manual-verification.md`.
- Don't use `AGEDEBUG=plugin` with real secrets: age prints the decrypted file key.
