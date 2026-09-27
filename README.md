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

Requires Go 1.27.1 and [Task](https://taskfile.dev).

```sh
git clone https://github.com/untcha/age-plugin-onepassword
cd age-plugin-onepassword
task project:install   # builds with the version from git describe, installs to ~/.local/bin
```

`~/.local/bin` must be on `PATH` so age can find the plugin.

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

# Several pinned keys in one file (e.g. laptop + backup).
age-plugin-onepassword identity --key "op://Private/laptop" --key "op://Private/backup" -o ~/.config/age/op.id
```

Neither contains key material. `-o` never overwrites an existing file. A pinned identity survives the item being moved or recreated
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
log_file: ~/.local/state/age-plugin-onepassword.log
log_level: debug
```

Paths (`op`, `log_file`) must be absolute or start with `~/`; `op` may also be a bare command
name found via `PATH`. Other relative paths are rejected, because age runs plugins with the
temp directory as working directory. Missing parent directories of `log_file` are created
(mode `0700`).

## Debugging

```sh
AGEDEBUG=plugin age -d -j onepassword secret.age
```

age then shows the plugin's debug logs on stderr. Note: age itself also prints the whole plugin
protocol exchange, **including the decrypted file key** — use it only with test files.
Alternatively set `log_file` (and `log_level: debug`) to log to a file.

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
task project:vuln      # govulncheck (pinned)
task build
```

Verification against the real 1Password CLI is a manual checklist:
[docs/manual-verification.md](docs/manual-verification.md).

## License

MIT, see [LICENSE](LICENSE).
