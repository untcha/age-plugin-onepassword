# Manual verification against real 1Password

Automated tests use a fake `op`. This checklist verifies the plugin against the real 1Password
CLI. Re-run it after significant `op` upgrades or changes to `internal/onepassword`.

## Last run

2026-09-27, `op` 2.39.0, age v1.3.2, macOS — all checks passed:

| Check | Result |
|---|---|
| `additional_information` is the `SHA256:…` fingerprint | confirmed |
| Not-found stderr contains `isn't an item` / `isn't a vault` | confirmed (`read`, `item get`, unknown vault) |
| `recipients` (text and `--json`) | only items of the configured vault |
| Decrypt with `-j onepassword` | one `item list` + one `read`; log names only the target item |
| Pinned identity | exactly one `read`, no list; identity file mode `0600` |
| File encrypted to a key not in 1Password | no private-key read; "no identity matched" |
| Setup error in plugin mode | shown by age (not only in the discarded plugin stderr) |
| App locked, unlock approved | waits at the prompt, then decrypts |
| App locked, prompt dismissed | fails fast with op's "authorization prompt dismissed" |

## Checklist

Use a vault that holds only a test SSH key, and point the plugin at it with
`AGE_PLUGIN_ONEPASSWORD_VAULT` or `vault:` in the config file.

1. Confirm the two facts the code relies on:

   ```sh
   op item list --categories "SSH Key" --vault <vault> --format json \
     | jq '.[] | {id, title, category, vault, additional_information}'
   op read "op://<vaultID>/doesnotexist/private key?ssh-format=openssh"
   op item get doesnotexist --vault <vault> --format json
   op item list --categories "SSH Key" --vault nosuchvault --format json
   ```

   - `additional_information` must be `SHA256:…` (the SSH public key fingerprint): it is how
     the plugin matches a file's stanza tag to an item.
   - The three errors must contain `isn't an item` / `isn't a vault`: `isNotFound` in
     `internal/onepassword/op.go` matches these phrases. Keep `fakeop` messages in sync.
   - Error hints (`internal/onepassword/hints.go`) match phrases in op's stderr. Only
     `authorization prompt dismissed` is confirmed (step 7). When you see a real
     not-signed-in, desktop-app or network error, check that its hint appears and add
     the phrase if not.

2. Create a test SSH Key item if the vault has none (check `op item create --help` for your
   `op` version):

   ```sh
   op item create --category ssh --title age-test --vault <vault> --ssh-generate-key ed25519
   ```

3. List recipients and encrypt a test file:

   ```sh
   age-plugin-onepassword recipients
   age-plugin-onepassword recipients --json
   echo "hello from 1Password" > secret.txt
   age -r "$(op read 'op://<vault>/age-test/public key')" -o secret.age secret.txt
   ```

4. Decrypt with the default identity and debug logging:

   ```sh
   AGE_PLUGIN_ONEPASSWORD_LOG_FILE=/tmp/aop.log AGE_PLUGIN_ONEPASSWORD_LOG_LEVEL=debug \
     age -d -j onepassword secret.age
   cat /tmp/aop.log
   ```

   Expect at most one approval prompt, one `item list` and one `read` in the log, and only the
   test item named. The log must contain no key material.

5. Repeat with a pinned identity; the log must show a single `read` and no `item list`:

   ```sh
   age-plugin-onepassword identity --key "op://<vault>/age-test" -o op.id
   age -d -i op.id secret.age
   ```

6. Encrypt to a key that is not in 1Password and decrypt with `-j onepassword`; expect
   "no identity matched" and no `read` in the log:

   ```sh
   ssh-keygen -q -t ed25519 -N '' -f foreign
   echo hi | age -r "$(cat foreign.pub)" -o foreign.age
   age -d -j onepassword foreign.age
   ```

7. Lock the 1Password app and decrypt twice: once approving the unlock prompt (decrypts), once
   dismissing it (clear error, no hang, no stack trace).

8. Delete the test files and, if you created it, the test item:
   `op item delete age-test --vault <vault>`.
