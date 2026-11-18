# Security Policy

## Supported Versions

Security fixes go into the latest release only. Upgrade to the newest
[release tag](https://github.com/untcha/age-plugin-onepassword/tags) before reporting.

## Reporting a Vulnerability

Please do not open a public issue for a security problem.

Report it privately instead: go to the repository's
[Security tab](https://github.com/untcha/age-plugin-onepassword/security) and choose
**Report a vulnerability**
([direct link](https://github.com/untcha/age-plugin-onepassword/security/advisories/new)).
Only the maintainer can see the report.

Please include:

- the plugin version (`age-plugin-onepassword --version`)
- your OS, and the `op` and `age` versions (`op --version`, `age --version`)
- steps to reproduce, and the impact you expect

Never include private keys, decrypted data, 1Password vault or item IDs, key
fingerprints, or other secrets in a report. Replace them with placeholders. Do not
attach `AGEDEBUG=plugin` output from real files: it contains the decrypted file key.

You can expect a first response within a week. Fixes are released as a new
patch version and credited in the advisory, unless you prefer to stay
anonymous.

## Scope

In scope are problems in age-plugin-onepassword itself, for example:

- private keys leaked to logs, stdout, files, or other processes
- untrusted identity payloads or IDs reaching `op` as unintended arguments or
  references
- identity, config, or log files written with unsafe permissions
- private keys fetched from 1Password when the file does not need them

Out of scope are vulnerabilities in 1Password itself, the 1Password CLI (`op`),
or age. Report those to their maintainers.
