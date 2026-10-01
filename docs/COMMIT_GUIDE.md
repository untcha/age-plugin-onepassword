# Semantic Commit Message (with emojis)

Use this guide to propose commit messages. Never git init, git add or git commit
without my explicit approval! I will handle all this on my own.

Format: `<type> <emoji>(<scope>): <subject>`

- `<type>` and `<emoji>` see table below.
- `<scope>`: optional, the area the change touches (e.g., `api`, `cli`, `config`, `auth`).
- Subject line: max. 80 characters, including type, emoji and scope.
- Body: always present, max. 1000 characters, lines wrapped at 72.

The `body` explains **why** the change was made: the problem it solves, the motivation, or
the consequence. Don't only list what changed; the diff already shows that.

Example (`fix 🐛(api): retry rate-limited requests with backoff`):

```text
Requests that hit the rate limit failed at once with HTTP 429, so
long-running imports aborted halfway and had to be restarted by hand.
Retry 429 responses with exponential backoff and honour the
Retry-After header, so short bursts no longer break an import.
```

Avoid bodies that only repeat the diff:

```text
Add a retry loop to client.go and a test for it.
```

| **Type**  | **Description**                                               | **Emoji** |
| --------- | ------------------------------------------------------------- | --------- |
| feat      | a new feature                                                 | ✨        |
| fix       | a bug fix                                                     | 🐛        |
| hotfix    | a critical hotfix                                             | 🚑        |
| build     | changes that affect the build system or external dependencies | 🏗️        |
| chore     | changes to the build process or auxiliary tools and libraries | 🔧        |
| ci        | changes to our CI configuration files and scripts             | 🔄        |
| docs      | documentation only changes                                    | 📚        |
| perf      | a code change that improves performance                       | ⚡        |
| deprecate | deprecate or remove dead code                                 | ⚰️        |
| refactor  | a code change that neither fixes a bug nor adds a feature     | ♻️        |
| revert    | reverts a previous commit                                     | ⏪        |
| style     | changes that do not affect the meaning of the code            | 💄        |
| test      | adding missing tests or correcting existing tests             | 🧪        |
| wip       | work in progress                                              | 🚧        |
| package   | add or update compiled files or packages                      | 📦        |

---

## Meta

Version: v0.3.0 | Updated: 2026-10-01 | Author: Alex Untch
