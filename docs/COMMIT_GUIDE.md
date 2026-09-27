# Semantic Commit Message (with emojis)

Use this guide to propose commit messages. Never git init, git add or git commit
without my explicit approval! I will handle all this on my own.

Format: `<type> <emoji>(<scope>): <subject>`

`<type>` and `<emoji>` see table below!
`<scope>` is optional and should be derived from the current change

`<subject>` max. character limit is `80` (including `type`, `emoji` and `(scope)`!!!)

Every commit message should also have a longer commit `body` with max. character limit `1000` and line length `72`.

| **Type**  | **Description**                                               | **Emoji** |
| --------- | ------------------------------------------------------------- | --------- |
| feat      | a new feature                                                 | ✨        |
| fix       | a bug fix                                                     | 🐛        |
| hotfix    | a critical hotfix                                             | 🚑        |
| build     | changes that affect the build system or external dependencies | 🏗        |
| chore     | changes to the build process or auxiliary tools and libraries | 🔧        |
| ci        | changes to our CI configuration files and scripts             | 🔄        |
| docs      | documentation only changes                                    | 📚        |
| perf      | a code change that improves performance                       | ⚡        |
| deprecate | remove dead code                                              | ⚰         |
| refactor  | a code change that neither fixes a bug nor adds a feature     | ♻         |
| revert    | reverts a previous commit                                     | ⏪        |
| style     | changes that do not affect the meaning of the code            | 💄        |
| test      | adding missing tests or correcting existing tests             | 🧪        |
| wip       | work in progress                                              | 🚧        |
| package   | add or update compiled files or packages                      | 📦        |
