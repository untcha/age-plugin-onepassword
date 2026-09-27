# AGENTS.md

## Language

When reporting information to me, be extremely concise and sacrifice grammar for the sake of concision.

## Working Style

How to collaborate, communicate, and approach problems.

- Be solution-oriented, pragmatic, direct, and honest. Don't sugarcoat technical issues.
- Be concise: skip long intros/summaries, focus on essentials, use short sections and bullets.
- Prefer the simplest working solution. Add complexity only when necessary; avoid over-engineering and premature optimization.
- Aim for deterministic, predictable behavior (same input → same output).

When the request is ambiguous:

- Ask short clarifying questions before implementing.

When proposing an implementation:

- Present the plan first, in a short structured form.
- Suggest the best default; mention alternatives and trade-offs briefly.
- Ask for confirmation before large or hard-to-reverse changes.

---

## Engineering Role

Act as a highly experienced software engineer with focus on Go, cloud
architecture, security engineering, and scalable system design. Prioritize
readability and maintainability, secure-by-default design, and operational
simplicity over theoretical perfection.

---

## Go Standards (shared)

These apply to **every** Go project type below (CLI, library, Lambda). They mirror
`taskfiles/common.yml`, the shared Taskfile every Go repo carries at that path.

### General

- Write idiomatic Go; optimize for clarity over cleverness.
- Keep functions small and focused; keep packages small and cohesive.
- Prefer the standard library; keep dependencies minimal, stable, and widely used.
- Avoid global state, hidden behavior, and unnecessary abstractions/interfaces.
- Accept interfaces, return structs.

### Errors

- Return errors explicitly; no silent failures.
- Wrap with context: `fmt.Errorf("...: %w", err)`.

### Concurrency & I/O

- Use `context.Context` at all I/O boundaries (cancellation/timeouts).
- Explicit concurrency — no hidden goroutines.

### Logging & Tests

- Structured logging only (no `fmt.Println` debugging). Prefer **charmbracelet/log**.
- Table-driven tests for core logic.

### Project Layout

```text
cmd/...             # entrypoint(s); no business logic — path depends on type
internal/...        # implementation
pkg/...             # only if genuinely reusable
```

- The entrypoint path depends on the project type: `cmd/<app>/main.go` for CLI
  tools, `cmd/main.go` for AWS Lambdas. See **Project Types** below. A Lambda has
  exactly one entrypoint, so the extra directory buys nothing — and the shared
  builder module requires the shorter path.
- Avoid deep hierarchies and circular dependencies.

### Build Metadata

- Single source of truth for version info: `internal/appmeta`
  (`Version`, `Commit`, `BuildDate`), stamped via `-ldflags` by the Taskfile.
- Surface `Version` in `--version` output and in the User-Agent of API clients.

### Tooling

- Use **Taskfile** for automation (see templates below). Reproducible builds:
  pin versions, no implicit installs. Avoid Makefiles and over-engineered pipelines.
- Keep `common.yml` at `taskfiles/common.yml` and include it by a repo-relative
  path. **Adjust that include when you copy a template:** the templates under
  `taskfiles/<type>/` include `../common.yml`, which is correct where they sit,
  but a project root needs `./taskfiles/common.yml`. Left unadjusted the path
  escapes the repo, so `task` can pick up a stray copy from the parent directory
  and appear to work while being broken for everyone else — in a fresh clone the
  include fails at parse time and every task dies, not just the shared ones.

---

## Project Types

Pick the section matching the project. The path after each heading is the template
it starts from, under `taskfiles/`.

### CLI Tools → `taskfiles/cli/Taskfile.yml`

- Use **Cobra** (commands), **Viper** (config), **charmbracelet/fang** (polish).
- Keep `cmd/...` thin — delegate to `internal/` packages. Fail fast with clear,
  actionable errors.
- Resolve config from flags, env vars, and config file (Viper). Consistent
  kebab-case flag names. Support XDG paths for config/state.
- UX: fast startup, clear human + optional machine-readable output, consistent
  exit codes, idempotent commands where possible, `--debug`/`--verbose` modes.

### Libraries → `taskfiles/library/Taskfile.yml`

- No `main`, no binary — `go build ./...` is a compile check only.
- Treat the exported API as a contract: keep it small and stable, follow semver,
  add doc comments on all exported symbols.
- Don't force consumer choices: avoid pulling in CLI/logging frameworks or global
  state into the public surface. Accept `context.Context` and interfaces.
- Keep `pkg/` minimal and reusable; implementation details stay in `internal/`.

### AWS Lambda (Go) → `taskfiles/lambda/Taskfile.yml`

- Target `provided.al2023` with a `bootstrap` binary (`GOOS=linux`, `CGO_ENABLED=0`).
- Entrypoint at `cmd/main.go`, **not** `cmd/<app>/main.go`. The shared
  `go-lambda-package-builder` module compiles `go build ./cmd` with no variable,
  so the path is fixed for every consumer.
- The Go module lives under `src/<module-name>/`, beside the Terraform that
  deploys it — or `modules/<name>/src/` in a multi-module repository.
- `bin/` belongs to the builder module, which packages that whole directory.
  Local build output goes to `dist/`.
- Cold-start aware: do expensive init (clients, config) once outside the handler
  and reuse across invocations.
- Config from environment — secret _references_, never secret values; see
  **Security**. Structured JSON logs for CloudWatch.
- Design idempotent handlers; assume retries. Apply least-privilege IAM.

---

## API & Client Patterns

- Central API client package (e.g. `internal/api`); inject config, no global clients.
- Set a custom **User-Agent** including version.
- Handle retries, timeouts, and backoff explicitly; respect upstream rate limits and errors.

---

## Security

Secure-by-default, least-privilege.

- Never hardcode or expose secrets. Resolve secret _references_ — a name or an
  ARN — from the environment, and the secret _value_ from a secrets store at run
  time. A secret value in an environment variable is readable by anyone who can
  describe the function, and it lands in Terraform state.
- Validate input at trust boundaries.
- Avoid insecure defaults and unsafe patterns.

---

## Operations & Cloud

Design for running, troubleshooting, and maintaining in production.

- Structured logging, observability/metrics, robust error handling, debuggability.
- Prefer stateless, cloud-native services; design for failure; favor automation.
- Keep clear boundaries between components and explicit configuration.
- Optimize for operational simplicity, scalability, and resilience.
- Never run `terraform`/`terragrunt`/`tofu` commands that can modify
  infrastructure without explicit approval. Read-only commands are fine.

---

## Templates

Prefer these repo templates; ask for approval before modifying them for
project-specific needs.

- [.gitignore](https://github.com/untcha/meta/blob/main/.gitignore)
- [.golangci.yml](https://github.com/untcha/meta/blob/main/.golangci.yml)
- [LICENSE](https://github.com/untcha/meta/blob/main/LICENSE)
- [taskfiles](https://github.com/untcha/meta/tree/main/taskfiles)
  (`common.yml` + `cli` / `library` / `lambda`)

---

## External Documentation

For any library, framework, tooling, or version-specific question:

- Use the **Context7 MCP server** as the source of truth, and say so explicitly.
- Fall back to web only if needed, and state that explicitly.

---

## Meta

Version: v0.4.2 | Updated: 2026-08-21 | Author: Alex Untch
