# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Code Quality Rules

- **We own this code. There is no such thing as a "pre-existing" issue.** Every warning, lint finding, or tool error must be fixed immediately. Never dismiss, defer, or label something as "expected."
- **Fix everything you find.** If shellcheck, bats, or any tool reports a problem, fix it in the same pass. Zero findings is the only acceptable state.
- **`make check` (lint + format check + test) must pass clean before any work is considered done.**
- **Format with shfmt** before committing: `make fmt`. Settings: 2-space indent, binary ops on next line, case body indented (`shfmt -i 2 -bn -ci`).
- **Never reference Claude/AI in git commits or history.** Use `git commit -s` with the user's identity.

## Project Overview

This is a single-script security audit tool (`gh-actions-audit.sh`) that scans a GitHub organization's Actions workflows for CI/CD security misconfigurations. It produces markdown and optional CSV reports. Runtime dependencies: `bash` (4.0+), `gh` CLI, and standard Unix tools.

## Running the Script

```bash
# Full scan (requires gh CLI authenticated as org admin)
./gh-actions-audit.sh <ORG>

# With all options
./gh-actions-audit.sh <ORG> --out report.md --csv report.csv --cleanup

# Reuse previously downloaded workflows (skips API download phase)
./gh-actions-audit.sh <ORG> --local /path/to/previous/audit/dir
```

The script requires `admin:org` scope and repo admin access via `gh auth`.

## Architecture

The entire tool is a single bash script (`gh-actions-audit.sh`, ~700 lines) organized into five sequential phases:

1. **Phase 1 (Download)** — Enumerates org repos via `gh repo list`, downloads `.github/workflows/*.yml` files via GitHub API. Skipped with `--local`.
2. **Phase 2 (Per-repo analysis)** — Scans each workflow file for: explicit `permissions:` blocks, `pull_request_target` triggers (sub-classified by risk: API-only, checkout+guard, checkout+exec/no guard), `issue_comment` triggers (with/without author gates), and repo-level secret names.
3. **Phase 3 (Org secrets)** — Lists org-level secrets, maps each to repos that reference it in workflows via grep, generates `gh secret set` remediation commands for overly broad secrets.
4. **Phase 4 (Org settings)** — Fetches default workflow token permissions, PR approval policy, allowed actions policy via `gh api --jq`.
5. **Phase 5 (Report)** — Writes markdown report (and optional CSV) using heredocs and pipe-delimited temp files.

Key implementation details:
- Workflow analysis is entirely grep-based heuristics (no YAML parser)
- Temp files (`mktemp`) store intermediate table rows; cleaned up at end
- Progress output uses ANSI colors (auto-disabled when not a TTY)
- Downloaded workflows are cached under `/tmp/gh-actions-audit-<ORG>-<timestamp>/workflows/`

## Testing

Tests use [bats-core](https://github.com/bats-core/bats-core) with bats-support and bats-assert. See [TESTING.md](TESTING.md) for full details.

```bash
make test-deps     # Install bats + helpers + shellcheck + shfmt
make test          # Run bats tests
make lint          # Run shellcheck
make fmt           # Auto-format with shfmt
make fmt-check     # Verify formatting (no changes)
make check         # All three: lint + format check + test
```

Test structure:
- `test/test_helper/common-setup.bash` — Shared setup, mock helpers
- `test/fixtures/workflows/` — Sample workflow YAMLs for each scenario
- `test/test_*.bats` — Test files organized by phase/feature

Tests prefixed with `BUG:` document known bugs (they pass, proving the bug exists). When fixing a bug, invert the assertion.

## Known Issue

The LICENSE file is MIT but README.md states Apache-2.0. These should be reconciled.
