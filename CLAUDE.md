# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Vision

A comprehensive GitHub Actions security scanner, distributed as a **`gh` CLI extension** (`gh actions-audit`), that evolves with the threat landscape and community best practices. The tool:

- **Detects real-world attack patterns** — pwn requests, expression injection, supply chain poisoning, artifact trust violations, and more
- **Maps findings to CCI controls** — each detection maps to [CCI](https://cyber.trackr.live/api/cci) identifiers, providing transitive mapping to NIST SP 800-53 controls. Enables integration with GRC tooling like [MITRE Heimdall](https://saf.mitre.org). [OWASP CI/CD Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/) categories used for informational context
- **Uses a structured JSONL intermediate format** — one JSON object per repo, decoupling analysis from rendering. All output formats (markdown, CSV, JSONL, and potentially [HDF v2](https://saf.mitre.org)) are rendered from this single source of truth
- **Follows `gh` CLI conventions** — `--json`, `--jq`, proper exit codes, `NO_COLOR` support, installable via `gh extension install`
- **Stays grep-based and dependency-light** — bash 3.2+, `gh` CLI, standard Unix tools. No YAML parser, no runtime beyond what ships with macOS/Linux

## Code Quality Rules

- **We own this code. There is no such thing as a "pre-existing" issue.** Every warning, lint finding, or tool error must be fixed immediately. Never dismiss, defer, or label something as "expected."
- **Fix everything you find.** If shellcheck, bats, or any tool reports a problem, fix it in the same pass. Zero findings is the only acceptable state.
- **`make check` (lint + format check + test) must pass clean before any work is considered done.**
- **Format with shfmt** before committing: `make fmt`. Settings: 2-space indent, binary ops on next line, case body indented (`shfmt -i 2 -bn -ci`).
- **Never reference Claude/AI in git commits or history.** Use `git commit -s` with the user's identity.

## Project Overview

A single-script security audit tool (`gh-actions-audit.sh`) that scans a GitHub organization's Actions workflows for CI/CD security misconfigurations. Produces markdown, CSV, and (soon) JSONL reports with 12 detection checks across per-repo and org-level analysis. Runtime dependencies: `bash` (3.2+), `gh` CLI, and standard Unix tools. Future: packaged as a `gh` CLI extension.

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

The entire tool is a single bash script (`gh-actions-audit.sh`, ~1000 lines) organized into five sequential phases:

1. **Phase 1 (Download)** — Enumerates org repos via `gh repo list`, downloads `.github/workflows/*.yml` files via GitHub API. Skipped with `--local`.
2. **Phase 2 (Per-repo analysis)** — `run_repo_classifiers()` scans each workflow file through 10 classify functions: `classify_prt()`, `classify_ic()`, `classify_unpinned()`, `classify_expr_injection()`, `classify_wfr()`, `classify_self_hosted()`, `classify_dangerous_perms()`, `classify_hardcoded_secrets()`, plus permissions and harden-runner checks. Results are cached, then `build_hdf_repo_target()` produces HDF v2 JSON (the single source of truth for pass/fail status), and `render_md_csv_row()` produces MD/CSV rows from HDF status + cached display strings. Trigger detection uses `extract_on_triggers()` to avoid false positives.
3. **Phase 3 (Org secrets)** — Lists org-level secrets, maps each to repos via single-pass `SECRET_MAP_FILE`, generates `gh secret set` remediation commands.
4. **Phase 4 (Org settings)** — Fetches default workflow token permissions, PR approval policy, allowed actions policy via `gh api --jq`.
5. **Phase 5 (Report)** — Writes markdown report (and optional CSV) with 12-field per-repo table and summary statistics. Soon: JSONL intermediate format.

Key implementation details:
- Workflow analysis is entirely grep-based heuristics (no YAML parser)
- All classify functions use `wf_uncommented` (comment-stripped content) to prevent false positives
- Temp files (`mktemp`) store intermediate table rows; cleaned up via `trap EXIT`
- Progress output uses ANSI colors (auto-disabled when not a TTY)
- Downloaded workflows are cached under `/tmp/gh-actions-audit-<ORG>-<XXXXXX>/workflows/`

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

## Research Reports

Agent research reports are saved in `.beads/research-*.md` for reference across sessions. Current reports cover: security detection gaps (OWASP-mapped), GitHub API schema verification, and `gh` CLI extension packaging conventions.
