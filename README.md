# gh-action-security-audit

A security audit tool for GitHub Actions workflows across an entire GitHub organization. Distributed as a [`gh` CLI extension](https://docs.github.com/en/github-cli/github-cli/using-github-cli-extensions).

## Installation

### As a `gh` CLI extension (recommended)

```bash
gh extension install rapidfort/gh-action-security-audit
gh action-security-audit <ORG>
```

### Standalone

```bash
./gh-action-security-audit <ORG>
```

## Why this exists

In February 2026, the [hackerbot-claw](https://www.stepsecurity.io/blog/hacking-millions-of-repos-with-github-actions) campaign demonstrated large-scale exploitation of misconfigured GitHub Actions workflows. The attack leveraged five vectors:

1. **Pwn requests** — `pull_request_target` workflows that check out and execute fork code, giving attackers RCE with the target repo's secrets and write token
2. **Unguarded `issue_comment` triggers** — workflows any GitHub user can invoke by commenting on a public repo's issues
3. **Shell injection** — `${{ github.event.* }}` expressions interpolated directly into `run:` blocks (branch names, PR titles, commit messages)
4. **Filename injection** — base64-encoded commands in filenames processed by bash loops in CI
5. **AI prompt injection** — poisoned config files (e.g. `CLAUDE.md`) executed by AI coding agents during `pull_request_target` checkouts

This tool scans an org's workflows for these patterns and generates a report highlighting what needs review.

## Detection Coverage

### Per-Repository Checks

| ID | Check | Risk | What it detects | CCI | NIST 800-53 |
|----|-------|------|-----------------|-----|-------------|
| GHA-001 | **Explicit `permissions:`** | Medium | Workflows missing `permissions:` blocks inherit org default (often `write`) | CCI-000225 | AC-6 |
| GHA-002 | **`pull_request_target`** | Critical | Pwn request attack surface — checkout+exec of fork code with target repo secrets | CCI-000213, CCI-001310 | AC-3, SI-10 |
| GHA-003 | **`issue_comment` gating** | High | Workflows any GitHub user can trigger by commenting on public issues/PRs | CCI-000213 | AC-3 |
| GHA-004 | **Unpinned Actions** | High | Action references using mutable tags (`@v4`, `@main`) vulnerable to tag-override attacks | CCI-002706 | SI-7 (1) |
| GHA-005 | **Expression Injection** | Critical | `${{ github.event.* }}` in `run:` blocks — shell injection via PR titles, branch names, etc. | CCI-001310 | SI-10 |
| GHA-006 | **`workflow_run` artifacts** | High | `workflow_run` workflows that download and execute artifacts (poisoning risk) | CCI-002706, CCI-000213 | SI-7 (1), AC-3 |
| GHA-007 | **Self-Hosted Runners** | High | `runs-on: self-hosted` — persistent machines vulnerable to credential theft | CCI-000366 | CM-6 |
| GHA-008 | **Dangerous Permissions** | Medium | `permissions: write-all`, `contents: write`, and other excessive grants | CCI-000225, CCI-000381 | AC-6, CM-7 |
| GHA-009 | **Hardcoded Secrets** | Critical | Hardcoded tokens/keys in workflow files (`ghp_*`, `gho_*`, `AKIA*`) | CCI-000196 | IA-5 (1) |
| GHA-010 | **Harden-Runner** | Info | Whether the repo uses [step-security/harden-runner](https://github.com/step-security/harden-runner) | CCI-002724 | SI-7 (8) |
| GHA-014 | **`secrets: inherit`** | High | Reusable workflow calls using `secrets: inherit` — passes all secrets | CCI-000225 | AC-6 |
| GHA-015 | **Env injection** | Critical | Untrusted data written to `GITHUB_ENV`, `GITHUB_PATH`, or `GITHUB_OUTPUT` | CCI-001310 | SI-10 |
| GHA-016 | **Extended expression contexts** | Critical | Additional dangerous contexts: `discussion.title`, `head_commit.message`, `pages.*.page_name` | CCI-001310 | SI-10 |
| GHA-017 | **Deprecated commands** | High | `::set-output`, `::set-env`, `::add-path` — deprecated injection vectors | CCI-001310, CCI-000366 | SI-10, CM-6 |
| GHA-018 | **Known-compromised actions** | Critical | `tj-actions/changed-files`, `reviewdog/action-setup`, and other compromised actions | CCI-002706 | SI-7 (1) |
| GHA-019 | **`github.event.ref` injection** | High | `github.event.ref` in `run:` blocks — attacker-controlled branch/tag names | CCI-001310 | SI-10 |
| GHA-020 | **Third-party unpinned** | Medium | Distinguishes first-party (`actions/*`) from third-party unpinned actions | CCI-002706 | SI-7 (1) |
| GHA-021 | **PRT untrusted ref checkout** | Critical | `pull_request_target` checkout of `head.sha`, `head.ref`, or PR merge ref | CCI-000213, CCI-001310 | AC-3, SI-10 |
| GHA-022 | **`always()` + secrets** | High | `if: always()` or `continue-on-error` combined with secret access | CCI-000213 | AC-3 |
| GHA-023 | **Artifact trust** | High | `actions/download-artifact` usage without integrity validation | CCI-002706 | SI-7 (1) |
| GHA-024 | **Missing environment** | Medium | Deployment workflows (`docker push`, `terraform apply`) without `environment:` protection | CCI-000213, CCI-000366 | AC-3, CM-6 |
| GHA-025 | **Cache poisoning** | High | `actions/cache` in fork-triggered workflows — shared cache poisoning risk | CCI-002706 | SI-7 (1) |
| GHA-026 | **Static credentials** | Medium | Static cloud credentials (`AWS_ACCESS_KEY_ID`, etc.) instead of OIDC federation | CCI-000225, CCI-000196 | AC-6, IA-5 (1) |
| — | **Repo Secrets** | Info | Secret names configured on the repo (informational listing) | CCI-000183 | IA-5 |

### Org-Level Checks

| ID | Check | Risk | What it detects | CCI | NIST 800-53 |
|----|-------|------|-----------------|-----|-------------|
| GHA-011 | **Default workflow permissions** | High | Org default `write` gives all workflows read/write `GITHUB_TOKEN` | CCI-000225 | AC-6 |
| GHA-012 | **PR approval by workflows** | Medium | Whether workflows can approve pull requests (self-approval risk) | CCI-000213 | AC-3 |
| GHA-013 | **Allowed actions policy** | Medium | Whether all actions are allowed or restricted to verified/selected | CCI-000381, CCI-001762 | CM-7, CM-7 (1) |
| GHA-027 | **SHA pinning enforcement** | Medium | Whether the org enforces SHA pinning for all action references | CCI-002706, CCI-000366 | SI-7 (1), CM-6 |
| GHA-028 | **Actions repository policy** | Medium | Whether Actions is restricted to selected repositories or allowed for all | CCI-000381 | CM-7 |
| GHA-029 | **Org secret scoping** | Medium | Secrets with `All repositories` scope accessible from any repo | CCI-000225, CCI-000183 | AC-6, IA-5 |
| — | **Secret usage mapping** | Info | Maps each org secret to repos that reference it, flags unused broad access | CCI-000225, CCI-000183 | AC-6, IA-5 |
| — | **Remediation commands** | — | Generates `gh secret set` commands to restrict overly broad secrets | CCI-000225 | AC-6 |

### Key Incidents Driving These Checks

| Incident | Date | Attack Vector | Checks That Detect It |
|----------|------|---------------|----------------------|
| [SpotBugs → Coinbase → tj-actions cascade](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised) | Nov 2024–Mar 2025 | `pull_request_target` → PAT theft → tag override | `pull_request_target`, Unpinned Actions |
| [Ultralytics YOLO](https://www.stepsecurity.io/blog/ultralytics-workflow-compromise) | Dec 2024 | Branch name injection via `${{ github.head_ref }}` + artifact poisoning via `workflow_run` | `pull_request_target`, Expression Injection, `workflow_run` |
| [Nx Build System](https://cycode.com/blog/github-actions-vulnerabilities/) | Aug 2025 | PR title injection in PRT workflow | `pull_request_target`, Expression Injection |
| [hackerbot-claw](https://www.stepsecurity.io/blog/hacking-millions-of-repos-with-github-actions) | Feb 2026 | AI bot exploiting PRT + CLAUDE.md poisoning | `pull_request_target` |

## Requirements

- [GitHub CLI (`gh`)](https://cli.github.com/) authenticated as an **admin** of the target org
- `bash` (3.2+), standard Unix tools (`grep`, `find`, `sort`, etc.)
- Admin scopes needed: `admin:org` (for org settings and secrets), repo admin access (for repo secrets)

Verify your access:

```bash
gh auth status
gh api orgs/<YOUR_ORG>/actions/permissions
```

## Usage

```
gh action-security-audit <ORG> [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `--out FILE` | Path for markdown report output. Default: `./<ORG>-actions-audit.md` |
| `--csv FILE` | Path for CSV report output. Omit to skip CSV generation. |
| `--hdf FILE` | Path for HDF v2 JSON report output (for MITRE Heimdall). |
| `--local DIR` | Reuse previously downloaded workflow files instead of re-fetching from the API. |
| `--cleanup` | Delete cached workflow files after the run completes. |
| `--exit-code` | Exit with status 1 if critical or high findings are detected. |
| `-V, --version` | Print version and exit. |
| `-h, --help` | Show built-in help and exit. |

### Examples

```bash
# Full scan — downloads all workflows, writes markdown report
gh action-security-audit my-org

# Output both markdown and CSV
gh action-security-audit my-org --out audit.md --csv audit.csv

# Reuse a previous download (saves time on large orgs)
gh action-security-audit my-org --local /tmp/gh-actions-audit-my-org-20260301

# Scan and clean up cached files afterward
gh action-security-audit my-org --cleanup
```

### How it works

1. **Download** — Enumerates all non-archived repos in the org, downloads `.github/workflows/*.yml` files via the GitHub API (skipped with `--local`)
2. **Analyze** — Scans each workflow for `pull_request_target`, `issue_comment`, `permissions:` blocks, unpinned action references, expression injection in `run:` blocks, and secret references using grep-based heuristics
3. **Org secrets** — Lists all org-level secrets, maps each to the repos that reference it in workflows, and generates remediation commands for overly broad access
4. **Org settings** — Checks default workflow permissions, PR approval policy, and allowed actions
5. **Report** — Writes a markdown report (and optionally CSV) with per-repo tables, org-level findings, and review guidance

For large orgs (hundreds of repos), the initial download can take several minutes. The `--local` flag lets you re-run analysis without re-downloading.

## Output

The markdown report includes:

- **Org-Level Settings** table with current values and recommendations
- **Per-Repository Audit** table with columns for permissions, `pull_request_target` classification, `issue_comment` triggers, unpinned actions, expression injection, and repo secrets
- **Org-Level Secrets** table showing visibility, configured access, actual workflow usage, and `gh secret set` remediation commands
- **Review Guidance** section explaining priority items, what the fork approval setting does and does not protect, and mitigations to look for

## Development

See [TESTING.md](TESTING.md) for the full testing guide.

Quick start:

```bash
make test-deps     # Install bats-core, shellcheck, shfmt, and helpers
make check         # Run shellcheck + shfmt format check + bats tests
make fmt           # Auto-format with shfmt
```

### Contributing

This project follows a TDD workflow. Before fixing a bug or adding a feature:

1. Write a failing test in the appropriate `test/test_*.bats` file
2. Make the change in `gh-action-security-audit`
3. Verify with `make check`

## License

MIT
