# gh-actions-audit

A security audit tool for GitHub Actions workflows across an entire GitHub organization.

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

| Check | Risk | What it detects | Sub-classifications | References |
|-------|------|-----------------|---------------------|------------|
| **Explicit `permissions:`** | Medium | Workflows missing `permissions:` blocks inherit org default (often `write`) | All, Partial, None (with ratio) | [GitHub docs: permissions](https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs) |
| **`pull_request_target`** | Critical | Pwn request attack surface — workflows that run with target repo secrets on fork PRs | API-only (low), checkout+guard (review), checkout+exec no guard (**critical**), checkout no fork ref (review), Dependabot-gated | [Pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) · [Ultralytics YOLO exploit](https://www.stepsecurity.io/blog/ultralytics-workflow-compromise) · [hackerbot-claw](https://www.stepsecurity.io/blog/hacking-millions-of-repos-with-github-actions) |
| **`issue_comment`** | High | Workflows any GitHub user can trigger by commenting on public issues/PRs | has author_association, has actor check, **no author gate** | [GitHub docs: events](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#issue_comment) |
| **Unpinned Actions** | High | Action references using mutable tags (`@v4`, `@main`) vulnerable to tag-override supply chain attacks | Pinned/total ratio per workflow | [tj-actions/changed-files compromise (CVE-2025-30066)](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised) · [CISA guidance](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066) |
| **Expression Injection** | Critical | `${{ github.event.* }}` expressions in `run:` blocks allowing shell command injection via PR titles, branch names, issue bodies, comments. Also detects `${{ inputs.* }}` (workflow_dispatch) and `${{ github.event.client_payload.* }}` (repository_dispatch) | Lists specific dangerous contexts found | [GitHub docs: security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections) · [Nx exploit](https://cycode.com/blog/github-actions-vulnerabilities/) |
| **`workflow_run`** | High | Workflows triggered by `workflow_run` bypass fork PR restrictions and run with write permissions | download-artifact (**high** — artifact poisoning), checkout (medium), API-only (low) | [GitHub docs: workflow_run](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_run) · [Ultralytics YOLO artifact attack](https://www.stepsecurity.io/blog/ultralytics-workflow-compromise) |
| **Self-Hosted Runners** | High | Workflows using `runs-on: self-hosted` — persistent machines vulnerable to credential theft and lateral movement | Flags self-hosted per workflow | [GitHub docs: self-hosted runners](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security) |
| **Dangerous Permissions** | Medium | Workflows with `permissions:` granting excessive access (`write-all`, `contents: write`, etc.) | Lists specific dangerous grants found | [GitHub docs: permissions](https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs) |
| **Hardcoded Secrets** | Critical | Hardcoded tokens/keys in workflow files (`ghp_*`, `gho_*`, `AKIA*`) that should use GitHub Secrets | Lists detected token types per workflow | [SpotBugs PAT theft](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised) |
| **Harden-Runner** | Info | Whether the repo uses [step-security/harden-runner](https://github.com/step-security/harden-runner) for runtime monitoring | Yes/No per repo | [harden-runner detected tj-actions compromise](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised) |
| **Repo Secrets** | Info | Secret names configured on the repo (accessible from any workflow, including exploited ones) | Comma-separated list | [GitHub docs: encrypted secrets](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions) |

### Org-Level Checks

| Check | Risk | What it detects | References |
|-------|------|-----------------|------------|
| **Default workflow permissions** | High | Org default `write` gives all workflows read/write `GITHUB_TOKEN` | [GitHub docs: default permissions](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#setting-the-permissions-of-the-github_token-for-your-organization) |
| **PR approval by workflows** | Medium | Whether workflows can approve pull requests (self-approval risk) | [GitHub docs: workflow permissions](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization) |
| **Allowed actions policy** | Medium | Whether all actions are allowed or restricted to verified/selected | [GitHub docs: allowed actions](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#allowing-select-actions-and-reusable-workflows-to-run) |
| **Org secret visibility** | High | Secrets with `All repositories` scope are accessible from any repo | [GitHub docs: org secrets](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions#creating-secrets-for-an-organization) |
| **Secret usage mapping** | Info | Maps each org secret to repos that actually reference it, flags unused broad access | — |
| **Remediation commands** | — | Generates `gh secret set` commands to restrict overly broad secrets | — |

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
./gh-actions-audit.sh <ORG> [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `--out FILE` | Path for markdown report output. Default: `./<ORG>-actions-audit.md` |
| `--csv FILE` | Path for CSV report output. Omit to skip CSV generation. |
| `--local DIR` | Reuse previously downloaded workflow files instead of re-fetching from the API. Accepts the top-level audit directory or its `workflows/` subdirectory. |
| `--cleanup` | Delete cached workflow files after the run completes. |
| `-h, --help` | Show built-in help and exit. |

### Examples

```bash
# Full scan — downloads all workflows, writes markdown report
./gh-actions-audit.sh my-org

# Output both markdown and CSV
./gh-actions-audit.sh my-org --out audit.md --csv audit.csv

# Reuse a previous download (saves time on large orgs)
./gh-actions-audit.sh my-org --local /tmp/gh-actions-audit-my-org-20260301

# Scan and clean up cached files afterward
./gh-actions-audit.sh my-org --cleanup
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
2. Make the change in `gh-actions-audit.sh`
3. Verify with `make check`

## License

MIT
