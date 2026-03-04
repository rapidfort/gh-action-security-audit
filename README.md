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

## What it checks

### Per-repository
- Whether workflows have explicit `permissions:` blocks (workflows without one inherit the org default, which may be `write`)
- `pull_request_target` usage, sub-classified by risk:
  - **API-only** — no checkout, used for labeling/auto-merge (low risk)
  - **checkout, has guard** — checks out fork code but gates on author (e.g. `dependabot[bot]`)
  - **checkout+exec, no guard** — checks out and runs fork code with no restriction (highest risk)
- `issue_comment` triggers, noting whether an `author_association` or actor check is present
- Repo-level secret names (not values)
- Dependabot false-positive tagging — workflows gated to `dependabot[bot]` are marked so reviewers can skip them

### Org-level
- Default workflow token permissions (`read` vs `write`)
- Whether workflows can approve pull requests
- Allowed actions policy (all, verified creators, or selected)
- All org secrets with visibility scope, which repos are configured for access, and which repos actually reference each secret in their workflow files
- For overly broad secrets (`All repositories` visibility): a ready-to-run `gh secret set` command to restrict them to only the repos that use them

## Requirements

- [GitHub CLI (`gh`)](https://cli.github.com/) authenticated as an **admin** of the target org
- `bash` (4.0+), `python3` (for JSON parsing), standard Unix tools (`grep`, `find`, `sort`, etc.)
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
2. **Analyze** — Scans each workflow for `pull_request_target`, `issue_comment`, `permissions:` blocks, and secret references using grep-based heuristics
3. **Org secrets** — Lists all org-level secrets, maps each to the repos that reference it in workflows, and generates remediation commands for overly broad access
4. **Org settings** — Checks default workflow permissions, PR approval policy, and allowed actions
5. **Report** — Writes a markdown report (and optionally CSV) with per-repo tables, org-level findings, and review guidance

For large orgs (hundreds of repos), the initial download can take several minutes. The `--local` flag lets you re-run analysis without re-downloading.

## Output

The markdown report includes:

- **Org-Level Settings** table with current values and recommendations
- **Per-Repository Audit** table with columns for permissions, `pull_request_target` classification, `issue_comment` triggers, and repo secrets
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
