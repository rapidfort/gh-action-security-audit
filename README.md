# gha-security-audit

A shell script that scans GitHub repositories across your organizations for common GitHub Actions security misconfigurations — before attackers find them first.

---

## Why This Matters

GitHub Actions workflows are a frequent target for supply chain attacks. Two of the most dangerous misconfigurations are:

1. **`pull_request_target` trigger with a write-permission token** — This trigger runs in the context of the *base* repository (not the fork), meaning a malicious PR from an external contributor can execute code with full write access to your repo secrets and contents. This was the attack vector in several high-profile CI/CD breaches.

2. **Default `GITHUB_TOKEN` set to `write`** — When any workflow in your repo is triggered (including from forks or third-party actions), it gets write access by default — a broad privilege that violates the principle of least privilege.

This tool gives you a single command to audit your entire GitHub organization for these patterns, so you can fix them before they become incidents.

---

## What It Detects

| Check | What It Looks For |
|---|---|
| `pull_request_target` usage | Workflows that use this high-risk trigger |
| Default `GITHUB_TOKEN` permissions | Whether the token defaults to `read` or `write` |
| PR review approval by Actions | Whether workflows can auto-approve pull request reviews |
| Per-workflow permission blocks | Whether workflows explicitly scope down their permissions |
| Effective write risk | Combines token default + explicit `permissions:` block to assess real exposure |

### Risk Flags

| Flag | Meaning |
|---|---|
| `CHECK` | `pull_request_target` + write-default token — **needs immediate review** |
| `SAFE?` | `pull_request_target` + read-default token — lower risk, but verify |
| `NOTE` | Write-default token, no `pull_request_target` — worth tightening |
| `-` | No issues detected |

---

## Prerequisites

- [`gh` CLI](https://cli.github.com/) — authenticated via `gh auth login`
- [`jq`](https://jqlang.github.io/jq/) — JSON processor
- Admin access to the repositories or organization you want to scan

---

## Installation

```bash
# Clone the repo
git clone https://github.com/rapidfort/gha-security-audit.git
cd gha-security-audit

# Make the script executable
chmod +x gh-actions-audit.sh
```

No dependencies to install beyond `gh` and `jq`.

---

## Usage

```bash
# Scan all organizations where you have admin access (auto-discovery)
./gh-actions-audit.sh

# Scan a specific organization
./gh-actions-audit.sh <org-name>

# Scan your personal repositories only
./gh-actions-audit.sh --user

# Scan all orgs + personal repos
./gh-actions-audit.sh --all

# Show help
./gh-actions-audit.sh --help
```

### Example

```bash
./gh-actions-audit.sh rapidfort
```

```
Fetching repos for org: rapidfort

===========================================================================
GitHub Actions Security Audit
Scope: pull_request_target usage + Default GITHUB_TOKEN permissions
===========================================================================
Repositories to scan: 42

REPOSITORY                                    VIS      TOKEN-DEFAULT   PR-APPROVE   PR-TARGET    RISK
----------                                    ---      -------------   ----------   ---------    ----
rapidfort/api-service                         public   write           false        YES(2)       CHECK
rapidfort/frontend                            private  read            false        no           -
rapidfort/deploy-scripts                      private  write           false        no           NOTE
rapidfort/community-charts                    public   read            false        YES(1)       SAFE?
...

===========================================================================
SUMMARY
===========================================================================
  Total repos scanned:          42
  Repos with pull_request_target:
    needing review (CHECK):     3
    likely safe (SAFE?):        2

Detailed per-workflow analysis saved to: /tmp/gh-audit-details-1709123456.txt
```

---

## Output

### Console Table

| Column | Description |
|---|---|
| `REPOSITORY` | `org/repo` slug |
| `VIS` | `public` or `private` |
| `TOKEN-DEFAULT` | Default `GITHUB_TOKEN` permission (`read`, `write`, or `unknown`) |
| `PR-APPROVE` | Whether Actions can approve pull request reviews (`true`/`false`) |
| `PR-TARGET` | Number of workflows using `pull_request_target`, e.g. `YES(2)` |
| `RISK` | Summary risk flag: `CHECK`, `SAFE?`, `NOTE`, or `-` |

### Detail File

A detailed per-workflow breakdown is saved to `/tmp/gh-audit-details-<timestamp>.txt`, including:

- Visibility and default token permission
- Whether each workflow uses `pull_request_target`
- Whether a `permissions:` block is present
- Explicit `contents:` and `pull-requests:` permission values
- Whether the workflow follows the safe pattern (`contents: read` + `pull-requests: write`)
- Per-workflow effective write risk and risk level (`HIGH`, `MEDIUM`, `LOW`)

---

## Remediation Guide

### Fix 1 — Restrict the default `GITHUB_TOKEN` to read-only

In your GitHub organization or repository settings:

> **Settings → Actions → General → Workflow permissions → Read repository contents and packages permissions**

Or enforce it at the org level so all repos inherit it automatically.

### Fix 2 — Add explicit `permissions:` blocks to workflows using `pull_request_target`

```yaml
# Bad: inherits default (possibly write) token
on:
  pull_request_target:

jobs:
  triage:
    runs-on: ubuntu-latest
    steps: ...
```

```yaml
# Good: explicitly scoped permissions
on:
  pull_request_target:

permissions:
  contents: read
  pull-requests: write   # only if the workflow needs to comment on PRs

jobs:
  triage:
    runs-on: ubuntu-latest
    steps: ...
```

### Fix 3 — Avoid checking out PR code in `pull_request_target` workflows

If you must use `pull_request_target`, **never** check out the PR's code (`ref: ${{ github.event.pull_request.head.sha }}`) in a step that also has access to secrets. Keep secret-using steps separate from untrusted code execution.

---

## Understanding the Risk

### The `pull_request_target` + write token attack chain

1. Attacker forks your public repo and opens a pull request
2. Your workflow uses `pull_request_target` — it runs in the context of **your** repo with **your** token
3. If the workflow checks out the PR's code and runs it (e.g., `npm install`, `make`, scripts), the attacker's code executes with your write token
4. Attacker can exfiltrate secrets, push malicious code, or tamper with releases

This is not theoretical — it has been exploited in real CI/CD pipeline attacks.

### Why `unknown` token default matters

If `TOKEN-DEFAULT` shows `unknown`, the `gh` API couldn't determine the setting, which typically means the org-level setting is in an intermediate state. Treat it as potentially `write` and verify manually in your GitHub settings UI.

---

## Limitations

- Requires admin access to each repository to read workflow permissions settings
- Workflow content analysis is text-based (regex), not a full YAML parser — complex anchors or multi-document YAML may not be fully analyzed
- Does not detect secrets misconfiguration, third-party action pinning issues, or OIDC misconfigurations (these may be added in future versions)
- Scans up to 1000 repositories per organization (GitHub API limit per page with `--paginate`)

---

## Contributing

Contributions are welcome. If you find a misconfiguration pattern that isn't detected, or want to improve the output format or remediation guidance, please open an issue or pull request.

Areas where help is especially appreciated:
- Additional security checks (unpinned actions, OIDC configuration, secret exposure patterns)
- Output formats (JSON, CSV, SARIF for GitHub Code Scanning integration)
- GitHub Actions workflow to run this as a scheduled org-wide audit

---

## References

- [StepSecurity — hackerbot-claw: An AI-Powered Bot Actively Exploiting GitHub Actions (Microsoft, DataDog, CNCF projects hit)](https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation)
- [GitHub Docs — Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [GitHub Docs — Keeping your GitHub Actions and workflows secure: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [CISA — Defending CI/CD Environments](https://www.cisa.gov/resources-tools/resources/defending-continuous-integration-continuous-delivery-cicd-environments)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

*Built by [RapidFort](https://rapidfort.com) to help the community secure their software supply chains.*
