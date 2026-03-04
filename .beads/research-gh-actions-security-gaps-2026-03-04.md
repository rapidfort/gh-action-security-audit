# GitHub Actions Security Gap Analysis

Based on extensive research across GitHub official docs, OWASP CI/CD Top 10, StepSecurity, Palo Alto Unit 42, GitHub Security Lab, Wiz, Orca Security, GitGuardian, and real-world incident reports, here is a prioritized analysis of what your tool covers and what gaps remain.

---

## CURRENT COVERAGE (10 Detections)

Your existing detections map well to the most critical attack vectors:

| # | Detection | OWASP Mapping |
|---|-----------|---------------|
| 1 | `pull_request_target` misconfigurations | CICD-SEC-4 (Poisoned Pipeline Execution) |
| 2 | `issue_comment` without author gates | CICD-SEC-4 |
| 3 | Unpinned actions (tag vs SHA) | CICD-SEC-3 (Dependency Chain Abuse) |
| 4 | Expression injection in `run:` blocks | CICD-SEC-4 |
| 5 | `workflow_run` triggers | CICD-SEC-4 |
| 6 | Self-hosted runners | CICD-SEC-5 (Insufficient PBAC) |
| 7 | Dangerous permissions | CICD-SEC-6 (Insufficient Credential Hygiene) |
| 8 | Missing explicit `permissions:` blocks | CICD-SEC-6 |
| 9 | Org-level secret visibility | CICD-SEC-6 |
| 10 | `workflow_dispatch`/`repository_dispatch` input injection | CICD-SEC-4 |

---

## PRIORITIZED GAPS TO ADD

### Priority 1 (HIGH) -- High impact, easy grep detection

---

**GAP 1: `GITHUB_ENV` / `GITHUB_PATH` injection**

- **What:** Workflows that write untrusted input to `$GITHUB_ENV` or `$GITHUB_PATH` environment files. Any value written to these files becomes an environment variable or PATH entry for ALL subsequent steps in the job. If untrusted data (artifact contents, API responses, user-controlled strings) is written without sanitization, an attacker achieves arbitrary code execution.
- **Why it matters:** This was a high-profile vulnerability found in Google Firebase and Apache projects. The deprecated `set-env`/`add-path` commands were removed for this exact reason, but the replacement `GITHUB_ENV`/`GITHUB_PATH` files have the same risk if fed untrusted input. An attacker who controls a value written to `GITHUB_ENV` can inject `LD_PRELOAD=/tmp/evil.so` or similar, and every subsequent step is compromised.
- **Already covered?** NO. Your script does not grep for `GITHUB_ENV` or `GITHUB_PATH`.
- **Detection feasibility:** EASY. Grep for `>> $GITHUB_ENV`, `>> "$GITHUB_ENV"`, `>> $GITHUB_PATH`, `>> "$GITHUB_PATH"` in `run:` blocks. Flag as HIGH risk when combined with untrusted contexts (`${{ github.event.* }}`) being written to these files. Flag as MEDIUM (informational) when any write to these files exists without obvious sanitization.
- **Pattern:**
  ```
  GITHUB_ENV
  GITHUB_PATH
  ```

---

**GAP 2: `GITHUB_OUTPUT` injection**

- **What:** Workflows that write untrusted input to `$GITHUB_OUTPUT` (the replacement for the deprecated `::set-output` command). Step outputs can be consumed by subsequent steps via `${{ steps.*.outputs.* }}`, so poisoned output values flow through the workflow.
- **Why it matters:** CVE-2025-53104 (gluestack-ui) demonstrated this exact pattern: a workflow wrote user-controlled GitHub Discussion title/body to `GITHUB_OUTPUT`, which was then interpolated into subsequent steps. Attacker achieved arbitrary code execution via `$(curl ...)` payload.
- **Already covered?** NO.
- **Detection feasibility:** EASY. Grep for `>> $GITHUB_OUTPUT` or `>> "$GITHUB_OUTPUT"` in `run:` blocks. Higher severity when combined with `${{ github.event.* }}` expressions in the same block.
- **Pattern:**
  ```
  GITHUB_OUTPUT
  ```

---

**GAP 3: `secrets: inherit` in reusable workflow calls**

- **What:** Workflows using `secrets: inherit` when calling reusable workflows via `workflow_call`. This passes ALL repository secrets to the called workflow, violating the principle of least privilege.
- **Why it matters:** If the reusable workflow is compromised (or if it is a third-party workflow), every secret in the repository is exposed. StepSecurity, GitGuardian, and Wiz all specifically recommend against this pattern. The blast radius of a compromised reusable workflow is dramatically increased.
- **Already covered?** NO. Your script does not grep for `secrets: inherit`.
- **Detection feasibility:** TRIVIAL. Single grep:
  ```
  secrets:\s*inherit
  ```

---

**GAP 4: Deprecated / dangerous workflow commands**

- **What:** Usage of `::set-output`, `::save-state`, `::set-env`, `::add-path` workflow commands. These were deprecated precisely because they are injection vectors (any action that prints to STDOUT can inject workflow commands).
- **Why it matters:** GitHub deprecated these in 2022 but they still work (with warnings). Workflows using them are vulnerable to injection from any step that prints untrusted data to STDOUT. GitHub has repeatedly signaled they will disable these.
- **Already covered?** NO.
- **Detection feasibility:** EASY. Grep for the literal strings in `run:` blocks:
  ```
  ::set-output
  ::save-state
  ::set-env
  ::add-path
  ```

---

**GAP 5: Actions referencing deprecated/vulnerable action versions**

- **What:** Detect usage of known-compromised or known-vulnerable action versions, particularly `tj-actions/changed-files` at any tag (pre-v46), `reviewdog/action-setup@v1`, and `dawidd6/action-download-artifact` at versions < v6.
- **Why it matters:** The tj-actions/changed-files compromise (CVE-2025-30066, March 2025) is the most impactful GitHub Actions supply chain attack to date, affecting 23,000+ repositories and leading to the Coinbase breach. CISA issued an emergency advisory. `reviewdog/action-setup@v1` (CVE-2025-30154) was the initial vector. `dawidd6/action-download-artifact` < v6 searches fork artifacts by default, enabling artifact poisoning.
- **Already covered?** PARTIALLY. Your unpinned action detection catches tag-based references, but does not flag SPECIFIC known-bad actions regardless of pinning method.
- **Detection feasibility:** EASY. Maintain a small blocklist of action name patterns:
  ```
  tj-actions/changed-files
  reviewdog/action-setup
  dawidd6/action-download-artifact
  ```
  Grep for `uses:.*<action-name>` and report the version/SHA. This is a "known-vulnerable action" check rather than a pinning check.

---

### Priority 2 (MEDIUM) -- Moderate impact, grep-detectable

---

**GAP 6: `actions/checkout` of untrusted code in privileged contexts**

- **What:** Workflows triggered by `pull_request_target` or `workflow_run` that use `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}` or similar untrusted refs. This checks out attacker-controlled code into a context that has access to secrets.
- **Why it matters:** This is the core "pwn request" pattern. Your `classify_prt()` already sub-classifies PRT workflows, but the specific pattern of checking out the PR HEAD ref (as opposed to the base ref) is the critical distinguishing factor.
- **Already covered?** PARTIALLY. `classify_prt()` detects checkout+exec vs checkout+guard, but could be enhanced to specifically flag `ref:` parameters that reference `github.event.pull_request.head.sha`, `github.event.pull_request.head.ref`, or `${{ github.event.pull_request.number }}` with checkout.
- **Detection feasibility:** MODERATE. Grep in the context of workflows that have PRT triggers:
  ```
  ref:.*github\.event\.pull_request\.head\.(sha|ref)
  ```

---

**GAP 7: Artifact trust boundary violations**

- **What:** Workflows using `actions/download-artifact` or `dawidd6/action-download-artifact` that subsequently execute or source the downloaded content (via `run:`, `source`, `bash`, `node`, etc.) without validation.
- **Why it matters:** The Rust project artifact poisoning (Legit Security), the ArtiPACKED vulnerability (Palo Alto Unit 42), and the fork-based artifact injection in `dawidd6/action-download-artifact` all demonstrate that artifacts are an untrusted boundary. Downloading and executing artifact contents is equivalent to executing arbitrary attacker code.
- **Already covered?** PARTIALLY. `classify_wfr()` detects `download-artifact` in `workflow_run` contexts, but doesn't flag it in ALL contexts (e.g., a workflow that downloads artifacts from a different workflow or repo).
- **Detection feasibility:** MODERATE. Grep for `download-artifact` across all workflows, not just `workflow_run` ones:
  ```
  uses:.*download-artifact
  ```

---

**GAP 8: Mutable tag references on first-party GitHub actions**

- **What:** Even `actions/checkout@v4`, `actions/setup-node@v4`, and other first-party GitHub actions are vulnerable when referenced by mutable tag. The tj-actions attack showed that tags can be force-pushed to point at malicious commits.
- **Why it matters:** Many organizations assume "official" actions are safe with tag references. They are not. Tags are mutable pointers. The only immutable reference is a full SHA. Your unpinned detection counts pinned/total ratio but does not differentiate the risk level between first-party and third-party actions.
- **Already covered?** PARTIALLY. `classify_unpinned()` counts pinned vs unpinned, but treats `actions/checkout@v4` the same as `random-user/random-action@v1`. Could add severity differentiation.
- **Detection feasibility:** MODERATE. Could parse the org/owner prefix from `uses:` lines and categorize risk:
  - `actions/*` and `github/*` -- lower risk (but still flagged if not SHA-pinned)
  - Everything else -- higher risk if not SHA-pinned

---

**GAP 9: `if: always()` or `continue-on-error: true` combined with secret access**

- **What:** Steps that use `if: always()` or `continue-on-error: true` combined with secret access. These patterns ensure a step runs even when previous steps fail, which can be exploited to exfiltrate secrets after a "canary" step detects the attack and fails.
- **Why it matters:** An attacker who can trigger a workflow failure (e.g., by injecting a deliberately failing test) can bypass security gates if subsequent steps use `if: always()` and have access to secrets.
- **Already covered?** NO.
- **Detection feasibility:** MODERATE. Grep for:
  ```
  if:.*always()
  continue-on-error:\s*true
  ```
  Elevated concern when combined with `secrets.` access in the same job/step.

---

**GAP 10: `create` / `delete` / `deployment` / `deployment_status` triggers**

- **What:** Workflows triggered by `create`, `delete`, or similar events where `github.event.ref` (branch/tag name) is attacker-controlled and can be used for injection if interpolated into `run:` blocks.
- **Why it matters:** The `create` event fires when someone creates a branch or tag. The branch/tag name (`github.event.ref`) is fully attacker-controlled. If it appears in `${{ github.event.ref }}` inside a `run:` block, it's script injection. GitHub's own security hardening docs call this out.
- **Already covered?** PARTIALLY. Your expression injection detection checks `github.event.*` patterns, but `github.event.ref` is not in your dangerous pattern list (currently limited to `issue.title`, `issue.body`, `pull_request.title/body`, `comment.body`, `review.body`, `commits[`, `client_payload.`, `head_ref`, `inputs.`).
- **Detection feasibility:** EASY. Add to the existing `dangerous_pattern` regex in `classify_expr_injection()`:
  ```
  github\.event\.ref|github\.event\.pages\[\]\.page_name
  ```
  Also consider: `github.event.head_commit.message`, `github.event.head_commit.author.name`, `github.event.head_commit.author.email`, `github.event.discussion.title`, `github.event.discussion.body`.

---

### Priority 3 (LOW) -- Worth detecting but lower urgency or harder to grep

---

**GAP 11: Missing `environment:` protection for deployment workflows**

- **What:** Workflows that deploy (push to registries, cloud providers, etc.) without using GitHub Environment protection rules (required reviewers, branch restrictions).
- **Why it matters:** Environment protection rules are the only mechanism to require human approval before a workflow accesses production secrets. Without them, any workflow triggered by an automated event can deploy to production.
- **Already covered?** NO.
- **Detection feasibility:** HARD. Heuristic-based: grep for common deployment patterns (docker push, aws, gcloud, kubectl, terraform apply) and check for absence of `environment:` key. High false-positive risk, but could be informational.

---

**GAP 12: Typosquatting risk in action references**

- **What:** Actions referenced from organizations with names similar to official ones (e.g., `actons/checkout` instead of `actions/checkout`, `google-github-actons/` instead of `google-github-actions/`).
- **Why it matters:** Orca Security research demonstrated that typosquatted action organizations received real traffic. Attackers register look-alike org names and wait for developers to make typos.
- **Already covered?** NO.
- **Detection feasibility:** HARD. Would require maintaining a list of known-good action organizations and computing edit distance. Not practical for a grep-based tool. Could do a simpler check: flag any action from an org not in a known-good allowlist, but that would be very noisy.

---

**GAP 13: Cache poisoning vectors**

- **What:** Workflows that use `actions/cache` or have caching enabled (many actions like `actions/setup-node` cache implicitly) while also running on events that process untrusted code (PRs from forks).
- **Why it matters:** Adnan Khan's "Monsters in Your Build Cache" research showed that cache entries are shared across workflows and branches. A PR-triggered workflow that poisons a cache entry can affect the main branch build.
- **Already covered?** NO.
- **Detection feasibility:** MODERATE but noisy. Grep for `actions/cache` or `cache:` in workflows triggered by `pull_request` from forks. The problem is that many setups use implicit caching, making detection incomplete.

---

**GAP 14: Absence of StepSecurity harden-runner**

- **What:** Flag workflows that do NOT include `step-security/harden-runner` as the first step. Harden-runner provides runtime monitoring (network egress, file integrity, process tracking) and has detected real supply chain attacks including tj-actions and GhostAction.
- **Why it matters:** It is the only runtime defense mechanism for GitHub-hosted runners. It detected the tj-actions compromise in real-time for protected repositories.
- **Already covered?** NO.
- **Detection feasibility:** EASY. Grep for absence of `step-security/harden-runner` in workflow files. Could be a recommendation/informational finding rather than a critical alert:
  ```
  uses:.*step-security/harden-runner
  ```

---

**GAP 15: Long-lived credentials instead of OIDC**

- **What:** Workflows that use static cloud credentials (`AWS_ACCESS_KEY_ID`, `AZURE_CREDENTIALS`, `GCP_SA_KEY`, etc.) instead of OIDC federation (`id-token: write` + cloud provider OIDC configuration).
- **Why it matters:** GitHub's OIDC support provides short-lived, job-scoped tokens that expire when the job finishes. Static credentials in secrets can be exfiltrated and used indefinitely. Every major cloud provider supports GitHub OIDC federation.
- **Already covered?** PARTIALLY. You flag `id-token: write` as a dangerous permission, but it is actually a GOOD security practice (it enables OIDC). The presence of cloud credential secret names WITHOUT `id-token: write` is the actual risk indicator.
- **Detection feasibility:** MODERATE. Grep for common cloud credential secret name patterns:
  ```
  AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY
  AZURE_CREDENTIALS|AZURE_CLIENT_SECRET
  GCP_SA_KEY|GOOGLE_APPLICATION_CREDENTIALS
  ```
  Flag as "Consider OIDC" recommendation when these appear without `id-token: write`.

---

## SUMMARY TABLE

| # | Gap | Priority | Grep Feasibility | OWASP Risk |
|---|-----|----------|-----------------|------------|
| 1 | `GITHUB_ENV`/`GITHUB_PATH` injection | P1 HIGH | EASY | CICD-SEC-4 |
| 2 | `GITHUB_OUTPUT` injection | P1 HIGH | EASY | CICD-SEC-4 |
| 3 | `secrets: inherit` | P1 HIGH | TRIVIAL | CICD-SEC-6 |
| 4 | Deprecated workflow commands | P1 HIGH | EASY | CICD-SEC-4 |
| 5 | Known-vulnerable action blocklist | P1 HIGH | EASY | CICD-SEC-3 |
| 6 | Untrusted ref checkout in PRT | P2 MED | MODERATE | CICD-SEC-4 |
| 7 | Artifact trust boundary | P2 MED | MODERATE | CICD-SEC-4 |
| 8 | First-party vs third-party unpinned risk | P2 MED | MODERATE | CICD-SEC-3 |
| 9 | `if: always()` + secrets | P2 MED | MODERATE | CICD-SEC-4 |
| 10 | Missing dangerous expression contexts | P2 MED | EASY | CICD-SEC-4 |
| 11 | Missing environment protection | P3 LOW | HARD | CICD-SEC-1 |
| 12 | Typosquatting | P3 LOW | HARD | CICD-SEC-3 |
| 13 | Cache poisoning | P3 LOW | MODERATE | CICD-SEC-4 |
| 14 | Absence of harden-runner | P3 LOW | EASY | Defense-in-depth |
| 15 | Static creds instead of OIDC | P3 LOW | MODERATE | CICD-SEC-6 |

## EXISTING DETECTION ENHANCEMENT: `id-token: write`

One note on your existing `classify_dangerous_perms()`: you currently flag `id-token: write` as dangerous. This is a nuanced case. `id-token: write` does NOT grant write access to anything in the repository -- it only allows the workflow to request an OIDC JWT from GitHub's OIDC provider. This is actually a security BEST PRACTICE for cloud authentication. You might want to reclassify it as informational/neutral rather than dangerous, or at minimum add a note that it indicates OIDC usage (which is good).

## TOP 5 RECOMMENDATIONS FOR IMMEDIATE IMPLEMENTATION

Based on impact, attack frequency, and implementation effort:

1. **`secrets: inherit`** -- One-line grep, high impact, zero false positives
2. **Expand `classify_expr_injection()` dangerous patterns** -- Add `github.event.ref`, `github.event.head_commit.message`, `github.event.head_commit.author.name`, `github.event.discussion.title`, `github.event.discussion.body`, `github.event.pages[].page_name` to the existing regex
3. **`GITHUB_ENV`/`GITHUB_PATH`/`GITHUB_OUTPUT` injection** -- New classifier, simple grep, catches a major real-world attack class
4. **Known-vulnerable action blocklist** -- Small hardcoded list, catches the biggest supply chain incident of 2025
5. **Deprecated workflow commands** -- Simple string matching, catches an entire class of injection vulnerabilities

These five additions would significantly expand coverage with minimal implementation complexity, all fitting your existing grep-based heuristic architecture.

---

## Sources

- [GitHub Docs: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [GitHub Docs: Script injections](https://docs.github.com/en/actions/concepts/security/script-injections)
- [GitHub Docs: Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub Docs: OpenID Connect](https://docs.github.com/en/actions/concepts/security/openid-connect)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [OWASP CICD-SEC-4: Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution)
- [StepSecurity: GitHub Actions Security Best Practices](https://www.stepsecurity.io/blog/github-actions-security-best-practices)
- [StepSecurity: Harden-Runner](https://github.com/step-security/harden-runner)
- [GitGuardian: GitHub Actions Security Cheat Sheet](https://blog.gitguardian.com/github-actions-security-cheat-sheet/)
- [GitGuardian: GhostAction Campaign - 3,325 Secrets Stolen](https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/)
- [Palo Alto Unit 42: GitHub Actions Supply Chain Attack (tj-actions)](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/)
- [Palo Alto Unit 42: ArtiPACKED - GitHub Actions Artifacts Leak Tokens](https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/)
- [CISA: Supply Chain Compromise of tj-actions/changed-files and reviewdog/action-setup](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)
- [Wiz: GitHub Action tj-actions/changed-files Supply Chain Attack](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)
- [Wiz: Hardening GitHub Actions - Lessons from Recent Attacks](https://www.wiz.io/blog/github-actions-security-guide)
- [Orca Security: Typosquatting in GitHub Actions](https://orca.security/resources/blog/typosquatting-in-github-actions/)
- [Orca Security: GitHub Actions Security - Common Risks](https://orca.security/resources/blog/github-actions-security-risks/)
- [Dark Reading: Supply Chain Attacks Targeting GitHub Actions Increased in 2025](https://www.darkreading.com/application-security/supply-chain-attacks-targeting-github-actions-increased-in-2025)
- [Legit Security: GitHub Privilege Escalation - GITHUB_ENV Injection](https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability-0)
- [Legit Security: Artifact Poisoning in Rust](https://www.legitsecurity.com/blog/artifact-poisoning-vulnerability-discovered-in-rust)
- [Synacktiv: GitHub Actions Exploitation - Repo Jacking and Environment Manipulation](https://www.synacktiv.com/en/publications/github-actions-exploitation-repo-jacking-and-environment-manipulation)
- [GitHub Security Lab: New Vulnerability Patterns and Mitigations](https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/)
- [GitHub Blog: Four Tips to Keep Your GitHub Actions Workflows Secure](https://github.blog/security/supply-chain-security/four-tips-to-keep-your-github-actions-workflows-secure/)
- [Adnan Khan: Monsters in Your Build Cache - GitHub Actions Cache Poisoning](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/)
- [OpenSSF: Mitigating Attack Vectors in GitHub Workflows](https://openssf.org/blog/2024/08/12/mitigating-attack-vectors-in-github-workflows/)
- [Salesforce Engineering: GitHub Actions Security Best Practices](https://engineering.salesforce.com/github-actions-security-best-practices-b8f9df5c75f5/)
- [Arctiq: Top 10 GitHub Actions Security Pitfalls](https://arctiq.com/blog/top-10-github-actions-security-pitfalls-the-ultimate-guide-to-bulletproof-workflows/)
- [Sysdig: CVE-2025-53104 Command Injection via GITHUB_OUTPUT](https://www.sysdig.com/blog/cve-2025-53104-command-injection-via-github-actions-workflow-in-gluestack-ui)
- [Ken Muse: GitHub Actions Injection Attacks](https://www.kenmuse.com/blog/github-actions-injection-attacks/)
