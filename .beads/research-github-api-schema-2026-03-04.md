# GitHub REST API Schema Verification

Findings for each of the five GitHub REST API endpoints used by our security audit tool.

---

## Endpoint 1: `GET /orgs/{org}/actions/permissions/workflow`

**Our usage** (line 851 of `gh-actions-audit.sh`):
```bash
wf_perms_response=$(gh api "orgs/$ORG/actions/permissions/workflow" \
  --jq '(.default_workflow_permissions // "unknown") + "|" + ((.can_approve_pull_request_reviews // "unknown") | tostring)' 2>/dev/null)
```

**Confirmed response fields:**
| Field | Type | Confirmed | Notes |
|---|---|---|---|
| `default_workflow_permissions` | string (`"read"` or `"write"`) | YES | We use this correctly |
| `can_approve_pull_request_reviews` | boolean | YES | We use this correctly |

**Additional useful fields:** None -- this is a minimal two-field response. No additional fields exist.

**Deprecations:** None found. This endpoint is stable.

**Verdict: CORRECT. No changes needed.**

---

## Endpoint 2: `GET /orgs/{org}/actions/permissions`

**Our usage** (line 858):
```bash
allowed_actions=$(gh api "orgs/$ORG/actions/permissions" --jq '.allowed_actions // "unknown"' 2>/dev/null)
```

**Confirmed response fields:**
| Field | Type | Confirmed | Notes |
|---|---|---|---|
| `enabled_repositories` | string (`"all"`, `"none"`, `"selected"`) | YES (not used by us) | Could be useful to report |
| `allowed_actions` | string (`"all"`, `"local_only"`, `"selected"`) | YES | We use this correctly |
| `selected_actions_url` | string (URL) | YES (not used by us) | Only present when `allowed_actions` is `"selected"` |
| `sha_pinning_required` | boolean | **NEW -- not used by us** | Added August 2025 per [GitHub Changelog](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/). Indicates whether the org enforces SHA pinning for action references |

**Missing from our tool:**
1. **`enabled_repositories`** -- We don't report whether the org restricts which repos can use Actions. This is a meaningful security setting (an org set to `"all"` lets every repo run workflows).
2. **`sha_pinning_required`** -- This is a **new field** (August 2025). It directly relates to our `classify_unpinned()` detection. If the org enforces SHA pinning at the policy level, our per-repo unpinned-action findings become less critical (the org has a backstop). We should consider reporting this.

**Deprecations:** None found.

**Verdict: CORRECT for what we use, but we are missing two fields that are relevant to our security audit (`enabled_repositories` and `sha_pinning_required`).**

---

## Endpoint 3: `GET /orgs/{org}/actions/secrets`

**Our usage** (line 776):
```bash
org_secrets=$(gh api "orgs/$ORG/actions/secrets" --paginate --jq '.secrets[] | "\(.name)|\(.visibility)"' 2>/dev/null)
```

**Confirmed response fields:**
| Field | Type | Confirmed | Notes |
|---|---|---|---|
| `total_count` | integer | YES (not used by us) | Top-level field |
| `secrets` | array | YES | We iterate this |
| `secrets[].name` | string | YES | We use this correctly |
| `secrets[].visibility` | string (`"all"`, `"private"`, `"selected"`) | YES | We use this correctly |
| `secrets[].created_at` | string (ISO 8601) | YES (not used by us) | Could be useful for audit age analysis |
| `secrets[].updated_at` | string (ISO 8601) | YES (not used by us) | Could flag stale secrets |
| `secrets[].selected_repositories_url` | string (URL) | YES (not used by us) | Alternative to our separate API call for `selected` visibility |

**Missing from our tool:**
1. **`created_at` / `updated_at`** -- Not critical, but could add value to the report by flagging secrets that haven't been rotated recently.
2. **`selected_repositories_url`** -- We already make a separate API call to `orgs/$ORG/actions/secrets/$secret_name/repositories` for secrets with `selected` visibility. We could instead follow this URL, but functionally it is equivalent.

**Deprecations:** None found.

**Verdict: CORRECT. Our jq extraction of `.name` and `.visibility` matches the documented schema perfectly.**

---

## Endpoint 4: `GET /orgs/{org}/actions/secrets/{secret_name}/repositories`

**Our usage** (line 813):
```bash
configured_repos=$(gh api "orgs/$ORG/actions/secrets/$secret_name/repositories" \
  --jq '.repositories[].name' 2>/dev/null | sort | paste -sd',' -)
```

**Confirmed response fields:**
| Field | Type | Confirmed | Notes |
|---|---|---|---|
| `total_count` | integer | YES (not used by us) | Top-level field |
| `repositories` | array | YES | We iterate this |
| `repositories[].id` | integer | YES (not used by us) | |
| `repositories[].node_id` | string | YES (not used by us) | |
| `repositories[].name` | string | YES | **We use this** |
| `repositories[].full_name` | string | YES (not used by us) | e.g. `"octocat/Hello-World"` |
| `repositories[].owner` | object | YES (not used by us) | Full owner/org object |
| (plus other standard repo fields) | various | YES | `private`, `html_url`, etc. |

**Missing from our tool:** Nothing significant. We correctly extract `.repositories[].name` which gives us the short repo name, which is all we need since we already know the org.

**Deprecations:** None found.

**Verdict: CORRECT. No changes needed.**

---

## Endpoint 5: `GET /repos/{owner}/{repo}/actions/secrets`

**Our usage** (line 735):
```bash
secret_names=$(gh api "repos/$ORG/$repo/actions/secrets" --jq '.secrets[].name' 2>/dev/null)
```

**Confirmed response fields:**
| Field | Type | Confirmed | Notes |
|---|---|---|---|
| `total_count` | integer | YES (not used by us) | Top-level field |
| `secrets` | array | YES | We iterate this |
| `secrets[].name` | string | YES | **We use this** |
| `secrets[].created_at` | string (ISO 8601) | YES (not used by us) | |
| `secrets[].updated_at` | string (ISO 8601) | YES (not used by us) | |

**Important note:** Repo-level secrets do **NOT** have a `visibility` field (unlike org-level secrets). This is expected -- visibility is an org-level concept where secrets can be scoped to all repos, private repos, or selected repos. Repo-level secrets are inherently scoped to just that one repo. Our code correctly does not try to extract a `visibility` field here.

**Deprecations:** None found.

**Verdict: CORRECT. No changes needed.**

---

## Summary

| Endpoint | Fields Used Correctly? | Missing Useful Fields | Deprecations |
|---|---|---|---|
| `GET /orgs/{org}/actions/permissions/workflow` | YES | None | None |
| `GET /orgs/{org}/actions/permissions` | YES | `enabled_repositories`, `sha_pinning_required` (new Aug 2025) | None |
| `GET /orgs/{org}/actions/secrets` | YES | `created_at`, `updated_at` (for rotation age) | None |
| `GET /orgs/{org}/actions/secrets/{name}/repositories` | YES | None | None |
| `GET /repos/{owner}/{repo}/actions/secrets` | YES | `created_at`, `updated_at` (minor) | None |

### Actionable Findings

1. **`sha_pinning_required`** (Priority: HIGH) -- This new boolean field on `GET /orgs/{org}/actions/permissions` was added in August 2025. It reports whether the org enforces SHA pinning for action references at the policy level. This is directly relevant to our `classify_unpinned()` detection. We should fetch and report it in the Phase 4 org settings section. Since we already call this endpoint, it would be a single `--jq` change.

2. **`enabled_repositories`** (Priority: MEDIUM) -- From the same `GET /orgs/{org}/actions/permissions` endpoint. Reports whether Actions is enabled for `"all"`, `"none"`, or `"selected"` repositories. An org with `"all"` has a broader attack surface than one limiting Actions to selected repos. We already call this endpoint, so this is free to add.

3. **Secret rotation age** (Priority: LOW) -- `created_at`/`updated_at` on org and repo secrets could flag stale secrets that haven't been rotated. Nice-to-have, not critical.

### Sources

- [REST API endpoints for GitHub Actions permissions - GitHub Docs](https://docs.github.com/en/rest/actions/permissions)
- [REST API endpoints for GitHub Actions Secrets - GitHub Docs](https://docs.github.com/en/rest/actions/secrets)
- [GitHub Actions policy now supports blocking and SHA pinning actions - GitHub Changelog (August 2025)](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/)
- [GitHub REST API Description (OpenAPI spec)](https://github.com/github/rest-api-description)
- [REST API endpoints for GitHub Actions permissions - Enterprise Cloud Docs](https://docs.github.com/en/enterprise-cloud@latest/rest/actions/permissions)
