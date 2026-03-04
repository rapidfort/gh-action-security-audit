#!/usr/bin/env bash
#
# gh-actions-audit.sh — GitHub Actions Security Audit Report
#
# Scans a GitHub org's workflows for CI/CD security posture and generates
# a report flagging configurations that warrant review, based on attack
# patterns from the hackerbot-claw campaign (Feb 2026) and related supply
# chain exploits (tj-actions, Ultralytics YOLO, Coinbase/SpotBugs).
#
# The report covers:
#   - Org-level default workflow token permissions
#   - Per-repo: explicit permissions blocks, pull_request_target usage,
#     issue_comment triggers, and configured secrets
#   - Org-level secrets and their visibility (all repos, private, selected)
#
# Usage:
#   ./gh-actions-audit.sh <ORG> [OPTIONS]
#
# Arguments:
#   ORG              GitHub organization name to audit (required)
#
# Options:
#   --local DIR      Reuse previously downloaded workflow files from DIR
#                    instead of fetching them from the GitHub API. Accepts
#                    either the top-level audit directory or its workflows/
#                    subdirectory. API calls for secrets and org settings
#                    still require gh authentication.
#
#   --out FILE       Path for the markdown report output.
#                    Default: ./<ORG>-actions-audit.md
#
#   --csv FILE       Path for the CSV report output. Contains two tables
#                    (per-repo audit and org-level secrets) separated by a
#                    blank row. Omit this flag to skip CSV generation.
#
#   --cleanup        Delete cached workflow files after the run completes.
#                    By default the script keeps them for reuse with --local.
#
#   -h, --help       Show this help message and exit.
#
# Authentication:
#   This script requires the gh CLI authenticated as an ADMIN of the target
#   org. Specifically:
#     - Reading workflow permissions: requires admin:org scope
#     - Listing repo secrets: requires repo admin access
#     - Listing/modifying org secrets: requires admin:org scope

#   Run 'gh auth login' before using this script. You can verify your access
#   with 'gh api orgs/<ORG>/actions/permissions'.
#
# Examples:
#   # Full scan of an org (downloads all workflows, writes markdown):
#   ./gh-actions-audit.sh my-org
#
#   # Reuse a previous download, output both markdown and CSV:
#   ./gh-actions-audit.sh my-org --local /tmp/gh-actions-audit-my-org-20260301 \
#     --out my-org-audit.md --csv my-org-audit.csv
#
#   # Scan and write results to a specific directory:
#   ./gh-actions-audit.sh my-org --out reports/my-org.md --csv reports/my-org.csv

set -euo pipefail

# --- Cleanup on exit ---------------------------------------------------------

cleanup() {
  rm -f "${TABLE_ROWS:-}" "${TABLE_ROWS_CSV:-}" "${ORG_SECRETS_FILE:-}"
}
trap cleanup EXIT

# --- Argument Parsing --------------------------------------------------------

LOCAL_DIR=""
ORG=""
OUT_FILE=""
CSV_FILE=""
CLEANUP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local)
      if [ -z "${2:-}" ] || [[ "$2" == -* ]]; then
        echo "Error: --local requires a directory path." >&2
        echo "Usage: $0 <ORG> --local /path/to/previous/audit/dir" >&2
        exit 1
      fi
      LOCAL_DIR="$2"
      shift 2
      ;;
    --out)
      if [ -z "${2:-}" ] || [[ "$2" == -* ]]; then
        echo "Error: --out requires a filename." >&2
        echo "Usage: $0 <ORG> --out report.md" >&2
        exit 1
      fi
      OUT_FILE="$2"
      shift 2
      ;;
    --csv)
      if [ -z "${2:-}" ] || [[ "$2" == -* ]]; then
        echo "Error: --csv requires a filename." >&2
        echo "Usage: $0 <ORG> --csv report.csv" >&2
        exit 1
      fi
      CSV_FILE="$2"
      shift 2
      ;;
    --cleanup)
      CLEANUP=1
      shift
      ;;
    -h | --help)
      # Print comment block from line 2 until the first non-comment line
      awk 'NR==1{next} /^[^#]/{exit} {sub(/^# ?/,""); print}' "$0"
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *)
      if [ -z "$ORG" ]; then
        ORG="$1"
      else
        echo "Only one org at a time. Got '$1' after '$ORG'." >&2
        exit 1
      fi
      shift
      ;;
  esac
done

if [ -z "$ORG" ]; then
  echo "Usage: $0 <ORG> [--local DIR] [--out FILE]" >&2
  exit 1
fi

if ! [[ $ORG =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Invalid org name: '$ORG'. GitHub org names may only contain [a-zA-Z0-9_-]." >&2
  exit 1
fi

# --- Configuration -----------------------------------------------------------

if [ -n "$LOCAL_DIR" ]; then
  if [ -d "$LOCAL_DIR/workflows" ]; then
    WORKFLOWS_DIR="$LOCAL_DIR/workflows"
  elif [ -d "$LOCAL_DIR" ]; then
    WORKFLOWS_DIR="$LOCAL_DIR"
  else
    echo "Error: --local directory does not exist: $LOCAL_DIR" >&2
    exit 1
  fi
  AUDIT_DIR="$(dirname "$WORKFLOWS_DIR")"
else
  AUDIT_DIR=$(mktemp -d "/tmp/gh-actions-audit-${ORG}-XXXXXX")
  WORKFLOWS_DIR="$AUDIT_DIR/workflows"
  mkdir -p "$WORKFLOWS_DIR"
fi

: "${OUT_FILE:=./${ORG}-actions-audit.md}"

# ANSI colors (disabled if not a terminal)
if [ -t 1 ]; then
  RED='\033[0;31m'
  YELLOW='\033[1;33m'
  GREEN='\033[0;32m'
  CYAN='\033[0;36m'
  DIM='\033[2m'
  RESET='\033[0m'
else
  RED=''
  YELLOW=''
  GREEN=''
  CYAN=''
  DIM=''
  RESET=''
fi

info() { printf "${CYAN}[INFO]${RESET}  %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${RESET}  %s\n" "$*"; }
crit() { printf "${RED}[CRIT]${RESET}  %s\n" "$*"; }
ok() { printf "${GREEN}[ OK ]${RESET}  %s\n" "$*"; }
progress() { printf "${DIM}  ... %s${RESET}\r" "$*"; }

# --- Preflight ---------------------------------------------------------------

info "Org: $ORG"
info "Report output: $OUT_FILE"

if ! command -v gh &>/dev/null; then
  crit "'gh' CLI not found. Install from https://cli.github.com/"
  exit 1
fi

if ! gh auth status &>/dev/null; then
  crit "'gh' is not authenticated. Run 'gh auth login' first."
  exit 1
fi

# Detect portable base64 decode flag (GNU: -d, macOS: -D)
if echo "dGVzdA==" | base64 --decode &>/dev/null; then
  BASE64_DECODE=(base64 --decode)
elif echo "dGVzdA==" | base64 -d &>/dev/null; then
  BASE64_DECODE=(base64 -d)
elif echo "dGVzdA==" | base64 -D &>/dev/null; then
  BASE64_DECODE=(base64 -D)
else
  crit "No working base64 decode flag found."
  exit 1
fi

AUTHED_USER=$(gh api user --jq '.login' 2>/dev/null) || {
  warn "Could not determine authenticated user."
  AUTHED_USER="unknown"
}
info "Authenticated as: $AUTHED_USER"

# =============================================================================
# PHASE 1: Download workflows (unless --local)
# =============================================================================

if [ -n "$LOCAL_DIR" ]; then
  wf_count=$(find "$WORKFLOWS_DIR" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | wc -l | tr -d ' ')
  info "Using $wf_count local workflow files from $WORKFLOWS_DIR"

  # Discover which repos are present locally
  REPOS=()
  for d in "$WORKFLOWS_DIR/$ORG"/*/; do
    [ -d "$d" ] || continue
    repo_name=$(basename "$d")
    REPOS+=("$repo_name")
  done
  info "Found ${#REPOS[@]} repos in local data"
else
  info "Enumerating non-archived repos with workflows..."

  # Get all non-archived repos
  all_repos=$(gh repo list "$ORG" --limit 1000 --no-archived --json name --jq '.[].name' 2>/dev/null)
  total_repos=$(echo "$all_repos" | grep -c . || echo 0)

  if [ "$total_repos" -ge 1000 ]; then
    warn "Repo list hit 1000 limit — some repos may be missing from the audit."
  fi

  info "Found $total_repos non-archived repos. Downloading workflows..."

  REPOS=()
  downloaded=0
  skipped_no_wf=0

  while IFS= read -r repo; do
    [ -z "$repo" ] && continue
    progress "$repo ($downloaded downloaded, $skipped_no_wf skipped)"

    wf_list=$(gh api "repos/$ORG/$repo/contents/.github/workflows" --jq '.[].name' 2>/dev/null || true)

    if [ -z "$wf_list" ]; then
      skipped_no_wf=$((skipped_no_wf + 1))
      continue
    fi

    repo_dir="$WORKFLOWS_DIR/$ORG/$repo"
    mkdir -p "$repo_dir"

    while IFS= read -r wf; do
      [ -z "$wf" ] && continue
      content=$(gh api "repos/$ORG/$repo/contents/.github/workflows/$wf" --jq '.content' 2>/dev/null || true)
      if [ -n "$content" ]; then
        echo "$content" | "${BASE64_DECODE[@]}" >"$repo_dir/$wf" 2>/dev/null || true
        downloaded=$((downloaded + 1))
      fi
    done <<<"$wf_list"

    REPOS+=("$repo")
    sleep 0.1
  done <<<"$all_repos"

  printf "%-80s\n" " " # clear progress line
  info "Downloaded $downloaded workflow files from ${#REPOS[@]} repos ($skipped_no_wf repos had no workflows)"
fi

# =============================================================================
# PHASE 2: Analyze workflows per-repo
# =============================================================================

info "Analyzing workflows..."

# --- analyze_repo: analyze a single repo's workflow files ---
# Outputs two lines to stdout: markdown row, then csv row (pipe-delimited)
# Globals: ORG, WORKFLOWS_DIR
analyze_repo() {
  local repo="$1"
  local repo_dir="$2"

  local wf_files=()
  while IFS= read -r f; do
    wf_files+=("$f")
  done < <(find "$repo_dir" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null)

  [ ${#wf_files[@]} -eq 0 ] && return 1

  local total_wf=${#wf_files[@]}
  local wf_with_perms=0
  local prt_wfs=()
  local prt_wfs_csv=()
  local ic_wfs=()
  local ic_wfs_csv=()

  local f wf_name wf_content wf_uncommented
  local has_checkout has_fork_ref has_author_guard is_dependabot
  local dep_tag detail detail_csv

  for f in "${wf_files[@]}"; do
    wf_name=$(basename "$f")
    wf_content=$(cat "$f" 2>/dev/null) || continue
    wf_uncommented=$(echo "$wf_content" | grep -v '^\s*#')

    # --- Permissions ---
    if echo "$wf_uncommented" | grep -q 'permissions:'; then
      wf_with_perms=$((wf_with_perms + 1))
    fi

    # --- pull_request_target ---
    if [[ $wf_content == *pull_request_target* ]]; then
      has_checkout=0
      has_fork_ref=0
      has_author_guard=0
      is_dependabot=0

      [[ $wf_content == *actions/checkout* ]] && has_checkout=1
      echo "$wf_content" | grep -qE 'github\.head_ref|pull_request\.head\.(sha|ref|repo\.full_name)' && has_fork_ref=1
      echo "$wf_content" | grep -qE "(user\.login|github\.actor)\s*==\s*['\"]dependabot" && is_dependabot=1
      echo "$wf_content" | grep -qE "(user\.login|github\.actor)\s*==\s*['\"](dependabot|github-actions|renovate)" && has_author_guard=1
      echo "$wf_uncommented" | grep -q 'author_association' && has_author_guard=1

      dep_tag=""
      [ "$is_dependabot" = "1" ] && dep_tag=" (Dependabot)"

      if [ "$has_fork_ref" = "1" ] && [ "$has_author_guard" = "0" ]; then
        detail="$wf_name$dep_tag (**checkout+exec, no guard**)"
        detail_csv="$wf_name$dep_tag (checkout+exec; no guard)"
      elif [ "$has_fork_ref" = "1" ] && [ "$has_author_guard" = "1" ]; then
        detail="$wf_name$dep_tag (checkout, has guard)"
        detail_csv="$wf_name$dep_tag (checkout; has guard)"
      elif [ "$has_checkout" = "1" ]; then
        detail="$wf_name$dep_tag (checkout, no fork ref)"
        detail_csv="$wf_name$dep_tag (checkout; no fork ref)"
      else
        detail="$wf_name$dep_tag (API-only)"
        detail_csv="$wf_name$dep_tag (API-only)"
      fi

      prt_wfs+=("$detail")
      prt_wfs_csv+=("$detail_csv")
    fi

    # --- issue_comment ---
    if [[ $wf_content == *issue_comment* ]]; then
      if echo "$wf_uncommented" | grep -q 'author_association'; then
        ic_wfs+=("$wf_name (has author_association)")
        ic_wfs_csv+=("$wf_name (has author_association)")
      elif echo "$wf_content" | grep -qE "user\.login\s*==|actor\s*=="; then
        ic_wfs+=("$wf_name (has actor check)")
        ic_wfs_csv+=("$wf_name (has actor check)")
      else
        ic_wfs+=("$wf_name (**no author gate**)")
        ic_wfs_csv+=("$wf_name (no author gate)")
      fi
    fi
  done

  # --- Build cells ---
  local perms_cell perms_csv
  if [ "$wf_with_perms" -eq "$total_wf" ]; then
    perms_cell="All ($total_wf/$total_wf)"
    perms_csv="All ($total_wf/$total_wf)"
  elif [ "$wf_with_perms" -eq 0 ]; then
    perms_cell="**None** (0/$total_wf)"
    perms_csv="None (0/$total_wf)"
  else
    perms_cell="Partial ($wf_with_perms/$total_wf)"
    perms_csv="Partial ($wf_with_perms/$total_wf)"
  fi

  local prt_cell prt_csv
  if [ ${#prt_wfs[@]} -eq 0 ]; then
    prt_cell="No"
    prt_csv="No"
  else
    prt_cell=$(printf '%s' "${prt_wfs[0]}")
    prt_csv=$(printf '%s' "${prt_wfs_csv[0]}")
    local i
    for ((i = 1; i < ${#prt_wfs[@]}; i++)); do
      prt_cell+=$(printf '<br/>%s' "${prt_wfs[$i]}")
      prt_csv+=$(printf '; %s' "${prt_wfs_csv[$i]}")
    done
  fi

  local ic_cell ic_csv
  if [ ${#ic_wfs[@]} -eq 0 ]; then
    ic_cell="No"
    ic_csv="No"
  else
    ic_cell=$(printf '%s' "${ic_wfs[0]}")
    ic_csv=$(printf '%s' "${ic_wfs_csv[0]}")
    local i
    for ((i = 1; i < ${#ic_wfs[@]}; i++)); do
      ic_cell+=$(printf '<br/>%s' "${ic_wfs[$i]}")
      ic_csv+=$(printf '; %s' "${ic_wfs_csv[$i]}")
    done
  fi

  local secrets_cell=""
  local secret_names
  secret_names=$(gh api "repos/$ORG/$repo/actions/secrets" --jq '.secrets[].name' 2>/dev/null) || {
    warn "Could not fetch secrets for $repo (may lack repo admin access)."
    secret_names=""
  }
  if [ -z "$secret_names" ]; then
    secrets_cell="(none)"
  else
    secrets_cell=$(echo "$secret_names" | paste -sd', ' -)
  fi

  # Output: markdown row, then csv row
  echo "${repo}|${perms_cell}|${prt_cell}|${ic_cell}|${secrets_cell}"
  echo "${repo}|${perms_csv}|${prt_csv}|${ic_csv}|${secrets_cell}"
}

# Temp files to accumulate table rows
TABLE_ROWS=$(mktemp)
TABLE_ROWS_CSV=$(mktemp)

for repo in "${REPOS[@]}"; do
  repo_dir="$WORKFLOWS_DIR/$ORG/$repo"
  [ -d "$repo_dir" ] || continue

  result=$(analyze_repo "$repo" "$repo_dir") || continue

  # First line is markdown, second is csv
  echo "$result" | head -1 >>"$TABLE_ROWS"
  echo "$result" | tail -1 >>"$TABLE_ROWS_CSV"
  progress "$repo"
done

printf "%-80s\n" " " # clear progress line
info "Workflow analysis complete."

# =============================================================================
# PHASE 3: Org-level secrets (with workflow usage mapping)
# =============================================================================

info "Fetching org-level secrets..."

# Format: SECRET_NAME|visibility_display|configured_repos|referenced_repos
# configured_repos = repos the secret is configured to be visible to
# referenced_repos = repos whose workflows actually reference secrets.SECRET_NAME
ORG_SECRETS_FILE=$(mktemp)

org_secrets=$(gh api "orgs/$ORG/actions/secrets" --paginate --jq '.secrets[] | "\(.name)|\(.visibility)"' 2>/dev/null) || {
  warn "Could not fetch org secrets (check admin:org scope). Skipping org secret analysis."
  org_secrets=""
}

if [ -n "$org_secrets" ]; then
  while IFS='|' read -r secret_name visibility; do
    progress "secret: $secret_name"

    # Determine configured repo access
    case "$visibility" in
      all)
        vis_display="All repositories"
        configured_repos="(all)"
        ;;
      private)
        vis_display="Private repositories only"
        configured_repos="(all private)"
        ;;
      selected)
        vis_display="Selected"
        configured_repos=$(gh api "orgs/$ORG/actions/secrets/$secret_name/repositories" \
          --jq '.repositories[].name' 2>/dev/null | sort | paste -sd',' - || echo "(could not read)")
        ;;
      *)
        vis_display="$visibility"
        configured_repos="(unknown)"
        ;;
    esac

    # Grep all downloaded workflows for references to this secret
    # Use word boundary to prevent partial matching (e.g., FOO matching FOOBAR)
    referenced_repos=$(grep -rlE "secrets\.$secret_name([^a-zA-Z0-9_]|$)" "$WORKFLOWS_DIR" 2>/dev/null \
      | sed "s|$WORKFLOWS_DIR/$ORG/||" \
      | cut -d/ -f1 \
      | sort -u \
      | paste -sd',' - || true)
    [ -z "$referenced_repos" ] && referenced_repos="(none)"

    echo "${secret_name}|${vis_display}|${configured_repos}|${referenced_repos}" >>"$ORG_SECRETS_FILE"
  done <<<"$org_secrets"
fi

printf "%-80s\n" " " # clear progress line
info "Org secrets enumeration complete."

# =============================================================================
# PHASE 4: Org-level settings
# =============================================================================

info "Fetching org-level Actions settings..."

default_wf_perm=$(gh api "orgs/$ORG/actions/permissions/workflow" --jq '.default_workflow_permissions // "unknown"' 2>/dev/null) || {
  warn "Could not fetch org workflow permissions (check admin:org scope)."
  default_wf_perm="unknown"
}
can_approve_prs=$(gh api "orgs/$ORG/actions/permissions/workflow" --jq '.can_approve_pull_request_reviews // "unknown"' 2>/dev/null) || {
  warn "Could not fetch org PR approval setting (check admin:org scope)."
  can_approve_prs="unknown"
}
allowed_actions=$(gh api "orgs/$ORG/actions/permissions" --jq '.allowed_actions // "unknown"' 2>/dev/null) || {
  warn "Could not fetch org actions permissions (check admin:org scope)."
  allowed_actions="unknown"
}

# =============================================================================
# PHASE 5: Write the report
# =============================================================================

info "Writing report to $OUT_FILE..."

cat >"$OUT_FILE" <<EOF
# GitHub Actions Security Audit: \`$ORG\`

**Date:** $(date -u '+%Y-%m-%d %H:%M UTC')
**Auditor:** $AUTHED_USER
**Scope:** All non-archived repos with GitHub Actions workflows in the \`$ORG\` org

> **Note:** This report flags configurations that warrant review. The presence
> of a flag does not necessarily indicate a vulnerability — individual workflows
> may have mitigations (author guards, environment protections, etc.) that
> reduce or eliminate risk. Each flag should be reviewed in context.

## Org-Level Settings

| Setting | Value | Recommendation |
|---------|-------|----------------|
EOF

{
  # Default workflow permissions
  if [ "$default_wf_perm" = "write" ]; then
    echo "| Default workflow permissions | \`write\` | Set to \`read\`. Workflows needing write access should declare explicit \`permissions:\` blocks. |"
  elif [ "$default_wf_perm" = "read" ]; then
    echo "| Default workflow permissions | \`read\` | No action needed. |"
  else
    echo "| Default workflow permissions | \`$default_wf_perm\` | Could not determine (may need admin scope). |"
  fi

  # Can approve PRs
  if [ "$can_approve_prs" = "True" ] || [ "$can_approve_prs" = "true" ]; then
    echo "| Workflows can approve PRs | Yes | Consider disabling unless required. |"
  else
    echo "| Workflows can approve PRs | No | No action needed. |"
  fi

  # Allowed actions
  case "$allowed_actions" in
    all) echo "| Allowed actions | All | Consider restricting to verified creators or a selected list. |" ;;
    selected) echo "| Allowed actions | Selected | No action needed. |" ;;
    *) echo "| Allowed actions | \`$allowed_actions\` | — |" ;;
  esac

  # --- Per-repo table ---

  cat <<'PERREPO'

## Per-Repository Audit

Columns:
- **Permissions**: How many workflow files in the repo have explicit `permissions:` blocks.
  Workflows without one inherit the org default.
- **`pull_request_target`**: Whether any workflow uses this trigger. Sub-classifications:
  - **(API-only)** — no code checkout; used for labeling, auto-merge, etc. Low risk.
  - **(checkout, has guard)** — checks out fork code but gates on author (e.g. `dependabot[bot]`). Review the guard.
  - **(checkout+exec, no guard)** — checks out and runs fork code with no author restriction. **Highest risk.**
  - **(checkout, no fork ref)** — has `actions/checkout` but doesn't explicitly ref the fork head. Review.
  - Workflows gated to run only for `dependabot[bot]` are tagged **(Dependabot)**.
- **`issue_comment`**: Whether any workflow triggers on issue/PR comments. Notes whether an
  `author_association` or actor check is present. Without one, any GitHub user can trigger the workflow.
- **Repo Secrets**: Secret names configured directly on the repo (not values). These are accessible
  to any workflow that runs in the repo, including exploited `pull_request_target` workflows.

PERREPO

  echo "| Repository | Permissions | \`pull_request_target\` | \`issue_comment\` | Repo Secrets |"
  echo "|------------|-------------|----------------------|-----------------|--------------|"

  sort "$TABLE_ROWS" | while IFS='|' read -r repo perms prt ic secrets; do
    echo "| \`$repo\` | $perms | $prt | $ic | $secrets |"
  done

  # --- Org secrets section ---

  cat <<'ORGSECRETS'

## Org-Level Secrets

Organization secrets are shared across repos based on their visibility setting.
Secrets with **All repositories** visibility are accessible from any repo in the org,
including repos exploitable via `pull_request_target` pwn requests.

Columns:
- **Visibility**: The configured access scope (`All repositories`, `Private repositories only`, or `Selected`)
- **Configured Access**: Which repos can currently access this secret
- **Referenced In Workflows**: Which repos actually use `secrets.SECRET_NAME` in their workflow files.
  Repos in the "Configured Access" column but NOT in this column have access to a secret they don't use.
- **Suggested Command**: For `All repositories` secrets, a `gh secret set` command to restrict the
  secret to only the repos that reference it. Running the command will prompt for the secret value.

ORGSECRETS

  org_secret_count=$(wc -l <"$ORG_SECRETS_FILE" | tr -d ' ')

  if [ "$org_secret_count" -eq 0 ]; then
    echo "No org-level secrets found (or insufficient permissions to list them)."
  else
    echo "| Secret Name | Visibility | Configured Access | Referenced In Workflows | Suggested Command |"
    echo "|-------------|------------|-------------------|------------------------|-------------------|"

    sort "$ORG_SECRETS_FILE" | while IFS='|' read -r name vis configured referenced; do
      case "$vis" in
        "All repositories")
          if [ "$referenced" = "(none)" ]; then
            cmd="Unreferenced — verify if still needed"
          else
            cmd="\`gh secret set $name --org $ORG --visibility selected --repos $referenced\`"
          fi
          echo "| \`$name\` | **All repositories** | (all) | $referenced | $cmd |"
          ;;
        *)
          echo "| \`$name\` | $vis | $configured | $referenced | — |"
          ;;
      esac
    done
  fi

  # --- Guidance ---

  cat <<'GUIDANCE'

## Review Guidance

### Priority items to investigate

1. **`pull_request_target` with "checkout+exec, no guard"**: These are potential pwn request
   vulnerabilities. An attacker can fork the repo, inject code, and open a PR to achieve RCE
   with access to the repo's secrets. The `pull_request_target` trigger **bypasses** the
   "require approval for first-time contributors" setting entirely.

2. **`issue_comment` with "no author gate"**: Any GitHub user can comment on a public repo's
   issues/PRs. If the workflow executes code or passes comment content to a shell without
   sanitization, this is exploitable. The fork PR approval setting does not apply.

3. **Repos with no explicit `permissions:` blocks**: These inherit the org default. If the
   org default is `write`, every workflow in these repos runs with a read/write `GITHUB_TOKEN`.

4. **Org secrets with "All repositories" visibility**: These are accessible from any workflow
   in any repo — including repos with exploitable workflow configurations.

### What the fork approval setting does and does not protect

The "Require approval for first-time contributors" setting **only** gates `pull_request`
events from forks. It provides **no protection** for:
- `pull_request_target` (explicitly exempt — always runs immediately)
- `issue_comment` (not a fork PR event)
- `workflow_run`, `repository_dispatch`, and other non-PR triggers

### Mitigations to look for when reviewing flagged items

- **Author guards**: `if: github.event.pull_request.user.login == 'dependabot[bot]'`
- **`author_association` checks**: `if: github.event.comment.author_association == 'MEMBER'`
- **Environment protections**: Secrets in environments with required reviewers and branch restrictions
- **Explicit `permissions:` blocks**: Limits `GITHUB_TOKEN` blast radius even if RCE is achieved
- **No checkout**: Workflows that only make API calls (approve, label, merge) without checking
  out fork code are not vulnerable to code injection
GUIDANCE
} >>"$OUT_FILE"

# --- CSV output ---

if [ -n "$CSV_FILE" ]; then
  info "Writing CSV to $CSV_FILE..."

  # Helper: quote a CSV field (double any internal quotes, wrap in quotes)
  csv_field() {
    local val="$1"
    # If the field contains commas, quotes, or newlines, quote it
    if [[ "$val" == *,* ]] || [[ "$val" == *\"* ]] || [[ "$val" == *$'\n'* ]]; then
      val="${val//\"/\"\"}" # escape double quotes
      printf '"%s"' "$val"
    else
      printf '%s' "$val"
    fi
  }

  {
    echo "Repository,Explicit Permissions,pull_request_target,issue_comment,Repo Secrets"
    sort "$TABLE_ROWS_CSV" | while IFS='|' read -r repo perms prt ic secrets; do
      printf '%s,%s,%s,%s,%s\n' \
        "$(csv_field "$repo")" \
        "$(csv_field "$perms")" \
        "$(csv_field "$prt")" \
        "$(csv_field "$ic")" \
        "$(csv_field "$secrets")"
    done

    # Blank row separator, then org secrets
    echo ""
    echo "Org Secret,Visibility,Configured Access,Referenced In Workflows,Suggested Command"
    if [ -s "$ORG_SECRETS_FILE" ]; then
      sort "$ORG_SECRETS_FILE" | while IFS='|' read -r name vis configured referenced; do
        cmd=""
        if [ "$vis" = "All repositories" ]; then
          if [ "$referenced" = "(none)" ]; then
            cmd="Unreferenced - verify if still needed"
          else
            cmd="gh secret set $name --org $ORG --visibility selected --repos $referenced"
          fi
        fi
        printf '%s,%s,%s,%s,%s\n' \
          "$(csv_field "$name")" \
          "$(csv_field "$vis")" \
          "$(csv_field "$configured")" \
          "$(csv_field "$referenced")" \
          "$(csv_field "$cmd")"
      done
    fi
  } >"$CSV_FILE"

  info "CSV written to: $CSV_FILE"
fi

# --- Cleanup (temp files handled by trap EXIT) ---

info "Report written to: $OUT_FILE"

# Workflow cache cleanup
wf_size=$(du -sh "$WORKFLOWS_DIR" 2>/dev/null | cut -f1 || echo "unknown")

if [ -n "$LOCAL_DIR" ]; then
  # Using pre-existing local data — don't offer to delete it
  info "Workflows (pre-existing): $WORKFLOWS_DIR ($wf_size)"
elif [ "$CLEANUP" = "1" ]; then
  # Explicit --cleanup flag
  rm -rf "$AUDIT_DIR"
  info "Cleaned up cached workflows ($wf_size)"
else
  info "Workflows cached at: $WORKFLOWS_DIR ($wf_size)"

  if [ -t 0 ] && [ -t 1 ]; then
    # Interactive terminal — prompt
    printf "\nDelete cached workflow files? They can be reused with --local. [y/N]: "
    read -r cleanup_choice
    if [[ "$cleanup_choice" =~ ^[yY]$ ]]; then
      rm -rf "$AUDIT_DIR"
      info "Cleaned up cached workflows."
    else
      echo ""
      info "To re-run without re-downloading:"
      if [ -n "$CSV_FILE" ]; then
        echo "  $0 $ORG --local $AUDIT_DIR --out $OUT_FILE --csv $CSV_FILE"
      else
        echo "  $0 $ORG --local $AUDIT_DIR --out $OUT_FILE"
      fi
      info "To delete later: rm -rf $AUDIT_DIR"
    fi
  else
    # Non-interactive — just print the reuse command
    echo ""
    info "To re-run without re-downloading:"
    if [ -n "$CSV_FILE" ]; then
      echo "  $0 $ORG --local $AUDIT_DIR --out $OUT_FILE --csv $CSV_FILE"
    else
      echo "  $0 $ORG --local $AUDIT_DIR --out $OUT_FILE"
    fi
    info "To delete cached workflows: rm -rf $AUDIT_DIR"
    info "Or re-run with --cleanup to auto-delete after completion."
  fi
fi
