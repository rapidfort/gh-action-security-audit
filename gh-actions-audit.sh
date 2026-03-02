#!/usr/bin/env bash
set -uo pipefail

# ============================================================================
# GitHub Actions Security Audit
# Scans all repos you admin for: pull_request_target, token defaults, perms
# Requires: gh CLI (authenticated), jq
# Usage:
#   ./gh-actions-audit.sh                   # scan all orgs you admin
#   ./gh-actions-audit.sh myorg             # scan a specific org
#   ./gh-actions-audit.sh --user            # scan your personal repos
# ============================================================================

# --- Color helpers (disabled if not a tty) ---
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

# --- Preflight checks ---
for cmd in gh jq; do
  command -v "$cmd" &>/dev/null || { echo "ERROR: '$cmd' not found. Install it first."; exit 1; }
done
gh auth status &>/dev/null 2>&1 || { echo "ERROR: gh not authenticated. Run 'gh auth login' first."; exit 1; }

# --- Help ---
show_help() {
  cat <<'EOF'
GitHub Actions Security Audit
Scans repos where you have admin access for pull_request_target usage,
default GITHUB_TOKEN permissions, and workflow permission blocks.

USAGE:
  ./gh-actions-audit.sh                   Scan all orgs where you are admin
  ./gh-actions-audit.sh <org>             Scan a specific organization
  ./gh-actions-audit.sh --user            Scan your personal repos only
  ./gh-actions-audit.sh --all             Scan all orgs + personal repos
  ./gh-actions-audit.sh -h | --help       Show this help

REQUIRES:
  gh    GitHub CLI (authenticated via 'gh auth login')
  jq    JSON processor

OUTPUT COLUMNS:
  VIS             public / private
  TOKEN-DEFAULT   Default GITHUB_TOKEN permission (read / write / unknown)
  PR-APPROVE      Whether Actions can auto-approve PR reviews
  PR-TARGET       Workflows using pull_request_target trigger
  RISK            Assessment flag:
                    CHECK  = pull_request_target + write token (needs review)
                    SAFE?  = pull_request_target + read token (likely ok)
                    NOTE   = write token default (no pull_request_target)
                    -      = no issues detected

DETAILS:
  Per-workflow analysis is saved to /tmp/gh-audit-details-<timestamp>.txt
  including: permissions blocks, contents/pull-requests perms, risk level.

EXAMPLES:
  ./gh-actions-audit.sh rapidfort         Audit all rapidfort repos you admin
  ./gh-actions-audit.sh --user            Audit only your personal repos
  ./gh-actions-audit.sh                   Auto-discover and audit all your orgs
EOF
  exit 0
}

# --- Determine targets ---
MODE="${1:-}"
declare -a TARGETS=()

if [[ "$MODE" == "-h" || "$MODE" == "--help" ]]; then
  show_help
elif [[ "$MODE" == "--user" ]]; then
  # Personal repos where user is owner (admin)
  TARGETS=("__USER__")
elif [[ "$MODE" == "--all" ]]; then
  # All orgs + personal repos
  echo -e "${CYAN}Discovering organizations where you have admin access...${RESET}"
  mapfile -t TARGETS < <(
    gh api --paginate "/user/memberships/orgs" \
      --jq '.[] | select(.role == "admin") | .organization.login'
  )
  TARGETS+=("__USER__")
  echo -e "Found ${BOLD}$((${#TARGETS[@]} - 1))${RESET} org(s) + personal repos"
  echo
elif [[ -n "$MODE" ]]; then
  TARGETS=("$MODE")
else
  # Auto-discover: all orgs where you have admin role
  echo -e "${CYAN}Discovering organizations where you have admin access...${RESET}"
  mapfile -t TARGETS < <(
    gh api --paginate "/user/memberships/orgs" \
      --jq '.[] | select(.role == "admin") | .organization.login'
  )
  if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "No orgs found with admin access. Falling back to personal repos."
    TARGETS=("__USER__")
  else
    echo -e "Found ${BOLD}${#TARGETS[@]}${RESET} org(s): ${TARGETS[*]}"
    echo
  fi
fi

# --- Collect repos ---
declare -a ALL_REPOS=()

for target in "${TARGETS[@]}"; do
  if [[ "$target" == "__USER__" ]]; then
    echo -e "${CYAN}Fetching personal repos (owner/admin)...${RESET}"
    mapfile -t user_repos < <(
      gh repo list --limit 1000 --json nameWithOwner,viewerPermission \
        --jq '.[] | select(.viewerPermission == "ADMIN") | .nameWithOwner'
    )
    ALL_REPOS+=("${user_repos[@]}")
  else
    echo -e "${CYAN}Fetching repos for org: ${BOLD}$target${RESET}"
    mapfile -t org_repos < <(
      gh repo list "$target" --limit 1000 --json nameWithOwner,viewerPermission \
        --jq '.[] | select(.viewerPermission == "ADMIN") | .nameWithOwner'
    )
    ALL_REPOS+=("${org_repos[@]}")
  fi
done

if [[ ${#ALL_REPOS[@]} -eq 0 ]]; then
  echo "No repositories found with admin access."
  exit 0
fi

echo
echo "==========================================================================="
echo "GitHub Actions Security Audit"
echo "Scope: pull_request_target usage + Default GITHUB_TOKEN permissions"
echo "==========================================================================="
echo "Repositories to scan: ${#ALL_REPOS[@]}"
echo
echo "COLUMN LEGEND:"
echo "  VIS             -> public / private"
echo "  TOKEN-DEFAULT   -> Default GITHUB_TOKEN permission (read / write / unknown)"
echo "  PR-APPROVE      -> Whether Actions can approve PR reviews"
echo "  PR-TARGET       -> Workflows using pull_request_target"
echo "                     no              = none found"
echo "                     YES(n)          = n workflows found"
echo "                     DENIED/none     = cannot read workflows or none exist"
echo "  RISK            -> Assessment based on token + pr_target combination"
echo
printf "${BOLD}%-45s %-8s %-15s %-12s %-12s %-8s${RESET}\n" \
  "REPOSITORY" "VIS" "TOKEN-DEFAULT" "PR-APPROVE" "PR-TARGET" "RISK"
printf "%-45s %-8s %-15s %-12s %-12s %-8s\n" \
  "----------" "---" "-------------" "----------" "---------" "----"

# --- Detail output file ---
DETAIL_FILE="/tmp/gh-audit-details-$(date +%s).txt"
: > "$DETAIL_FILE"

# --- Counters ---
total=0; risky=0; check=0; safe=0

# --- Scan each repo ---
for repo in "${ALL_REPOS[@]}"; do
  ((total++)) || true

  {
  # 1. Repo metadata
  repo_json=$(gh api "repos/$repo" --jq '{
    visibility: .visibility,
    default_branch: .default_branch
  }' 2>/dev/null || echo '{}')

  vis=$(echo "$repo_json" | jq -r '.visibility // "unknown"')
  default_branch=$(echo "$repo_json" | jq -r '.default_branch // "main"')

  # 2. Actions permissions (token default + PR approval)
  actions_json=$(gh api "repos/$repo/actions/permissions/workflow" 2>/dev/null || echo '{}')
  default_token=$(echo "$actions_json" | jq -r '
    if .default_workflow_permissions then .default_workflow_permissions
    else "unknown" end
  ')
  pr_approve=$(echo "$actions_json" | jq -r '
    if .can_approve_pull_request_reviews != null
    then (.can_approve_pull_request_reviews | tostring)
    else "unknown" end
  ')

  # 3. List workflow files
  workflows_json=$(gh api "repos/$repo/contents/.github/workflows?ref=$default_branch" 2>/dev/null || echo "DENIED")

  pr_target_count=0
  pr_target_label="no"
  detail_lines=""

  if [[ "$workflows_json" == "DENIED" ]] || ! echo "$workflows_json" | jq -e 'type == "array"' &>/dev/null; then
    pr_target_label="DENIED/none"
  else
    # Parse each workflow file
    workflow_files=$(echo "$workflows_json" | jq -r '.[] | select(type == "object" and .name != null) | select(.name | test("\\.(yml|yaml)$")) | .path' 2>/dev/null)

    if [[ -z "$workflow_files" ]]; then
      pr_target_label="no"
    else
      while IFS= read -r wf_path; do
        # Fetch raw content
        content=$(gh api "repos/$repo/contents/$wf_path?ref=$default_branch" \
          --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || echo "")

        [[ -z "$content" ]] && continue

        # Check for pull_request_target
        has_prt="NO"
        if grep -qE 'pull_request_target' <<<"$content"; then
          has_prt="YES"
          ((pr_target_count++)) || true
        fi

        # Check permissions block
        has_perms="NO"
        contents_perm="none"
        pr_perm="none"
        safe_pr_permissions="NO"

        if grep -qE '^[[:space:]]*permissions:' <<<"$content" || grep -qE '^permissions:' <<<"$content"; then
          has_perms="YES"

          # Extract contents permission
          contents_line=$(grep -E '^[[:space:]]*contents:[[:space:]]' <<<"$content" | head -1 || true)
          if [[ -n "$contents_line" ]]; then
            contents_perm=$(echo "$contents_line" | sed 's/.*contents:[[:space:]]*//' | tr -d '[:space:]')
          fi

          # Extract pull-requests permission
          pr_line=$(grep -E '^[[:space:]]*pull-requests:[[:space:]]' <<<"$content" | head -1 || true)
          if [[ -n "$pr_line" ]]; then
            pr_perm=$(echo "$pr_line" | sed 's/.*pull-requests:[[:space:]]*//' | tr -d '[:space:]')
          fi

          # Safe pattern: contents:read + pull-requests:write
          if [[ "$contents_perm" == "read" && "$pr_perm" == "write" ]]; then
            safe_pr_permissions="YES"
          fi
        fi

        # Determine effective write risk
        effective_write="UNKNOWN"
        if [[ "$has_perms" == "YES" && "$contents_perm" == "read" ]]; then
          effective_write="NO"
        elif [[ "$has_perms" == "YES" && "$contents_perm" == "write" ]]; then
          effective_write="YES"
        elif [[ "$has_perms" == "NO" && "$default_token" == "read" ]]; then
          effective_write="NO"
        elif [[ "$has_perms" == "NO" && "$default_token" == "write" ]]; then
          effective_write="YES"
        fi

        # Workflow risk
        wf_risk="LOW"
        if [[ "$has_prt" == "YES" ]]; then
          if [[ "$effective_write" == "YES" ]]; then
            wf_risk="HIGH"
          elif [[ "$effective_write" == "UNKNOWN" ]]; then
            wf_risk="MEDIUM"
          else
            wf_risk="LOW"
          fi
        fi

        detail_lines+="  Workflow: $wf_path
    pull_request_target: $has_prt
    permissions block: $has_perms
    contents perm: $contents_perm
    pull-requests perm: $pr_perm
    safe PR permission block (contents:read + pull-requests:write): $safe_pr_permissions
    effective write token: $effective_write
    RISK: $wf_risk
"
      done <<<"$workflow_files"
    fi
  fi

  # PR target label
  if [[ $pr_target_count -gt 0 ]]; then
    pr_target_label="YES($pr_target_count)"
  fi

  # Summary risk flag
  risk_flag="-"
  if [[ $pr_target_count -gt 0 ]]; then
    if [[ "$default_token" == "write" ]]; then
      risk_flag="CHECK"
      ((check++)) || true
    elif [[ "$default_token" == "read" ]]; then
      risk_flag="SAFE?"
      ((safe++)) || true
    else
      risk_flag="CHECK"
      ((check++)) || true
    fi
  elif [[ "$default_token" == "write" ]]; then
    risk_flag="NOTE"
  fi

  # Colorize risk
  case "$risk_flag" in
    CHECK) risk_display="${RED}CHECK${RESET}" ;;
    "SAFE?") risk_display="${GREEN}SAFE?${RESET}" ;;
    NOTE)  risk_display="${YELLOW}NOTE${RESET}" ;;
    *)     risk_display="-" ;;
  esac

  printf "%-45s %-8s %-15s %-12s %-12s " \
    "$repo" "$vis" "$default_token" "$pr_approve" "$pr_target_label"
  echo -e "$risk_display"

  # Write detail
  {
    echo "=== $repo ==="
    echo "  visibility: $vis"
    echo "  default token: $default_token"
    echo "  PR approve: $pr_approve"
    echo "  pr_target workflows: $pr_target_count"
    if [[ -n "$detail_lines" ]]; then
      echo "$detail_lines"
    fi
    echo
  } >> "$DETAIL_FILE"

  } || {
    # Catch-all: continue even if something unexpected breaks inside the repo block
    printf "%-45s %-8s %-15s %-12s %-12s %-8s\n" \
      "$repo" "?" "ERROR" "ERROR" "ERROR" "ERROR"
    continue
  }
done

# --- Summary ---
echo
echo "==========================================================================="
echo "SUMMARY"
echo "==========================================================================="
echo "  Total repos scanned:          $total"
echo "  Repos with pull_request_target:"
echo "    needing review (CHECK):     $check"
echo "    likely safe (SAFE?):        $safe"
echo
echo -e "Detailed per-workflow analysis saved to: ${BOLD}$DETAIL_FILE${RESET}"
echo
echo "NOTE: If TOKEN-DEFAULT shows 'unknown', check your org settings UI."
echo "      Org-level 'Read repository contents' means unknown ≠ write."
