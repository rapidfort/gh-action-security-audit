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
#   --hdf FILE       Path for the HDF v2 JSON report output. This is the
#                    structured format used by MITRE Heimdall and other
#                    security tooling. Omit this flag to skip HDF generation.
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
  rm -f "${TABLE_ROWS_FILE:-}" "${TABLE_ROWS_CSV_FILE:-}" "${ORG_SECRETS_FILE:-}" "${SECRET_MAP_FILE:-}" \
    "${HDF_REPO_TARGETS_FILE:-}" "${HDF_OUTPUT_FILE:-}" "${CLASSIFIER_CACHE_FILE:-}"
}
trap cleanup EXIT

# --- JSON helpers -------------------------------------------------------------

# json_escape: escape a string for safe inclusion in a JSON value.
# Handles: backslashes, double quotes, newlines, tabs, carriage returns.
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/\\r}"
  printf '%s' "$s"
}

# emit_hdf_requirement: output a single HDF v2 Evaluated_Requirement JSON object.
# Schema: hdf-results.schema.json → $defs/Evaluated_Requirement
# Args: id title impact severity status code_desc message
# severity: "critical" | "high" | "medium" | "low" | "informational"
# status: "passed" | "failed" | "notApplicable" | "notReviewed" | "error"
# code_desc: description of what was checked
# message: detail message (omit for no message)
emit_hdf_requirement() {
  local id="$1" title="$2" impact="$3" severity="$4" status="$5"
  local code_desc="$6" message="${7:-}"
  local esc_title esc_code_desc
  esc_title=$(json_escape "$title")
  esc_code_desc=$(json_escape "$code_desc")
  local now
  now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # Build message field only if provided
  local message_field=""
  if [ -n "$message" ]; then
    local esc_message
    esc_message=$(json_escape "$message")
    message_field=", \"message\": \"$esc_message\""
  fi

  printf '{"id": "%s", "title": "%s", "descriptions": [{"label": "default", "data": "%s"}], "impact": %s, "severity": "%s", "tags": {}, "results": [{"status": "%s", "codeDesc": "%s", "startTime": "%s"%s}]}' \
    "$id" "$esc_title" "$esc_title" "$impact" "$severity" "$status" "$esc_code_desc" "$now" "$message_field"
}

# --- Argument Parsing --------------------------------------------------------

# require_arg: validate that an option has a non-empty, non-flag argument
# Args: option_name next_arg description example
require_arg() {
  local opt="$1" next="${2:-}" desc="$3" example="$4"
  if [ -z "$next" ] || [[ "$next" == -* ]]; then
    echo "Error: $opt requires $desc." >&2
    echo "Usage: $0 <ORG> $opt $example" >&2
    exit 1
  fi
}

LOCAL_DIR=""
ORG=""
OUT_FILE=""
CSV_FILE=""
HDF_FILE=""
CLEANUP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local)
      require_arg "--local" "${2:-}" "a directory path" "/path/to/previous/audit/dir"
      LOCAL_DIR="$2"
      shift 2
      ;;
    --out)
      require_arg "--out" "${2:-}" "a filename" "report.md"
      OUT_FILE="$2"
      shift 2
      ;;
    --csv)
      require_arg "--csv" "${2:-}" "a filename" "report.csv"
      CSV_FILE="$2"
      shift 2
      ;;
    --hdf)
      require_arg "--hdf" "${2:-}" "a filename" "report.json"
      HDF_FILE="$2"
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

if [ -n "$LOCAL_DIR" ] && [ "$CLEANUP" = "1" ]; then
  warn "--cleanup is ignored when using --local (won't delete your pre-existing files)."
  CLEANUP=0
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

# --- handle_cache_cleanup: manage workflow cache after run ---
# Globals: LOCAL_DIR, CLEANUP, AUDIT_DIR, WORKFLOWS_DIR, ORG, OUT_FILE, CSV_FILE
handle_cache_cleanup() {
  local wf_size
  wf_size=$(du -sh "$WORKFLOWS_DIR" 2>/dev/null | cut -f1 || echo "unknown")

  if [ -n "$LOCAL_DIR" ]; then
    info "Workflows (pre-existing): $WORKFLOWS_DIR ($wf_size)"
    return
  fi

  if [ "$CLEANUP" = "1" ]; then
    rm -rf "$AUDIT_DIR"
    info "Cleaned up cached workflows ($wf_size)"
    return
  fi

  info "Workflows cached at: $WORKFLOWS_DIR ($wf_size)"

  local reuse_cmd="$0 $ORG --local $AUDIT_DIR --out $OUT_FILE"
  [ -n "$CSV_FILE" ] && reuse_cmd+=" --csv $CSV_FILE"
  [ -n "$HDF_FILE" ] && reuse_cmd+=" --hdf $HDF_FILE"

  if [ -t 0 ] && [ -t 1 ]; then
    printf "\nDelete cached workflow files? They can be reused with --local. [y/N]: "
    local cleanup_choice
    read -r cleanup_choice
    if [[ "$cleanup_choice" =~ ^[yY]$ ]]; then
      rm -rf "$AUDIT_DIR"
      info "Cleaned up cached workflows."
    else
      echo ""
      info "To re-run without re-downloading:"
      echo "  $reuse_cmd"
      info "To delete later: rm -rf $AUDIT_DIR"
    fi
  else
    echo ""
    info "To re-run without re-downloading:"
    echo "  $reuse_cmd"
    info "To delete cached workflows: rm -rf $AUDIT_DIR"
    info "Or re-run with --cleanup to auto-delete after completion."
  fi
}

# --- find_workflow_files: find all workflow YAML files in a directory ---
# Args: directory
# Outputs: one file path per line
find_workflow_files() {
  find "$1" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null
}

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
  wf_count=$(find_workflow_files "$WORKFLOWS_DIR" | wc -l | tr -d ' ')
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
  all_repos=$(gh repo list "$ORG" --limit 99999 --no-archived --json name --jq '.[].name' 2>/dev/null) || {
    crit "Failed to list repos for '$ORG'. Check gh auth and org access."
    exit 1
  }
  if [ -z "$all_repos" ]; then
    crit "No repos found for '$ORG'. Verify the org name and your permissions."
    exit 1
  fi
  total_repos=$(grep -c . <<<"$all_repos" || echo 0)

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
  done <<<"$all_repos"

  printf '\033[2K\r' # clear progress line
  info "Downloaded $downloaded workflow files from ${#REPOS[@]} repos ($skipped_no_wf repos had no workflows)"
fi

# =============================================================================
# PHASE 2: Analyze workflows per-repo
# =============================================================================

info "Analyzing workflows..."

# --- extract_on_triggers: extract the on:/true: trigger section from a workflow ---
# Args: wf_uncommented (workflow content with comments stripped)
# Outputs: the text of the on: section (trigger declarations only)
# Used to prevent false positives from trigger keywords appearing in run: blocks
extract_on_triggers() {
  local wf="$1"
  awk '
    /^on[[:space:]]*:/ || /^"on"[[:space:]]*:/ || /^'"'"'on'"'"'[[:space:]]*:/ || /^true[[:space:]]*:/ {
      in_on=1; print; next
    }
    in_on {
      if (/^[^[:space:]]/) { in_on=0; next }
      print
    }
  ' <<<"$wf"
}

# --- classify_prt: classify a pull_request_target workflow ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail
classify_prt() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  local has_checkout=0 has_fork_ref=0 has_author_guard=0 is_dependabot=0

  [[ $wf_uncommented == *actions/checkout* ]] && has_checkout=1
  grep -qE 'github\.head_ref|pull_request\.head\.(sha|ref|repo\.full_name)' <<<"$wf_uncommented" && has_fork_ref=1
  grep -qE "(user\.login|github\.actor)\s*==\s*['\"]dependabot" <<<"$wf_uncommented" && is_dependabot=1
  grep -qE "(user\.login|github\.actor)\s*==\s*['\"](dependabot|github-actions|renovate)" <<<"$wf_uncommented" && has_author_guard=1
  grep -q 'author_association' <<<"$wf_uncommented" && has_author_guard=1

  local dep_tag=""
  [ "$is_dependabot" = "1" ] && dep_tag=" (Dependabot)"

  local detail="" detail_csv=""
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

  echo "${detail}|${detail_csv}"
}

# --- join_array_cells: join array elements with a separator, or "No" if empty ---
# Args: separator element [element ...]
# Outputs: joined string (or "No" if no elements)
join_array_cells() {
  local sep="$1"
  shift
  if [ $# -eq 0 ]; then
    echo "No"
    return
  fi
  local result="$1"
  shift
  while [ $# -gt 0 ]; do
    result+="${sep}$1"
    shift
  done
  echo "$result"
}

# --- classify_ic: classify an issue_comment workflow ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail
classify_ic() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  local detail="" detail_csv=""

  if grep -q 'author_association' <<<"$wf_uncommented"; then
    detail="$wf_name (has author_association)"
    detail_csv="$wf_name (has author_association)"
  elif grep -qE "user\.login\s*==|actor\s*==" <<<"$wf_uncommented"; then
    detail="$wf_name (has actor check)"
    detail_csv="$wf_name (has actor check)"
  else
    detail="$wf_name (**no author gate**)"
    detail_csv="$wf_name (no author gate)"
  fi

  echo "${detail}|${detail_csv}"
}

# --- classify_expr_injection: detect dangerous expressions in run: blocks ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty string if no dangerous expressions found)
# Dangerous: ${{ github.event.issue.title }}, ${{ github.head_ref }}, etc.
# Safe: same expressions in env: blocks (assigned to env vars before run:)
classify_expr_injection() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"

  # Extract content of run: blocks (inline and multiline |)
  # Uses awk: when we see "run:" capture that line and subsequent indented lines
  local run_content
  run_content=$(awk '
    /^[[:space:]]*-?[[:space:]]*run:[[:space:]]*\|/ { in_run=1; run_indent=0; match($0, /^[[:space:]]*/); run_indent=RLENGTH; next }
    /^[[:space:]]*-?[[:space:]]*run:/ { print; next }
    in_run {
      if (NF == 0) { next }
      match($0, /^[[:space:]]*/);
      if (RLENGTH <= run_indent) { in_run=0; next }
      print
    }
  ' <<<"$wf_uncommented")

  [ -z "$run_content" ] && return 0

  # Pattern for dangerous user-controlled expressions
  # Includes: github.event.* user-controlled fields, github.head_ref,
  # inputs.* (workflow_dispatch), github.event.client_payload.* (repository_dispatch),
  # github.event.ref (create/delete triggers), head_commit.message/author,
  # discussion.title/body, pages[].page_name
  local dangerous_pattern='github\.event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body|review\.body|review_comment\.body|commits\[|client_payload\.|ref|head_commit\.(message|author\.(name|email))|discussion\.(title|body)|pages\[)|github\.head_ref|inputs\.'

  # Find dangerous expressions in run: block content
  local found
  found=$(grep -oE '\$\{\{[^}]*('"${dangerous_pattern}"')[^}]*\}\}' <<<"$run_content" 2>/dev/null \
    | grep -oE "${dangerous_pattern}" \
    | sort -u || true)

  [ -z "$found" ] && return 0

  # Format as comma-separated list of dangerous contexts
  local contexts
  contexts=$(paste -sd', ' - <<<"$found")

  local detail="" detail_csv=""
  detail="$wf_name (**${contexts}**)"
  detail_csv="$wf_name (${contexts})"

  echo "${detail}|${detail_csv}"
}

# --- classify_wfr: classify a workflow_run trigger workflow ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if no workflow_run trigger)
# Sub-classification: download-artifact (HIGH), checkout (MEDIUM), API-only (LOW)
classify_wfr() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"

  [[ $wf_uncommented == *workflow_run* ]] || return 0

  local detail="" detail_csv=""
  if [[ $wf_uncommented == *download-artifact* ]]; then
    detail="$wf_name (**download-artifact**)"
    detail_csv="$wf_name (download-artifact)"
  elif [[ $wf_uncommented == *actions/checkout* ]]; then
    detail="$wf_name (checkout)"
    detail_csv="$wf_name (checkout)"
  else
    detail="$wf_name (API-only)"
    detail_csv="$wf_name (API-only)"
  fi

  echo "${detail}|${detail_csv}"
}

# --- classify_self_hosted: detect self-hosted runner usage ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if no self-hosted runners)
classify_self_hosted() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"

  if grep -qiE 'runs-on:.*self-hosted' <<<"$wf_uncommented"; then
    echo "$wf_name (**self-hosted**)|$wf_name (self-hosted)"
  fi
}

# --- classify_dangerous_perms: detect dangerous permissions grants ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if no dangerous grants)
classify_dangerous_perms() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"

  local dangers=()

  # Check for write-all (blanket write)
  if grep -qE '^\s*permissions:\s*write-all' <<<"$wf_uncommented"; then
    dangers+=("write-all")
  fi

  # Check for specific dangerous permission grants
  local perm
  for perm in "contents: write" "actions: write" "packages: write" "id-token: write"; do
    if grep -qE "^\s+${perm}" <<<"$wf_uncommented"; then
      dangers+=("$perm")
    fi
  done

  [ ${#dangers[@]} -eq 0 ] && return 0

  local danger_list
  danger_list=$(printf '%s, ' "${dangers[@]}")
  danger_list="${danger_list%, }"

  echo "$wf_name (**${danger_list}**)|$wf_name (${danger_list})"
}

# --- classify_hardcoded_secrets: detect hardcoded tokens/keys in a workflow ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if none found)
# Detects: ghp_ (GitHub PAT), gho_ (GitHub OAuth), AKIA (AWS access key)
classify_hardcoded_secrets() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  local found
  found=$(grep -oE 'ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}' <<<"$wf_uncommented" 2>/dev/null \
    | sort -u || true)
  [ -z "$found" ] && return 0

  local types=()
  [[ $found == *ghp_* ]] && types+=("ghp_*")
  [[ $found == *gho_* ]] && types+=("gho_*")
  [[ $found == *AKIA* ]] && types+=("AKIA*")

  local type_list
  type_list=$(printf '%s, ' "${types[@]}")
  type_list="${type_list%, }"

  echo "$wf_name (**${type_list}**)|$wf_name (${type_list})"
}

# --- classify_unpinned: report pinned vs unpinned action refs in a workflow ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty string if no uses: lines)
classify_unpinned() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"

  # Extract all uses: lines (excluding commented ones via wf_uncommented)
  local uses_lines
  uses_lines=$(grep -E 'uses:.*@' <<<"$wf_uncommented" || true)
  [ -z "$uses_lines" ] && return 0

  local total=0 pinned=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    total=$((total + 1))
    if echo "$line" | grep -qE '@[0-9a-f]{40}'; then
      pinned=$((pinned + 1))
    fi
  done <<<"$uses_lines"

  local detail="" detail_csv=""
  if [ "$pinned" -eq "$total" ]; then
    detail="$wf_name ($pinned/$total pinned)"
    detail_csv="$wf_name ($pinned/$total pinned)"
  else
    detail="$wf_name (**$pinned/$total pinned**)"
    detail_csv="$wf_name ($pinned/$total pinned)"
  fi

  echo "${detail}|${detail_csv}"
}

# --- classify_secrets_inherit: detect secrets: inherit in reusable workflow calls ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if none found)
classify_secrets_inherit() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  if grep -qE 'secrets:\s*inherit' <<<"$wf_uncommented"; then
    echo "$wf_name (**secrets: inherit**)|$wf_name (secrets: inherit)"
  fi
}

# --- classify_env_injection: detect writes to GITHUB_ENV/PATH/OUTPUT ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if none found)
# Flags any write to GITHUB_ENV, GITHUB_PATH, or GITHUB_OUTPUT as a risk.
classify_env_injection() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  local targets=()
  # shellcheck disable=SC2016
  if grep -qE '>>\s*"?\$GITHUB_ENV' <<<"$wf_uncommented"; then
    targets+=("GITHUB_ENV")
  fi
  # shellcheck disable=SC2016
  if grep -qE '>>\s*"?\$GITHUB_PATH' <<<"$wf_uncommented"; then
    targets+=("GITHUB_PATH")
  fi
  # shellcheck disable=SC2016
  if grep -qE '>>\s*"?\$GITHUB_OUTPUT' <<<"$wf_uncommented"; then
    targets+=("GITHUB_OUTPUT")
  fi
  [ ${#targets[@]} -eq 0 ] && return 0

  local target_list
  target_list=$(printf '%s, ' "${targets[@]}")
  target_list="${target_list%, }"

  echo "$wf_name (**${target_list}**)|$wf_name (${target_list})"
}

# --- classify_deprecated_commands: detect deprecated workflow commands ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if none found)
# Detects: ::set-output, ::save-state, ::set-env, ::add-path
classify_deprecated_commands() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  local cmds=()
  if grep -q '::set-output' <<<"$wf_uncommented"; then
    cmds+=("set-output")
  fi
  if grep -q '::save-state' <<<"$wf_uncommented"; then
    cmds+=("save-state")
  fi
  if grep -q '::set-env' <<<"$wf_uncommented"; then
    cmds+=("set-env")
  fi
  if grep -q '::add-path' <<<"$wf_uncommented"; then
    cmds+=("add-path")
  fi
  [ ${#cmds[@]} -eq 0 ] && return 0

  local cmd_list
  cmd_list=$(printf '%s, ' "${cmds[@]}")
  cmd_list="${cmd_list%, }"

  echo "$wf_name (**::${cmd_list}**)|$wf_name (::${cmd_list})"
}

# --- classify_known_vulnerable: detect known-compromised actions ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if none found)
# Blocklist: tj-actions/changed-files, reviewdog/action-setup,
#            dawidd6/action-download-artifact
classify_known_vulnerable() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  local found=()
  if grep -qE 'uses:.*tj-actions/changed-files' <<<"$wf_uncommented"; then
    found+=("tj-actions/changed-files")
  fi
  if grep -qE 'uses:.*reviewdog/action-setup' <<<"$wf_uncommented"; then
    found+=("reviewdog/action-setup")
  fi
  if grep -qE 'uses:.*dawidd6/action-download-artifact' <<<"$wf_uncommented"; then
    found+=("dawidd6/action-download-artifact")
  fi
  [ ${#found[@]} -eq 0 ] && return 0

  local found_list
  found_list=$(printf '%s, ' "${found[@]}")
  found_list="${found_list%, }"

  echo "$wf_name (**${found_list}**)|$wf_name (${found_list})"
}

# --- classify_unpinned_third_party: distinguish first-party vs third-party unpinned ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if no third-party unpinned actions)
# First-party: actions/*, github/* — lower risk when unpinned
classify_unpinned_third_party() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  local uses_lines
  uses_lines=$(grep -E 'uses:.*@' <<<"$wf_uncommented" || true)
  [ -z "$uses_lines" ] && return 0

  local third_party=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    # Skip SHA-pinned
    echo "$line" | grep -qE '@[0-9a-f]{40}' && continue
    # Skip first-party (actions/*, github/*)
    echo "$line" | grep -qE 'uses:\s*(actions|github)/' && continue
    third_party=$((third_party + 1))
  done <<<"$uses_lines"

  [ "$third_party" -eq 0 ] && return 0
  echo "$wf_name (**$third_party third-party unpinned**)|$wf_name ($third_party third-party unpinned)"
}

# --- classify_always_secrets: detect always()/continue-on-error + secrets ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if none found)
classify_always_secrets() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  local has_always=0 has_continue=0 has_secrets=0
  if grep -qE 'if:.*always\(\)' <<<"$wf_uncommented"; then
    has_always=1
  fi
  if grep -qE 'continue-on-error:\s*true' <<<"$wf_uncommented"; then
    has_continue=1
  fi
  if grep -qE 'secrets\.' <<<"$wf_uncommented"; then
    has_secrets=1
  fi

  [ "$has_secrets" -eq 0 ] && return 0
  [ "$has_always" -eq 0 ] && [ "$has_continue" -eq 0 ] && return 0

  local patterns=()
  [ "$has_always" -eq 1 ] && patterns+=("always()")
  [ "$has_continue" -eq 1 ] && patterns+=("continue-on-error")

  local pattern_list
  pattern_list=$(printf '%s, ' "${patterns[@]}")
  pattern_list="${pattern_list%, }"

  echo "$wf_name (**${pattern_list} + secrets**)|$wf_name (${pattern_list} + secrets)"
}

# --- classify_artifact_trust: detect download-artifact without validation ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if none found)
classify_artifact_trust() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  if grep -qE 'uses:.*download-artifact' <<<"$wf_uncommented"; then
    echo "$wf_name (**download-artifact**)|$wf_name (download-artifact)"
  fi
}

# --- classify_missing_environment: detect deployment without environment protection ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if none found)
# Deployment patterns: docker push, aws deploy, kubectl apply, terraform apply, helm upgrade
classify_missing_environment() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  local has_deploy=0
  if grep -qEi 'docker\s+push|aws\s+deploy|kubectl\s+apply|terraform\s+apply|helm\s+upgrade|gcloud\s+.*deploy' <<<"$wf_uncommented"; then
    has_deploy=1
  fi
  [ "$has_deploy" -eq 0 ] && return 0

  if grep -q 'environment:' <<<"$wf_uncommented"; then
    return 0
  fi

  echo "$wf_name (**deploy without environment**)|$wf_name (deploy without environment)"
}

# --- classify_cache_poisoning: detect cache usage in fork-triggered workflows ---
# Args: wf_name wf_content wf_uncommented wf_triggers
# Outputs: md_detail|csv_detail (or empty if none found)
classify_cache_poisoning() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  if ! grep -qE 'uses:.*actions/cache' <<<"$wf_uncommented"; then
    return 0
  fi
  echo "$wf_name (**actions/cache**)|$wf_name (actions/cache)"
}

# --- classify_static_credentials: detect static cloud credentials vs OIDC ---
# Args: wf_name wf_content wf_uncommented
# Outputs: md_detail|csv_detail (or empty if none found)
# Checks for AWS_ACCESS_KEY_ID, AZURE_CREDENTIALS, GCP_SA_KEY without id-token: write
classify_static_credentials() {
  local wf_name="$1" wf_content="$2" wf_uncommented="$3"
  local has_static=0
  if grep -qE 'AWS_ACCESS_KEY_ID|AZURE_CREDENTIALS|GCP_SA_KEY|GOOGLE_APPLICATION_CREDENTIALS' <<<"$wf_uncommented"; then
    has_static=1
  fi
  [ "$has_static" -eq 0 ] && return 0

  if grep -qE 'id-token:\s*write' <<<"$wf_uncommented"; then
    return 0
  fi

  echo "$wf_name (**static cloud credentials**)|$wf_name (static cloud credentials)"
}

# --- run_repo_classifiers: run all per-repo classifiers on a repo's workflows ---
# Writes results to a cache file for consumption by build_hdf_repo_target and render_md_csv_row.
# Args: repo_dir cache_file
# Cache format: TAG|md_detail|csv_detail  or  META|key|value
# Returns 1 if no workflow files found.
run_repo_classifiers() {
  local repo_dir="$1"
  local cache_file="$2"

  local wf_files=()
  while IFS= read -r f; do
    wf_files+=("$f")
  done < <(find_workflow_files "$repo_dir")

  [ ${#wf_files[@]} -eq 0 ] && return 1

  local total_wf=${#wf_files[@]}
  local wf_with_perms=0
  local has_harden_runner=0

  local f wf_name wf_content wf_uncommented wf_triggers

  for f in "${wf_files[@]}"; do
    wf_name=$(basename "$f")
    wf_content=$(cat "$f" 2>/dev/null) || continue
    wf_uncommented=$(grep -v '^\s*#' <<<"$wf_content")
    wf_triggers=$(extract_on_triggers "$wf_uncommented")

    # --- Permissions ---
    if grep -q 'permissions:' <<<"$wf_uncommented"; then
      wf_with_perms=$((wf_with_perms + 1))
    fi

    # --- pull_request_target ---
    if [[ $wf_triggers == *pull_request_target* ]]; then
      local prt_result
      prt_result=$(classify_prt "$wf_name" "$wf_content" "$wf_uncommented")
      echo "PRT|${prt_result}" >>"$cache_file"
    fi

    # --- issue_comment ---
    if [[ $wf_triggers == *issue_comment* ]]; then
      local ic_result
      ic_result=$(classify_ic "$wf_name" "$wf_content" "$wf_uncommented")
      echo "IC|${ic_result}" >>"$cache_file"
    fi

    # --- Unpinned actions ---
    local unpin_result
    unpin_result=$(classify_unpinned "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$unpin_result" ]; then
      echo "UNPIN|${unpin_result}" >>"$cache_file"
    fi

    # --- Expression injection ---
    local expr_result
    expr_result=$(classify_expr_injection "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$expr_result" ]; then
      echo "EXPR|${expr_result}" >>"$cache_file"
    fi

    # --- workflow_run ---
    if [[ $wf_triggers == *workflow_run* ]]; then
      local wfr_result
      wfr_result=$(classify_wfr "$wf_name" "$wf_content" "$wf_uncommented")
      if [ -n "$wfr_result" ]; then
        echo "WFR|${wfr_result}" >>"$cache_file"
      fi
    fi

    # --- Self-hosted runners ---
    local sh_result
    sh_result=$(classify_self_hosted "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$sh_result" ]; then
      echo "SH|${sh_result}" >>"$cache_file"
    fi

    # --- Dangerous permissions ---
    local dp_result
    dp_result=$(classify_dangerous_perms "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$dp_result" ]; then
      echo "DP|${dp_result}" >>"$cache_file"
    fi

    # --- Hardcoded secrets ---
    local hs_result
    hs_result=$(classify_hardcoded_secrets "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$hs_result" ]; then
      echo "HS|${hs_result}" >>"$cache_file"
    fi

    # --- secrets: inherit ---
    local si_result
    si_result=$(classify_secrets_inherit "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$si_result" ]; then
      echo "SI|${si_result}" >>"$cache_file"
    fi

    # --- GITHUB_ENV/PATH/OUTPUT injection ---
    local ei_result
    ei_result=$(classify_env_injection "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$ei_result" ]; then
      echo "EI|${ei_result}" >>"$cache_file"
    fi

    # --- Deprecated workflow commands ---
    local dc_result
    dc_result=$(classify_deprecated_commands "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$dc_result" ]; then
      echo "DC|${dc_result}" >>"$cache_file"
    fi

    # --- Known-compromised actions ---
    local kv_result
    kv_result=$(classify_known_vulnerable "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$kv_result" ]; then
      echo "KV|${kv_result}" >>"$cache_file"
    fi

    # --- Unpinned third-party actions ---
    local utp_result
    utp_result=$(classify_unpinned_third_party "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$utp_result" ]; then
      echo "UTP|${utp_result}" >>"$cache_file"
    fi

    # --- always()/continue-on-error + secrets ---
    local as_result
    as_result=$(classify_always_secrets "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$as_result" ]; then
      echo "AS|${as_result}" >>"$cache_file"
    fi

    # --- Artifact trust ---
    local at_result
    at_result=$(classify_artifact_trust "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$at_result" ]; then
      echo "AT|${at_result}" >>"$cache_file"
    fi

    # --- Missing deployment environment ---
    local me_result
    me_result=$(classify_missing_environment "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$me_result" ]; then
      echo "ME|${me_result}" >>"$cache_file"
    fi

    # --- Cache poisoning ---
    local cp_result
    cp_result=$(classify_cache_poisoning "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$cp_result" ]; then
      echo "CP|${cp_result}" >>"$cache_file"
    fi

    # --- Static cloud credentials ---
    local sc_result
    sc_result=$(classify_static_credentials "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$sc_result" ]; then
      echo "SC|${sc_result}" >>"$cache_file"
    fi

    # --- Harden-runner ---
    if [[ $wf_uncommented == *step-security/harden-runner* ]]; then
      has_harden_runner=1
    fi
  done

  # Write META lines
  {
    echo "META|total_wf|$total_wf"
    echo "META|wf_with_perms|$wf_with_perms"
    echo "META|has_harden_runner|$has_harden_runner"
  } >>"$cache_file"
}

# _hdf_result_*: per-check result functions for HDF output.
# Each returns: status|codeDesc[|message]
# These adapt existing classifier outputs into the standard 3-field format
# used by the YAML-driven loop in build_hdf_repo_target/build_hdf_org_target.

# GHA-001: Explicit permissions check
# Args: $1=wf_with_perms $2=total_wf
_hdf_result_GHA_001() {
  local wf_with_perms="$1" total_wf="$2"
  if [ "$wf_with_perms" -eq "$total_wf" ]; then
    printf 'passed|All %s/%s workflows have permissions blocks' \
      "$total_wf" "$total_wf"
  else
    printf 'failed|%s/%s workflows have permissions blocks|%s workflow(s) missing permissions: block' \
      "$wf_with_perms" "$total_wf" "$((total_wf - wf_with_perms))"
  fi
}

# GHA-002: pull_request_target
# Args: findings as positional params (pass "${prt_findings[@]}")
_hdf_result_GHA_002() {
  if [ $# -eq 0 ]; then
    printf 'passed|No pull_request_target with unchecked fork code found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|pull_request_target findings|%s' "$detail"
  fi
}

# GHA-003: issue_comment
_hdf_result_GHA_003() {
  if [ $# -eq 0 ]; then
    printf 'passed|No ungated issue_comment triggers found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|issue_comment findings|%s' "$detail"
  fi
}

# GHA-004: Unpinned actions
_hdf_result_GHA_004() {
  if [ $# -eq 0 ]; then
    printf 'passed|All actions are SHA-pinned or no actions found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Unpinned action findings|%s' "$detail"
  fi
}

# GHA-005: Expression injection
_hdf_result_GHA_005() {
  if [ $# -eq 0 ]; then
    printf 'passed|No expression injection patterns found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Expression injection findings|%s' "$detail"
  fi
}

# GHA-006: workflow_run
_hdf_result_GHA_006() {
  if [ $# -eq 0 ]; then
    printf 'passed|No risky workflow_run patterns found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|workflow_run findings|%s' "$detail"
  fi
}

# GHA-007: Self-hosted runners
_hdf_result_GHA_007() {
  if [ $# -eq 0 ]; then
    printf 'passed|No self-hosted runner usage found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Self-hosted runner findings|%s' "$detail"
  fi
}

# GHA-008: Dangerous permissions
_hdf_result_GHA_008() {
  if [ $# -eq 0 ]; then
    printf 'passed|No excessive permissions found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Dangerous permissions findings|%s' "$detail"
  fi
}

# GHA-009: Hardcoded secrets
_hdf_result_GHA_009() {
  if [ $# -eq 0 ]; then
    printf 'passed|No hardcoded secrets found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Hardcoded secret findings|%s' "$detail"
  fi
}

# GHA-010: Harden-runner
# Args: $1=has_harden_runner (0 or 1)
_hdf_result_GHA_010() {
  if [ "$1" -eq 1 ]; then
    printf 'passed|step-security/harden-runner detected'
  else
    printf 'failed|No step-security/harden-runner usage found|Consider adding harden-runner for supply chain attack detection'
  fi
}

# GHA-014: secrets: inherit
_hdf_result_GHA_014() {
  if [ $# -eq 0 ]; then
    printf 'passed|No secrets: inherit found in reusable workflow calls'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|secrets: inherit findings|%s' "$detail"
  fi
}

# GHA-015: GITHUB_ENV/PATH/OUTPUT injection
_hdf_result_GHA_015() {
  if [ $# -eq 0 ]; then
    printf 'passed|No writes to GITHUB_ENV/PATH/OUTPUT found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|GITHUB_ENV/PATH/OUTPUT write findings|%s' "$detail"
  fi
}

# GHA-017: Deprecated workflow commands
_hdf_result_GHA_017() {
  if [ $# -eq 0 ]; then
    printf 'passed|No deprecated workflow commands found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Deprecated workflow command findings|%s' "$detail"
  fi
}

# GHA-018: Known-compromised actions
_hdf_result_GHA_018() {
  if [ $# -eq 0 ]; then
    printf 'passed|No known-compromised actions found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Known-compromised action findings|%s' "$detail"
  fi
}

# GHA-016: Additional expression injection contexts
# Uses same expr_findings as GHA-005 (shared classifier)
_hdf_result_GHA_016() {
  if [ $# -eq 0 ]; then
    printf 'passed|No additional dangerous expression contexts found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Additional expression injection contexts|%s' "$detail"
  fi
}

# GHA-019: github.event.ref injection
# Uses same expr_findings as GHA-005 (shared classifier)
_hdf_result_GHA_019() {
  if [ $# -eq 0 ]; then
    printf 'passed|No github.event.ref injection found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|github.event.ref injection findings|%s' "$detail"
  fi
}

# GHA-021: PRT checkout of untrusted refs
# Uses same prt_findings as GHA-002 (shared classifier)
_hdf_result_GHA_021() {
  if [ $# -eq 0 ]; then
    printf 'passed|No pull_request_target checkout of untrusted refs found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|PRT checkout of untrusted refs|%s' "$detail"
  fi
}

# GHA-020: Unpinned third-party actions
_hdf_result_GHA_020() {
  if [ $# -eq 0 ]; then
    printf 'passed|No unpinned third-party actions found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Unpinned third-party action findings|%s' "$detail"
  fi
}

# GHA-022: always()/continue-on-error + secrets
_hdf_result_GHA_022() {
  if [ $# -eq 0 ]; then
    printf 'passed|No always()/continue-on-error combined with secrets found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|always()/continue-on-error + secrets findings|%s' "$detail"
  fi
}

# GHA-023: Artifact trust validation
_hdf_result_GHA_023() {
  if [ $# -eq 0 ]; then
    printf 'passed|No unvalidated artifact downloads found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Artifact trust findings|%s' "$detail"
  fi
}

# GHA-024: Missing deployment environment
_hdf_result_GHA_024() {
  if [ $# -eq 0 ]; then
    printf 'passed|No deployments without environment protection found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Deployment without environment protection|%s' "$detail"
  fi
}

# GHA-025: Fork-triggered cache poisoning
_hdf_result_GHA_025() {
  if [ $# -eq 0 ]; then
    printf 'passed|No cache usage found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Cache poisoning risk|%s' "$detail"
  fi
}

# GHA-026: OIDC federation vs static credentials
_hdf_result_GHA_026() {
  if [ $# -eq 0 ]; then
    printf 'passed|No static cloud credentials without OIDC found'
  else
    local detail
    detail=$(printf '%s; ' "$@")
    printf 'failed|Static cloud credential findings|%s' "$detail"
  fi
}

# GHA-011: Org default workflow permissions
# Args: $1=default_wf_perm (e.g., "read" or "write")
_hdf_result_GHA_011() {
  if [ "$1" = "read" ]; then
    printf 'passed|default_workflow_permissions is read'
  else
    printf 'failed|default_workflow_permissions is %s|Should be read, not %s' "$1" "$1"
  fi
}

# GHA-012: Org PR approval policy
# Args: $1=can_approve_prs ("true" or "false")
_hdf_result_GHA_012() {
  if [ "$1" = "false" ]; then
    printf 'passed|can_approve_pull_request_reviews is false'
  else
    printf 'failed|can_approve_pull_request_reviews is %s|Workflows should not be able to approve PRs' "$1"
  fi
}

# GHA-013: Org allowed actions policy
# Args: $1=allowed_actions (e.g., "all", "selected", "verified")
_hdf_result_GHA_013() {
  if [ "$1" = "selected" ] || [ "$1" = "verified" ]; then
    printf 'passed|allowed_actions is %s' "$1"
  else
    printf 'failed|allowed_actions is %s|Should be selected or verified, not %s' "$1" "$1"
  fi
}

# GHA-029: Org secret scoping
# Args: $1=org_secrets_file (pipe-delimited file from Phase 3)
_hdf_result_GHA_029() {
  local org_secrets_file="$1"
  if [ ! -s "$org_secrets_file" ]; then
    printf 'passed|No org secrets found or file empty'
    return 0
  fi
  local all_vis_secrets
  all_vis_secrets=$(awk -F'|' '$2 == "All repositories" {print $1}' "$org_secrets_file" | paste -sd', ' -)
  if [ -z "$all_vis_secrets" ]; then
    printf 'passed|All org secrets are scoped to selected or private repositories'
  else
    printf 'failed|Org secrets with visibility all: %s|Scope these secrets to selected repositories' "$all_vis_secrets"
  fi
}

# build_hdf_repo_target: produce an HDF v2 target JSON object for a single repo.
# Reads classifier results from a pre-built cache file.
# Args: repo repo_dir cache_file
# Output: JSON object with targetId and requirements[] array to stdout.
build_hdf_repo_target() {
  local repo="$1"
  local repo_dir="$2"
  local cache_file="$3"

  # Read META values from cache
  local total_wf wf_with_perms has_harden_runner
  total_wf=$(awk -F'|' '$1 == "META" && $2 == "total_wf" {print $3}' "$cache_file")
  wf_with_perms=$(awk -F'|' '$1 == "META" && $2 == "wf_with_perms" {print $3}' "$cache_file")
  has_harden_runner=$(awk -F'|' '$1 == "META" && $2 == "has_harden_runner" {print $3}' "$cache_file")

  [ -z "$total_wf" ] || [ "$total_wf" -eq 0 ] && return 1

  # Read classifier findings from cache (MD detail only, used for HDF codeDesc)
  local prt_findings=() ic_findings=() unpin_findings=() expr_findings=()
  local wfr_findings=() sh_findings=() dp_findings=() hs_findings=()
  local si_findings=() ei_findings=() dc_findings=() kv_findings=()
  local utp_findings=() as_findings=() at_findings=()
  local me_findings=() cp_findings=() sc_findings=()

  local tag md_detail csv_detail
  while IFS='|' read -r tag md_detail csv_detail; do
    case "$tag" in
      PRT) prt_findings+=("$md_detail") ;;
      IC) ic_findings+=("$md_detail") ;;
      UNPIN) unpin_findings+=("$md_detail") ;;
      EXPR) expr_findings+=("$md_detail") ;;
      WFR) wfr_findings+=("$md_detail") ;;
      SH) sh_findings+=("$md_detail") ;;
      DP) dp_findings+=("$md_detail") ;;
      HS) hs_findings+=("$md_detail") ;;
      SI) si_findings+=("$md_detail") ;;
      EI) ei_findings+=("$md_detail") ;;
      DC) dc_findings+=("$md_detail") ;;
      KV) kv_findings+=("$md_detail") ;;
      UTP) utp_findings+=("$md_detail") ;;
      AS) as_findings+=("$md_detail") ;;
      AT) at_findings+=("$md_detail") ;;
      ME) me_findings+=("$md_detail") ;;
      CP) cp_findings+=("$md_detail") ;;
      SC) sc_findings+=("$md_detail") ;;
    esac
  done < <(grep -v '^META|' "$cache_file")

  # --- Build requirements JSON array via YAML-driven loop ---
  local reqs=()
  local profile_yaml="${HDF_PROFILE_DIR:-${BASH_SOURCE[0]%/*}/hdf-profile}/requirements.yaml"
  if [ -f "$profile_yaml" ]; then
    local req_id req_title req_impact req_severity req_impl
    local result status code_desc message
    while IFS='|' read -r req_id req_title req_impact req_severity req_impl; do
      [ -z "$req_id" ] && continue
      if [ "$req_impl" = "true" ]; then
        # Dispatch to the matching _hdf_result_GHA_XXX function
        case "$req_id" in
          GHA-001) result=$(_hdf_result_GHA_001 "$wf_with_perms" "$total_wf") ;;
          GHA-002) result=$(_hdf_result_GHA_002 "${prt_findings[@]}") ;;
          GHA-003) result=$(_hdf_result_GHA_003 "${ic_findings[@]}") ;;
          GHA-004) result=$(_hdf_result_GHA_004 "${unpin_findings[@]}") ;;
          GHA-005) result=$(_hdf_result_GHA_005 "${expr_findings[@]}") ;;
          GHA-006) result=$(_hdf_result_GHA_006 "${wfr_findings[@]}") ;;
          GHA-007) result=$(_hdf_result_GHA_007 "${sh_findings[@]}") ;;
          GHA-008) result=$(_hdf_result_GHA_008 "${dp_findings[@]}") ;;
          GHA-009) result=$(_hdf_result_GHA_009 "${hs_findings[@]}") ;;
          GHA-010) result=$(_hdf_result_GHA_010 "$has_harden_runner") ;;
          GHA-014) result=$(_hdf_result_GHA_014 "${si_findings[@]}") ;;
          GHA-015) result=$(_hdf_result_GHA_015 "${ei_findings[@]}") ;;
          GHA-017) result=$(_hdf_result_GHA_017 "${dc_findings[@]}") ;;
          GHA-018) result=$(_hdf_result_GHA_018 "${kv_findings[@]}") ;;
          GHA-016) result=$(_hdf_result_GHA_016 "${expr_findings[@]}") ;;
          GHA-019) result=$(_hdf_result_GHA_019 "${expr_findings[@]}") ;;
          GHA-020) result=$(_hdf_result_GHA_020 "${utp_findings[@]}") ;;
          GHA-021) result=$(_hdf_result_GHA_021 "${prt_findings[@]}") ;;
          GHA-022) result=$(_hdf_result_GHA_022 "${as_findings[@]}") ;;
          GHA-023) result=$(_hdf_result_GHA_023 "${at_findings[@]}") ;;
          GHA-024) result=$(_hdf_result_GHA_024 "${me_findings[@]}") ;;
          GHA-025) result=$(_hdf_result_GHA_025 "${cp_findings[@]}") ;;
          GHA-026) result=$(_hdf_result_GHA_026 "${sc_findings[@]}") ;;
          *) result="notReviewed|Detection not yet implemented" ;;
        esac
        IFS='|' read -r status code_desc message <<<"$result"
        reqs+=("$(emit_hdf_requirement "$req_id" \
          "$req_title" \
          "$req_impact" "$req_severity" "$status" "$code_desc" "$message")")
      else
        # Unimplemented → notReviewed
        reqs+=("$(emit_hdf_requirement "$req_id" \
          "$req_title" \
          "$req_impact" "$req_severity" "notReviewed" \
          "Detection not yet implemented")")
      fi
    done < <(
      awk '
      /^- id:/ { id=$3 }
      /^  title:/ { gsub(/^  title: "?/, ""); gsub(/"$/, ""); title=$0 }
      /^  impact:/ { impact=$2 }
      /^  severity:/ { severity=$2 }
      /^  classifier:/ { classifier=$2 }
      /^  implemented:/ {
        impl=$2
        if (index(classifier, "org_") != 1) {
          printf "%s|%s|%s|%s|%s\n", id, title, impact, severity, impl
        }
      }' "$profile_yaml"
    )
  fi

  # --- Assemble target JSON ---
  local esc_repo
  esc_repo=$(json_escape "$repo")
  printf '{"targetId": "%s", "requirements": [' "$esc_repo"
  local i
  for i in "${!reqs[@]}"; do
    if [ "$i" -gt 0 ]; then
      printf ', '
    fi
    printf '%s' "${reqs[$i]}"
  done
  printf ']}\n'
}

# _extract_hdf_status: extract the status of a requirement from HDF target JSON.
# Uses bash string manipulation (no jq dependency).
# Args: hdf_json req_id
# Output: "passed", "failed", "notReviewed", etc.
_extract_hdf_status() {
  local json="$1" req_id="$2"
  local after_id="${json#*\"id\": \""$req_id"\"}"
  local after_status="${after_id#*\"status\": \"}"
  printf '%s' "${after_status%%\"*}"
}

# render_md_csv_row: render a single repo's MD/CSV row from HDF status + cache.
# HDF determines pass/fail. The classifier cache provides display strings.
# Args: repo hdf_json cache_file repo_secrets md_file csv_file
render_md_csv_row() {
  local repo="$1"
  local hdf_json="$2"
  local cache_file="$3"
  local repo_secrets="$4"
  local md_file="$5"
  local csv_file="$6"

  # Read META values from cache
  local total_wf wf_with_perms has_harden_runner
  total_wf=$(awk -F'|' '$1 == "META" && $2 == "total_wf" {print $3}' "$cache_file")
  wf_with_perms=$(awk -F'|' '$1 == "META" && $2 == "wf_with_perms" {print $3}' "$cache_file")
  has_harden_runner=$(awk -F'|' '$1 == "META" && $2 == "has_harden_runner" {print $3}' "$cache_file")

  [ -z "$total_wf" ] || [ "$total_wf" -eq 0 ] && return 1

  # Read classifier findings from cache into arrays
  local prt_wfs=() prt_wfs_csv=()
  local ic_wfs=() ic_wfs_csv=()
  local unpin_wfs=() unpin_wfs_csv=()
  local expr_wfs=() expr_wfs_csv=()
  local wfr_wfs=() wfr_wfs_csv=()
  local sh_wfs=() sh_wfs_csv=()
  local dp_wfs=() dp_wfs_csv=()
  local hs_wfs=() hs_wfs_csv=()

  local tag md_detail csv_detail
  while IFS='|' read -r tag md_detail csv_detail; do
    case "$tag" in
      PRT)
        prt_wfs+=("$md_detail")
        prt_wfs_csv+=("$csv_detail")
        ;;
      IC)
        ic_wfs+=("$md_detail")
        ic_wfs_csv+=("$csv_detail")
        ;;
      UNPIN)
        unpin_wfs+=("$md_detail")
        unpin_wfs_csv+=("$csv_detail")
        ;;
      EXPR)
        expr_wfs+=("$md_detail")
        expr_wfs_csv+=("$csv_detail")
        ;;
      WFR)
        wfr_wfs+=("$md_detail")
        wfr_wfs_csv+=("$csv_detail")
        ;;
      SH)
        sh_wfs+=("$md_detail")
        sh_wfs_csv+=("$csv_detail")
        ;;
      DP)
        dp_wfs+=("$md_detail")
        dp_wfs_csv+=("$csv_detail")
        ;;
      HS)
        hs_wfs+=("$md_detail")
        hs_wfs_csv+=("$csv_detail")
        ;;
    esac
  done < <(grep -v '^META|' "$cache_file")

  # --- Build cells using HDF status as source of truth ---

  # Permissions: special case — needs N/M ratio from META, not a simple pass/fail
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

  # GHA-002..009: HDF status decides pass/fail; cache provides display detail
  local prt_cell prt_csv
  if [ "$(_extract_hdf_status "$hdf_json" "GHA-002")" = "passed" ]; then
    prt_cell="No"
    prt_csv="No"
  else
    prt_cell=$(join_array_cells '<br/>' "${prt_wfs[@]+"${prt_wfs[@]}"}")
    prt_csv=$(join_array_cells '; ' "${prt_wfs_csv[@]+"${prt_wfs_csv[@]}"}")
  fi

  local ic_cell ic_csv
  if [ "$(_extract_hdf_status "$hdf_json" "GHA-003")" = "passed" ]; then
    ic_cell="No"
    ic_csv="No"
  else
    ic_cell=$(join_array_cells '<br/>' "${ic_wfs[@]+"${ic_wfs[@]}"}")
    ic_csv=$(join_array_cells '; ' "${ic_wfs_csv[@]+"${ic_wfs_csv[@]}"}")
  fi

  local unpin_cell unpin_csv
  if [ "$(_extract_hdf_status "$hdf_json" "GHA-004")" = "passed" ]; then
    unpin_cell="No"
    unpin_csv="No"
  else
    unpin_cell=$(join_array_cells '<br/>' "${unpin_wfs[@]+"${unpin_wfs[@]}"}")
    unpin_csv=$(join_array_cells '; ' "${unpin_wfs_csv[@]+"${unpin_wfs_csv[@]}"}")
  fi

  local expr_cell expr_csv
  if [ "$(_extract_hdf_status "$hdf_json" "GHA-005")" = "passed" ]; then
    expr_cell="No"
    expr_csv="No"
  else
    expr_cell=$(join_array_cells '<br/>' "${expr_wfs[@]+"${expr_wfs[@]}"}")
    expr_csv=$(join_array_cells '; ' "${expr_wfs_csv[@]+"${expr_wfs_csv[@]}"}")
  fi

  local wfr_cell wfr_csv
  if [ "$(_extract_hdf_status "$hdf_json" "GHA-006")" = "passed" ]; then
    wfr_cell="No"
    wfr_csv="No"
  else
    wfr_cell=$(join_array_cells '<br/>' "${wfr_wfs[@]+"${wfr_wfs[@]}"}")
    wfr_csv=$(join_array_cells '; ' "${wfr_wfs_csv[@]+"${wfr_wfs_csv[@]}"}")
  fi

  local sh_cell sh_csv
  if [ "$(_extract_hdf_status "$hdf_json" "GHA-007")" = "passed" ]; then
    sh_cell="No"
    sh_csv="No"
  else
    sh_cell=$(join_array_cells '<br/>' "${sh_wfs[@]+"${sh_wfs[@]}"}")
    sh_csv=$(join_array_cells '; ' "${sh_wfs_csv[@]+"${sh_wfs_csv[@]}"}")
  fi

  local dp_cell dp_csv
  if [ "$(_extract_hdf_status "$hdf_json" "GHA-008")" = "passed" ]; then
    dp_cell="No"
    dp_csv="No"
  else
    dp_cell=$(join_array_cells '<br/>' "${dp_wfs[@]+"${dp_wfs[@]}"}")
    dp_csv=$(join_array_cells '; ' "${dp_wfs_csv[@]+"${dp_wfs_csv[@]}"}")
  fi

  local hs_cell hs_csv
  if [ "$(_extract_hdf_status "$hdf_json" "GHA-009")" = "passed" ]; then
    hs_cell="No"
    hs_csv="No"
  else
    hs_cell=$(join_array_cells '<br/>' "${hs_wfs[@]+"${hs_wfs[@]}"}")
    hs_csv=$(join_array_cells '; ' "${hs_wfs_csv[@]+"${hs_wfs_csv[@]}"}")
  fi

  # Harden-runner: HDF status passed→"Yes", failed→"No"
  local hr_cell
  if [ "$(_extract_hdf_status "$hdf_json" "GHA-010")" = "passed" ]; then
    hr_cell="Yes"
  else
    hr_cell="No"
  fi

  # Write directly to output files
  echo "${repo}|${perms_cell}|${prt_cell}|${ic_cell}|${unpin_cell}|${expr_cell}|${wfr_cell}|${sh_cell}|${dp_cell}|${hs_cell}|${hr_cell}|${repo_secrets}" >>"$md_file"
  echo "${repo}|${perms_csv}|${prt_csv}|${ic_csv}|${unpin_csv}|${expr_csv}|${wfr_csv}|${sh_csv}|${dp_csv}|${hs_csv}|${hr_cell}|${repo_secrets}" >>"$csv_file"
}

# build_hdf_org_target: produce an HDF v2 target JSON object for org-level checks.
# Uses the same YAML-driven loop as build_hdf_repo_target, filtered for org_ classifiers.
# Args: org default_wf_perm can_approve_prs allowed_actions [org_secrets_file]
# Output: JSON object with targetId and requirements[] array to stdout.
build_hdf_org_target() {
  local org="$1"
  local default_wf_perm="$2"
  local can_approve_prs="$3"
  local allowed_actions="$4"
  local org_secrets_file="${5:-}"

  local reqs=()
  local profile_yaml="${HDF_PROFILE_DIR:-${BASH_SOURCE[0]%/*}/hdf-profile}/requirements.yaml"
  if [ -f "$profile_yaml" ]; then
    local req_id req_title req_impact req_severity req_impl
    local result status code_desc message
    while IFS='|' read -r req_id req_title req_impact req_severity req_impl; do
      [ -z "$req_id" ] && continue
      if [ "$req_impl" = "true" ]; then
        case "$req_id" in
          GHA-011) result=$(_hdf_result_GHA_011 "$default_wf_perm") ;;
          GHA-012) result=$(_hdf_result_GHA_012 "$can_approve_prs") ;;
          GHA-013) result=$(_hdf_result_GHA_013 "$allowed_actions") ;;
          GHA-029) result=$(_hdf_result_GHA_029 "$org_secrets_file") ;;
          *) result="notReviewed|Detection not yet implemented" ;;
        esac
        IFS='|' read -r status code_desc message <<<"$result"
        reqs+=("$(emit_hdf_requirement "$req_id" \
          "$req_title" \
          "$req_impact" "$req_severity" "$status" "$code_desc" "$message")")
      else
        reqs+=("$(emit_hdf_requirement "$req_id" \
          "$req_title" \
          "$req_impact" "$req_severity" "notReviewed" \
          "Detection not yet implemented")")
      fi
    done < <(
      awk '
      /^- id:/ { id=$3 }
      /^  title:/ { gsub(/^  title: "?/, ""); gsub(/"$/, ""); title=$0 }
      /^  impact:/ { impact=$2 }
      /^  severity:/ { severity=$2 }
      /^  classifier:/ { classifier=$2 }
      /^  implemented:/ {
        impl=$2
        if (index(classifier, "org_") == 1) {
          printf "%s|%s|%s|%s|%s\n", id, title, impact, severity, impl
        }
      }' "$profile_yaml"
    )
  fi

  # --- Assemble target JSON ---
  local esc_org
  esc_org=$(json_escape "$org")
  printf '{"targetId": "%s", "requirements": [' "$esc_org"
  local i
  for i in "${!reqs[@]}"; do
    if [ "$i" -gt 0 ]; then
      printf ', '
    fi
    printf '%s' "${reqs[$i]}"
  done
  printf ']}\n'
}

# _emit_hdf_baseline: wrap a target JSON object in HDF v2 Evaluated_Baseline metadata.
# Args: target_json (JSON string with targetId and requirements fields)
# Output: one Evaluated_Baseline JSON object to stdout.
_emit_hdf_baseline() {
  local target_json="$1"

  # Extract targetId — simple parameter expansion (no jq)
  local target_id
  target_id="${target_json#*\"targetId\": \"}"
  target_id="${target_id%%\"*}"

  # Extract requirements array — everything between first [ and last ]
  local requirements
  requirements="${target_json#*\"requirements\": }"
  requirements="${requirements%\}}"
  # Trim trailing whitespace/newlines
  requirements="${requirements%"${requirements##*[![:space:]]}"}"

  local esc_id
  esc_id=$(json_escape "$target_id")

  printf '{"name": "%s", "title": "GitHub Actions Security Audit", "version": "0.1.0", "summary": "Security findings for %s", "maintainer": "gh-actions-audit", "license": "MIT", "supports": [], "status": "loaded", "requirements": %s}' \
    "$esc_id" "$esc_id" "$requirements"
}

# build_hdf_wrapper: assemble a complete HDF v2 document from target JSON objects.
# Args: org repo_targets_file org_target_json
#   org: organization name
#   repo_targets_file: temp file with one build_hdf_repo_target JSON object per line
#   org_target_json: single JSON string from build_hdf_org_target
# Output: complete HDF v2 JSON document to stdout.
build_hdf_wrapper() {
  local org="$1"
  local repo_targets_file="$2"
  local org_target_json="$3"

  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # --- baselines ---
  printf '{"baselines": ['
  local first=1
  local line
  # Read repo targets (one JSON per line, skip empty lines)
  if [ -s "$repo_targets_file" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      if [ "$first" -eq 0 ]; then
        printf ', '
      fi
      _emit_hdf_baseline "$line"
      first=0
    done <"$repo_targets_file"
  fi
  # Org baseline
  if [ -n "$org_target_json" ]; then
    if [ "$first" -eq 0 ]; then
      printf ', '
    fi
    _emit_hdf_baseline "$org_target_json"
  fi
  printf '], '

  # --- targets ---
  printf '"targets": ['
  first=1
  if [ -s "$repo_targets_file" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      local target_id
      target_id="${line#*\"targetId\": \"}"
      target_id="${target_id%%\"*}"
      if [ "$first" -eq 0 ]; then
        printf ', '
      fi
      local esc_name
      esc_name=$(json_escape "$org/$target_id")
      printf '{"type": "repository", "name": "%s"}' "$esc_name"
      first=0
    done <"$repo_targets_file"
  fi
  printf '], '

  # --- generator + timestamp ---
  printf '"generator": {"name": "gh-actions-audit", "version": "0.1.0"}, '
  printf '"timestamp": "%s"}\n' "$timestamp"
}

# Temp files to accumulate table rows
TABLE_ROWS_FILE=$(mktemp)
TABLE_ROWS_CSV_FILE=$(mktemp)
HDF_REPO_TARGETS_FILE=$(mktemp)
HDF_OUTPUT_FILE=$(mktemp)

CLASSIFIER_CACHE_FILE=$(mktemp)

for repo in "${REPOS[@]}"; do
  repo_dir="$WORKFLOWS_DIR/$ORG/$repo"
  [ -d "$repo_dir" ] || continue

  : >"$CLASSIFIER_CACHE_FILE"
  run_repo_classifiers "$repo_dir" "$CLASSIFIER_CACHE_FILE" || continue

  # HDF is the source of truth for pass/fail status
  hdf_target_json=$(build_hdf_repo_target "$repo" "$repo_dir" "$CLASSIFIER_CACHE_FILE") || continue
  printf '%s\n' "$hdf_target_json" >>"$HDF_REPO_TARGETS_FILE"

  # Per-repo secrets (inventory metadata, not an HDF requirement)
  repo_secrets=""
  secret_names=$(gh api "repos/$ORG/$repo/actions/secrets" --jq '.secrets[].name' 2>/dev/null) || {
    warn "Could not fetch secrets for $repo (may lack repo admin access)."
    secret_names=""
  }
  if [ -z "$secret_names" ]; then
    repo_secrets="(none)"
  else
    repo_secrets=$(paste -sd', ' - <<<"$secret_names")
  fi

  # Render MD/CSV from HDF status + cache display strings
  render_md_csv_row "$repo" "$hdf_target_json" "$CLASSIFIER_CACHE_FILE" \
    "$repo_secrets" "$TABLE_ROWS_FILE" "$TABLE_ROWS_CSV_FILE"

  progress "$repo"
done

printf '\033[2K\r' # clear progress line
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
  # Build secret→repo mapping in a single pass over all workflow files.
  # Format: SECRET_NAME|repo_name (one line per reference, sorted/deduped later)
  # This avoids O(N×M) grep calls (one per secret × all files).
  SECRET_MAP_FILE=$(mktemp)
  while IFS= read -r wf_file; do
    [ -z "$wf_file" ] && continue
    repo_name=$(echo "$wf_file" | sed "s|$WORKFLOWS_DIR/$ORG/||" | cut -d/ -f1)
    # Extract all secret names referenced in this file
    grep -oE 'secrets\.[A-Za-z0-9_]+' "$wf_file" 2>/dev/null \
      | sed 's/^secrets\.//' \
      | sort -u \
      | while IFS= read -r ref_secret; do
        echo "${ref_secret}|${repo_name}"
      done
  done < <(find_workflow_files "$WORKFLOWS_DIR") >>"$SECRET_MAP_FILE"

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

    # Look up from pre-built map file
    referenced_repos=$(awk -F'|' -v name="$secret_name" '$1 == name {print $2}' "$SECRET_MAP_FILE" 2>/dev/null \
      | sort -u | paste -sd',' - || true)
    [ -z "$referenced_repos" ] && referenced_repos="(none)"

    # Build remediation command once (used by both md and csv reports)
    remediation_cmd=""
    if [ "$vis_display" = "All repositories" ]; then
      if [ "$referenced_repos" = "(none)" ]; then
        remediation_cmd="Unreferenced - verify if still needed"
      else
        remediation_cmd="gh secret set $secret_name --org $ORG --visibility selected --repos $referenced_repos"
      fi
    fi

    echo "${secret_name}|${vis_display}|${configured_repos}|${referenced_repos}|${remediation_cmd}" >>"$ORG_SECRETS_FILE"
  done <<<"$org_secrets"
fi

printf '\033[2K\r' # clear progress line
info "Org secrets enumeration complete."

# =============================================================================
# PHASE 4: Org-level settings
# =============================================================================

info "Fetching org-level Actions settings..."

# Fetch workflow permissions + PR approval in a single API call
wf_perms_response=$(gh api "orgs/$ORG/actions/permissions/workflow" \
  --jq '(.default_workflow_permissions // "unknown") + "|" + ((.can_approve_pull_request_reviews // "unknown") | tostring)' 2>/dev/null) || {
  warn "Could not fetch org workflow permissions (check admin:org scope)."
  wf_perms_response="unknown|unknown"
}
default_wf_perm="${wf_perms_response%%|*}"
can_approve_prs="${wf_perms_response#*|}"
allowed_actions=$(gh api "orgs/$ORG/actions/permissions" --jq '.allowed_actions // "unknown"' 2>/dev/null) || {
  warn "Could not fetch org actions permissions (check admin:org scope)."
  allowed_actions="unknown"
}

# --- Build HDF v2 document ---
HDF_ORG_TARGET_JSON=$(build_hdf_org_target "$ORG" "$default_wf_perm" "$can_approve_prs" "$allowed_actions" "$ORG_SECRETS_FILE")
build_hdf_wrapper "$ORG" "$HDF_REPO_TARGETS_FILE" "$HDF_ORG_TARGET_JSON" >"$HDF_OUTPUT_FILE"

if [ -n "$HDF_FILE" ]; then
  cp "$HDF_OUTPUT_FILE" "$HDF_FILE"
  info "HDF v2 report written to $HDF_FILE"
fi

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
- **Unpinned Actions**: Action references using mutable tags (`@v4`, `@main`) instead of immutable SHA
  pins (`@692973e3...`). Unpinned actions are vulnerable to tag-override attacks (e.g. tj-actions/changed-files
  compromise, CVE-2025-30066). Shows pinned/total ratio per workflow file.
- **Expression Injection**: Dangerous `${{ }}` expressions used directly in `run:` blocks. User-controlled
  values like `github.event.pull_request.title` or `github.head_ref` can inject arbitrary shell commands
  when interpolated into `run:` scripts. The safe alternative is to assign to an `env:` variable first.
- **`workflow_run`**: Workflows triggered by `workflow_run` bypass fork PR restrictions and run with
  write permissions and secrets. Sub-classified by risk: download-artifact (HIGH — artifact poisoning),
  checkout (MEDIUM), API-only (LOW).
- **Self-Hosted Runners**: Workflows using `runs-on: self-hosted` (or custom labels). Self-hosted runners
  are persistent machines — a compromised runner gives attackers host network access and cached credentials.
  Especially dangerous when combined with `pull_request_target` or `issue_comment` triggers.
- **Dangerous Permissions**: Workflows granting elevated permissions like `write-all`, `contents: write`,
  `actions: write`, or `id-token: write`. A `permissions:` block exists but grants excessive access.
- **Hardcoded Secrets**: Workflows containing hardcoded tokens or API keys (e.g. `ghp_*`, `gho_*`, `AKIA*`).
  These should use GitHub Secrets instead. The SpotBugs attack chain started with a PAT in a workflow file.
- **Harden-Runner**: Whether any workflow uses [step-security/harden-runner](https://github.com/step-security/harden-runner)
  for runtime monitoring (network egress, file integrity). Harden-runner detected the tj-actions compromise in real-time.
- **Repo Secrets**: Secret names configured directly on the repo (not values). These are accessible
  to any workflow that runs in the repo, including exploited `pull_request_target` workflows.

PERREPO

  # --- Summary statistics ---
  # Fields: repo(1)|perms(2)|prt(3)|ic(4)|unpin(5)|expr(6)|wfr(7)|sh(8)|dp(9)|hs(10)|hr(11)|secrets(12)
  total_repos_scanned=$(wc -l <"$TABLE_ROWS_FILE" | tr -d ' ')
  no_perms_count=$(awk -F'|' '$2 ~ /None/ {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  prt_count=$(awk -F'|' '$3 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  ic_count=$(awk -F'|' '$4 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  unpin_count=$(awk -F'|' '$5 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  expr_count=$(awk -F'|' '$6 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  wfr_count=$(awk -F'|' '$7 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  sh_count=$(awk -F'|' '$8 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  dp_count=$(awk -F'|' '$9 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  hs_count=$(awk -F'|' '$10 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  hr_count=$(awk -F'|' '$11 == "Yes" {c++} END {print c+0}' "$TABLE_ROWS_FILE")

  echo "### Summary"
  echo ""
  echo "| Metric | Count |"
  echo "|--------|-------|"
  echo "| Repos scanned | $total_repos_scanned |"
  echo "| Repos with no \`permissions:\` blocks | $no_perms_count |"
  [ "$prt_count" -gt 0 ] && echo "| Repos with \`pull_request_target\` | $prt_count |"
  [ "$ic_count" -gt 0 ] && echo "| Repos with \`issue_comment\` | $ic_count |"
  [ "$unpin_count" -gt 0 ] && echo "| Repos with unpinned actions | $unpin_count |"
  [ "$expr_count" -gt 0 ] && echo "| Repos with expression injection risk | $expr_count |"
  [ "$wfr_count" -gt 0 ] && echo "| Repos with \`workflow_run\` | $wfr_count |"
  [ "$sh_count" -gt 0 ] && echo "| Repos with self-hosted runners | $sh_count |"
  [ "$dp_count" -gt 0 ] && echo "| Repos with dangerous permissions | $dp_count |"
  [ "$hs_count" -gt 0 ] && echo "| Repos with hardcoded secrets | $hs_count |"
  echo "| Repos with harden-runner | $hr_count/$total_repos_scanned |"
  echo ""

  echo "| Repository | Permissions | \`pull_request_target\` | \`issue_comment\` | Unpinned Actions | Expr Injection | \`workflow_run\` | Self-Hosted | Dangerous Perms | Hardcoded Secrets | Harden-Runner | Repo Secrets |"
  echo "|------------|-------------|----------------------|-----------------|-----------------|----------------|---------------|-------------|-----------------|-------------------|---------------|--------------|"

  while IFS='|' read -r repo perms prt ic unpin expr wfr sh dp hs hr secrets; do
    echo "| [\`$repo\`](https://github.com/$ORG/$repo/tree/HEAD/.github/workflows) | $perms | $prt | $ic | $unpin | $expr | $wfr | $sh | $dp | $hs | $hr | $secrets |"
  done < <(sort "$TABLE_ROWS_FILE")

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

    while IFS='|' read -r name vis configured referenced cmd; do
      if [ -n "$cmd" ]; then
        echo "| \`$name\` | **$vis** | $configured | $referenced | \`$cmd\` |"
      else
        echo "| \`$name\` | $vis | $configured | $referenced | — |"
      fi
    done < <(sort "$ORG_SECRETS_FILE")
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

4. **Expression injection in `run:` blocks**: Dangerous `${{ }}` expressions like
   `github.event.pull_request.title` or `github.head_ref` used directly in `run:` blocks allow
   arbitrary command injection. Attackers control these values via PR titles, branch names, issue
   bodies, and comments. Use `env:` variables instead: `env: TITLE: ${{ github.event.pull_request.title }}`
   then reference `$TITLE` in the `run:` block.

5. **Unpinned actions**: Actions referenced by mutable tag (`@v4`, `@main`) instead of immutable
   SHA (`@692973e3...`) are vulnerable to tag-override supply chain attacks (CVE-2025-30066,
   tj-actions/changed-files compromise affected 23K+ repos). Pin all third-party actions to full SHAs.

6. **Org secrets with "All repositories" visibility**: These are accessible from any workflow
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
- **SHA-pinned actions**: `uses: actions/checkout@692973e3...` is immutable; `@v4` can be moved
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
    echo "Repository,Explicit Permissions,pull_request_target,issue_comment,Unpinned Actions,Expression Injection,workflow_run,Self-Hosted,Dangerous Perms,Hardcoded Secrets,Harden-Runner,Repo Secrets"
    while IFS='|' read -r repo perms prt ic unpin expr wfr sh dp hs hr secrets; do
      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv_field "$repo")" \
        "$(csv_field "$perms")" \
        "$(csv_field "$prt")" \
        "$(csv_field "$ic")" \
        "$(csv_field "$unpin")" \
        "$(csv_field "$expr")" \
        "$(csv_field "$wfr")" \
        "$(csv_field "$sh")" \
        "$(csv_field "$dp")" \
        "$(csv_field "$hs")" \
        "$(csv_field "$hr")" \
        "$(csv_field "$secrets")"
    done < <(sort "$TABLE_ROWS_CSV_FILE")

    # Blank row separator, then org secrets
    echo ""
    echo "Org Secret,Visibility,Configured Access,Referenced In Workflows,Suggested Command"
    if [ -s "$ORG_SECRETS_FILE" ]; then
      while IFS='|' read -r name vis configured referenced cmd; do
        printf '%s,%s,%s,%s,%s\n' \
          "$(csv_field "$name")" \
          "$(csv_field "$vis")" \
          "$(csv_field "$configured")" \
          "$(csv_field "$referenced")" \
          "$(csv_field "$cmd")"
      done < <(sort "$ORG_SECRETS_FILE")
    fi
  } >"$CSV_FILE"

  info "CSV written to: $CSV_FILE"
fi

# --- Cleanup (temp files handled by trap EXIT) ---

info "Report written to: $OUT_FILE"
handle_cache_cleanup
