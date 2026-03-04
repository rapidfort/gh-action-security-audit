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
  rm -f "${TABLE_ROWS_FILE:-}" "${TABLE_ROWS_CSV_FILE:-}" "${ORG_SECRETS_FILE:-}" "${SECRET_MAP_FILE:-}"
}
trap cleanup EXIT

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

  printf "%-80s\n" " " # clear progress line
  info "Downloaded $downloaded workflow files from ${#REPOS[@]} repos ($skipped_no_wf repos had no workflows)"
fi

# =============================================================================
# PHASE 2: Analyze workflows per-repo
# =============================================================================

info "Analyzing workflows..."

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
  local dangerous_pattern='github\.event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body|review\.body|commits\[)|github\.head_ref'

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

# --- analyze_repo: analyze a single repo's workflow files ---
# Writes pipe-delimited rows directly to md and csv temp files.
# Args: repo repo_dir md_file csv_file
# Globals: ORG, WORKFLOWS_DIR
analyze_repo() {
  local repo="$1"
  local repo_dir="$2"
  local md_file="$3"
  local csv_file="$4"

  local wf_files=()
  while IFS= read -r f; do
    wf_files+=("$f")
  done < <(find_workflow_files "$repo_dir")

  [ ${#wf_files[@]} -eq 0 ] && return 1

  local total_wf=${#wf_files[@]}
  local wf_with_perms=0
  local prt_wfs=()
  local prt_wfs_csv=()
  local ic_wfs=()
  local ic_wfs_csv=()
  local unpin_wfs=()
  local unpin_wfs_csv=()
  local expr_wfs=()
  local expr_wfs_csv=()
  local wfr_wfs=()
  local wfr_wfs_csv=()
  local sh_wfs=()
  local sh_wfs_csv=()
  local dp_wfs=()
  local dp_wfs_csv=()

  local f wf_name wf_content wf_uncommented

  for f in "${wf_files[@]}"; do
    wf_name=$(basename "$f")
    wf_content=$(cat "$f" 2>/dev/null) || continue
    wf_uncommented=$(grep -v '^\s*#' <<<"$wf_content")

    # --- Permissions ---
    if grep -q 'permissions:' <<<"$wf_uncommented"; then
      wf_with_perms=$((wf_with_perms + 1))
    fi

    # --- pull_request_target ---
    if [[ $wf_uncommented == *pull_request_target* ]]; then
      local prt_result
      prt_result=$(classify_prt "$wf_name" "$wf_content" "$wf_uncommented")
      prt_wfs+=("${prt_result%%|*}")
      prt_wfs_csv+=("${prt_result#*|}")
    fi

    # --- issue_comment ---
    if [[ $wf_uncommented == *issue_comment* ]]; then
      local ic_result
      ic_result=$(classify_ic "$wf_name" "$wf_content" "$wf_uncommented")
      ic_wfs+=("${ic_result%%|*}")
      ic_wfs_csv+=("${ic_result#*|}")
    fi

    # --- Unpinned actions ---
    local unpin_result
    unpin_result=$(classify_unpinned "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$unpin_result" ]; then
      unpin_wfs+=("${unpin_result%%|*}")
      unpin_wfs_csv+=("${unpin_result#*|}")
    fi

    # --- Expression injection ---
    local expr_result
    expr_result=$(classify_expr_injection "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$expr_result" ]; then
      expr_wfs+=("${expr_result%%|*}")
      expr_wfs_csv+=("${expr_result#*|}")
    fi

    # --- workflow_run ---
    if [[ $wf_uncommented == *workflow_run* ]]; then
      local wfr_result
      wfr_result=$(classify_wfr "$wf_name" "$wf_content" "$wf_uncommented")
      if [ -n "$wfr_result" ]; then
        wfr_wfs+=("${wfr_result%%|*}")
        wfr_wfs_csv+=("${wfr_result#*|}")
      fi
    fi

    # --- Self-hosted runners ---
    local sh_result
    sh_result=$(classify_self_hosted "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$sh_result" ]; then
      sh_wfs+=("${sh_result%%|*}")
      sh_wfs_csv+=("${sh_result#*|}")
    fi

    # --- Dangerous permissions ---
    local dp_result
    dp_result=$(classify_dangerous_perms "$wf_name" "$wf_content" "$wf_uncommented")
    if [ -n "$dp_result" ]; then
      dp_wfs+=("${dp_result%%|*}")
      dp_wfs_csv+=("${dp_result#*|}")
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
  prt_cell=$(join_array_cells '<br/>' "${prt_wfs[@]+"${prt_wfs[@]}"}")
  prt_csv=$(join_array_cells '; ' "${prt_wfs_csv[@]+"${prt_wfs_csv[@]}"}")

  local ic_cell ic_csv
  ic_cell=$(join_array_cells '<br/>' "${ic_wfs[@]+"${ic_wfs[@]}"}")
  ic_csv=$(join_array_cells '; ' "${ic_wfs_csv[@]+"${ic_wfs_csv[@]}"}")

  local unpin_cell unpin_csv
  unpin_cell=$(join_array_cells '<br/>' "${unpin_wfs[@]+"${unpin_wfs[@]}"}")
  unpin_csv=$(join_array_cells '; ' "${unpin_wfs_csv[@]+"${unpin_wfs_csv[@]}"}")

  local expr_cell expr_csv
  expr_cell=$(join_array_cells '<br/>' "${expr_wfs[@]+"${expr_wfs[@]}"}")
  expr_csv=$(join_array_cells '; ' "${expr_wfs_csv[@]+"${expr_wfs_csv[@]}"}")

  local wfr_cell wfr_csv
  wfr_cell=$(join_array_cells '<br/>' "${wfr_wfs[@]+"${wfr_wfs[@]}"}")
  wfr_csv=$(join_array_cells '; ' "${wfr_wfs_csv[@]+"${wfr_wfs_csv[@]}"}")

  local sh_cell sh_csv
  sh_cell=$(join_array_cells '<br/>' "${sh_wfs[@]+"${sh_wfs[@]}"}")
  sh_csv=$(join_array_cells '; ' "${sh_wfs_csv[@]+"${sh_wfs_csv[@]}"}")

  local dp_cell dp_csv
  dp_cell=$(join_array_cells '<br/>' "${dp_wfs[@]+"${dp_wfs[@]}"}")
  dp_csv=$(join_array_cells '; ' "${dp_wfs_csv[@]+"${dp_wfs_csv[@]}"}")

  local secrets_cell=""
  local secret_names
  secret_names=$(gh api "repos/$ORG/$repo/actions/secrets" --jq '.secrets[].name' 2>/dev/null) || {
    warn "Could not fetch secrets for $repo (may lack repo admin access)."
    secret_names=""
  }
  if [ -z "$secret_names" ]; then
    secrets_cell="(none)"
  else
    secrets_cell=$(paste -sd', ' - <<<"$secret_names")
  fi

  # Write directly to output files — no fragile head/tail split
  echo "${repo}|${perms_cell}|${prt_cell}|${ic_cell}|${unpin_cell}|${expr_cell}|${wfr_cell}|${sh_cell}|${dp_cell}|${secrets_cell}" >>"$md_file"
  echo "${repo}|${perms_csv}|${prt_csv}|${ic_csv}|${unpin_csv}|${expr_csv}|${wfr_csv}|${sh_csv}|${dp_csv}|${secrets_cell}" >>"$csv_file"
}

# Temp files to accumulate table rows
TABLE_ROWS_FILE=$(mktemp)
TABLE_ROWS_CSV_FILE=$(mktemp)

for repo in "${REPOS[@]}"; do
  repo_dir="$WORKFLOWS_DIR/$ORG/$repo"
  [ -d "$repo_dir" ] || continue

  analyze_repo "$repo" "$repo_dir" "$TABLE_ROWS_FILE" "$TABLE_ROWS_CSV_FILE" || continue
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

printf "%-80s\n" " " # clear progress line
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
- **Repo Secrets**: Secret names configured directly on the repo (not values). These are accessible
  to any workflow that runs in the repo, including exploited `pull_request_target` workflows.

PERREPO

  # --- Summary statistics ---
  # Fields: repo(1)|perms(2)|prt(3)|ic(4)|unpin(5)|expr(6)|wfr(7)|sh(8)|dp(9)|secrets(10)
  total_repos_scanned=$(wc -l <"$TABLE_ROWS_FILE" | tr -d ' ')
  no_perms_count=$(awk -F'|' '$2 ~ /None/ {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  prt_count=$(awk -F'|' '$3 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  ic_count=$(awk -F'|' '$4 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  unpin_count=$(awk -F'|' '$5 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  expr_count=$(awk -F'|' '$6 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  wfr_count=$(awk -F'|' '$7 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  sh_count=$(awk -F'|' '$8 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")
  dp_count=$(awk -F'|' '$9 != "No" {c++} END {print c+0}' "$TABLE_ROWS_FILE")

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
  echo ""

  echo "| Repository | Permissions | \`pull_request_target\` | \`issue_comment\` | Unpinned Actions | Expr Injection | \`workflow_run\` | Self-Hosted | Dangerous Perms | Repo Secrets |"
  echo "|------------|-------------|----------------------|-----------------|-----------------|----------------|---------------|-------------|-----------------|--------------|"

  while IFS='|' read -r repo perms prt ic unpin expr wfr sh dp secrets; do
    echo "| [\`$repo\`](https://github.com/$ORG/$repo/tree/HEAD/.github/workflows) | $perms | $prt | $ic | $unpin | $expr | $wfr | $sh | $dp | $secrets |"
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
    echo "Repository,Explicit Permissions,pull_request_target,issue_comment,Unpinned Actions,Expression Injection,workflow_run,Self-Hosted,Dangerous Perms,Repo Secrets"
    while IFS='|' read -r repo perms prt ic unpin expr wfr sh dp secrets; do
      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv_field "$repo")" \
        "$(csv_field "$perms")" \
        "$(csv_field "$prt")" \
        "$(csv_field "$ic")" \
        "$(csv_field "$unpin")" \
        "$(csv_field "$expr")" \
        "$(csv_field "$wfr")" \
        "$(csv_field "$sh")" \
        "$(csv_field "$dp")" \
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
