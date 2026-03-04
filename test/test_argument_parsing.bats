#!/usr/bin/env bats

setup() {
  load test_helper/common-setup
}

# =============================================================================
# Temp file safety — all temp files must be created via mktemp
# =============================================================================

@test "TABLE_ROWS_FILE and TABLE_ROWS_CSV_FILE use separate mktemp calls" {
  # Each temp file must be its own mktemp call, not string concatenation
  run grep -c 'TABLE_ROWS.*mktemp\|mktemp.*TABLE_ROWS' "$SCRIPT"
  # Should appear at least twice (one for md, one for csv)
  assert_success
  local count="${output}"
  [ "$count" -ge 2 ]
}

@test "AUDIT_DIR uses mktemp -d when not using --local" {
  run grep -n 'AUDIT_DIR=' "$SCRIPT"
  assert_output --partial 'mktemp -d'
}

@test "script has trap EXIT for temp file cleanup" {
  run grep -n 'trap.*EXIT' "$SCRIPT"
  assert_success
  assert_output --partial 'cleanup'
}

@test "cleanup function removes temp files" {
  run grep -A5 'cleanup()' "$SCRIPT"
  assert_success
  assert_output --partial 'TABLE_ROWS_FILE'
  assert_output --partial 'ORG_SECRETS_FILE'
}

@test "gh api calls for org settings warn on failure instead of silent fallback" {
  # Phase 4 org settings API calls should use warn() on failure, not just
  # silently fall back to 'unknown' or '{}'
  run grep -A2 'gh api "orgs/\$ORG/actions/permissions' "$SCRIPT"
  assert_success
  assert_output --partial 'warn'
}

@test "gh api call for org secrets warns on failure" {
  run grep -A2 'gh api "orgs/\$ORG/actions/secrets"' "$SCRIPT"
  assert_success
  assert_output --partial 'warn'
}

@test "render_md_csv_row function is defined and called in Phase 2" {
  run grep -c 'render_md_csv_row()' "$SCRIPT"
  assert_success
  # Should appear at least once (the definition)
  run grep 'render_md_csv_row ' "$SCRIPT"
  assert_success
}

@test "handle_cache_cleanup function is defined and called" {
  run grep -c 'handle_cache_cleanup()' "$SCRIPT"
  assert_output "1"
  run grep -c 'handle_cache_cleanup$' "$SCRIPT"
  assert_output "1"
}

@test "workflow files are read once into a variable, not grepped repeatedly" {
  # Each workflow should be read into wf_content once, not grepped 10 times
  # Check that we use cat/read into variable, not direct grep on file for analysis
  run grep -c 'wf_content' "$SCRIPT"
  assert_success
  # Should appear multiple times (read + multiple checks)
  local count="${output}"
  [ "$count" -ge 5 ]
}

@test "repo list uses while-read loop, not for-in word splitting" {
  # for repo in $all_repos is unsafe with spaces; must use while read
  run grep -n 'for repo in \$all_repos' "$SCRIPT"
  assert_failure
}

@test "workflow list uses while-read loop, not for-in word splitting" {
  run grep -n 'for wf in \$wf_list' "$SCRIPT"
  assert_failure
}

@test "warns when repo list hits 1000 limit" {
  run grep -c 'warn.*1000 limit\|1000.*warn' "$SCRIPT"
  assert_success
}

@test "sort-pipe-while loops use process substitution" {
  # sort FILE | while runs the while body in a subshell (variable scoping risk).
  # Use: while ... done < <(sort FILE) instead.
  run grep -c 'sort.*| while' "$SCRIPT"
  assert_output "0"
}

@test "script does not use python3 for JSON parsing" {
  # All JSON parsing should use gh api --jq, not python3
  run grep -n 'python3' "$SCRIPT"
  assert_failure
}

@test "base64 decode uses portable detection, not hardcoded -d" {
  # Stock macOS base64 uses -D or --decode, not -d (which is GNU-only).
  # The script should detect the correct flag via BASE64_DECODE array.
  # Verify: the actual decode call uses the variable, not a hardcoded flag.
  run grep -n 'BASE64_DECODE' "$SCRIPT"
  assert_success
  # The pipe usage should reference the array, not a literal base64 -d
  run grep 'echo.*| base64 -d' "$SCRIPT"
  refute_output --partial '> "$repo_dir'
}

# =============================================================================
# require_arg() unit tests
# =============================================================================

_run_require_arg() {
  local tmpscript
  tmpscript=$(mktemp)
  {
    sed -n '/^require_arg()/,/^}/p' "$SCRIPT"
    echo "$@"
  } >"$tmpscript"
  bash "$tmpscript"
  local rc=$?
  rm -f "$tmpscript"
  return $rc
}

@test "require_arg: missing arg exits 1 with error" {
  run _run_require_arg 'require_arg "--local" "" "a directory path" "/path/to/dir"'
  assert_failure
  assert_output --partial "Error: --local requires a directory path"
}

@test "require_arg: flag-like arg exits 1 with error" {
  run _run_require_arg 'require_arg "--out" "--csv" "a filename" "report.md"'
  assert_failure
  assert_output --partial "Error: --out requires a filename"
}

@test "require_arg: valid arg succeeds silently" {
  run _run_require_arg 'require_arg "--csv" "report.csv" "a filename" "report.csv"'
  assert_success
  assert_output ""
}

# --- Help flag ---

@test "--help prints usage and exits 0" {
  run bash "$SCRIPT" --help
  assert_success
  assert_output --partial "GitHub Actions Security Audit"
}

@test "-h prints usage and exits 0" {
  run bash "$SCRIPT" -h
  assert_success
  assert_output --partial "GitHub Actions Security Audit"
}

# --- Missing org ---

@test "no arguments prints usage to stderr and exits 1" {
  run bash "$SCRIPT"
  assert_failure
  assert_output --partial "Usage:"
}

# --- Unknown option ---

@test "unknown option exits 1" {
  run bash "$SCRIPT" my-org --bogus
  assert_failure
  assert_output --partial "Unknown option"
}

# --- Duplicate org ---

@test "two positional args exits 1" {
  run bash "$SCRIPT" org1 org2
  assert_failure
  assert_output --partial "Only one org at a time"
}

# --- ORG name validation ---

@test "ORG with slashes is rejected" {
  run bash "$SCRIPT" "../../etc"
  assert_failure
  assert_output --partial "Invalid org name"
}

@test "ORG with spaces is rejected" {
  run bash "$SCRIPT" "my org"
  assert_failure
  assert_output --partial "Invalid org name"
}

@test "valid ORG names are accepted (alphanumeric, hyphen, underscore)" {
  # This should pass validation but fail later at gh auth — we just check it doesn't
  # fail with "Invalid org name"
  run bash "$SCRIPT" "my-org_123"
  refute_output --partial "Invalid org name"
}

# --- --local requires a directory ---

@test "--local without argument exits 1" {
  run bash "$SCRIPT" my-org --local
  assert_failure
  assert_output --partial "requires a directory"
}

# --- --local with nonexistent directory exits 1 ---

@test "--local with nonexistent dir exits 1" {
  run bash "$SCRIPT" my-org --local /tmp/nonexistent-dir-$$
  assert_failure
  assert_output --partial "does not exist"
}

# --- --out requires a filename ---

@test "--out without argument exits 1" {
  run bash "$SCRIPT" my-org --out
  assert_failure
  assert_output --partial "requires a filename"
}

# --- --csv requires a filename ---

@test "--csv without argument exits 1" {
  run bash "$SCRIPT" my-org --csv
  assert_failure
  assert_output --partial "requires a filename"
}

# --- --hdf requires a filename ---

@test "--hdf without argument exits 1" {
  run bash "$SCRIPT" my-org --hdf
  assert_failure
  assert_output --partial "requires a filename"
}

# =============================================================================
# Structural: robustness checks (ct5, i45, 1rx)
# =============================================================================

@test "gh repo list failure is handled with crit and exit" {
  # ct5: repo list must not silently produce empty reports
  run grep -A2 'gh repo list' "$SCRIPT"
  assert_success
  assert_output --partial "crit"
}

@test "Phase 4: permissions/workflow endpoint called only once" {
  # i45: single API call, not two separate calls
  local count
  count=$(grep -c 'actions/permissions/workflow' "$SCRIPT")
  [ "$count" -eq 1 ]
}

@test "render_md_csv_row writes directly to files (no head/tail split)" {
  # 1rx: render_md_csv_row must not output to stdout for head/tail parsing
  run grep -E 'head -1.*TABLE_ROWS|tail -1.*TABLE_ROWS' "$SCRIPT"
  assert_failure
}
