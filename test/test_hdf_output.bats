#!/usr/bin/env bats
#
# Tests for HDF v2 JSON output generation.
# TDD: Red phase — json_escape() and HDF rendering functions.

setup() {
  load test_helper/common-setup
}

# =============================================================================
# json_escape() unit tests
# =============================================================================

# Helper: extract json_escape from the script and run it
_run_json_escape() {
  local input="$1"
  local tmpscript tmpinput
  tmpscript=$(mktemp)
  tmpinput=$(mktemp)
  printf '%s' "$input" >"$tmpinput"
  {
    sed -n '/^json_escape()/,/^}/p' "$SCRIPT"
    printf 'json_escape "$(cat %s)"\n' "$tmpinput"
  } >"$tmpscript"
  bash "$tmpscript"
  rm -f "$tmpscript" "$tmpinput"
}

@test "json_escape: plain string passes through unchanged" {
  run _run_json_escape "hello world"
  assert_success
  assert_output "hello world"
}

@test "json_escape: double quotes are escaped" {
  run _run_json_escape 'say "hi"'
  assert_success
  assert_output 'say \"hi\"'
}

@test "json_escape: backslashes are escaped" {
  run _run_json_escape 'path\to\file'
  assert_success
  assert_output 'path\\to\\file'
}

@test "json_escape: newlines are escaped" {
  run _run_json_escape $'line1\nline2'
  assert_success
  assert_output 'line1\nline2'
}

@test "json_escape: tabs are escaped" {
  run _run_json_escape $'col1\tcol2'
  assert_success
  assert_output 'col1\tcol2'
}

@test "json_escape: combined special characters" {
  run _run_json_escape $'she said "hello\\world"\nend'
  assert_success
  assert_output 'she said \"hello\\world\"\nend'
}

@test "json_escape: empty string returns empty" {
  run _run_json_escape ""
  assert_success
  assert_output ""
}

@test "json_escape: forward slashes pass through (not escaped in JSON)" {
  run _run_json_escape "path/to/file"
  assert_success
  assert_output "path/to/file"
}

# =============================================================================
# emit_hdf_requirement() unit tests
# =============================================================================
# Tests validate against HDF v2 schema:
# https://github.com/mitre/hdf-libs/blob/hdf-libs-development/hdf-schema/src/schemas/hdf-results.schema.json
# Key v2 differences: camelCase fields (codeDesc, startTime, sourceLocation),
# descriptions array with {label,data}, severity enum, tags required.

# Helper: extract HDF functions from script and run emit_hdf_requirement
_run_emit_hdf_requirement() {
  local tmpscript
  tmpscript=$(mktemp)
  {
    sed -n '/^json_escape()/,/^}/p' "$SCRIPT"
    sed -n '/^emit_hdf_requirement()/,/^}/p' "$SCRIPT"
    echo "$@"
  } >"$tmpscript"
  bash "$tmpscript"
  rm -f "$tmpscript"
}

@test "emit_hdf_requirement: produces valid HDF v2 JSON structure" {
  run _run_emit_hdf_requirement \
    'emit_hdf_requirement "GHA-001" "Workflows MUST use explicit permissions" 0.5 "medium" "failed" "deploy.yml: no permissions block" ""'
  assert_success
  # Required HDF v2 fields
  assert_output --partial '"id": "GHA-001"'
  assert_output --partial '"impact": 0.5'
  assert_output --partial '"results":'
  assert_output --partial '"status": "failed"'
  assert_output --partial '"tags":'
  assert_output --partial '"descriptions":'
}

@test "emit_hdf_requirement: uses camelCase field names per v2 schema" {
  run _run_emit_hdf_requirement \
    'emit_hdf_requirement "GHA-001" "Test" 0.5 "medium" "passed" "ci.yml: ok" ""'
  assert_success
  # v2 uses camelCase
  assert_output --partial '"codeDesc":'
  assert_output --partial '"startTime":'
  # Must NOT use snake_case
  refute_output --partial '"code_desc"'
  refute_output --partial '"start_time"'
  refute_output --partial '"source_location"'
}

@test "emit_hdf_requirement: descriptions array has default label" {
  run _run_emit_hdf_requirement \
    'emit_hdf_requirement "GHA-002" "PRT check" 0.9 "critical" "failed" "detail" ""'
  assert_success
  # v2 requires descriptions array with at least one {label: "default"} entry
  assert_output --partial '"label": "default"'
}

@test "emit_hdf_requirement: severity field matches v2 enum" {
  run _run_emit_hdf_requirement \
    'emit_hdf_requirement "GHA-002" "PRT check" 0.9 "critical" "failed" "detail" ""'
  assert_success
  assert_output --partial '"severity": "critical"'
}

@test "emit_hdf_requirement: passed status produces passed result" {
  run _run_emit_hdf_requirement \
    'emit_hdf_requirement "GHA-001" "Permissions check" 0.5 "medium" "passed" "ci.yml: has permissions block" ""'
  assert_success
  assert_output --partial '"status": "passed"'
  assert_output --partial "ci.yml: has permissions block"
}

@test "emit_hdf_requirement: title is included" {
  run _run_emit_hdf_requirement \
    'emit_hdf_requirement "GHA-002" "PRT check" 0.9 "critical" "failed" "detail" ""'
  assert_success
  assert_output --partial '"title": "PRT check"'
}

@test "emit_hdf_requirement: special characters in detail are escaped" {
  run _run_emit_hdf_requirement \
    'emit_hdf_requirement "GHA-005" "Expr injection" 0.9 "critical" "failed" "found: \${{ github.event.pull_request.title }}" ""'
  assert_success
  assert_output --partial '"status": "failed"'
}

@test "emit_hdf_requirement: message field populated on failure" {
  run _run_emit_hdf_requirement \
    'emit_hdf_requirement "GHA-009" "No hardcoded secrets" 0.9 "critical" "failed" "hardcoded-token.yml" "Found ghp_* token"'
  assert_success
  assert_output --partial '"message": "Found ghp_* token"'
}

@test "emit_hdf_requirement: no message on pass" {
  run _run_emit_hdf_requirement \
    'emit_hdf_requirement "GHA-009" "No hardcoded secrets" 0.9 "critical" "passed" "clean.yml: no secrets found" ""'
  assert_success
  refute_output --partial '"message":'
}

@test "emit_hdf_requirement: omits message field when arg not provided" {
  run _run_emit_hdf_requirement \
    'emit_hdf_requirement "GHA-001" "Test" 0.5 "medium" "passed" "Check"'
  assert_success
  refute_output --partial '"message"'
}

# =============================================================================
# build_hdf_repo_target() tests
# =============================================================================
# TDD for card wf6: build JSON with requirements[] array per repo.

_hdf_preamble() {
  cat <<PREAMBLE
    CYAN='' YELLOW='' RED='' GREEN='' DIM='' RESET=''
    warn() { printf '[WARN] %s\n' "\$*" >&2; }
    gh() { echo ''; return 0; }
    export -f gh
    HDF_PROFILE_DIR='${PROJECT_ROOT}/hdf-profile'
PREAMBLE
  sed -n '/^json_escape()/,/^}/p' "$SCRIPT"
  sed -n '/^emit_hdf_requirement()/,/^}/p' "$SCRIPT"
  sed -n '/^extract_on_triggers()/,/^}/p' "$SCRIPT"
  sed -n '/^find_workflow_files()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_prt()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_ic()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_unpinned()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_expr_injection()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_wfr()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_self_hosted()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_dangerous_perms()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_hardcoded_secrets()/,/^}/p' "$SCRIPT"
  sed -n '/^build_hdf_repo_target()/,/^}/p' "$SCRIPT"
}

_run_hdf_repo_target() {
  local repo="$1"
  local repo_dir="$2"
  local tmpscript
  tmpscript=$(mktemp)
  {
    _hdf_preamble
    echo "build_hdf_repo_target '$repo' '$repo_dir'"
  } >"$tmpscript"
  local rc=0
  bash "$tmpscript" || rc=$?
  rm -f "$tmpscript"
  return $rc
}

# --- Basic structure tests ---

@test "build_hdf_repo_target: returns valid JSON" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  echo "$output" | python3 -m json.tool >/dev/null 2>&1 || {
    assert_output --partial '"targetId"'
    assert_output --partial '"requirements"'
    return 0
  }
}

@test "build_hdf_repo_target: includes targetId field" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"targetId": "test-repo"'
}

@test "build_hdf_repo_target: includes requirements array" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"requirements": ['
}

@test "build_hdf_repo_target: empty directory returns failure" {
  setup_fixture_dir "test-org" "empty-repo"

  run _run_hdf_repo_target "empty-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/empty-repo"
  assert_failure
}

# --- GHA-001: Permissions check ---

@test "build_hdf_repo_target: GHA-001 passed when all workflows have permissions" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/permissions-explicit.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-001"'
  assert_output --partial '"passed"'
}

@test "build_hdf_repo_target: GHA-001 failed when no workflows have permissions" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/permissions-none.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-001"'
  assert_output --partial '"failed"'
}

# --- GHA-002: pull_request_target ---

@test "build_hdf_repo_target: GHA-002 failed for prt-checkout-no-guard" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/prt-checkout-no-guard.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-002"'
  assert_output --partial "checkout+exec, no guard"
}

@test "build_hdf_repo_target: GHA-002 passed for benign workflow" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-002"'
}

# --- GHA-003: issue_comment ---

@test "build_hdf_repo_target: GHA-003 failed for issue-comment-no-gate" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/issue-comment-no-gate.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-003"'
  assert_output --partial "no author gate"
}

# --- GHA-004: Unpinned actions ---

@test "build_hdf_repo_target: GHA-004 failed for unpinned-actions" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/unpinned-actions.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-004"'
  assert_output --partial "0/3 pinned"
}

@test "build_hdf_repo_target: GHA-004 passed for pinned-actions" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/pinned-actions.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-004"'
  assert_output --partial "3/3 pinned"
}

# --- GHA-005: Expression injection ---

@test "build_hdf_repo_target: GHA-005 failed for expr-injection-pr-title" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/expr-injection-pr-title.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-005"'
  assert_output --partial "pull_request.title"
}

@test "build_hdf_repo_target: GHA-005 passed for safe expressions" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/expr-injection-safe.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-005"'
}

# --- GHA-006: workflow_run ---

@test "build_hdf_repo_target: GHA-006 failed for workflow-run-artifact" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/workflow-run-artifact.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-006"'
  assert_output --partial "download-artifact"
}

# --- GHA-007: Self-hosted runners ---

@test "build_hdf_repo_target: GHA-007 failed for self-hosted-runner" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/self-hosted-runner.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-007"'
  assert_output --partial "self-hosted"
}

# --- GHA-008: Dangerous permissions ---

@test "build_hdf_repo_target: GHA-008 failed for dangerous-perms-write-all" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/dangerous-perms-write-all.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-008"'
  assert_output --partial "write-all"
}

# --- GHA-009: Hardcoded secrets ---

@test "build_hdf_repo_target: GHA-009 failed for hardcoded-token" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/hardcoded-token.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-009"'
  assert_output --partial "ghp_"
}

@test "build_hdf_repo_target: GHA-009 passed for clean workflow" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-009"'
}

# --- GHA-010: Harden-runner ---

@test "build_hdf_repo_target: GHA-010 passed for harden-runner-used" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/harden-runner-used.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-010"'
}

@test "build_hdf_repo_target: GHA-010 failed for benign workflow" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-010"'
}

# --- All per-repo requirements present (implemented + unimplemented) ---

@test "build_hdf_repo_target: all 23 per-repo requirement IDs present" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # 10 implemented per-repo checks
  for id in GHA-001 GHA-002 GHA-003 GHA-004 GHA-005 GHA-006 GHA-007 GHA-008 GHA-009 GHA-010; do
    assert_output --partial "\"$id\""
  done
  # 13 unimplemented per-repo checks (notReviewed)
  for id in GHA-014 GHA-015 GHA-016 GHA-017 GHA-018 GHA-019 GHA-020 GHA-021 GHA-022 GHA-023 GHA-024 GHA-025 GHA-026; do
    assert_output --partial "\"$id\""
  done
}

@test "build_hdf_repo_target: unimplemented requirements have notReviewed status" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"notReviewed"'
  assert_output --partial "Detection not yet implemented"
}

@test "build_hdf_repo_target: org-level requirements NOT included" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # GHA-011 through GHA-013 and GHA-027/028 are org-level — must NOT appear
  refute_output --partial '"GHA-011"'
  refute_output --partial '"GHA-012"'
  refute_output --partial '"GHA-013"'
  refute_output --partial '"GHA-027"'
  refute_output --partial '"GHA-028"'
}
