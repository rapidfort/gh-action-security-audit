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
  sed -n '/^classify_secrets_inherit()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_env_injection()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_deprecated_commands()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_known_vulnerable()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_unpinned_third_party()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_always_secrets()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_artifact_trust()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_missing_environment()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_cache_poisoning()/,/^}/p' "$SCRIPT"
  sed -n '/^classify_static_credentials()/,/^}/p' "$SCRIPT"
  sed -n '/^run_repo_classifiers()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_001()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_002()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_003()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_004()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_005()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_006()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_007()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_008()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_009()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_010()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_011()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_012()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_013()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_014()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_015()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_017()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_016()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_018()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_019()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_020()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_021()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_022()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_023()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_024()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_025()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_026()/,/^}/p' "$SCRIPT"
  sed -n '/^build_hdf_repo_target()/,/^}/p' "$SCRIPT"
}

_run_hdf_repo_target() {
  local repo="$1"
  local repo_dir="$2"
  local tmpscript cache_file
  tmpscript=$(mktemp)
  cache_file=$(mktemp)
  {
    _hdf_preamble
    echo "run_repo_classifiers '$repo_dir' '$cache_file' || exit 1"
    echo "build_hdf_repo_target '$repo' '$repo_dir' '$cache_file'"
  } >"$tmpscript"
  local rc=0
  bash "$tmpscript" || rc=$?
  rm -f "$tmpscript" "$cache_file"
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

# --- GHA-014: secrets: inherit ---

@test "build_hdf_repo_target: GHA-014 failed for secrets-inherit" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/secrets-inherit.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-014"'
  assert_output --partial '"failed"'
}

@test "build_hdf_repo_target: GHA-014 passed for explicit secrets" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/secrets-explicit.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-014"'
}

# --- GHA-015: GITHUB_ENV/PATH/OUTPUT injection ---

@test "build_hdf_repo_target: GHA-015 failed for env-injection" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/env-injection-github-env.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-015"'
  assert_output --partial '"failed"'
}

@test "build_hdf_repo_target: GHA-015 passed for benign workflow" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-015"'
}

# --- GHA-017: Deprecated workflow commands ---

@test "build_hdf_repo_target: GHA-017 failed for deprecated-set-output" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/deprecated-set-output.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-017"'
  assert_output --partial '"failed"'
}

@test "build_hdf_repo_target: GHA-017 passed for benign workflow" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-017"'
}

# --- GHA-018: Known-compromised actions ---

@test "build_hdf_repo_target: GHA-018 failed for tj-actions" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/known-vulnerable-tj-actions.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-018"'
  assert_output --partial '"failed"'
}

@test "build_hdf_repo_target: GHA-018 passed for benign workflow" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial '"GHA-018"'
}

# --- All per-repo requirements present (implemented + unimplemented) ---

@test "build_hdf_repo_target: all 23 per-repo requirement IDs present" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # All 23 per-repo checks implemented
  for id in GHA-001 GHA-002 GHA-003 GHA-004 GHA-005 GHA-006 GHA-007 GHA-008 GHA-009 GHA-010 GHA-014 GHA-015 GHA-016 GHA-017 GHA-018 GHA-019 GHA-020 GHA-021 GHA-022 GHA-023 GHA-024 GHA-025 GHA-026; do
    assert_output --partial "\"$id\""
  done
}

@test "build_hdf_repo_target: all per-repo requirements are implemented (no notReviewed)" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  refute_output --partial "Detection not yet implemented"
}

@test "build_hdf_repo_target: org-level requirements NOT included" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_hdf_repo_target "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # GHA-011 through GHA-013, GHA-027/028/029 are org-level — must NOT appear
  refute_output --partial '"GHA-011"'
  refute_output --partial '"GHA-012"'
  refute_output --partial '"GHA-013"'
  refute_output --partial '"GHA-027"'
  refute_output --partial '"GHA-028"'
  refute_output --partial '"GHA-029"'
}

# =============================================================================
# build_hdf_org_target() tests
# =============================================================================

_hdf_org_preamble() {
  cat <<PREAMBLE
    CYAN='' YELLOW='' RED='' GREEN='' DIM='' RESET=''
    warn() { printf '[WARN] %s\n' "\$*" >&2; }
    HDF_PROFILE_DIR='${PROJECT_ROOT}/hdf-profile'
PREAMBLE
  sed -n '/^json_escape()/,/^}/p' "$SCRIPT"
  sed -n '/^emit_hdf_requirement()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_011()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_012()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_013()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_027()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_028()/,/^}/p' "$SCRIPT"
  sed -n '/^_hdf_result_GHA_029()/,/^}/p' "$SCRIPT"
  sed -n '/^build_hdf_org_target()/,/^}/p' "$SCRIPT"
}

_run_hdf_org_target() {
  local org="$1" default_perm="$2" can_approve="$3" allowed="$4"
  local org_secrets_file="${5:-}"
  local enabled_repos="${6:-selected}"
  local sha_pinning="${7:-false}"
  local tmpscript
  tmpscript=$(mktemp)
  {
    _hdf_org_preamble
    echo "build_hdf_org_target '$org' '$default_perm' '$can_approve' '$allowed' '$org_secrets_file' '$enabled_repos' '$sha_pinning'"
  } >"$tmpscript"
  local rc=0
  bash "$tmpscript" || rc=$?
  rm -f "$tmpscript"
  return $rc
}

# --- Basic structure ---

@test "build_hdf_org_target: returns valid JSON with targetId" {
  run _run_hdf_org_target "test-org" "read" "false" "selected"
  assert_success
  assert_output --partial '"targetId": "test-org"'
  assert_output --partial '"requirements": ['
}

# --- GHA-011: Default workflow permissions ---

@test "build_hdf_org_target: GHA-011 passed when default_workflow_permissions is read" {
  run _run_hdf_org_target "test-org" "read" "false" "selected"
  assert_success
  assert_output --partial '"GHA-011"'
  assert_output --partial '"passed"'
}

@test "build_hdf_org_target: GHA-011 failed when default_workflow_permissions is write" {
  run _run_hdf_org_target "test-org" "write" "false" "selected"
  assert_success
  assert_output --partial '"GHA-011"'
  assert_output --partial '"failed"'
  assert_output --partial "default_workflow_permissions is write"
}

# --- GHA-012: PR approval policy ---

@test "build_hdf_org_target: GHA-012 passed when can_approve_prs is false" {
  run _run_hdf_org_target "test-org" "read" "false" "selected"
  assert_success
  assert_output --partial '"GHA-012"'
  assert_output --partial '"passed"'
}

@test "build_hdf_org_target: GHA-012 failed when can_approve_prs is true" {
  run _run_hdf_org_target "test-org" "read" "true" "selected"
  assert_success
  assert_output --partial '"GHA-012"'
  assert_output --partial '"failed"'
  assert_output --partial "can_approve_pull_request_reviews is true"
}

# --- GHA-013: Allowed actions ---

@test "build_hdf_org_target: GHA-013 passed when allowed_actions is selected" {
  run _run_hdf_org_target "test-org" "read" "false" "selected"
  assert_success
  assert_output --partial '"GHA-013"'
  assert_output --partial '"passed"'
}

@test "build_hdf_org_target: GHA-013 passed when allowed_actions is verified" {
  run _run_hdf_org_target "test-org" "read" "false" "verified"
  assert_success
  assert_output --partial '"GHA-013"'
  assert_output --partial '"passed"'
}

@test "build_hdf_org_target: GHA-013 failed when allowed_actions is all" {
  run _run_hdf_org_target "test-org" "read" "false" "all"
  assert_success
  assert_output --partial '"GHA-013"'
  assert_output --partial '"failed"'
  assert_output --partial "allowed_actions is all"
}

# --- GHA-029: Org secret scoping ---

@test "build_hdf_org_target: GHA-029 passed when no secrets have visibility all" {
  local secrets_file
  secrets_file=$(mktemp)
  echo "MY_SECRET|Selected|repo-a,repo-b|repo-a|" >"$secrets_file"
  echo "OTHER_SECRET|Private repositories only|(all private)|repo-c|" >>"$secrets_file"

  run _run_hdf_org_target "test-org" "read" "false" "selected" "$secrets_file"
  assert_success
  assert_output --partial '"GHA-029"'
  assert_output --partial '"passed"'
  rm -f "$secrets_file"
}

@test "build_hdf_org_target: GHA-029 failed when secret has visibility all" {
  local secrets_file
  secrets_file=$(mktemp)
  echo "BAD_SECRET|All repositories|(all)|repo-a|gh secret set BAD_SECRET --org test-org --visibility selected --repos repo-a" >"$secrets_file"
  echo "GOOD_SECRET|Selected|repo-b|repo-b|" >>"$secrets_file"

  run _run_hdf_org_target "test-org" "read" "false" "selected" "$secrets_file"
  assert_success
  assert_output --partial '"GHA-029"'
  assert_output --partial '"failed"'
  assert_output --partial "BAD_SECRET"
  rm -f "$secrets_file"
}

@test "build_hdf_org_target: GHA-029 passed when org secrets file is empty" {
  local secrets_file
  secrets_file=$(mktemp)
  # Empty file — no secrets at all

  run _run_hdf_org_target "test-org" "read" "false" "selected" "$secrets_file"
  assert_success
  assert_output --partial '"GHA-029"'
  assert_output --partial '"passed"'
  rm -f "$secrets_file"
}

# --- GHA-027: Org SHA pinning ---

@test "build_hdf_org_target: GHA-027 passed when sha_pinning_required is true" {
  run _run_hdf_org_target "test-org" "read" "false" "selected" "" "selected" "true"
  assert_success
  assert_output --partial '"GHA-027"'
  assert_output --partial '"passed"'
}

@test "build_hdf_org_target: GHA-027 failed when sha_pinning_required is false" {
  run _run_hdf_org_target "test-org" "read" "false" "selected" "" "selected" "false"
  assert_success
  assert_output --partial '"GHA-027"'
  assert_output --partial '"failed"'
}

# --- GHA-028: Org enabled_repositories ---

@test "build_hdf_org_target: GHA-028 passed when enabled_repositories is selected" {
  run _run_hdf_org_target "test-org" "read" "false" "selected" "" "selected" "false"
  assert_success
  assert_output --partial '"GHA-028"'
  assert_output --partial '"passed"'
}

@test "build_hdf_org_target: GHA-028 failed when enabled_repositories is all" {
  run _run_hdf_org_target "test-org" "read" "false" "selected" "" "all" "false"
  assert_success
  assert_output --partial '"GHA-028"'
  assert_output --partial '"failed"'
}

# --- All org requirement IDs present ---

@test "build_hdf_org_target: all 6 org-level requirement IDs present" {
  run _run_hdf_org_target "test-org" "read" "false" "selected"
  assert_success
  for id in GHA-011 GHA-012 GHA-013 GHA-027 GHA-028 GHA-029; do
    assert_output --partial "\"$id\""
  done
}

@test "build_hdf_org_target: all org requirements are implemented (no notReviewed)" {
  run _run_hdf_org_target "test-org" "read" "false" "selected"
  assert_success
  refute_output --partial "Detection not yet implemented"
}

@test "build_hdf_org_target: per-repo requirement IDs NOT included" {
  run _run_hdf_org_target "test-org" "read" "false" "selected"
  assert_success
  # Per-repo IDs must NOT appear in org target
  for id in GHA-001 GHA-002 GHA-003 GHA-004 GHA-005 GHA-006 GHA-007 GHA-008 GHA-009 GHA-010 GHA-014 GHA-015 GHA-016 GHA-017 GHA-018 GHA-019 GHA-020 GHA-021 GHA-022 GHA-023 GHA-024 GHA-025 GHA-026; do
    refute_output --partial "\"$id\""
  done
}

# --- Combined pass/fail scenarios ---

@test "build_hdf_org_target: all six implemented checks fail" {
  local secrets_file
  secrets_file=$(mktemp)
  echo "LEAK|All repositories|(all)|repo-a|gh secret set LEAK" >"$secrets_file"
  run _run_hdf_org_target "test-org" "write" "true" "all" "$secrets_file" "all" "false"
  assert_success
  # Count failed occurrences — should be 6 (011, 012, 013, 027, 028, 029)
  local fail_count
  fail_count=$(echo "$output" | grep -o '"failed"' | wc -l | tr -d ' ')
  [ "$fail_count" -ge 6 ]
  rm -f "$secrets_file"
}

@test "build_hdf_org_target: all six implemented checks pass" {
  local secrets_file
  secrets_file=$(mktemp)
  echo "GOOD|Selected|repo-a|repo-a|" >"$secrets_file"
  run _run_hdf_org_target "test-org" "read" "false" "selected" "$secrets_file" "selected" "true"
  assert_success
  # All 6 implemented checks should pass (011, 012, 013, 027, 028, 029)
  local pass_count
  pass_count=$(echo "$output" | grep -o '"passed"' | wc -l | tr -d ' ')
  [ "$pass_count" -ge 6 ]
  rm -f "$secrets_file"
}

# =============================================================================
# build_hdf_wrapper() tests
# =============================================================================

# Helper: extract build_hdf_wrapper and its dependencies
_hdf_wrapper_preamble() {
  cat <<PREAMBLE
    CYAN='' YELLOW='' RED='' GREEN='' DIM='' RESET=''
    warn() { printf '[WARN] %s\n' "\$*" >&2; }
    HDF_PROFILE_DIR='${PROJECT_ROOT}/hdf-profile'
PREAMBLE
  sed -n '/^json_escape()/,/^}/p' "$SCRIPT"
  sed -n '/^emit_hdf_requirement()/,/^}/p' "$SCRIPT"
  sed -n '/^_emit_hdf_baseline()/,/^}/p' "$SCRIPT"
  sed -n '/^build_hdf_wrapper()/,/^}/p' "$SCRIPT"
}

# Helper: create mock target JSON for testing
# Each target has targetId and a requirements array with one dummy requirement
_mock_repo_target() {
  local repo="$1"
  printf '{"targetId": "%s", "requirements": [{"id": "GHA-001", "title": "Test", "impact": 0.5, "severity": "medium", "results": [{"status": "passed", "codeDesc": "ok"}]}]}\n' "$repo"
}

_mock_org_target() {
  local org="$1"
  printf '{"targetId": "%s", "requirements": [{"id": "GHA-011", "title": "OrgTest", "impact": 0.7, "severity": "high", "results": [{"status": "passed", "codeDesc": "ok"}]}]}\n' "$org"
}

_run_hdf_wrapper() {
  local org="$1"
  shift
  local repo_targets_file="$1"
  shift
  local org_target_json="$1"
  local tmpscript
  tmpscript=$(mktemp)
  {
    _hdf_wrapper_preamble
    echo "build_hdf_wrapper '$org' '$repo_targets_file' '$org_target_json'"
  } >"$tmpscript"
  local rc=0
  bash "$tmpscript" || rc=$?
  rm -f "$tmpscript"
  return $rc
}

# --- Basic structure ---

@test "build_hdf_wrapper: returns valid JSON" {
  local repo_file
  repo_file=$(mktemp)
  _mock_repo_target "repo-a" >"$repo_file"
  local org_json
  org_json=$(_mock_org_target "test-org")

  run _run_hdf_wrapper "test-org" "$repo_file" "$org_json"
  assert_success
  echo "$output" | python3 -m json.tool >/dev/null 2>&1
  rm -f "$repo_file"
}

@test "build_hdf_wrapper: has baselines array" {
  local repo_file
  repo_file=$(mktemp)
  _mock_repo_target "repo-a" >"$repo_file"
  local org_json
  org_json=$(_mock_org_target "test-org")

  run _run_hdf_wrapper "test-org" "$repo_file" "$org_json"
  assert_success
  assert_output --partial '"baselines":'
  rm -f "$repo_file"
}

@test "build_hdf_wrapper: has generator object" {
  local repo_file
  repo_file=$(mktemp)
  _mock_repo_target "repo-a" >"$repo_file"
  local org_json
  org_json=$(_mock_org_target "test-org")

  run _run_hdf_wrapper "test-org" "$repo_file" "$org_json"
  assert_success
  assert_output --partial '"generator":'
  assert_output --partial '"name": "gh-actions-audit"'
  rm -f "$repo_file"
}

@test "build_hdf_wrapper: has timestamp in ISO-8601 format" {
  local repo_file
  repo_file=$(mktemp)
  _mock_repo_target "repo-a" >"$repo_file"
  local org_json
  org_json=$(_mock_org_target "test-org")

  run _run_hdf_wrapper "test-org" "$repo_file" "$org_json"
  assert_success
  assert_output --partial '"timestamp":'
  # Match ISO-8601 pattern: YYYY-MM-DDTHH:MM:SSZ
  [[ "$output" =~ [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z ]]
  rm -f "$repo_file"
}

@test "build_hdf_wrapper: baseline count matches targets (N repos + 1 org)" {
  local repo_file
  repo_file=$(mktemp)
  _mock_repo_target "repo-a" >>"$repo_file"
  _mock_repo_target "repo-b" >>"$repo_file"
  local org_json
  org_json=$(_mock_org_target "test-org")

  run _run_hdf_wrapper "test-org" "$repo_file" "$org_json"
  assert_success
  # 2 repos + 1 org = 3 baselines
  local baseline_count
  baseline_count=$(echo "$output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['baselines']))")
  [ "$baseline_count" -eq 3 ]
  rm -f "$repo_file"
}

@test "build_hdf_wrapper: repo baseline has requirements" {
  local repo_file
  repo_file=$(mktemp)
  _mock_repo_target "repo-a" >"$repo_file"
  local org_json
  org_json=$(_mock_org_target "test-org")

  run _run_hdf_wrapper "test-org" "$repo_file" "$org_json"
  assert_success
  # First baseline should have requirements array with GHA-001
  local has_req
  has_req=$(echo "$output" | python3 -c "
import sys,json
d=json.load(sys.stdin)
bl = d['baselines'][0]
print(any(r['id'] == 'GHA-001' for r in bl['requirements']))
")
  [ "$has_req" = "True" ]
  rm -f "$repo_file"
}

@test "build_hdf_wrapper: org baseline has requirements" {
  local repo_file
  repo_file=$(mktemp)
  _mock_repo_target "repo-a" >"$repo_file"
  local org_json
  org_json=$(_mock_org_target "test-org")

  run _run_hdf_wrapper "test-org" "$repo_file" "$org_json"
  assert_success
  # Last baseline should have org requirement GHA-011
  local has_req
  has_req=$(echo "$output" | python3 -c "
import sys,json
d=json.load(sys.stdin)
bl = d['baselines'][-1]
print(any(r['id'] == 'GHA-011' for r in bl['requirements']))
")
  [ "$has_req" = "True" ]
  rm -f "$repo_file"
}

@test "build_hdf_wrapper: baselines have profile metadata" {
  local repo_file
  repo_file=$(mktemp)
  _mock_repo_target "repo-a" >"$repo_file"
  local org_json
  org_json=$(_mock_org_target "test-org")

  run _run_hdf_wrapper "test-org" "$repo_file" "$org_json"
  assert_success
  # Each baseline should have name, version, status
  local ok
  ok=$(echo "$output" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for bl in d['baselines']:
  assert 'name' in bl, 'missing name'
  assert 'version' in bl, 'missing version'
  assert 'status' in bl, 'missing status'
print('ok')
")
  [ "$ok" = "ok" ]
  rm -f "$repo_file"
}

@test "build_hdf_wrapper: targets array has repository entries" {
  local repo_file
  repo_file=$(mktemp)
  _mock_repo_target "repo-a" >>"$repo_file"
  _mock_repo_target "repo-b" >>"$repo_file"
  local org_json
  org_json=$(_mock_org_target "test-org")

  run _run_hdf_wrapper "test-org" "$repo_file" "$org_json"
  assert_success
  # targets[] should have type=repository entries for each repo
  local target_info
  target_info=$(echo "$output" | python3 -c "
import sys,json
d=json.load(sys.stdin)
targets = d['targets']
print(len(targets), targets[0]['type'], targets[0]['name'])
")
  [[ "$target_info" == *"repository"* ]]
  [[ "$target_info" == *"test-org/repo-a"* ]]
  rm -f "$repo_file"
}

@test "build_hdf_wrapper: empty repo list produces org-only output" {
  local repo_file
  repo_file=$(mktemp)
  # Empty file — no repo targets
  local org_json
  org_json=$(_mock_org_target "test-org")

  run _run_hdf_wrapper "test-org" "$repo_file" "$org_json"
  assert_success
  # Should have exactly 1 baseline (org only)
  local baseline_count
  baseline_count=$(echo "$output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['baselines']))")
  [ "$baseline_count" -eq 1 ]
  # targets[] should be empty
  local target_count
  target_count=$(echo "$output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['targets']))")
  [ "$target_count" -eq 0 ]
  rm -f "$repo_file"
}
