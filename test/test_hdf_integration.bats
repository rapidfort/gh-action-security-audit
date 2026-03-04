#!/usr/bin/env bats
#
# Integration tests for HDF v2 pipeline wired into the main loop.
# Card 23o: validates that build_hdf_repo_target is called per-repo
# and build_hdf_wrapper assembles the final document.

setup() {
  load test_helper/common-setup
}

# =============================================================================
# Helper: full preamble with ALL HDF functions needed for integration tests
# =============================================================================

_hdf_full_preamble() {
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
  sed -n '/^_hdf_result_GHA_029()/,/^}/p' "$SCRIPT"
  sed -n '/^build_hdf_repo_target()/,/^}/p' "$SCRIPT"
  sed -n '/^build_hdf_org_target()/,/^}/p' "$SCRIPT"
  sed -n '/^_emit_hdf_baseline()/,/^}/p' "$SCRIPT"
  sed -n '/^build_hdf_wrapper()/,/^}/p' "$SCRIPT"
}

# Helper: run the repo-loop accumulation pattern against multiple repos
_run_hdf_accumulation() {
  local workflow_dir="$1"
  shift
  local repos=("$@")
  local tmpscript repo_targets_file cache_file
  tmpscript=$(mktemp)
  repo_targets_file=$(mktemp)
  cache_file=$(mktemp)
  {
    _hdf_full_preamble
    echo "HDF_REPO_TARGETS_FILE='$repo_targets_file'"
    echo "CACHE_FILE='$cache_file'"
    for repo in "${repos[@]}"; do
      cat <<LOOP
repo_dir='${workflow_dir}/${repo}'
if [ -d "\$repo_dir" ]; then
  : >"\$CACHE_FILE"
  if run_repo_classifiers "\$repo_dir" "\$CACHE_FILE"; then
    build_hdf_repo_target '${repo}' "\$repo_dir" "\$CACHE_FILE" >>"\$HDF_REPO_TARGETS_FILE" || true
  fi
fi
LOOP
    done
    echo "cat \"\$HDF_REPO_TARGETS_FILE\""
    echo "rm -f \"\$HDF_REPO_TARGETS_FILE\" \"\$CACHE_FILE\""
  } >"$tmpscript"
  local rc=0
  bash "$tmpscript" || rc=$?
  rm -f "$tmpscript"
  return $rc
}

# Helper: run the full pipeline (repo accumulation + org target + wrapper)
_run_hdf_full_pipeline() {
  local workflow_dir="$1"
  local org="$2"
  local default_perm="$3"
  local can_approve="$4"
  local allowed="$5"
  shift 5
  local repos=("$@")
  local tmpscript repo_targets_file hdf_output_file cache_file
  tmpscript=$(mktemp)
  repo_targets_file=$(mktemp)
  hdf_output_file=$(mktemp)
  cache_file=$(mktemp)
  {
    _hdf_full_preamble
    echo "HDF_REPO_TARGETS_FILE='$repo_targets_file'"
    echo "HDF_OUTPUT_FILE='$hdf_output_file'"
    echo "CACHE_FILE='$cache_file'"
    # Accumulate repo targets (same pattern as main loop)
    for repo in "${repos[@]}"; do
      cat <<LOOP
repo_dir='${workflow_dir}/${repo}'
if [ -d "\$repo_dir" ]; then
  : >"\$CACHE_FILE"
  if run_repo_classifiers "\$repo_dir" "\$CACHE_FILE"; then
    build_hdf_repo_target '${repo}' "\$repo_dir" "\$CACHE_FILE" >>"\$HDF_REPO_TARGETS_FILE" || true
  fi
fi
LOOP
    done
    # Build org target + assemble wrapper (same pattern as after Phase 4)
    cat <<ASSEMBLE
HDF_ORG_TARGET_JSON=\$(build_hdf_org_target '${org}' '${default_perm}' '${can_approve}' '${allowed}')
build_hdf_wrapper '${org}' "\$HDF_REPO_TARGETS_FILE" "\$HDF_ORG_TARGET_JSON" >"\$HDF_OUTPUT_FILE"
cat "\$HDF_OUTPUT_FILE"
rm -f "\$HDF_REPO_TARGETS_FILE" "\$HDF_OUTPUT_FILE" "\$CACHE_FILE"
ASSEMBLE
  } >"$tmpscript"
  local rc=0
  bash "$tmpscript" || rc=$?
  rm -f "$tmpscript"
  return $rc
}

# =============================================================================
# Test 1: accumulate_hdf_repo_targets: produces one JSON line per repo
# =============================================================================

@test "accumulate_hdf_repo_targets: produces one JSON line per repo" {
  setup_fixture_dir "test-org" "repo-a"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"
  cp "$FIXTURES_DIR/workflows/permissions-explicit.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b/"

  run _run_hdf_accumulation "$BATS_TEST_WORKFLOW_DIR/test-org" "repo-a" "repo-b"
  assert_success
  local line_count
  line_count=$(echo "$output" | wc -l | tr -d ' ')
  [ "$line_count" -eq 2 ]
}

# =============================================================================
# Test 2: accumulate_hdf_repo_targets: each line has correct targetId
# =============================================================================

@test "accumulate_hdf_repo_targets: each line has correct targetId" {
  setup_fixture_dir "test-org" "repo-a"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"
  cp "$FIXTURES_DIR/workflows/permissions-explicit.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b/"

  run _run_hdf_accumulation "$BATS_TEST_WORKFLOW_DIR/test-org" "repo-a" "repo-b"
  assert_success
  # First line should have repo-a, second repo-b
  local line1 line2
  line1=$(echo "$output" | sed -n '1p')
  line2=$(echo "$output" | sed -n '2p')
  [[ "$line1" == *'"targetId": "repo-a"'* ]]
  [[ "$line2" == *'"targetId": "repo-b"'* ]]
}

# =============================================================================
# Test 3: full_hdf_pipeline: produces valid JSON
# =============================================================================

@test "full_hdf_pipeline: produces valid JSON" {
  setup_fixture_dir "test-org" "repo-a"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"

  run _run_hdf_full_pipeline \
    "$BATS_TEST_WORKFLOW_DIR/test-org" "test-org" "read" "false" "selected" "repo-a"
  assert_success
  echo "$output" | python3 -m json.tool >/dev/null 2>&1
}

# =============================================================================
# Test 4: full_hdf_pipeline: produces valid HDF v2 document with repos and org
# =============================================================================

@test "full_hdf_pipeline: produces valid HDF v2 document with repos and org" {
  setup_fixture_dir "test-org" "repo-a"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"

  run _run_hdf_full_pipeline \
    "$BATS_TEST_WORKFLOW_DIR/test-org" "test-org" "read" "false" "selected" "repo-a"
  assert_success
  # Top-level keys
  assert_output --partial '"baselines":'
  assert_output --partial '"targets":'
  assert_output --partial '"generator":'
  assert_output --partial '"timestamp":'
  # Repo content
  assert_output --partial '"GHA-001"'
  # Org content
  assert_output --partial '"GHA-011"'
}

# =============================================================================
# Test 5: full_hdf_pipeline: multiple repos produce correct baseline count
# =============================================================================

@test "full_hdf_pipeline: multiple repos produce correct baseline count" {
  setup_fixture_dir "test-org" "repo-a"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-c"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"
  cp "$FIXTURES_DIR/workflows/permissions-explicit.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b/"
  cp "$FIXTURES_DIR/workflows/unpinned-actions.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-c/"

  run _run_hdf_full_pipeline \
    "$BATS_TEST_WORKFLOW_DIR/test-org" "test-org" "read" "false" "selected" \
    "repo-a" "repo-b" "repo-c"
  assert_success
  # 3 repos + 1 org = 4 baselines
  local baseline_count
  baseline_count=$(echo "$output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['baselines']))")
  [ "$baseline_count" -eq 4 ]
}

# =============================================================================
# Test 6: full_hdf_pipeline: empty repo skipped, others produce targets
# =============================================================================

@test "full_hdf_pipeline: empty repo skipped, others produce targets" {
  setup_fixture_dir "test-org" "repo-a"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/empty-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"
  # empty-repo has no workflow files — build_hdf_repo_target will fail, || true skips it

  run _run_hdf_full_pipeline \
    "$BATS_TEST_WORKFLOW_DIR/test-org" "test-org" "read" "false" "selected" \
    "repo-a" "empty-repo"
  assert_success
  # Only 1 repo target + 1 org = 2 baselines (empty-repo skipped)
  local baseline_count
  baseline_count=$(echo "$output" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['baselines']))")
  [ "$baseline_count" -eq 2 ]
}

# =============================================================================
# Test 7: full_hdf_pipeline: org target reflects org settings
# =============================================================================

@test "full_hdf_pipeline: org target reflects org settings" {
  setup_fixture_dir "test-org" "repo-a"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"

  # Use "write" perms + "true" approve + "all" actions — all should fail
  run _run_hdf_full_pipeline \
    "$BATS_TEST_WORKFLOW_DIR/test-org" "test-org" "write" "true" "all" "repo-a"
  assert_success
  # Org-level failures should appear
  assert_output --partial "default_workflow_permissions is write"
  assert_output --partial "can_approve_pull_request_reviews is true"
  assert_output --partial "allowed_actions is all"
}
