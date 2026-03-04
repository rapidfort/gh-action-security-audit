#!/usr/bin/env bats
#
# Tests for Phase 2 workflow analysis heuristics.
# These tests use fixture workflow files and grep commands extracted from
# the main script to validate detection logic.

setup() {
  load test_helper/common-setup
}

# =============================================================================
# Permissions detection
# =============================================================================

@test "detects explicit permissions block" {
  run grep -q 'permissions:' "$FIXTURES_DIR/workflows/permissions-explicit.yml"
  assert_success
}

@test "reports no permissions when block is absent" {
  run grep -c '^permissions:' "$FIXTURES_DIR/workflows/permissions-none.yml"
  assert_output "0"
}

@test "permissions-in-comment: NOT a false positive — comment-only permissions: is ignored" {
  # Fixed: strips comment lines before checking for permissions:.
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/permissions-in-comment.yml' | grep -q 'permissions:'"
  assert_failure
}

# =============================================================================
# pull_request_target detection
# =============================================================================

@test "detects pull_request_target trigger" {
  run grep -q 'pull_request_target' "$FIXTURES_DIR/workflows/prt-checkout-no-guard.yml"
  assert_success
}

@test "prt-api-only: no checkout detected" {
  run grep -q 'actions/checkout' "$FIXTURES_DIR/workflows/prt-api-only.yml"
  assert_failure
}

@test "prt-checkout-no-guard: checkout detected, no author guard" {
  run grep -q 'actions/checkout' "$FIXTURES_DIR/workflows/prt-checkout-no-guard.yml"
  assert_success
  # Verify no author guard (using the fixed regex)
  run grep -qE "(user\.login|github\.actor)\s*==\s*['\"](dependabot|github-actions|renovate)" "$FIXTURES_DIR/workflows/prt-checkout-no-guard.yml"
  assert_failure
}

@test "prt-checkout-with-guard-single-quote: guard with single quotes detected" {
  run grep -qE "user\.login\s*==\s*'dependabot" "$FIXTURES_DIR/workflows/prt-checkout-with-guard-single-quote.yml"
  assert_success
}

@test "prt-checkout-with-guard-double-quote: guard with double quotes detected" {
  # Fixed: regex now accepts both single and double quotes around actor names.
  run grep -qE "user\.login\s*==\s*['\"]dependabot" "$FIXTURES_DIR/workflows/prt-checkout-with-guard-double-quote.yml"
  assert_success
}

@test "prt-checkout-with-guard-actor: github.actor guard detected" {
  # github.actor == 'dependabot[bot]' is an equivalent guard pattern.
  run grep -qE "(user\.login|github\.actor)\s*==\s*['\"]dependabot" "$FIXTURES_DIR/workflows/prt-checkout-with-guard-actor.yml"
  assert_success
}

@test "prt-head-ref: github.head_ref detected as fork ref" {
  # Fixed: regex now matches github.head_ref shorthand.
  run grep -qE 'github\.head_ref|pull_request\.head\.(sha|ref|repo\.full_name)' "$FIXTURES_DIR/workflows/prt-head-ref.yml"
  assert_success
}

@test "prt-head-repo-fullname: head.repo.full_name detected as fork ref" {
  run grep -qE 'github\.head_ref|pull_request\.head\.(sha|ref|repo\.full_name)' "$FIXTURES_DIR/workflows/prt-head-repo-fullname.yml"
  assert_success
}

@test "prt-checkout-commented-out: commented-out checkout is NOT detected" {
  # A commented-out actions/checkout should not count as a checkout
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/prt-checkout-commented-out.yml' | grep -q 'actions/checkout'"
  assert_failure
}

@test "prt-in-comment: NOT a false positive — comment-only pull_request_target is ignored" {
  # The trigger check should use uncommented content only
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/prt-in-comment.yml' | grep -q 'pull_request_target'"
  assert_failure
}

# =============================================================================
# issue_comment detection
# =============================================================================

@test "detects issue_comment trigger" {
  run grep -q 'issue_comment' "$FIXTURES_DIR/workflows/issue-comment-with-gate.yml"
  assert_success
}

@test "issue-comment-with-gate: author_association detected" {
  run grep -q 'author_association' "$FIXTURES_DIR/workflows/issue-comment-with-gate.yml"
  assert_success
}

@test "issue-comment-no-gate: no author_association present" {
  # Only check non-comment lines
  run grep -v '^#' "$FIXTURES_DIR/workflows/issue-comment-no-gate.yml"
  refute_output --partial 'author_association'
}

@test "issue-comment-author-in-comment: NOT a false positive — comment-only author_association is ignored" {
  # Fixed: strips comment lines before checking for author_association.
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/issue-comment-author-in-comment.yml' | grep -q 'author_association'"
  assert_failure
}

@test "ic-in-comment: NOT a false positive — comment-only issue_comment is ignored" {
  # The trigger check should use uncommented content only
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/ic-in-comment.yml' | grep -q 'issue_comment'"
  assert_failure
}

# =============================================================================
# Secret reference grep
# =============================================================================

@test "detects secrets.FOO reference" {
  run grep -q 'secrets\.FOO' "$FIXTURES_DIR/workflows/secret-reference-foo.yml"
  assert_success
}

@test "secrets.FOO grep does NOT match secrets.FOOBAR (no partial match)" {
  # Fixed: uses word boundary to prevent substring matching.
  run grep -qE 'secrets\.FOO([^a-zA-Z0-9_]|$)' "$FIXTURES_DIR/workflows/secret-reference-foobar.yml"
  assert_failure
}

@test "secret mapping uses single-pass file-based approach" {
  # Phase 3 should build SECRET_MAP_FILE in one pass, not grep per secret
  run grep -c 'SECRET_MAP_FILE' "$SCRIPT"
  assert_success
  local count="${output}"
  [ "$count" -ge 3 ]
}

# =============================================================================
# join_array_cells() unit tests
# =============================================================================

_run_join_array_cells() {
  local tmpscript
  tmpscript=$(mktemp)
  {
    sed -n '/^join_array_cells()/,/^}/p' "$SCRIPT"
    echo "$@"
  } >"$tmpscript"
  bash "$tmpscript"
  rm -f "$tmpscript"
}

@test "join_array_cells: empty array returns No" {
  run _run_join_array_cells 'join_array_cells "<br/>"'
  assert_success
  assert_output "No"
}

@test "join_array_cells: single element returns element" {
  run _run_join_array_cells 'join_array_cells "<br/>" "foo.yml (API-only)"'
  assert_success
  assert_output "foo.yml (API-only)"
}

@test "join_array_cells: multiple elements joined with separator" {
  run _run_join_array_cells 'join_array_cells "<br/>" "a.yml (API-only)" "b.yml (checkout)"'
  assert_success
  assert_output "a.yml (API-only)<br/>b.yml (checkout)"
}

@test "join_array_cells: CSV separator works" {
  run _run_join_array_cells 'join_array_cells "; " "a.yml (API-only)" "b.yml (checkout)"'
  assert_success
  assert_output "a.yml (API-only); b.yml (checkout)"
}

# =============================================================================
# classify_prt() / classify_ic() unit tests
# =============================================================================

# Helper: run classify_prt or classify_ic on a fixture file
_run_classifier() {
  local func="$1" fixture="$2"
  local tmpscript
  tmpscript=$(mktemp)
  {
    _script_preamble
    echo 'content=$(cat "'"$fixture"'")'
    echo 'uncommented=$(grep -v "^\s*#" <<<"$content")'
    echo "$func"' "test.yml" "$content" "$uncommented"'
  } >"$tmpscript"
  bash "$tmpscript"
  rm -f "$tmpscript"
}

@test "classify_prt: checkout+exec no guard detected" {
  run _run_classifier classify_prt "$FIXTURES_DIR/workflows/prt-checkout-no-guard.yml"
  assert_success
  assert_output --partial "checkout+exec, no guard"
}

@test "classify_prt: checkout with guard detected" {
  run _run_classifier classify_prt "$FIXTURES_DIR/workflows/prt-checkout-with-guard-single-quote.yml"
  assert_success
  assert_output --partial "has guard"
}

@test "classify_prt: API-only (no checkout) detected" {
  run _run_classifier classify_prt "$FIXTURES_DIR/workflows/prt-api-only.yml"
  assert_success
  assert_output --partial "API-only"
}

@test "classify_prt: commented-out checkout classified as API-only" {
  run _run_classifier classify_prt "$FIXTURES_DIR/workflows/prt-checkout-commented-out.yml"
  assert_success
  assert_output --partial "API-only"
}

@test "classify_ic: author_association gate detected" {
  run _run_classifier classify_ic "$FIXTURES_DIR/workflows/issue-comment-with-gate.yml"
  assert_success
  assert_output --partial "has author_association"
}

@test "classify_ic: no gate detected" {
  run _run_classifier classify_ic "$FIXTURES_DIR/workflows/issue-comment-no-gate.yml"
  assert_success
  assert_output --partial "no author gate"
}

@test "classify_ic: comment-only author_association NOT counted as gate" {
  run _run_classifier classify_ic "$FIXTURES_DIR/workflows/issue-comment-author-in-comment.yml"
  assert_success
  assert_output --partial "no author gate"
}

# =============================================================================
# render_md_csv_row() integration tests (HDF pipeline)
# =============================================================================

# Helper: extract functions from script for testing
_script_preamble() {
  cat <<'PREAMBLE'
    CYAN='' YELLOW='' RED='' GREEN='' DIM='' RESET=''
    warn() { printf '[WARN] %s\n' "$*" >&2; }
    gh() { echo ''; return 0; }
    export -f gh
PREAMBLE
  # Extract helper and classify functions
  sed -n '/^extract_on_triggers()/,/^}/p' "$SCRIPT"
  sed -n '/^find_workflow_files()/,/^}/p' "$SCRIPT"
  sed -n '/^join_array_cells()/,/^}/p' "$SCRIPT"
  sed -n '/^json_escape()/,/^}/p' "$SCRIPT"
  sed -n '/^emit_hdf_requirement()/,/^}/p' "$SCRIPT"
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
  # HDF result functions and HDF pipeline
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
  sed -n '/^_extract_hdf_status()/,/^}/p' "$SCRIPT"
  sed -n '/^render_md_csv_row()/,/^}/p' "$SCRIPT"
}

_run_render_pipeline() {
  local repo="$1"
  local repo_dir="$2"
  local md_file csv_file cache_file
  md_file=$(mktemp)
  csv_file=$(mktemp)
  cache_file=$(mktemp)
  bash -c "
    $(_script_preamble)
    ORG='test-org'
    WORKFLOWS_DIR='$BATS_TEST_WORKFLOW_DIR'
    HDF_PROFILE_DIR='${PROJECT_ROOT}/hdf-profile'
    run_repo_classifiers '$repo_dir' '$cache_file' || exit 1
    hdf_json=\$(build_hdf_repo_target '$repo' '$repo_dir' '$cache_file') || exit 1
    render_md_csv_row '$repo' \"\$hdf_json\" '$cache_file' \
      '(none)' '$md_file' '$csv_file'
  "
  local rc=$?
  # Output md row then csv row (same format tests expect)
  if [ -s "$md_file" ]; then
    cat "$md_file"
    cat "$csv_file"
  fi
  rm -f "$md_file" "$csv_file" "$cache_file"
  return $rc
}

@test "render_md_csv_row: permissions-explicit workflow reports All permissions" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/permissions-explicit.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # First line is markdown row
  assert_line --index 0 --partial "All (1/1)"
}

@test "render_md_csv_row: permissions-none workflow reports None permissions" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/permissions-none.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "**None** (0/1)"
}

@test "render_md_csv_row: prt-checkout-no-guard reports checkout+exec, no guard" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/prt-checkout-no-guard.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "checkout+exec, no guard"
}

@test "render_md_csv_row: issue-comment-with-gate reports has author_association" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/issue-comment-with-gate.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "has author_association"
}

@test "render_md_csv_row: issue-comment-author-in-comment NOT flagged as gated" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/issue-comment-author-in-comment.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "no author gate"
}

@test "render_md_csv_row: prt-checkout-commented-out classified as API-only" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/prt-checkout-commented-out.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "API-only"
  refute_output --partial "checkout+exec"
  refute_output --partial "checkout, no fork ref"
}

@test "render_md_csv_row: prt-in-comment does NOT report pull_request_target" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/prt-in-comment.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # PRT column should say "No" (third pipe-field)
  refute_output --partial "pull_request_target"
  refute_output --partial "checkout"
  refute_output --partial "API-only"
  assert_line --index 0 --partial "|No|"
}

@test "render_md_csv_row: ic-in-comment does NOT report issue_comment" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/ic-in-comment.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # IC column should say "No" (fourth pipe-field)
  refute_output --partial "issue_comment"
  refute_output --partial "author"
}

@test "render_md_csv_row: empty directory returns failure" {
  setup_fixture_dir "test-org" "empty-repo"
  # No files copied — empty repo dir

  run _run_render_pipeline "empty-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/empty-repo"
  assert_failure
}

# =============================================================================
# Unpinned action detection (e2w)
# =============================================================================

@test "unpinned-actions: detects uses: lines with tag refs (not SHA)" {
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/unpinned-actions.yml' | grep -E 'uses:.*@' | grep -vE '@[0-9a-f]{40}'"
  assert_success
  assert_output --partial "@v4"
}

@test "pinned-actions: all uses: lines have SHA refs" {
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/pinned-actions.yml' | grep -E 'uses:.*@' | grep -vE '@[0-9a-f]{40}'"
  assert_failure
}

@test "mixed-pinning: detects unpinned subset" {
  local unpinned
  unpinned=$(grep -v '^\s*#' "$FIXTURES_DIR/workflows/mixed-pinning.yml" | grep -E 'uses:.*@' | grep -vE '@[0-9a-f]{40}' | wc -l | tr -d ' ')
  [ "$unpinned" -eq 2 ]
  local total
  total=$(grep -v '^\s*#' "$FIXTURES_DIR/workflows/mixed-pinning.yml" | grep -cE 'uses:.*@' | tr -d ' ')
  [ "$total" -eq 4 ]
}

@test "unpinned-actions-commented: commented-out unpinned action is NOT counted" {
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/unpinned-actions-commented.yml' | grep -E 'uses:.*@' | grep -vE '@[0-9a-f]{40}'"
  assert_failure
}

# --- classify_unpinned() unit tests ---

_run_classify_unpinned() {
  local fixture="$1"
  local tmpscript
  tmpscript=$(mktemp)
  {
    _script_preamble
    echo 'content=$(cat "'"$fixture"'")'
    echo 'uncommented=$(grep -v "^\s*#" <<<"$content")'
    echo 'classify_unpinned "test.yml" "$content" "$uncommented"'
  } >"$tmpscript"
  bash "$tmpscript"
  rm -f "$tmpscript"
}

@test "classify_unpinned: all unpinned reports 0/N pinned" {
  run _run_classify_unpinned "$FIXTURES_DIR/workflows/unpinned-actions.yml"
  assert_success
  assert_output --partial "0/3 pinned"
}

@test "classify_unpinned: all pinned reports N/N pinned" {
  run _run_classify_unpinned "$FIXTURES_DIR/workflows/pinned-actions.yml"
  assert_success
  assert_output --partial "3/3 pinned"
}

@test "classify_unpinned: mixed reports correct ratio" {
  run _run_classify_unpinned "$FIXTURES_DIR/workflows/mixed-pinning.yml"
  assert_success
  assert_output --partial "2/4 pinned"
}

@test "classify_unpinned: commented-out action not counted" {
  run _run_classify_unpinned "$FIXTURES_DIR/workflows/unpinned-actions-commented.yml"
  assert_success
  assert_output --partial "1/1 pinned"
}

@test "classify_unpinned: no uses: lines returns empty" {
  # issue-comment-no-gate.yml has no uses: lines (only run: steps)
  run _run_classify_unpinned "$FIXTURES_DIR/workflows/issue-comment-no-gate.yml"
  assert_success
  assert_output ""
}

# --- render_md_csv_row integration tests for unpinned actions ---

@test "render_md_csv_row: unpinned-actions reports 0/3 pinned in unpinned column" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/unpinned-actions.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "0/3 pinned"
}

@test "render_md_csv_row: pinned-actions reports 3/3 pinned in unpinned column" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/pinned-actions.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "3/3 pinned"
}

@test "render_md_csv_row: mixed-pinning reports 2/4 pinned" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/mixed-pinning.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "2/4 pinned"
}

@test "render_md_csv_row: benign workflow reports unpinned action" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # benign-workflow.yml has uses: actions/checkout@v4 (unpinned)
  assert_line --index 0 --partial "0/1 pinned"
}

@test "render_md_csv_row: workflow with no uses: lines has No in unpinned column" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/issue-comment-no-gate.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # issue-comment-no-gate.yml has no uses: lines → unpinned column = No
  local md_row
  md_row=$(echo "$output" | head -1)
  # Fields: repo(1)|perms(2)|prt(3)|ic(4)|unpin(5)|secrets(6)
  local unpinned_col
  unpinned_col=$(echo "$md_row" | cut -d'|' -f5)
  [ "$unpinned_col" = "No" ]
}

# =============================================================================
# Expression injection detection (exh)
# =============================================================================

# Dangerous expression patterns that can be injected via user-controlled input
# when used inside run: blocks (not in env: blocks which are safe)

# Helper: check for dangerous expressions in uncommented lines of a fixture
_grep_dangerous_expr() {
  local file="$1"
  grep -v '^\s*#' "$file" \
    | grep -E '\$\{\{.*(github\.event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body|review\.body|commits\[)|github\.head_ref)'
}

@test "expr-injection-pr-title: detects dangerous expression in run: block" {
  run _grep_dangerous_expr "$FIXTURES_DIR/workflows/expr-injection-pr-title.yml"
  assert_success
}

@test "expr-injection-head-ref: detects github.head_ref in run: block" {
  run _grep_dangerous_expr "$FIXTURES_DIR/workflows/expr-injection-head-ref.yml"
  assert_success
}

@test "expr-injection-safe: safe expressions NOT flagged" {
  run _grep_dangerous_expr "$FIXTURES_DIR/workflows/expr-injection-safe.yml"
  assert_failure
}

@test "expr-injection-in-comment: commented-out expression NOT flagged" {
  run _grep_dangerous_expr "$FIXTURES_DIR/workflows/expr-injection-in-comment.yml"
  assert_failure
}

# --- classify_expr_injection() unit tests ---

_run_classify_expr_injection() {
  local fixture="$1"
  local tmpscript
  tmpscript=$(mktemp)
  {
    _script_preamble
    echo 'content=$(cat "'"$fixture"'")'
    echo 'uncommented=$(grep -v "^\s*#" <<<"$content")'
    echo 'classify_expr_injection "test.yml" "$content" "$uncommented"'
  } >"$tmpscript"
  bash "$tmpscript"
  rm -f "$tmpscript"
}

@test "classify_expr_injection: PR title injection detected" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/expr-injection-pr-title.yml"
  assert_success
  assert_output --partial "pull_request.title"
}

@test "classify_expr_injection: head_ref injection detected" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/expr-injection-head-ref.yml"
  assert_success
  assert_output --partial "head_ref"
}

@test "classify_expr_injection: comment.body injection detected" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/expr-injection-comment-body.yml"
  assert_success
  assert_output --partial "comment.body"
}

@test "classify_expr_injection: multiple injections detected" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/expr-injection-multiple.yml"
  assert_success
  assert_output --partial "pull_request.title"
  assert_output --partial "head_ref"
}

@test "classify_expr_injection: safe expressions return empty" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/expr-injection-safe.yml"
  assert_success
  assert_output ""
}

@test "classify_expr_injection: commented-out injection returns empty" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/expr-injection-in-comment.yml"
  assert_success
  assert_output ""
}

@test "classify_expr_injection: env-block usage returns empty (safe pattern)" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/expr-injection-in-env.yml"
  assert_success
  assert_output ""
}

@test "classify_expr_injection: workflow_dispatch inputs.* detected" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/dispatch-input-injection.yml"
  assert_success
  assert_output --partial "inputs."
}

@test "classify_expr_injection: repository_dispatch client_payload detected" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/dispatch-client-payload.yml"
  assert_success
  assert_output --partial "client_payload."
}

@test "classify_expr_injection: dispatch with env: block is safe" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/dispatch-safe.yml"
  assert_success
  assert_output ""
}

@test "classify_expr_injection: discussion.title detected (GHA-016)" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/expr-injection-discussion.yml"
  assert_success
  assert_output --partial "discussion."
}

@test "classify_expr_injection: head_commit.message detected (GHA-016)" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/expr-injection-head-commit.yml"
  assert_success
  assert_output --partial "head_commit."
}

@test "classify_expr_injection: github.event.ref detected (GHA-019)" {
  run _run_classify_expr_injection "$FIXTURES_DIR/workflows/expr-injection-event-ref.yml"
  assert_success
  assert_output --partial "ref"
}

# --- render_md_csv_row integration tests for expression injection ---

@test "render_md_csv_row: expr-injection-pr-title reports expression injection" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/expr-injection-pr-title.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "pull_request.title"
}

@test "render_md_csv_row: expr-injection-safe has No in injection column" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/expr-injection-safe.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # Expr injection column (7th field) should be No
  local md_row
  md_row=$(echo "$output" | head -1)
  local expr_col
  expr_col=$(echo "$md_row" | cut -d'|' -f6)
  [ "$expr_col" = "No" ]
}

# =============================================================================
# workflow_run trigger detection (8yr)
# =============================================================================

_run_classify_wfr() {
  local fixture="$1"
  local tmpscript
  tmpscript=$(mktemp)
  {
    _script_preamble
    echo 'content=$(cat "'"$fixture"'")'
    echo 'uncommented=$(grep -v "^\s*#" <<<"$content")'
    echo 'classify_wfr "test.yml" "$content" "$uncommented"'
  } >"$tmpscript"
  bash "$tmpscript"
  rm -f "$tmpscript"
}

@test "classify_wfr: artifact download detected as high risk" {
  run _run_classify_wfr "$FIXTURES_DIR/workflows/workflow-run-artifact.yml"
  assert_success
  assert_output --partial "download-artifact"
}

@test "classify_wfr: checkout detected as medium risk" {
  run _run_classify_wfr "$FIXTURES_DIR/workflows/workflow-run-checkout.yml"
  assert_success
  assert_output --partial "checkout"
}

@test "classify_wfr: API-only detected as low risk" {
  run _run_classify_wfr "$FIXTURES_DIR/workflows/workflow-run-api-only.yml"
  assert_success
  assert_output --partial "API-only"
}

@test "classify_wfr: no workflow_run returns empty" {
  run _run_classify_wfr "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

@test "render_md_csv_row: workflow-run-artifact reports in wfr column" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/workflow-run-artifact.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "download-artifact"
}

# =============================================================================
# Self-hosted runner detection (6c6)
# =============================================================================

@test "self-hosted-runner: detects runs-on: self-hosted" {
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/self-hosted-runner.yml' | grep -qiE 'runs-on:.*self-hosted'"
  assert_success
}

@test "self-hosted-custom-label: detects self-hosted in array" {
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/self-hosted-custom-label.yml' | grep -qiE 'runs-on:.*self-hosted'"
  assert_success
}

@test "self-hosted-in-comment: commented-out self-hosted NOT detected" {
  run bash -c "grep -v '^\s*#' '$FIXTURES_DIR/workflows/self-hosted-in-comment.yml' | grep -qiE 'runs-on:.*self-hosted'"
  assert_failure
}

_run_classify_self_hosted() {
  local fixture="$1"
  local tmpscript
  tmpscript=$(mktemp)
  {
    _script_preamble
    echo 'content=$(cat "'"$fixture"'")'
    echo 'uncommented=$(grep -v "^\s*#" <<<"$content")'
    echo 'classify_self_hosted "test.yml" "$content" "$uncommented"'
  } >"$tmpscript"
  bash "$tmpscript"
  rm -f "$tmpscript"
}

@test "classify_self_hosted: detects self-hosted runner" {
  run _run_classify_self_hosted "$FIXTURES_DIR/workflows/self-hosted-runner.yml"
  assert_success
  assert_output --partial "self-hosted"
}

@test "classify_self_hosted: detects self-hosted in label array" {
  run _run_classify_self_hosted "$FIXTURES_DIR/workflows/self-hosted-custom-label.yml"
  assert_success
  assert_output --partial "self-hosted"
}

@test "classify_self_hosted: commented-out self-hosted returns empty" {
  run _run_classify_self_hosted "$FIXTURES_DIR/workflows/self-hosted-in-comment.yml"
  assert_success
  assert_output ""
}

@test "classify_self_hosted: github-hosted runner returns empty" {
  run _run_classify_self_hosted "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

@test "render_md_csv_row: self-hosted runner reported in output" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/self-hosted-runner.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "self-hosted"
}

@test "render_md_csv_row: github-hosted runner has No in self-hosted column" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # Self-hosted column should be "No"
  local md_row
  md_row=$(echo "$output" | head -1)
  local sh_col
  sh_col=$(echo "$md_row" | cut -d'|' -f8)
  [ "$sh_col" = "No" ]
}

# =============================================================================
# Dangerous permissions values detection (zys)
# =============================================================================

_run_classify_dangerous_perms() {
  local fixture="$1"
  local tmpscript
  tmpscript=$(mktemp)
  {
    _script_preamble
    echo 'content=$(cat "'"$fixture"'")'
    echo 'uncommented=$(grep -v "^\s*#" <<<"$content")'
    echo 'classify_dangerous_perms "test.yml" "$content" "$uncommented"'
  } >"$tmpscript"
  bash "$tmpscript"
  rm -f "$tmpscript"
}

@test "classify_dangerous_perms: detects write-all" {
  run _run_classify_dangerous_perms "$FIXTURES_DIR/workflows/dangerous-perms-write-all.yml"
  assert_success
  assert_output --partial "write-all"
}

@test "classify_dangerous_perms: detects contents:write" {
  run _run_classify_dangerous_perms "$FIXTURES_DIR/workflows/dangerous-perms-contents-write.yml"
  assert_success
  assert_output --partial "contents: write"
}

@test "classify_dangerous_perms: safe read-only perms return empty" {
  run _run_classify_dangerous_perms "$FIXTURES_DIR/workflows/safe-perms-read.yml"
  assert_success
  assert_output ""
}

@test "classify_dangerous_perms: no permissions block returns empty" {
  run _run_classify_dangerous_perms "$FIXTURES_DIR/workflows/permissions-none.yml"
  assert_success
  assert_output ""
}

@test "render_md_csv_row: dangerous-perms-write-all reports write-all" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/dangerous-perms-write-all.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "write-all"
}

@test "render_md_csv_row: safe-perms-read has No in dangerous perms column" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/safe-perms-read.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # Dangerous perms column should be "No"
  local md_row
  md_row=$(echo "$output" | head -1)
  local dp_col
  dp_col=$(echo "$md_row" | cut -d'|' -f9)
  [ "$dp_col" = "No" ]
}

# =============================================================================
# Hardcoded secrets detection (ub8)
# =============================================================================

@test "hardcoded-token: detects ghp_ token in workflow" {
  run grep -cE 'ghp_[A-Za-z0-9]{36}' "$FIXTURES_DIR/workflows/hardcoded-token.yml"
  assert_success
}

@test "hardcoded-aws-key: detects AKIA prefix in workflow" {
  run grep -cE 'AKIA[A-Z0-9]{16}' "$FIXTURES_DIR/workflows/hardcoded-aws-key.yml"
  assert_success
}

@test "hardcoded-token-in-comment: token in comment line NOT detected" {
  run grep -v '^\s*#' "$FIXTURES_DIR/workflows/hardcoded-token-in-comment.yml"
  assert_success
  refute_output --partial "ghp_"
}

@test "classify_hardcoded_secrets: detects ghp_ token" {
  run _run_classifier classify_hardcoded_secrets "$FIXTURES_DIR/workflows/hardcoded-token.yml"
  assert_success
  assert_output --partial "ghp_"
}

@test "classify_hardcoded_secrets: detects AKIA key" {
  run _run_classifier classify_hardcoded_secrets "$FIXTURES_DIR/workflows/hardcoded-aws-key.yml"
  assert_success
  assert_output --partial "AKIA"
}

@test "classify_hardcoded_secrets: comment-only token returns empty" {
  run _run_classifier classify_hardcoded_secrets "$FIXTURES_DIR/workflows/hardcoded-token-in-comment.yml"
  assert_success
  assert_output ""
}

@test "classify_hardcoded_secrets: clean workflow returns empty" {
  run _run_classifier classify_hardcoded_secrets "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

# =============================================================================
# Harden-runner adoption (ub8)
# =============================================================================

@test "harden-runner-used: detects step-security/harden-runner" {
  run grep -q 'step-security/harden-runner' "$FIXTURES_DIR/workflows/harden-runner-used.yml"
  assert_success
}

@test "harden-runner: benign workflow does NOT have harden-runner" {
  run grep -q 'step-security/harden-runner' "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_failure
}

@test "render_md_csv_row: hardcoded ghp_ token reported in output" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/hardcoded-token.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial "ghp_"
}

@test "render_md_csv_row: hardcoded AKIA key reported in output" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/hardcoded-aws-key.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial "AKIA"
}

@test "render_md_csv_row: commented-out token has No in hardcoded secrets column" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/hardcoded-token-in-comment.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # Field 10 (hardcoded secrets) should be No
  local md_row
  md_row=$(echo "$output" | head -1)
  local hs_col
  hs_col=$(echo "$md_row" | cut -d'|' -f10)
  [ "$hs_col" = "No" ]
}

@test "render_md_csv_row: harden-runner workflow reports adoption" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/harden-runner-used.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial "harden-runner"
}

@test "render_md_csv_row: benign workflow has No in hardcoded secrets and harden-runner columns" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  local md_row
  md_row=$(echo "$output" | head -1)
  # Field 10 (hardcoded secrets) = No, Field 11 (harden-runner) = No
  local hs_col hr_col
  hs_col=$(echo "$md_row" | cut -d'|' -f10)
  hr_col=$(echo "$md_row" | cut -d'|' -f11)
  [ "$hs_col" = "No" ]
  [ "$hr_col" = "No" ]
}

# =============================================================================
# False positive: trigger keywords in run: string values (3zo)
# =============================================================================

@test "extract_on_triggers: extracts on: section from workflow" {
  local input
  input=$(cat <<'YAML'
name: CI
on:
  pull_request_target:
    types: [opened]
  issue_comment:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
YAML
  )
  run bash -c "
    $(_script_preamble)
    extract_on_triggers \"\$1\"
  " -- "$input"
  assert_success
  assert_output --partial "pull_request_target"
  assert_output --partial "issue_comment"
  refute_output --partial "jobs:"
  refute_output --partial "echo"
}

@test "extract_on_triggers: does not include run: block content" {
  local input
  input=$(cat <<'YAML'
name: Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "pull_request_target issue_comment workflow_run"
YAML
  )
  run bash -c "
    $(_script_preamble)
    extract_on_triggers \"\$1\"
  " -- "$input"
  assert_success
  assert_output --partial "push"
  refute_output --partial "pull_request_target"
  refute_output --partial "issue_comment"
  refute_output --partial "workflow_run"
}

@test "render_md_csv_row: trigger keywords in run: string NOT flagged" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/trigger-keyword-in-run.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # PRT, IC, and WFR columns should all be "No"
  refute_output --partial "pull_request_target"
  refute_output --partial "issue_comment"
  refute_output --partial "workflow_run"
  refute_output --partial "checkout"
  refute_output --partial "API-only"
  refute_output --partial "author"
}

@test "render_md_csv_row: real PRT trigger still detected after on: extraction" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/prt-api-only.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_render_pipeline "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial "API-only"
}

# =============================================================================
# run_repo_classifiers() unit tests
# =============================================================================

_run_repo_classifiers() {
  local repo_dir="$1"
  local cache_file
  cache_file=$(mktemp)
  local tmpscript
  tmpscript=$(mktemp)
  {
    _script_preamble
    echo "run_repo_classifiers '$repo_dir' '$cache_file' || exit 1"
    echo "cat '$cache_file'"
  } >"$tmpscript"
  local rc=0
  bash "$tmpscript" || rc=$?
  rm -f "$tmpscript" "$cache_file"
  return $rc
}

@test "run_repo_classifiers: writes META lines" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_repo_classifiers "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial "META|total_wf|1"
  assert_output --partial "META|wf_with_perms|"
  assert_output --partial "META|has_harden_runner|"
}

@test "run_repo_classifiers: PRT finding for prt workflow" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/prt-checkout-no-guard.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_repo_classifiers "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial "PRT|"
  assert_output --partial "checkout+exec, no guard"
}

@test "run_repo_classifiers: empty dir returns failure" {
  setup_fixture_dir "test-org" "empty-repo"

  run _run_repo_classifiers "$BATS_TEST_WORKFLOW_DIR/test-org/empty-repo"
  assert_failure
}

@test "run_repo_classifiers: benign workflow produces only META lines" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_repo_classifiers "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # Should have META lines and an UNPIN finding (benign has unpinned checkout@v4)
  assert_output --partial "META|total_wf|1"
  # No PRT, IC, WFR, SH, DP, HS findings
  refute_output --partial "PRT|"
  refute_output --partial "IC|"
  refute_output --partial "WFR|"
  refute_output --partial "SH|"
  refute_output --partial "DP|"
  refute_output --partial "HS|"
}

# =============================================================================
# secrets: inherit detection (GHA-014)
# =============================================================================

@test "classify_secrets_inherit: detects secrets: inherit" {
  run _run_classifier classify_secrets_inherit "$FIXTURES_DIR/workflows/secrets-inherit.yml"
  assert_success
  assert_output --partial "secrets: inherit"
}

@test "classify_secrets_inherit: explicit secrets returns empty" {
  run _run_classifier classify_secrets_inherit "$FIXTURES_DIR/workflows/secrets-explicit.yml"
  assert_success
  assert_output ""
}

@test "classify_secrets_inherit: commented-out inherit returns empty" {
  run _run_classifier classify_secrets_inherit "$FIXTURES_DIR/workflows/secrets-inherit-in-comment.yml"
  assert_success
  assert_output ""
}

@test "classify_secrets_inherit: benign workflow returns empty" {
  run _run_classifier classify_secrets_inherit "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

# =============================================================================
# GITHUB_ENV/PATH/OUTPUT injection detection (GHA-015)
# =============================================================================

@test "classify_env_injection: detects GITHUB_ENV write" {
  run _run_classifier classify_env_injection "$FIXTURES_DIR/workflows/env-injection-github-env.yml"
  assert_success
  assert_output --partial "GITHUB_ENV"
}

@test "classify_env_injection: detects GITHUB_PATH write" {
  run _run_classifier classify_env_injection "$FIXTURES_DIR/workflows/env-injection-github-path.yml"
  assert_success
  assert_output --partial "GITHUB_PATH"
}

@test "classify_env_injection: detects GITHUB_OUTPUT write" {
  run _run_classifier classify_env_injection "$FIXTURES_DIR/workflows/env-injection-github-output.yml"
  assert_success
  assert_output --partial "GITHUB_OUTPUT"
}

@test "classify_env_injection: detects multiple targets" {
  run _run_classifier classify_env_injection "$FIXTURES_DIR/workflows/env-injection-multiple.yml"
  assert_success
  assert_output --partial "GITHUB_ENV"
  assert_output --partial "GITHUB_PATH"
}

@test "classify_env_injection: commented-out write returns empty" {
  run _run_classifier classify_env_injection "$FIXTURES_DIR/workflows/env-injection-in-comment.yml"
  assert_success
  assert_output ""
}

@test "classify_env_injection: benign workflow returns empty" {
  run _run_classifier classify_env_injection "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

# =============================================================================
# Deprecated workflow commands detection (GHA-017)
# =============================================================================

@test "classify_deprecated_commands: detects ::set-output" {
  run _run_classifier classify_deprecated_commands "$FIXTURES_DIR/workflows/deprecated-set-output.yml"
  assert_success
  assert_output --partial "set-output"
}

@test "classify_deprecated_commands: detects ::set-env and ::add-path" {
  run _run_classifier classify_deprecated_commands "$FIXTURES_DIR/workflows/deprecated-set-env.yml"
  assert_success
  assert_output --partial "set-env"
  assert_output --partial "add-path"
}

@test "classify_deprecated_commands: commented-out command returns empty" {
  run _run_classifier classify_deprecated_commands "$FIXTURES_DIR/workflows/deprecated-in-comment.yml"
  assert_success
  assert_output ""
}

@test "classify_deprecated_commands: benign workflow returns empty" {
  run _run_classifier classify_deprecated_commands "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

# =============================================================================
# Known-compromised actions detection (GHA-018)
# =============================================================================

@test "classify_known_vulnerable: detects tj-actions/changed-files" {
  run _run_classifier classify_known_vulnerable "$FIXTURES_DIR/workflows/known-vulnerable-tj-actions.yml"
  assert_success
  assert_output --partial "tj-actions/changed-files"
}

@test "classify_known_vulnerable: detects reviewdog/action-setup" {
  run _run_classifier classify_known_vulnerable "$FIXTURES_DIR/workflows/known-vulnerable-reviewdog.yml"
  assert_success
  assert_output --partial "reviewdog/action-setup"
}

@test "classify_known_vulnerable: commented-out action returns empty" {
  run _run_classifier classify_known_vulnerable "$FIXTURES_DIR/workflows/known-vulnerable-in-comment.yml"
  assert_success
  assert_output ""
}

@test "classify_known_vulnerable: benign workflow returns empty" {
  run _run_classifier classify_known_vulnerable "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

# --- run_repo_classifiers integration for new detections ---

@test "run_repo_classifiers: SI finding for secrets-inherit" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/secrets-inherit.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_repo_classifiers "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial "SI|"
  assert_output --partial "secrets: inherit"
}

@test "run_repo_classifiers: EI finding for env injection" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/env-injection-github-env.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_repo_classifiers "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial "EI|"
  assert_output --partial "GITHUB_ENV"
}

@test "run_repo_classifiers: DC finding for deprecated commands" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/deprecated-set-output.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_repo_classifiers "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial "DC|"
  assert_output --partial "set-output"
}

@test "run_repo_classifiers: KV finding for known-vulnerable" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/known-vulnerable-tj-actions.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_repo_classifiers "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_output --partial "KV|"
  assert_output --partial "tj-actions/changed-files"
}

@test "run_repo_classifiers: benign workflow has no SI, EI, DC, KV findings" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_repo_classifiers "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  refute_output --partial "SI|"
  refute_output --partial "EI|"
  refute_output --partial "DC|"
  refute_output --partial "KV|"
}

# =============================================================================
# Unpinned third-party actions (GHA-020)
# =============================================================================

@test "classify_unpinned_third_party: detects third-party unpinned" {
  run _run_classifier classify_unpinned_third_party "$FIXTURES_DIR/workflows/unpinned-third-party.yml"
  assert_success
  assert_output --partial "third-party unpinned"
}

@test "classify_unpinned_third_party: benign (first-party only) returns empty" {
  run _run_classifier classify_unpinned_third_party "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

@test "classify_unpinned_third_party: pinned actions returns empty" {
  run _run_classifier classify_unpinned_third_party "$FIXTURES_DIR/workflows/pinned-actions.yml"
  assert_success
  assert_output ""
}

# =============================================================================
# always()/continue-on-error + secrets (GHA-022)
# =============================================================================

@test "classify_always_secrets: detects always() + secrets" {
  run _run_classifier classify_always_secrets "$FIXTURES_DIR/workflows/always-secrets.yml"
  assert_success
  assert_output --partial "always()"
  assert_output --partial "secrets"
}

@test "classify_always_secrets: detects continue-on-error + secrets" {
  run _run_classifier classify_always_secrets "$FIXTURES_DIR/workflows/continue-on-error-secrets.yml"
  assert_success
  assert_output --partial "continue-on-error"
  assert_output --partial "secrets"
}

@test "classify_always_secrets: benign workflow returns empty" {
  run _run_classifier classify_always_secrets "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

# =============================================================================
# Artifact trust (GHA-023)
# =============================================================================

@test "classify_artifact_trust: detects download-artifact" {
  run _run_classifier classify_artifact_trust "$FIXTURES_DIR/workflows/download-artifact.yml"
  assert_success
  assert_output --partial "download-artifact"
}

@test "classify_artifact_trust: benign workflow returns empty" {
  run _run_classifier classify_artifact_trust "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

# =============================================================================
# Deployment without environment (GHA-024)
# =============================================================================

@test "classify_missing_environment: detects deploy without environment" {
  run _run_classifier classify_missing_environment "$FIXTURES_DIR/workflows/deploy-no-environment.yml"
  assert_success
  assert_output --partial "deploy without environment"
}

@test "classify_missing_environment: deploy with environment returns empty" {
  run _run_classifier classify_missing_environment "$FIXTURES_DIR/workflows/deploy-with-environment.yml"
  assert_success
  assert_output ""
}

@test "classify_missing_environment: benign workflow returns empty" {
  run _run_classifier classify_missing_environment "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

# =============================================================================
# Cache poisoning (GHA-025)
# =============================================================================

@test "classify_cache_poisoning: detects actions/cache" {
  run _run_classifier classify_cache_poisoning "$FIXTURES_DIR/workflows/cache-usage.yml"
  assert_success
  assert_output --partial "actions/cache"
}

@test "classify_cache_poisoning: benign workflow returns empty" {
  run _run_classifier classify_cache_poisoning "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

# =============================================================================
# Static credentials vs OIDC (GHA-026)
# =============================================================================

@test "classify_static_credentials: detects static AWS credentials" {
  run _run_classifier classify_static_credentials "$FIXTURES_DIR/workflows/static-credentials.yml"
  assert_success
  assert_output --partial "static cloud credentials"
}

@test "classify_static_credentials: OIDC with id-token:write returns empty" {
  run _run_classifier classify_static_credentials "$FIXTURES_DIR/workflows/oidc-credentials.yml"
  assert_success
  assert_output ""
}

@test "classify_static_credentials: benign workflow returns empty" {
  run _run_classifier classify_static_credentials "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_success
  assert_output ""
}

# =============================================================================
# Benign workflow (no findings)
# =============================================================================

@test "benign workflow has no pull_request_target" {
  run grep -q 'pull_request_target' "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_failure
}

@test "benign workflow has no issue_comment" {
  run grep -q 'issue_comment' "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_failure
}
