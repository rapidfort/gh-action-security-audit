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
# analyze_repo() integration tests
# =============================================================================

# Helper: extract analyze_repo function from script and call it
_run_analyze_repo() {
  local repo="$1"
  local repo_dir="$2"
  # Extract the function definition, helper functions, and call it
  bash -c "
    # Define color variables and helper functions needed by analyze_repo
    CYAN='' YELLOW='' RED='' GREEN='' DIM='' RESET=''
    warn() { printf '[WARN] %s\n' \"\$*\" >&2; }
    # Set globals
    ORG='test-org'
    WORKFLOWS_DIR='$BATS_TEST_WORKFLOW_DIR'
    # Extract and define analyze_repo from the script
    $(sed -n '/^analyze_repo()/,/^}/p' "$SCRIPT")
    # Mock gh api for secrets (return empty)
    gh() { echo ''; return 0; }
    export -f gh
    analyze_repo '$repo' '$repo_dir'
  "
}

@test "analyze_repo: permissions-explicit workflow reports All permissions" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/permissions-explicit.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_analyze_repo "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  # First line is markdown row
  assert_line --index 0 --partial "All (1/1)"
}

@test "analyze_repo: permissions-none workflow reports None permissions" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/permissions-none.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_analyze_repo "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "**None** (0/1)"
}

@test "analyze_repo: prt-checkout-no-guard reports checkout+exec, no guard" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/prt-checkout-no-guard.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_analyze_repo "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "checkout+exec, no guard"
}

@test "analyze_repo: issue-comment-with-gate reports has author_association" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/issue-comment-with-gate.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_analyze_repo "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "has author_association"
}

@test "analyze_repo: issue-comment-author-in-comment NOT flagged as gated" {
  setup_fixture_dir "test-org" "test-repo"
  cp "$FIXTURES_DIR/workflows/issue-comment-author-in-comment.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"

  run _run_analyze_repo "test-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo"
  assert_success
  assert_line --index 0 --partial "no author gate"
}

@test "analyze_repo: empty directory returns failure" {
  setup_fixture_dir "test-org" "empty-repo"
  # No files copied — empty repo dir

  run _run_analyze_repo "empty-repo" "$BATS_TEST_WORKFLOW_DIR/test-org/empty-repo"
  assert_failure
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
