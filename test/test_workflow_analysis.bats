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

@test "BUG: permissions-in-comment is a false positive with current grep" {
  # Current script uses 'grep -q permissions:' which matches inside comments.
  # This test documents the bug — it should PASS (proving the bug exists).
  # When we fix the bug, this test inverts to assert_failure.
  run grep -q 'permissions:' "$FIXTURES_DIR/workflows/permissions-in-comment.yml"
  assert_success
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

@test "BUG: prt-head-ref: github.head_ref not detected as fork ref by current regex" {
  # The script checks for 'pull_request.head.(sha|ref)' but not 'github.head_ref'.
  # github.head_ref is the shorthand that many workflows use.
  run grep -qE 'pull_request\.head\.(sha|ref)' "$FIXTURES_DIR/workflows/prt-head-ref.yml"
  assert_failure
}

@test "prt-head-repo-fullname: head.repo.full_name contains head.sha match" {
  run grep -qE 'pull_request\.head\.(sha|ref)' "$FIXTURES_DIR/workflows/prt-head-repo-fullname.yml"
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

@test "BUG: issue-comment-author-in-comment: false positive — author_association appears only in comment" {
  # Current script uses 'grep -q author_association' which matches comments.
  # This documents the bug.
  run grep -q 'author_association' "$FIXTURES_DIR/workflows/issue-comment-author-in-comment.yml"
  assert_success
}

# =============================================================================
# Secret reference grep
# =============================================================================

@test "detects secrets.FOO reference" {
  run grep -q 'secrets\.FOO' "$FIXTURES_DIR/workflows/secret-reference-foo.yml"
  assert_success
}

@test "BUG: secrets.FOO grep also matches secrets.FOOBAR (partial match)" {
  # Current script: grep -rl "secrets.$secret_name" which matches substrings.
  # This test documents the bug.
  run grep -q 'secrets\.FOO' "$FIXTURES_DIR/workflows/secret-reference-foobar.yml"
  assert_success
}

@test "benign workflow has no pull_request_target" {
  run grep -q 'pull_request_target' "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_failure
}

@test "benign workflow has no issue_comment" {
  run grep -q 'issue_comment' "$FIXTURES_DIR/workflows/benign-workflow.yml"
  assert_failure
}
