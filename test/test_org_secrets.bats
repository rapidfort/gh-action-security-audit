#!/usr/bin/env bats
#
# Tests for Phase 3 org secrets workflow usage mapping.

setup() {
  load test_helper/common-setup
}

# =============================================================================
# Secret-to-workflow mapping
# =============================================================================

@test "grep finds repos referencing a specific secret" {
  # Set up a temp workflow dir structure
  setup_fixture_dir "test-org" "repo-a"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b"
  cp "$FIXTURES_DIR/workflows/secret-reference-foo.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b/"

  # Grep for secrets.FOO
  run bash -c "grep -rl 'secrets\.FOO' '$BATS_TEST_WORKFLOW_DIR' | sed 's|$BATS_TEST_WORKFLOW_DIR/test-org/||' | cut -d/ -f1 | sort -u"
  assert_success
  assert_output "repo-a"
}

@test "BUG: partial secret name match — FOO matches FOOBAR" {
  setup_fixture_dir "test-org" "repo-a"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b"
  cp "$FIXTURES_DIR/workflows/secret-reference-foo.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"
  cp "$FIXTURES_DIR/workflows/secret-reference-foobar.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b/"

  # Current script greps for 'secrets.FOO' which also matches 'secrets.FOOBAR'
  run bash -c "grep -rl 'secrets\.FOO' '$BATS_TEST_WORKFLOW_DIR' | sed 's|$BATS_TEST_WORKFLOW_DIR/test-org/||' | cut -d/ -f1 | sort -u | paste -sd',' -"
  assert_success
  # Bug: returns both repos when it should only return repo-a
  assert_output "repo-a,repo-b"
}

@test "no repos reference a nonexistent secret" {
  setup_fixture_dir "test-org" "repo-a"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"

  run bash -c "grep -rl 'secrets\.NONEXISTENT' '$BATS_TEST_WORKFLOW_DIR' 2>/dev/null || true"
  assert_output ""
}
