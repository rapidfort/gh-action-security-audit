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

@test "secret name match is exact — FOO does NOT match FOOBAR" {
  setup_fixture_dir "test-org" "repo-a"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b"
  cp "$FIXTURES_DIR/workflows/secret-reference-foo.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"
  cp "$FIXTURES_DIR/workflows/secret-reference-foobar.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b/"

  # Fixed: uses word boundary grep to prevent substring matching
  run bash -c "grep -rlE 'secrets\.FOO([^a-zA-Z0-9_]|\$)' '$BATS_TEST_WORKFLOW_DIR' | sed 's|$BATS_TEST_WORKFLOW_DIR/test-org/||' | cut -d/ -f1 | sort -u | paste -sd',' -"
  assert_success
  # Should only return repo-a, not repo-b
  assert_output "repo-a"
}

@test "no repos reference a nonexistent secret" {
  setup_fixture_dir "test-org" "repo-a"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"

  run bash -c "grep -rl 'secrets\.NONEXISTENT' '$BATS_TEST_WORKFLOW_DIR' 2>/dev/null || true"
  assert_output ""
}
