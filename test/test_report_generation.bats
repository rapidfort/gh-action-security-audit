#!/usr/bin/env bats
#
# Tests for Phase 5 report generation.
# These tests run the full script with mocked gh CLI and local fixtures,
# then verify report content.

setup() {
  load test_helper/common-setup
  setup_mock_gh
  mock_gh_response "api user --jq .login" "test-user"
  mock_gh_response "auth status" ""

  # Set up a local workflow dir with test fixtures
  setup_fixture_dir "test-org" "repo-with-prt"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-clean"

  cp "$FIXTURES_DIR/workflows/prt-checkout-no-guard.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-with-prt/"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-clean/"

  # Mock org-level API calls
  mock_gh_response "api orgs/test-org/actions/secrets --paginate --jq .secrets[] | \"\(.name)|\(.visibility)\"" ""
  mock_gh_response "api orgs/test-org/actions/permissions/workflow" '{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}'
  mock_gh_response "api orgs/test-org/actions/permissions" '{"allowed_actions":"selected"}'

  # Repo secrets — return empty for each
  mock_gh_response "api repos/test-org/repo-with-prt/actions/secrets --jq .secrets[].name" ""
  mock_gh_response "api repos/test-org/repo-clean/actions/secrets --jq .secrets[].name" ""

  REPORT_FILE="$(mktemp)"
}

teardown() {
  rm -f "$REPORT_FILE"
  # Call parent teardown
  if [[ -n "${MOCK_GH_DIR:-}" && -d "${MOCK_GH_DIR:-}" ]]; then
    rm -rf "${MOCK_GH_DIR}"
  fi
  if [[ -n "${BATS_TEST_WORKFLOW_DIR:-}" && -d "${BATS_TEST_WORKFLOW_DIR:-}" ]]; then
    rm -rf "${BATS_TEST_WORKFLOW_DIR}"
  fi
}

@test "report contains org name in title" {
  run bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE"
  assert_success
  run cat "$REPORT_FILE"
  assert_output --partial "test-org"
}

@test "report contains per-repository audit section" {
  run bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE"
  assert_success
  run cat "$REPORT_FILE"
  assert_output --partial "Per-Repository Audit"
}

@test "report contains review guidance section" {
  run bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE"
  assert_success
  run cat "$REPORT_FILE"
  assert_output --partial "Review Guidance"
}
