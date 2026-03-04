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

  # Mock org-level API calls — use mock_gh_response_args for --jq calls
  # so args with spaces are hashed correctly (one per $@ element).
  # Org secrets
  mock_gh_response_args api "orgs/test-org/actions/secrets" --paginate \
    --jq '.secrets[] | "\(.name)|\(.visibility)"' -- ""
  # Workflow permissions (--jq produces pipe-delimited string)
  mock_gh_response_args api "orgs/test-org/actions/permissions/workflow" \
    --jq '(.default_workflow_permissions // "unknown") + "|" + ((.can_approve_pull_request_reviews // "unknown") | tostring)' \
    -- 'read|false'
  # Actions permissions (allowed_actions, enabled_repositories, sha_pinning_required)
  mock_gh_response_args api "orgs/test-org/actions/permissions" \
    --jq '(.allowed_actions // "unknown") + "|" + (.enabled_repositories // "unknown") + "|" + ((.sha_pinning_required // false) | tostring)' \
    -- "selected|selected|false"

  # Repo secrets — return empty for each
  mock_gh_response_args api "repos/test-org/repo-with-prt/actions/secrets" --jq '.secrets[].name' -- ""
  mock_gh_response_args api "repos/test-org/repo-clean/actions/secrets" --jq '.secrets[].name' -- ""

  REPORT_FILE="$(mktemp)"
  CSV_REPORT="$(mktemp)"
}

teardown() {
  rm -f "$REPORT_FILE" "$CSV_REPORT"
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

# --- Phase 4: org settings in report (5mv) ---

@test "report shows default workflow permissions from API" {
  run bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE"
  assert_success
  run cat "$REPORT_FILE"
  # Org settings table should show "read", not "unknown"
  assert_output --partial "| Default workflow permissions | \`read\`"
  refute_output --partial "unknown"
}

@test "report shows allowed actions policy from API" {
  run bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE"
  assert_success
  run cat "$REPORT_FILE"
  # "selected" maps to "Selected" in report
  assert_output --partial "| Allowed actions | Selected |"
}

@test "report shows PR approval policy from API" {
  run bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE"
  assert_success
  run cat "$REPORT_FILE"
  # "false" maps to "No" in report
  assert_output --partial "| Workflows can approve PRs | No |"
}

# --- CSV output tests (aov) ---

@test "CSV: --csv flag produces output file" {
  run bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE" --csv "$CSV_REPORT"
  assert_success
  [ -s "$CSV_REPORT" ]
}

@test "CSV: has per-repo header row" {
  bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE" --csv "$CSV_REPORT"
  run head -1 "$CSV_REPORT"
  assert_output "Repository,Explicit Permissions,pull_request_target,issue_comment,Unpinned Actions,Expression Injection,workflow_run,Self-Hosted,Dangerous Perms,Hardcoded Secrets,Harden-Runner,Repo Secrets"
}

@test "CSV: has org-secrets header after blank line" {
  bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE" --csv "$CSV_REPORT"
  run cat "$CSV_REPORT"
  assert_output --partial "Org Secret,Visibility,Configured Access,Referenced In Workflows,Suggested Command"
}

@test "CSV: contains per-repo data rows" {
  bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE" --csv "$CSV_REPORT"
  run cat "$CSV_REPORT"
  assert_output --partial "repo-clean"
  assert_output --partial "repo-with-prt"
}

@test "CSV: per-repo and org-secrets sections separated by blank row" {
  bash "$SCRIPT" test-org --local "$BATS_TEST_WORKFLOW_DIR" --out "$REPORT_FILE" --csv "$CSV_REPORT"
  # Check that there's an empty line between per-repo data and org-secrets header
  run awk '/^$/{blank=1; next} blank && /^Org Secret/{found=1} END{print found ? "yes" : "no"}' "$CSV_REPORT"
  assert_output "yes"
}

@test "csv_field: plain value passed through unquoted" {
  # csv_field is defined inside if [ -n CSV_FILE ]; extract it
  run bash -c '
    csv_field() {
      local val="$1"
      if [[ "$val" == *,* ]] || [[ "$val" == *\"* ]] || [[ "$val" == *$'"'"'\n'"'"'* ]]; then
        val="${val//\"/\"\"}"
        printf "%s" "\"$val\""
      else
        printf "%s" "$val"
      fi
    }
    csv_field "hello"
  '
  assert_output "hello"
}

@test "csv_field: value with comma is quoted" {
  run bash -c '
    csv_field() {
      local val="$1"
      if [[ "$val" == *,* ]] || [[ "$val" == *\"* ]] || [[ "$val" == *$'"'"'\n'"'"'* ]]; then
        val="${val//\"/\"\"}"
        printf "%s" "\"$val\""
      else
        printf "%s" "$val"
      fi
    }
    csv_field "a,b"
  '
  assert_output '"a,b"'
}

@test "csv_field: value with double quotes is escaped and quoted" {
  run bash -c '
    csv_field() {
      local val="$1"
      if [[ "$val" == *,* ]] || [[ "$val" == *\"* ]] || [[ "$val" == *$'"'"'\n'"'"'* ]]; then
        val="${val//\"/\"\"}"
        printf "%s" "\"$val\""
      else
        printf "%s" "$val"
      fi
    }
    csv_field "say \"hi\""
  '
  assert_output '"say ""hi"""'
}
