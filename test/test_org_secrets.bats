#!/usr/bin/env bats
#
# Tests for Phase 3 org secrets workflow usage mapping.

setup() {
  load test_helper/common-setup
}

# =============================================================================
# Secret-to-workflow mapping (single-pass associative array approach)
# =============================================================================

@test "single-pass secret extraction finds FOO in repo-a" {
  setup_fixture_dir "test-org" "repo-a"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b"
  cp "$FIXTURES_DIR/workflows/secret-reference-foo.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b/"

  # Simulate the single-pass extraction: grep -oE extracts exact secret names
  run bash -c "grep -oE 'secrets\.[A-Za-z0-9_]+' '$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/secret-reference-foo.yml' | sed 's/^secrets\.//' | sort -u"
  assert_success
  assert_output "FOO"
}

@test "single-pass extraction: FOO and FOOBAR are distinct secrets" {
  setup_fixture_dir "test-org" "repo-a"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b"
  cp "$FIXTURES_DIR/workflows/secret-reference-foo.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"
  cp "$FIXTURES_DIR/workflows/secret-reference-foobar.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b/"

  # Extract from repo-a: should find FOO only
  run bash -c "grep -oE 'secrets\.[A-Za-z0-9_]+' '$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/secret-reference-foo.yml' | sed 's/^secrets\.//' | sort -u"
  assert_output "FOO"

  # Extract from repo-b: should find FOOBAR only
  run bash -c "grep -oE 'secrets\.[A-Za-z0-9_]+' '$BATS_TEST_WORKFLOW_DIR/test-org/repo-b/secret-reference-foobar.yml' | sed 's/^secrets\.//' | sort -u"
  assert_output "FOOBAR"
}

@test "single-pass extraction: no secrets in benign workflow" {
  setup_fixture_dir "test-org" "repo-a"
  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"

  run bash -c "grep -oE 'secrets\.[A-Za-z0-9_]+' '$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/benign-workflow.yml' 2>/dev/null | sort -u"
  assert_output ""
}

@test "file-based secret map correctly maps secrets to repos" {
  setup_fixture_dir "test-org" "repo-a"
  mkdir -p "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b"
  cp "$FIXTURES_DIR/workflows/secret-reference-foo.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-a/"
  cp "$FIXTURES_DIR/workflows/secret-reference-foobar.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/repo-b/"

  # Simulate the single-pass file-based mapping from the script
  local map_file
  map_file=$(mktemp)
  run bash -c '
    WORKFLOWS_DIR="'"$BATS_TEST_WORKFLOW_DIR"'"
    ORG="test-org"
    MAP_FILE="'"$map_file"'"
    while IFS= read -r wf_file; do
      [ -z "$wf_file" ] && continue
      repo_name=$(echo "$wf_file" | sed "s|$WORKFLOWS_DIR/$ORG/||" | cut -d/ -f1)
      grep -oE "secrets\.[A-Za-z0-9_]+" "$wf_file" 2>/dev/null \
        | sed "s/^secrets\.//" \
        | sort -u \
        | while IFS= read -r ref_secret; do
          echo "${ref_secret}|${repo_name}"
        done
    done < <(find "$WORKFLOWS_DIR" -type f \( -name "*.yml" -o -name "*.yaml" \) 2>/dev/null) > "$MAP_FILE"

    # Look up FOO and FOOBAR
    foo_repos=$(grep "^FOO|" "$MAP_FILE" | cut -d"|" -f2 | sort -u | paste -sd"," -)
    foobar_repos=$(grep "^FOOBAR|" "$MAP_FILE" | cut -d"|" -f2 | sort -u | paste -sd"," -)
    echo "FOO=${foo_repos:-NONE}"
    echo "FOOBAR=${foobar_repos:-NONE}"
  '
  rm -f "$map_file"
  assert_success
  assert_line "FOO=repo-a"
  assert_line "FOOBAR=repo-b"
}
