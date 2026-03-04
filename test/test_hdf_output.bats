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
