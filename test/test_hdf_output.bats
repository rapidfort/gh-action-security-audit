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
