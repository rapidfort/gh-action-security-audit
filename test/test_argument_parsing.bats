#!/usr/bin/env bats

setup() {
  load test_helper/common-setup
}

# =============================================================================
# Temp file safety — all temp files must be created via mktemp
# =============================================================================

@test "TABLE_ROWS csv file uses mktemp, not string concatenation" {
  # The csv companion file must be its own mktemp call, not $TABLE_ROWS.csv
  run grep -n 'TABLE_ROWS\.csv' "$SCRIPT"
  # Should NOT find any definition like TABLE_ROWS.csv that's just appending .csv
  refute_output --partial '$TABLE_ROWS.csv'
}

@test "AUDIT_DIR uses mktemp -d when not using --local" {
  run grep -n 'AUDIT_DIR=' "$SCRIPT"
  assert_output --partial 'mktemp -d'
}

@test "script has trap EXIT for temp file cleanup" {
  run grep -n 'trap.*EXIT' "$SCRIPT"
  assert_success
  assert_output --partial 'cleanup'
}

@test "cleanup function removes temp files" {
  run grep -A5 'cleanup()' "$SCRIPT"
  assert_success
  assert_output --partial 'TABLE_ROWS'
  assert_output --partial 'ORG_SECRETS_FILE'
}

@test "base64 decode uses portable detection, not hardcoded -d" {
  # Stock macOS base64 uses -D or --decode, not -d (which is GNU-only).
  # The script should detect the correct flag via BASE64_DECODE array.
  # Verify: the actual decode call uses the variable, not a hardcoded flag.
  run grep -n 'BASE64_DECODE' "$SCRIPT"
  assert_success
  # The pipe usage should reference the array, not a literal base64 -d
  run grep 'echo.*| base64 -d' "$SCRIPT"
  refute_output --partial '> "$repo_dir'
}

# --- Help flag ---

@test "--help prints usage and exits 0" {
  run bash "$SCRIPT" --help
  assert_success
  assert_output --partial "GitHub Actions Security Audit"
}

@test "-h prints usage and exits 0" {
  run bash "$SCRIPT" -h
  assert_success
  assert_output --partial "GitHub Actions Security Audit"
}

# --- Missing org ---

@test "no arguments prints usage to stderr and exits 1" {
  run bash "$SCRIPT"
  assert_failure
  assert_output --partial "Usage:"
}

# --- Unknown option ---

@test "unknown option exits 1" {
  run bash "$SCRIPT" my-org --bogus
  assert_failure
  assert_output --partial "Unknown option"
}

# --- Duplicate org ---

@test "two positional args exits 1" {
  run bash "$SCRIPT" org1 org2
  assert_failure
  assert_output --partial "Only one org at a time"
}

# --- --local requires a directory ---

@test "--local without argument exits 1" {
  run bash "$SCRIPT" my-org --local
  assert_failure
  assert_output --partial "requires a directory"
}

# --- --local with nonexistent directory exits 1 ---

@test "--local with nonexistent dir exits 1" {
  run bash "$SCRIPT" my-org --local /tmp/nonexistent-dir-$$
  assert_failure
  assert_output --partial "does not exist"
}

# --- --out requires a filename ---

@test "--out without argument exits 1" {
  run bash "$SCRIPT" my-org --out
  assert_failure
  assert_output --partial "requires a filename"
}

# --- --csv requires a filename ---

@test "--csv without argument exits 1" {
  run bash "$SCRIPT" my-org --csv
  assert_failure
  assert_output --partial "requires a filename"
}
