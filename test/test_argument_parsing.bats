#!/usr/bin/env bats

setup() {
  load test_helper/common-setup
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
