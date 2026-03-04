#!/usr/bin/env bats

# Integration smoke test — runs the full pipeline with --local fixtures.

setup() {
  load test_helper/common-setup

  SMOKE_DIR="$(mktemp -d)"
  mkdir -p "$SMOKE_DIR/workflows/test-org/safe-repo"
  mkdir -p "$SMOKE_DIR/workflows/test-org/vuln-repo"

  cp "$FIXTURES_DIR/workflows/benign-workflow.yml" \
    "$SMOKE_DIR/workflows/test-org/safe-repo/ci.yml"
  cp "$FIXTURES_DIR/workflows/prt-checkout-no-guard.yml" \
    "$SMOKE_DIR/workflows/test-org/vuln-repo/pr-target.yml"
  cp "$FIXTURES_DIR/workflows/unpinned-actions.yml" \
    "$SMOKE_DIR/workflows/test-org/vuln-repo/deps.yml"

  SMOKE_MD="$SMOKE_DIR/report.md"
  SMOKE_CSV="$SMOKE_DIR/report.csv"
  SMOKE_HDF="$SMOKE_DIR/report.json"
}

teardown() {
  rm -rf "$SMOKE_DIR"
}

@test "smoke: full pipeline produces non-empty MD report" {
  run bash "$SCRIPT" test-org --local "$SMOKE_DIR" \
    --out "$SMOKE_MD" --csv "$SMOKE_CSV" --hdf "$SMOKE_HDF"
  assert_success

  [ -s "$SMOKE_MD" ]
  [ -s "$SMOKE_CSV" ]
  [ -s "$SMOKE_HDF" ]
}

@test "smoke: MD report contains both repos" {
  bash "$SCRIPT" test-org --local "$SMOKE_DIR" \
    --out "$SMOKE_MD" --csv "$SMOKE_CSV" --hdf "$SMOKE_HDF"

  run grep -c "safe-repo\|vuln-repo" "$SMOKE_MD"
  assert_success
  # Should find both repo names at least once each
  [ "$output" -ge 2 ]
}

@test "smoke: MD report detects PRT finding in vuln-repo" {
  bash "$SCRIPT" test-org --local "$SMOKE_DIR" \
    --out "$SMOKE_MD" --csv "$SMOKE_CSV" --hdf "$SMOKE_HDF"

  run grep "vuln-repo" "$SMOKE_MD"
  assert_success
  assert_output --partial "checkout+exec, no guard"
}

@test "smoke: CSV has header and data rows" {
  bash "$SCRIPT" test-org --local "$SMOKE_DIR" \
    --out "$SMOKE_MD" --csv "$SMOKE_CSV" --hdf "$SMOKE_HDF"

  run head -1 "$SMOKE_CSV"
  assert_output --partial "Repository"

  run grep -c "safe-repo\|vuln-repo" "$SMOKE_CSV"
  assert_success
  [ "$output" -ge 2 ]
}

@test "smoke: HDF JSON is valid and has baselines" {
  bash "$SCRIPT" test-org --local "$SMOKE_DIR" \
    --out "$SMOKE_MD" --csv "$SMOKE_CSV" --hdf "$SMOKE_HDF"

  # Basic JSON structure checks
  run grep -c '"baselines"' "$SMOKE_HDF"
  assert_output "1"

  run grep -c '"generator"' "$SMOKE_HDF"
  assert_output "1"
}

@test "smoke: terminal summary shows finding counts" {
  run bash "$SCRIPT" test-org --local "$SMOKE_DIR" \
    --out "$SMOKE_MD" --csv "$SMOKE_CSV" --hdf "$SMOKE_HDF"
  assert_success

  # Terminal output should include the summary line
  assert_output --partial "critical"
  assert_output --partial "high"
  assert_output --partial "medium"
}
