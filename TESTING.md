# Testing Guide

This project uses test-driven development (TDD) to refactor `gh-actions-audit.sh`. Tests are written first to document expected behavior (and existing bugs), then the script is updated to make them pass.

## Prerequisites

Install [bats-core](https://github.com/bats-core/bats-core) and its helper libraries:

```bash
# macOS (Homebrew)
brew install bats-core
brew tap bats-core/bats-core
brew install bats-support bats-assert bats-file

# Or via npm (any platform)
npm install -g bats bats-support bats-assert bats-file
```

Install [ShellCheck](https://www.shellcheck.net/) and [shfmt](https://github.com/mvdan/sh):

```bash
# macOS
brew install shellcheck shfmt

# Ubuntu/Debian
apt-get install shellcheck
curl -sS https://webinstall.dev/shfmt | bash
```

Or use the convenience target (installs everything):

```bash
make test-deps
```

## Running Tests

```bash
make test          # Run all bats tests
make lint          # Run shellcheck on gh-actions-audit.sh
make fmt-check     # Check formatting (no changes)
make fmt           # Auto-format with shfmt
make check         # Run lint + format check + test (CI equivalent)
```

Run a single test file:

```bash
bats test/test_argument_parsing.bats
```

Run a specific test by name:

```bash
bats test/test_workflow_analysis.bats --filter "detects explicit permissions"
```

## Test Structure

```
test/
├── test_helper/
│   └── common-setup.bash      # Shared setup: load libs, mock helpers, fixture paths
├── fixtures/
│   └── workflows/              # Sample .yml files for each scenario
│       ├── permissions-explicit.yml
│       ├── prt-checkout-no-guard.yml
│       ├── issue-comment-with-gate.yml
│       └── ...
├── test_argument_parsing.bats  # CLI flag parsing tests
├── test_workflow_analysis.bats # Phase 2 grep heuristic tests
├── test_org_secrets.bats       # Phase 3 secret mapping tests
└── test_report_generation.bats # Phase 5 output format tests
```

## Writing Tests

### Conventions

- File names: `test/test_<topic>.bats`
- Every test file loads the common setup: `load test_helper/common-setup`
- Test names should be descriptive: `@test "prt-checkout-no-guard: checkout detected, no author guard"`
- Tests documenting known bugs are prefixed with `BUG:` in the test name

### Fixtures

Add fixture workflow files to `test/fixtures/workflows/`. Name them descriptively for the scenario they test. Keep them minimal — only include the YAML needed to trigger the detection logic.

### Mocking `gh` CLI

The common setup provides helpers for mocking the `gh` CLI:

```bash
setup() {
  load test_helper/common-setup
  setup_mock_gh
  mock_gh_response "api user --jq .login" "test-user"
  mock_gh_response "auth status" ""
}
```

The mock intercepts `gh` calls by prepending a stub script to `PATH`. It returns canned responses based on argument hashing.

### TDD Workflow

1. **Red**: Write a test that describes the expected behavior. If it targets a known bug, it should _pass_ (proving the bug exists). Mark it with `BUG:` prefix.
2. **Green**: Fix the script so the test passes (or invert the bug test assertion).
3. **Refactor**: Clean up without breaking tests.

## Code Quality Standards

All of the following must pass before code is merged. `make check` runs them all.

### ShellCheck (static analysis)
Zero findings required. ShellCheck catches bugs, security issues, and portability problems. Configuration is in `.shellcheckrc`.

### shfmt (formatting)
All bash scripts must be formatted with shfmt. Settings: 2-space indent (`-i 2`), binary ops on next line (`-bn`), case body indented (`-ci`). Run `make fmt` to auto-format, `make fmt-check` to verify.

### bats-core (tests)
All tests must pass. Tests cover argument parsing, workflow analysis heuristics, secret mapping, and report generation.

## CI Pipeline

The `.github/workflows/ci.yml` pipeline runs on every push and PR:

- **ShellCheck** job: lints `gh-actions-audit.sh`
- **shfmt** job: verifies formatting matches `shfmt -i 2 -bn -ci`
- **Test** job: runs bats tests on ubuntu-latest and macos-latest via `bats-core/bats-action`

## Mocking Strategy

- **`gh` CLI**: Mocked via PATH stubs (returns canned JSON responses)
- **File I/O**: Uses fixture files and temp dirs (cleaned up in teardown)
- **Network**: No real API calls in tests — all `gh api` calls are intercepted by the mock
