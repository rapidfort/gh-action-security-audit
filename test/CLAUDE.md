# Test Directory — Claude Code Instructions

## Code Quality Rules

- **We own this code. There is no such thing as a "pre-existing" issue.** Every warning, lint finding, or tool error must be fixed immediately. Never dismiss, defer, or label something as "expected."
- **Fix everything you find.** If shellcheck, bats, or any tool reports a problem, fix it in the same pass. Zero findings is the only acceptable state.
- **All tests must pass before any work is considered done.** Run `make check` (lint + test) and confirm zero failures, zero warnings.

## Test Conventions

- Framework: bats-core with bats-support and bats-assert
- Shared setup: `test_helper/common-setup.bash` (load via `load test_helper/common-setup`)
- Fixtures: `fixtures/workflows/*.yml` — minimal YAML files for each detection scenario
- `BUG:` prefix on test names documents known bugs that pass (proving the bug exists). When fixing the bug, remove the prefix and invert the assertion.

## TDD Workflow

1. **Red**: Write or update tests to assert correct behavior (they should fail against current code)
2. **Green**: Fix the script so all tests pass
3. **Verify**: `make check` — zero shellcheck findings, zero test failures
4. **Close**: `bd close <card-id>`
