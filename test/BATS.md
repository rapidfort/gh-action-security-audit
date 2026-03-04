# Bats-core Reference

Lessons learned and patterns for working with [bats-core](https://github.com/bats-core/bats-core) in this project.

## Library Loading — How It Actually Works

Bats has **two distinct loading mechanisms** that are easy to confuse:

### `load` — for test-relative files

```bash
load test_helper/common-setup
```

Resolves **relative to the test file's directory** (`$BATS_TEST_DIRNAME`). This is what `.bats` files use to load shared setup. It calls `bats_load_safe` internally, which looks for `$BATS_TEST_DIRNAME/$slug.bash` or `$BATS_TEST_DIRNAME/$slug`. It does **not** use `BATS_LIB_PATH` at all.

### `bats_load_library` — for system-installed libraries

```bash
bats_load_library bats-support
bats_load_library bats-assert
```

Resolves against `BATS_LIB_PATH` (colon-delimited, like `PATH`). Searches each directory for `$dir/$name` or `$dir/$name/load.bash`. This is the correct function for loading bats-support, bats-assert, etc.

**Key fact**: `bats_load_library` reads `BATS_LIB_PATH` at **call time**, not at bats startup. So you can `export BATS_LIB_PATH=...` in a sourced helper file and then call `bats_load_library` — it will use the updated value.

## The `BATS_LIB_PATH` Gotcha

The bats binary (`libexec/bats-core/bats`) sets the default:

```bash
export BATS_LIB_PATH=${BATS_LIB_PATH-/usr/lib/bats}
```

Note the `-` (not `:-`). This means it only applies the default when the variable is **completely unset**. If you `export BATS_LIB_PATH=""`, the default won't kick in.

### The problem on macOS Homebrew

Homebrew installs bats helper libraries to:

| Platform | Path |
|----------|------|
| macOS Apple Silicon | `/opt/homebrew/lib/bats-{support,assert}/` |
| macOS Intel | `/usr/local/lib/bats-{support,assert}/` |
| Linux Homebrew | `/home/linuxbrew/.linuxbrew/lib/bats-{support,assert}/` |

But the bats default is `/usr/lib/bats`, which doesn't contain anything on macOS. So when you run `bats test/` without setting `BATS_LIB_PATH`, the variable is **set** (to `/usr/lib/bats`) but points to the **wrong location**.

### Our solution

Two layers of defense:

1. **Makefile** sets `BATS_LIB_PATH` before invoking bats:
   ```makefile
   test:
   	@BATS_LIB_PATH="$${BATS_LIB_PATH:-$$(brew --prefix 2>/dev/null || echo /usr)/lib}" bats test/
   ```

2. **`common-setup.bash`** has `_ensure_bats_lib_path()` which checks whether the current `BATS_LIB_PATH` *actually contains* `bats-support/` (not just whether it's non-empty). If not, it auto-detects the correct path and exports it before calling `bats_load_library`.

This means both `make test` and bare `bats test/` work on macOS Homebrew, Linux, and CI.

## CI — `bats-core/bats-action`

In GitHub Actions, [`bats-core/bats-action`](https://github.com/bats-core/bats-action) handles everything: it installs bats-core, bats-support, and bats-assert, and sets `BATS_LIB_PATH` automatically via `support-path` / `assert-path` parameters.

```yaml
- uses: bats-core/bats-action@3.0.0
  with:
    support-path: ${{ github.workspace }}/test/test_helper
    assert-path: ${{ github.workspace }}/test/test_helper
    tests-path: test/
```

## Mock `gh` CLI

The `setup_mock_gh` helper in `test_helper/common-setup.bash` creates a temp script prepended to `PATH` that intercepts `gh` calls:

```bash
setup() {
  load test_helper/common-setup
  setup_mock_gh
  mock_gh_response "api user --jq .login" "test-user"
  mock_gh_response "auth status" ""
}
```

How it works:
- Creates a temp directory with a `gh` script and a `responses/` subdirectory
- Each `mock_gh_response` call hashes the argument string (via `md5`/`md5sum`) and writes the response body to `responses/<hash>`
- The mock `gh` script hashes its `$@` the same way and looks up the response file
- Fallback: `gh auth status` always succeeds; everything else returns empty output with exit 0

### Caveat: argument matching is exact

The hash is computed from all arguments joined by newlines. So `mock_gh_response "api user --jq .login"` only matches when `gh` is called with exactly those four arguments in that order. Extra flags, different quoting, or reordered arguments won't match.

## Fixture Workflow Dir

For tests that need a temporary workflow directory tree (mimicking the structure the script creates):

```bash
setup_fixture_dir "test-org" "test-repo"
cp "$FIXTURES_DIR/workflows/some-file.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"
```

Creates `$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/` under a temp directory. Cleaned up automatically in `teardown()`.

## TDD Convention: `BUG:` Prefix

Tests that document **known bugs** in the current script are prefixed with `BUG:` in the test name:

```bash
@test "BUG: permissions-in-comment is a false positive with current grep" {
  run grep -q 'permissions:' "$FIXTURES_DIR/workflows/permissions-in-comment.yml"
  assert_success  # Bug: this SHOULD fail but doesn't
}
```

These tests **pass** — proving the bug exists. When fixing the bug, invert the assertion (e.g., change `assert_success` to `assert_failure`).

## Common Pitfalls

1. **Don't use `load` for system libraries.** `load bats-support` looks relative to the test file, not `BATS_LIB_PATH`.

2. **Don't assume `BATS_LIB_PATH` is unset.** Bats sets it to `/usr/lib/bats` by default. Check if it *contains the libraries*, not just if it's non-empty.

3. **`run` captures both stdout and stderr.** If your command writes to stderr and you're checking `$output`, both streams are mixed in. Use `run bash -c "cmd 2>/dev/null"` to separate them if needed.

4. **`set -euo pipefail` in the script under test.** When running the full script via `run bash "$SCRIPT" ...`, failures in the script are captured by `run` (they don't abort the test). But if you `source` the script directly, `set -e` can abort the test on the first error.
