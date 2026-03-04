#!/usr/bin/env bash
#
# common-setup.bash — Shared setup for all bats test files
#
# Loaded via: load test_helper/common-setup
# in each test file's setup() function.

# --- Library loading ---
# bats_load_library resolves against BATS_LIB_PATH (colon-delimited).
# The bats binary defaults BATS_LIB_PATH to /usr/lib/bats when unset,
# which is wrong for Homebrew installs. We detect the correct path here
# and override before calling bats_load_library (which reads it at call time).

_ensure_bats_lib_path() {
  # Check if current BATS_LIB_PATH already contains the libraries
  if [[ -n "${BATS_LIB_PATH:-}" ]]; then
    local -a dirs
    IFS=: read -ra dirs <<< "$BATS_LIB_PATH"
    for d in "${dirs[@]}"; do
      if [[ -d "${d}/bats-support" ]]; then
        return 0
      fi
    done
  fi

  # Auto-detect common install locations
  local candidates=(
    "/opt/homebrew/lib"            # Homebrew Apple Silicon
    "/usr/local/lib"               # Homebrew Intel / Linux Homebrew
    "/usr/lib/bats"                # System packages (Debian/Ubuntu)
    "/usr/lib/node_modules"        # npm global (Linux)
    "/usr/local/lib/node_modules"  # npm global (macOS)
  )

  for dir in "${candidates[@]}"; do
    if [[ -d "${dir}/bats-support" && -d "${dir}/bats-assert" ]]; then
      export BATS_LIB_PATH="${dir}"
      return 0
    fi
  done

  printf "ERROR: Could not find bats-support/bats-assert.\n" >&2
  printf "  Run 'make test-deps' or set BATS_LIB_PATH.\n" >&2
  return 1
}

_ensure_bats_lib_path
bats_load_library bats-support
bats_load_library bats-assert

# --- Project paths ---
PROJECT_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/.." && pwd)"
SCRIPT="${PROJECT_ROOT}/gh-action-security-audit"
FIXTURES_DIR="${PROJECT_ROOT}/test/fixtures"

# --- Mock helpers ---

# Create a mock 'gh' command that returns canned responses.
# Usage:
#   setup() {
#     setup_mock_gh
#     mock_gh_response "api orgs/test-org/actions/permissions/workflow" '{"default_workflow_permissions":"read"}'
#   }
#
# The mock stores responses in $MOCK_GH_DIR keyed by a hash of the arguments.
setup_mock_gh() {
  MOCK_GH_DIR="$(mktemp -d)"
  MOCK_GH_BIN="${MOCK_GH_DIR}/gh"

  cat > "${MOCK_GH_BIN}" << 'GHEOF'
#!/usr/bin/env bash
# Mock gh CLI — looks up canned responses by argument hash
MOCK_DIR="$(dirname "$0")/responses"
# Create a simple key from all args
key=$(printf '%s\n' "$@" | md5sum 2>/dev/null | cut -d' ' -f1 || printf '%s\n' "$@" | md5 2>/dev/null | cut -d' ' -f1)
if [[ -f "${MOCK_DIR}/${key}" ]]; then
  cat "${MOCK_DIR}/${key}"
  exit 0
fi
# Fallback: check if there's a status response (for 'gh auth status')
if [[ "$1" == "auth" && "$2" == "status" ]]; then
  exit 0
fi
# Default: empty output, success
exit 0
GHEOF
  chmod +x "${MOCK_GH_BIN}"
  mkdir -p "${MOCK_GH_DIR}/responses"

  # Prepend mock dir to PATH
  export PATH="${MOCK_GH_DIR}:${PATH}"
}

# Register a canned response for specific gh arguments.
# Args: <args-as-single-string> <response-body>
# Simple cases only — splits on spaces. For args with spaces (e.g. --jq
# expressions), use mock_gh_response_args instead.
# Example: mock_gh_response "api user --jq .login" "test-user"
mock_gh_response() {
  local args_str="$1"
  local response="$2"
  # Hash the args the same way the mock does — one arg per line
  local key
  key=$(echo "$args_str" | tr ' ' '\n' | md5sum 2>/dev/null | cut -d' ' -f1 || echo "$args_str" | tr ' ' '\n' | md5 2>/dev/null | cut -d' ' -f1)
  echo "$response" > "${MOCK_GH_DIR}/responses/${key}"
}

# Register a canned response with exact argument matching.
# Last argument is the response body; all preceding arguments are the gh args.
# The hash matches exactly how the mock gh script hashes $@ (one arg per line).
# Example: mock_gh_response_args api "orgs/foo/actions/permissions" --jq '.allowed_actions' -- "selected"
# The -- separator separates gh args from the response body.
mock_gh_response_args() {
  local args=()
  local response=""
  local found_sep=0
  for arg in "$@"; do
    if [ "$arg" = "--" ]; then
      found_sep=1
      continue
    fi
    if [ "$found_sep" -eq 1 ]; then
      response="$arg"
    else
      args+=("$arg")
    fi
  done
  local key
  key=$(printf '%s\n' "${args[@]}" | md5sum 2>/dev/null | cut -d' ' -f1 || printf '%s\n' "${args[@]}" | md5 2>/dev/null | cut -d' ' -f1)
  echo "$response" > "${MOCK_GH_DIR}/responses/${key}"
}

# --- Fixture helpers ---

# Create a temporary workflow directory structure for testing.
# Returns the path via BATS_TEST_WORKFLOW_DIR.
# Usage:
#   setup_fixture_dir "test-org" "test-repo"
#   cp "$FIXTURES_DIR/workflows/some-file.yml" "$BATS_TEST_WORKFLOW_DIR/test-org/test-repo/"
setup_fixture_dir() {
  local org="${1:?org required}"
  local repo="${2:?repo required}"
  BATS_TEST_WORKFLOW_DIR="$(mktemp -d)"
  mkdir -p "${BATS_TEST_WORKFLOW_DIR}/${org}/${repo}"
}

# --- Teardown ---

teardown() {
  # Clean up mock gh
  if [[ -n "${MOCK_GH_DIR:-}" && -d "${MOCK_GH_DIR:-}" ]]; then
    rm -rf "${MOCK_GH_DIR}"
  fi
  # Clean up fixture dirs
  if [[ -n "${BATS_TEST_WORKFLOW_DIR:-}" && -d "${BATS_TEST_WORKFLOW_DIR:-}" ]]; then
    rm -rf "${BATS_TEST_WORKFLOW_DIR}"
  fi
}
