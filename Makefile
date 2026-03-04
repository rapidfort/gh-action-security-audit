.PHONY: help test test-deps lint fmt fmt-check check

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

test-deps: ## Install bats-core, helpers, shellcheck, and shfmt (macOS: brew, Linux: npm)
	@if command -v brew >/dev/null 2>&1; then \
		echo "Installing via Homebrew..."; \
		brew install bats-core shellcheck shfmt; \
		brew tap bats-core/bats-core; \
		brew install bats-support bats-assert bats-file; \
	elif command -v npm >/dev/null 2>&1; then \
		echo "Installing via npm..."; \
		npm install -g bats bats-support bats-assert bats-file; \
		echo "Note: install shellcheck and shfmt separately for your platform."; \
	else \
		echo "Error: neither brew nor npm found. Install one of them first." >&2; \
		exit 1; \
	fi
	@echo "Done. Run 'make check' to verify."

lint: ## Run shellcheck on gh-actions-audit.sh
	shellcheck gh-actions-audit.sh

fmt: ## Format gh-actions-audit.sh with shfmt (in place)
	shfmt -w -i 2 -bn -ci gh-actions-audit.sh

fmt-check: ## Check formatting without modifying files
	shfmt -d -i 2 -bn -ci gh-actions-audit.sh

test: ## Run all bats tests
	@BATS_LIB_PATH="$${BATS_LIB_PATH:-$$(brew --prefix 2>/dev/null || echo /usr)/lib}" bats test/

check: lint fmt-check test ## Run lint + format check + test
