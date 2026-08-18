# mcp-secret-launcher — common developer tasks
# Usage: make <target>
# Run from the repository root (or any dir; recipes cd to ROOT).

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BIN  := $(ROOT)/target/release/mcp-secret-launcher
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

.PHONY: help build release install uninstall test check fmt clippy precommit \
	setup-user clean

help: ## Show this help
	@echo "mcp-secret-launcher make targets"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Variables: PREFIX=$(PREFIX)"

# ─── build & install ──────────────────────────────────────────────────────────

build: ## Debug build
	cd $(ROOT) && cargo build

release: ## Release build (optimized)
	cd $(ROOT) && cargo build --release

install: release ## Install binary to BINDIR (default: ~/.local/bin)
	install -d "$(BINDIR)"
	install -m 755 "$(BIN)" "$(BINDIR)/mcp-secret-launcher"
	@echo "Installed: $(BINDIR)/mcp-secret-launcher"
	@echo "Ensure $(BINDIR) is on your PATH"

uninstall: ## Remove binary from BINDIR
	rm -f "$(BINDIR)/mcp-secret-launcher"
	@echo "Removed $(BINDIR)/mcp-secret-launcher (if present)"

# ─── quality ──────────────────────────────────────────────────────────────────

test: ## Run tests (single-threaded; required for env/signal isolation)
	cd $(ROOT) && cargo test --all-features -- --test-threads=1

check: ## Fast typecheck (no binary)
	cd $(ROOT) && cargo check --all-targets --all-features

fmt: ## Format sources
	cd $(ROOT) && cargo fmt

clippy: ## Clippy with -D warnings
	cd $(ROOT) && cargo clippy --all-targets --all-features -- -D warnings

precommit: ## Full gate (fmt, clippy, tests; coverage if cargo-llvm-cov is installed)
	cd $(ROOT) && bash scripts/check.sh

setup-user: install ## Binary + path.env + shell PATH integration (macOS/Linux)
	bash "$(ROOT)/scripts/setup-user.sh" --bin "$(BINDIR)/mcp-secret-launcher"

# ─── maintenance ──────────────────────────────────────────────────────────────

clean: ## Remove cargo build artifacts
	cd $(ROOT) && cargo clean
