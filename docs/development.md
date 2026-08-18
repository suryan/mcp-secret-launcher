# Development Guide

## Prerequisites

- **Rust** (stable) — install via [rustup](https://rustup.rs/)
- **git**, plus a C linker (`build-essential` on Debian/Ubuntu, Xcode CLT on macOS)

Copy [`local.env.example`](../local.env.example) to `local.env` for optional local
overrides (`MCP_SECRET_LAUNCHER_*`). Do not commit `local.env`.

## Getting Started

```bash
# Clone
git clone https://github.com/suryan/mcp-secret-launcher.git
cd mcp-secret-launcher

# Debug build
cargo build

# Install a release binary to ~/.local/bin and put it on PATH
./scripts/install.sh --local --with-path
# or: make setup-user
```

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/install.sh` | macOS/Linux install-from-source (`--local`, `--with-path`, `--yes`) |
| `scripts/setup-user.sh` | Write `path.env` and source it from bash/zsh rc files |
| `scripts/check.sh` | Quality gate: format → clippy → tests (coverage if `cargo-llvm-cov` is installed) |

```bash
make help
make precommit     # same as bash scripts/check.sh
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `keyring` v3 | Cross-platform native keyring access |
| `clap` v4 | CLI argument parsing (derive) |
| `secrecy` v0.10 | Zeroize-on-drop secret wrappers |
| `rpassword` v5 | Secure non-echoing terminal prompts |
| `anyhow` | Error handling with context |
| `thiserror` | Structured error types |
| `serde_json` | Manifest serialization |

## Diagrams

If you modify the architecture or flow diagrams in `docs/`, you must regenerate the PNG files. This project uses [D2](https://d2lang.com/) and the ELK layout engine.

```bash
# Install D2 (if not already installed)
curl -fsSL https://d2lang.com/install.sh | sh -s --

# Generate PNGs
d2 --layout=elk docs/architecture.d2 docs/architecture.png
d2 --layout=elk docs/flow.d2 docs/flow.png
```

## Code Quality Checks

The project enforces strict code quality using `rustfmt` and `clippy`. See [clippy_policy.md](clippy_policy.md) for detailed linting requirements.

**To auto-fix formatting and some lints:**
```bash
# Auto-format code
cargo fmt

# Auto-fix clippy lints (where possible)
cargo clippy --fix --allow-dirty --allow-staged
```

**Quality gate (run before claiming a change is done):**
```bash
bash scripts/check.sh
# or: make precommit
```

**To check individually (e.g., before committing):**
```bash
# Check formatting without modifying files
cargo fmt --all -- --check

# Check lints without fixing
cargo clippy --all-targets --all-features -- -D warnings
```

### Git Hooks

To automatically enforce formatting, clippy lints, and test success before creating a commit, you can set up a local Git `pre-commit` hook. 

Create a file at `.git/hooks/pre-commit` with the following content and make it executable (`chmod +x .git/hooks/pre-commit`):

```sh
#!/bin/sh
# pre-commit hook to enforce formatting, clippy, and pass tests

echo "Running pre-commit checks..."

# 1. Check Formatting
echo "=> Running cargo fmt"
cargo fmt -- --check || { echo "❌ Formatting check failed."; exit 1; }

# 2. Check Clippy
echo "=> Running cargo clippy"
cargo clippy --all-targets --all-features || { echo "❌ Clippy failed."; exit 1; }

# 3. Run Tests
echo "=> Running cargo test"
cargo test || { echo "❌ Tests failed."; exit 1; }

echo "✅ All pre-commit checks passed!"
exit 0
```

## Running Tests

The project includes a comprehensive test suite of **108+ tests**. The suite uses `proptest` for property-based testing and a `MockKeyring` backend so no real keyring interaction is needed during tests.

**Important:** Some integration tests manipulate global process state:
1.  **Environment Variables**: Many tests set/check env vars. Since `std::env` is shared across the entire process, parallel tests can cause race conditions and flakiness.
2.  **Signal Handlers**: There can only be one global `SIGINT` (Ctrl-C) handler. Parallel tests can conflict over this registration.

Always run tests with a single thread to ensure complete isolation:

```bash
# Run all tests sequentially (Recommended)
cargo test -- --test-threads=1

# Run tests with the test-utils feature (Required for some advanced mocks)
cargo test --features test-utils -- --test-threads=1
```

## Code Coverage

We use `cargo-llvm-cov` to track and maintain high test coverage (currently **88.33%**).

```bash
# 1. Install llvm-cov
cargo install cargo-llvm-cov

# 2. Run coverage report
cargo llvm-cov --features test-utils -- --test-threads=1

# 3. Generate HTML report
cargo llvm-cov --features test-utils --show-missing-lines --html -- --test-threads=1
```

## Building

```bash
# Build debug binary for development
cargo build

# Build release binary for production
cargo build --release

# Install to ~/.local/bin (same as scripts/install.sh --local without PATH setup)
make install
```
