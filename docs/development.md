# Development Guide

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

The project enforces strict code quality using `rustfmt` and `clippy`. You should run these checks before committing.

**To auto-fix formatting and some lints:**
```bash
# Auto-format code
cargo fmt

# Auto-fix clippy lints (where possible)
cargo clippy --fix --allow-dirty --allow-staged
```

**To check for formatting and lints (e.g., in CI):**
```bash
# Check formatting without modifying files
cargo fmt -- --check

# Check lints without fixing
cargo clippy --all-targets --all-features
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
```
