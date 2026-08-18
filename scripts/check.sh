#!/usr/bin/env bash
# Quality gate: format → lint → tests (coverage floor when cargo-llvm-cov is present).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$ROOT"

MIN_COVERAGE="${MCP_SECRET_LAUNCHER_MIN_COVERAGE:-95}"

log() { printf '==> %s\n' "$*"; }

log "mcp-secret-launcher quality gate (cwd: ${ROOT})"

log "[1/3] cargo fmt --check"
cargo fmt --all -- --check

log "[2/3] cargo clippy (warnings as errors)"
cargo clippy --all-targets --all-features -- -D warnings

if cargo llvm-cov --version >/dev/null 2>&1; then
  log "[3/3] tests + coverage (min ${MIN_COVERAGE}% lines)"
  cargo llvm-cov --all-features --fail-under-lines "${MIN_COVERAGE}" -- --test-threads=1
else
  log "[3/3] cargo test (cargo-llvm-cov not installed; CI still enforces ${MIN_COVERAGE}%)"
  cargo test --all-features -- --test-threads=1
fi

log "ok"
