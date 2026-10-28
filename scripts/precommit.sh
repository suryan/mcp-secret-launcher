#!/usr/bin/env bash
# Pre-commit quality gate for mcp-secret-launcher.
#
#   bash scripts/precommit.sh
#
# Runs, in order: cargo fmt --check, cargo clippy (warnings as errors), the test
# suite (with the 95% line-coverage floor when cargo-llvm-cov is installed), and
# the osv-scanner dependency vulnerability gate. Exits non-zero on any failure.
#
# osv-scanner policy: a HIGH/CRITICAL finding (CVSS >= 7.0) that has a fixed
# version available blocks the commit. MODERATE/LOW findings and findings with
# no upstream fix are printed as accepted risk. A missing osv-scanner FAILS the
# gate unless ALLOW_MISSING_OSV_SCANNER=1 is set (local use only; never in CI).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MIN_COVERAGE="${MCP_SECRET_LAUNCHER_MIN_COVERAGE:-95}"
RESULTS=()
pass() { RESULTS+=("PASS  $1"); }
fail() { RESULTS+=("FAIL  $1"); summary; exit 1; }
# step <label> <command...>: run the command, record PASS or stop with FAIL.
step() {
  local label="$1"; shift
  if "$@"; then pass "$label"; else fail "$label"; fi
}
summary() {
  echo ""
  echo "=== Pre-commit summary ==="
  printf '  %s\n' "${RESULTS[@]}"
}

echo "=== Pre-commit checks (cwd: ${ROOT}) ==="

echo "[1/4] cargo fmt --check"
step "fmt (fix with: cargo fmt)" cargo fmt --all -- --check

echo "[2/4] cargo clippy --all-targets --all-features -- -D warnings"
step "clippy" cargo clippy --all-targets --all-features -- -D warnings

if cargo llvm-cov --version >/dev/null 2>&1; then
  echo "[3/4] tests + coverage (min ${MIN_COVERAGE}% lines)"
  step "tests + coverage >= ${MIN_COVERAGE}%" \
    cargo llvm-cov --all-features --fail-under-lines "${MIN_COVERAGE}"
else
  echo "[3/4] cargo test (cargo-llvm-cov not installed; CI still enforces ${MIN_COVERAGE}%)"
  step "tests (coverage not measured)" cargo test --all-features
fi

echo "[4/4] Security audit (osv-scanner)"
if ! command -v osv-scanner >/dev/null 2>&1; then
  if [ "${ALLOW_MISSING_OSV_SCANNER:-0}" = "1" ]; then
    echo "  WARN: osv-scanner not found; skipped via ALLOW_MISSING_OSV_SCANNER=1 (local only, never CI)"
    RESULTS+=("WARN  osv-scanner skipped (ALLOW_MISSING_OSV_SCANNER=1)")
    summary
    exit 0
  fi
  echo "  FAIL: osv-scanner not found; the CVE gate cannot be skipped (install: https://github.com/google/osv-scanner)"
  fail "osv-scanner missing"
fi
command -v python3 >/dev/null 2>&1 || fail "python3 is required to apply the osv-scanner blocking policy"

OSV_JSON="$(mktemp)"
trap 'rm -f "$OSV_JSON"' EXIT
set +e
osv-scanner scan source --recursive --format json . >"$OSV_JSON"
OSV_EXIT=$?
set -e
# osv-scanner exits 1 when it finds vulnerabilities; anything else non-zero is a scanner error.
if [ "$OSV_EXIT" -ne 0 ] && [ "$OSV_EXIT" -ne 1 ]; then
  fail "osv-scanner errored (exit ${OSV_EXIT})"
fi

if python3 - "$OSV_JSON" <<'PY'
import json, sys

data = json.load(open(sys.argv[1]))
blocking = []
for result in data.get("results", []):
    for pkg in result.get("packages", []):
        name = pkg["package"]["name"]
        version = pkg["package"].get("version", "?")
        severity = {}
        for group in pkg.get("groups", []):
            for vid in group.get("ids", []):
                severity[vid] = group.get("max_severity", "")
        for vuln in pkg.get("vulnerabilities", []):
            fixed = sorted({
                ev["fixed"]
                for aff in vuln.get("affected", [])
                for rng in aff.get("ranges", [])
                for ev in rng.get("events", [])
                if "fixed" in ev
            })
            raw = severity.get(vuln["id"], "")
            try:
                score = float(raw)
            except ValueError:
                score = None
            label = "unscored" if score is None else f"CVSS {score}"
            fix = ", ".join(fixed) if fixed else "no upstream fix"
            line = f"{name} {version}: {vuln['id']} ({label}; fixed in: {fix})"
            if score is not None and score >= 7.0 and fixed:
                blocking.append(line)
                print(f"  BLOCK  {line}")
            else:
                print(f"  ACCEPT {line}")
if blocking:
    print(f"  {len(blocking)} HIGH/CRITICAL finding(s) with a fix available: bump them before committing.")
    sys.exit(1)
PY
then
  pass "osv-scanner (no blocking findings)"
else
  fail "osv-scanner (blocking HIGH/CRITICAL findings)"
fi

summary
