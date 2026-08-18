#!/usr/bin/env bash
# mcp-secret-launcher install-from-source (macOS + Linux / WSL2)
#
# Builds and installs a release binary on the local machine. No GitHub release
# artifacts required — only git, a C toolchain, and Rust (rustup is bootstrapped
# if cargo is missing).
#
# One-liner (from GitHub):
#   curl -fsSL https://raw.githubusercontent.com/suryan/mcp-secret-launcher/main/scripts/install.sh | bash
#
# Recommended (binary + ~/.local/bin on PATH):
#   curl -fsSL …/install.sh | bash -s -- --with-path --yes
#
# From a local clone:
#   ./scripts/install.sh --local --with-path
#   ./scripts/install.sh --ref v0.1.0 --with-path --yes
#
# Environment (optional):
#   MCP_SECRET_LAUNCHER_REPO    git URL (default: https://github.com/suryan/mcp-secret-launcher.git)
#   MCP_SECRET_LAUNCHER_REF     branch/tag/commit (default: main)
#   MCP_SECRET_LAUNCHER_PREFIX  install prefix (default: $HOME/.local) → bin/mcp-secret-launcher
#   MCP_SECRET_LAUNCHER_DIR     source checkout dir (default: $HOME/.local/src/mcp-secret-launcher)
#   CARGO_HOME / RUSTUP_HOME    standard rustup vars
#
# Exit codes: 0 success, 1 user/env error, 2 build/install failure

set -euo pipefail

REPO_DEFAULT="https://github.com/suryan/mcp-secret-launcher.git"
REPO="${MCP_SECRET_LAUNCHER_REPO:-$REPO_DEFAULT}"
REF="${MCP_SECRET_LAUNCHER_REF:-main}"
PREFIX="${MCP_SECRET_LAUNCHER_PREFIX:-${PREFIX:-$HOME/.local}}"
SRC_DIR="${MCP_SECRET_LAUNCHER_DIR:-$HOME/.local/src/mcp-secret-launcher}"
WITH_PATH=0
NO_SHELL_RC=0
YES=0
KEEP_SRC=1
LOCAL_ONLY=0

usage() {
  cat <<'EOF'
Usage: install.sh [options]

  --prefix DIR     Install prefix (binary → DIR/bin/mcp-secret-launcher). Default: ~/.local
  --ref REF        Git branch, tag, or commit. Default: main
  --repo URL       Git remote URL
  --dir DIR        Source checkout directory. Default: ~/.local/src/mcp-secret-launcher
  --with-path      Write path.env and add $PREFIX/bin to shell rc (macOS/Linux)
  --no-shell-rc    With --with-path: write path.env only, do not edit rc
  --no-keep-src    Remove the checkout after a successful install
  --local          Build the repo containing this script (no clone/fetch)
  --yes            Non-interactive (auto-install rustup if needed)
  -h, --help       Show this help

Examples:
  # Recommended first-time setup
  curl -fsSL https://raw.githubusercontent.com/suryan/mcp-secret-launcher/main/scripts/install.sh \
    | bash -s -- --with-path --yes

  ./scripts/install.sh --local --with-path
  MCP_SECRET_LAUNCHER_REF=v0.1.0 ./scripts/install.sh --yes --with-path
EOF
}

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'warn: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# ─── args ────────────────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)      PREFIX="${2:-}"; shift 2 ;;
    --prefix=*)    PREFIX="${1#*=}"; shift ;;
    --ref)         REF="${2:-}"; shift 2 ;;
    --ref=*)       REF="${1#*=}"; shift ;;
    --repo)        REPO="${2:-}"; shift 2 ;;
    --repo=*)      REPO="${1#*=}"; shift ;;
    --dir)         SRC_DIR="${2:-}"; shift 2 ;;
    --dir=*)       SRC_DIR="${1#*=}"; shift ;;
    --with-path)   WITH_PATH=1; shift ;;
    --no-shell-rc) NO_SHELL_RC=1; shift ;;
    --no-keep-src) KEEP_SRC=0; shift ;;
    --local)       LOCAL_ONLY=1; shift ;;
    --yes|-y)      YES=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             die "unknown option: $1 (try --help)" ;;
  esac
done

[ -n "$PREFIX" ] || die "--prefix must not be empty"
[ -n "$REF" ] || die "--ref must not be empty"
[ -n "$REPO" ] || die "--repo must not be empty"
[ -n "$SRC_DIR" ] || die "--dir must not be empty"

BINDIR="${PREFIX}/bin"
BIN="${BINDIR}/mcp-secret-launcher"

# ─── platform ────────────────────────────────────────────────────────────────

OS="$(uname -s 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
log "platform: ${OS}/${ARCH}"

case "$OS" in
  Linux|Darwin) ;;
  MINGW*|MSYS*|CYGWIN*)
    die "Windows native shell is not supported yet. Use WSL2, then re-run this script."
    ;;
  *)
    warn "untested OS '${OS}' — continuing; need a Unix-like environment with cargo"
    ;;
esac

# ─── rust toolchain ──────────────────────────────────────────────────────────

ensure_rust() {
  if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    log "rustc $(rustc --version 2>/dev/null | awk '{print $2}')"
    log "cargo $(cargo --version 2>/dev/null | awk '{print $2}')"
    return 0
  fi

  # rustup may be installed but not on this shell's PATH yet
  if [ -f "${HOME}/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "${HOME}/.cargo/env"
  fi
  if command -v cargo >/dev/null 2>&1; then
    log "loaded cargo from ~/.cargo/env"
    return 0
  fi

  log "Rust toolchain not found; installing via rustup (https://rustup.rs)"
  need_cmd curl

  if [ "$YES" -ne 1 ] && [ -t 0 ]; then
    printf 'Install rustup into %s? [Y/n] ' "${CARGO_HOME:-$HOME/.cargo}"
    read -r ans || true
    case "${ans:-Y}" in
      n|N|no|NO) die "cargo is required to build mcp-secret-launcher" ;;
    esac
  fi

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  # shellcheck disable=SC1091
  . "${HOME}/.cargo/env"
  command -v cargo >/dev/null 2>&1 || die "rustup finished but cargo is still not on PATH"
  log "rustc $(rustc --version | awk '{print $2}')"
}

# Hint for missing C toolchain (common first-run failure on bare VMs / new Macs)
check_linker_hint() {
  if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
    return 0
  fi
  case "$OS" in
    Darwin)
      warn "no C compiler on PATH — install Xcode CLT: xcode-select --install"
      ;;
    Linux)
      warn "no C compiler on PATH — install build tools (e.g. sudo apt install build-essential)"
      ;;
  esac
}

# ─── source tree ─────────────────────────────────────────────────────────────

resolve_source() {
  if [ "$LOCAL_ONLY" -eq 1 ]; then
    # Script lives in <repo>/scripts/install.sh
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [ ! -f "${here}/Cargo.toml" ]; then
      die "--local set but Cargo.toml not found next to scripts/ (${here})"
    fi
    SRC_DIR="$here"
    log "building from local tree: ${SRC_DIR}"
    return 0
  fi

  need_cmd git

  mkdir -p "$(dirname "$SRC_DIR")"
  if [ -d "${SRC_DIR}/.git" ]; then
    log "updating existing checkout: ${SRC_DIR}"
    git -C "$SRC_DIR" remote set-url origin "$REPO" 2>/dev/null || true
    git -C "$SRC_DIR" fetch --tags --force origin
    if git -C "$SRC_DIR" rev-parse --verify "refs/remotes/origin/${REF}" >/dev/null 2>&1; then
      git -C "$SRC_DIR" checkout -B "$REF" "origin/${REF}"
    elif git -C "$SRC_DIR" rev-parse --verify "refs/tags/${REF}" >/dev/null 2>&1; then
      git -C "$SRC_DIR" checkout --detach "refs/tags/${REF}"
    elif git -C "$SRC_DIR" rev-parse --verify "${REF}" >/dev/null 2>&1; then
      git -C "$SRC_DIR" checkout --detach "${REF}"
    else
      die "ref not found after fetch: ${REF}"
    fi
  else
    log "cloning ${REPO} (${REF}) → ${SRC_DIR}"
    rm -rf "$SRC_DIR"
    if git ls-remote --exit-code --heads "$REPO" "$REF" >/dev/null 2>&1; then
      git clone --depth 1 --branch "$REF" "$REPO" "$SRC_DIR"
    elif git ls-remote --exit-code --tags "$REPO" "$REF" >/dev/null 2>&1 \
      || git ls-remote --exit-code --tags "$REPO" "${REF}^{}" >/dev/null 2>&1; then
      git clone --depth 1 --branch "$REF" "$REPO" "$SRC_DIR"
    else
      git clone "$REPO" "$SRC_DIR"
      git -C "$SRC_DIR" checkout "$REF"
    fi
  fi

  [ -f "${SRC_DIR}/Cargo.toml" ] || die "clone missing Cargo.toml"
}

# ─── build & install ─────────────────────────────────────────────────────────

build_release() {
  log "cargo build --release (this may take a few minutes on first build)"
  (
    cd "$SRC_DIR"
    cargo build --release --locked 2>/dev/null || cargo build --release
  )
  local built="${SRC_DIR}/target/release/mcp-secret-launcher"
  if [ ! -x "$built" ] && [ -f "${built}.exe" ]; then
    built="${built}.exe"
  fi
  [ -x "$built" ] || die "build finished but binary missing: ${SRC_DIR}/target/release/mcp-secret-launcher"
  BUILT_BIN="$built"
}

install_binary() {
  log "installing → ${BIN}"
  mkdir -p "$BINDIR"
  if command -v install >/dev/null 2>&1; then
    install -m 755 "$BUILT_BIN" "$BIN"
  else
    cp "$BUILT_BIN" "$BIN"
    chmod 755 "$BIN"
  fi
  [ -x "$BIN" ] || die "install failed: ${BIN} is not executable"
}

verify() {
  local ver
  ver="$("$BIN" --version 2>/dev/null || true)"
  if [ -z "$ver" ]; then
    warn "binary installed but --version failed"
  else
    log "ok: ${ver}"
  fi

  case ":${PATH}:" in
    *":${BINDIR}:"*) ;;
    *)
      warn "${BINDIR} is not on your PATH"
      printf '\n  Add this to your shell rc (bashrc/zshrc/profile):\n\n'
      # Intentionally print $PATH for the user to paste into a later shell.
      # shellcheck disable=SC2016
      printf '    export PATH="%s:$PATH"\n\n' "$BINDIR"
      ;;
  esac
}

# Prefer in-tree setup-user.sh (local or just-cloned).
run_user_setup() {
  [ "$WITH_PATH" -eq 1 ] || return 0

  local setup="${SRC_DIR}/scripts/setup-user.sh"
  local args=(--bin "$BIN")
  if [ "$NO_SHELL_RC" -eq 1 ]; then
    args+=(--no-shell-rc)
  fi

  if [ -f "$setup" ]; then
    log "configuring user PATH + shell integration"
    bash "$setup" "${args[@]}"
    return 0
  fi

  warn "setup-user.sh missing in source tree — add ${BINDIR} to PATH yourself"
  # Intentionally print $PATH for the user to paste into a later shell.
  # shellcheck disable=SC2016
  printf '\n  export PATH="%s:$PATH"\n\n' "$BINDIR"
}

cleanup_src() {
  [ "$KEEP_SRC" -eq 1 ] && return 0
  [ "$LOCAL_ONLY" -eq 1 ] && return 0
  log "removing source checkout (${SRC_DIR})"
  rm -rf "$SRC_DIR"
}

# ─── main ────────────────────────────────────────────────────────────────────

main() {
  log "mcp-secret-launcher install-from-source"
  check_linker_hint
  ensure_rust
  resolve_source
  build_release || exit 2
  install_binary || exit 2
  verify
  run_user_setup
  cleanup_src

  cat <<EOF

Installed: ${BIN}

Quick checks:
  mcp-secret-launcher --help
  mcp-secret-launcher set --profile my-server --key API_KEY

EOF

  if [ "$WITH_PATH" -eq 1 ]; then
    cat <<'EOF'
PATH:
  Open a new shell, then:  command -v mcp-secret-launcher

EOF
  else
    cat <<'EOF'
Optional next steps:
  ./scripts/setup-user.sh          # $PREFIX/bin on PATH + path.env + shell rc
  # or:  bash scripts/install.sh --local --with-path

EOF
  fi

  cat <<'EOF'
Docs: docs/usage.md  ·  https://github.com/suryan/mcp-secret-launcher

EOF
}

main
