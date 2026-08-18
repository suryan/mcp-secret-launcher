#!/usr/bin/env bash
# mcp-secret-launcher user setup (macOS + Linux)
#
# Idempotent helper used by install.sh and `make setup-user`:
#   - write ~/.config/mcp-secret-launcher/path.env
#   - source path.env from shell rc files (bash + zsh, login + interactive)
#
# Usage:
#   ./scripts/setup-user.sh
#   ./scripts/setup-user.sh --no-shell-rc       # path.env only, don't edit rc
#   MCP_SECRET_LAUNCHER_BIN=~/.local/bin/mcp-secret-launcher ./scripts/setup-user.sh
#
# Environment:
#   MCP_SECRET_LAUNCHER_BIN     path to binary (default: first on PATH or ~/.local/bin)
#   MCP_SECRET_LAUNCHER_PREFIX  used to find $PREFIX/bin/mcp-secret-launcher when BIN unset

set -euo pipefail

WRITE_SHELL_RC=1
BIN="${MCP_SECRET_LAUNCHER_BIN:-}"
PREFIX="${MCP_SECRET_LAUNCHER_PREFIX:-${HOME}/.local}"

usage() {
  cat <<'EOF'
Usage: setup-user.sh [options]

  Configure PATH so `mcp-secret-launcher` is found in new shells.

  --no-shell-rc    Do not modify ~/.bashrc ~/.zshrc ~/.profile ~/.zprofile
  --bin PATH       mcp-secret-launcher binary (default: PATH / $MCP_SECRET_LAUNCHER_PREFIX/bin)
  -h, --help       Show this help
EOF
}

log()  { printf '==> %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --no-shell-rc)
      WRITE_SHELL_RC=0; shift ;;
    --bin)
      BIN="${2:-}"; shift 2 ;;
    --bin=*)
      BIN="${1#*=}"; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "unknown option: $1 (try --help)" ;;
  esac
done

resolve_bin() {
  if [ -n "$BIN" ] && [ -x "$BIN" ]; then
    return 0
  fi
  if command -v mcp-secret-launcher >/dev/null 2>&1; then
    BIN="$(command -v mcp-secret-launcher)"
    return 0
  fi
  if [ -x "${PREFIX}/bin/mcp-secret-launcher" ]; then
    BIN="${PREFIX}/bin/mcp-secret-launcher"
    return 0
  fi
  die "mcp-secret-launcher not found; install first or pass --bin /path/to/mcp-secret-launcher"
}

config_dir() {
  if [ -n "${XDG_CONFIG_HOME:-}" ]; then
    printf '%s/mcp-secret-launcher' "$XDG_CONFIG_HOME"
  else
    printf '%s/.config/mcp-secret-launcher' "$HOME"
  fi
}

# Marker used for idempotent rc edits (do not change casually).
RC_MARKER_BEGIN="# >>> mcp-secret-launcher >>>"
RC_MARKER_END="# <<< mcp-secret-launcher <<<"

write_path_env() {
  local dir conf bindir
  dir="$(config_dir)"
  conf="${dir}/path.env"
  bindir="$(cd "$(dirname "$BIN")" && pwd)"
  mkdir -p "$dir"
  cat >"$conf" <<EOF
# mcp-secret-launcher — keep the install prefix bin dir on PATH.
export PATH="${bindir}:\${PATH}"
EOF
  log "wrote ${conf}"
}

# True if this rc already sources mcp-secret-launcher path.env (any marker / prior layout).
rc_already_has_path() {
  local file="$1"
  [ -f "$file" ] || return 1
  grep -qE 'mcp-secret-launcher/path\.env|mcp-secret-launcher >>>' "$file" 2>/dev/null
}

# Append marker block once per file. Safe on macOS (BSD sed) and GNU.
ensure_rc_snippet() {
  local file="$1"
  local parent snippet
  parent="$(dirname "$file")"
  mkdir -p "$parent"

  if rc_already_has_path "$file"; then
    log "shell rc already configured: ${file}"
    return 0
  fi

  # Create empty file if missing (common for fresh Linux/macOS accounts).
  if [ ! -f "$file" ]; then
    touch "$file"
  fi

  # Expand $HOME when the rc file is sourced, not when we write it.
  # shellcheck disable=SC2016
  snippet='[ -f "$HOME/.config/mcp-secret-launcher/path.env" ] && . "$HOME/.config/mcp-secret-launcher/path.env"'
  if [ -n "${XDG_CONFIG_HOME:-}" ]; then
    snippet="[ -f \"$(config_dir)/path.env\" ] && . \"$(config_dir)/path.env\""
  fi

  {
    printf '\n%s\n' "$RC_MARKER_BEGIN"
    printf '%s\n' "$snippet"
    printf '%s\n' "$RC_MARKER_END"
  } >>"$file"
  log "updated shell rc: ${file}"
}

setup_shell_rc() {
  [ "$WRITE_SHELL_RC" -eq 1 ] || {
    log "skipping shell rc edits (--no-shell-rc)"
    return 0
  }

  # Interactive shells
  ensure_rc_snippet "${HOME}/.bashrc"
  ensure_rc_snippet "${HOME}/.zshrc"
  # Login shells (macOS Terminal, many Linux GUI sessions, SSH login)
  ensure_rc_snippet "${HOME}/.profile"
  ensure_rc_snippet "${HOME}/.zprofile"
}

print_summary() {
  cat <<EOF

User setup complete.

  Binary:     ${BIN}
  Env file:   $(config_dir)/path.env

Open a new shell (or: source $(config_dir)/path.env), then:

  command -v mcp-secret-launcher
  mcp-secret-launcher --help

MCP / IDE hosts often skip shell rc — set PATH in the host env, or use
the absolute command:

  ${BIN}

Linux IDEs also need DBUS_SESSION_BUS_ADDRESS in the server env
(see docs/usage.md).

EOF
}

main() {
  log "mcp-secret-launcher user setup (macOS/Linux)"
  resolve_bin
  log "using ${BIN} ($("$BIN" --version 2>/dev/null || echo unknown))"
  write_path_env
  setup_shell_rc
  print_summary
}

main
