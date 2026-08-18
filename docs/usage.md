# Usage Guide

This guide covers how to install `mcp-secret-launcher`, manage secrets, and configure MCP servers.

## Installation

`mcp-secret-launcher` is a single Rust binary. Prefer **install from source** on each machine
(no GitHub release artifacts to maintain). Supported: **macOS**, **Linux**, **WSL2**.

### One-liner (recommended)

```bash
# Binary + ~/.local/bin on PATH
curl -fsSL https://raw.githubusercontent.com/suryan/mcp-secret-launcher/main/scripts/install.sh \
  | bash -s -- --with-path --yes
```

What it does:

1. Ensures a Rust toolchain (`rustup` if `cargo` is missing)
2. Clones/updates the repo under `~/.local/src/mcp-secret-launcher` (override with `--dir`)
3. `cargo build --release`
4. Installs to `~/.local/bin/mcp-secret-launcher` (override with `--prefix`)
5. With `--with-path`: runs `scripts/setup-user.sh`
   - writes `~/.config/mcp-secret-launcher/path.env`
   - sources it from `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.zprofile` (idempotent)

```bash
# Common options
bash scripts/install.sh --help
bash scripts/install.sh --prefix ~/.local --with-path --yes
bash scripts/install.sh --ref main
bash scripts/install.sh --local --with-path            # current clone only
MCP_SECRET_LAUNCHER_PREFIX=/usr/local sudo -E bash scripts/install.sh --yes   # system-wide (careful)
```

| Variable / flag | Default | Meaning |
|-----------------|---------|---------|
| `--prefix` / `MCP_SECRET_LAUNCHER_PREFIX` | `~/.local` | Binary at `$PREFIX/bin/mcp-secret-launcher` |
| `--ref` / `MCP_SECRET_LAUNCHER_REF` | `main` | Git branch, tag, or commit |
| `--repo` / `MCP_SECRET_LAUNCHER_REPO` | this GitHub repo | Clone URL |
| `--dir` / `MCP_SECRET_LAUNCHER_DIR` | `~/.local/src/mcp-secret-launcher` | Checkout path |
| `--with-path` | off | `path.env` + shell rc (see `setup-user.sh`) |
| `--no-shell-rc` | off | Write env file only; do not edit rc files |
| `--yes` | off | Non-interactive rustup install |

**Requirements:** `curl` + `git`, C linker (`build-essential` on Debian/Ubuntu,
Xcode CLT on macOS: `xcode-select --install`), network for crates.io.

### `cargo install` (Rust toolchain already present)

```bash
cargo install --git https://github.com/suryan/mcp-secret-launcher --locked
./scripts/setup-user.sh    # PATH + shell integration (from a clone)
```

### From a local clone

```bash
git clone https://github.com/suryan/mcp-secret-launcher.git
cd mcp-secret-launcher
./scripts/install.sh --local --with-path
# or stepwise:
make setup-user                 # release binary + path.env + shell rc
```

### Make shortcuts

```bash
make help          # list targets
make release       # optimized build
make install       # install binary to ~/.local/bin
make setup-user    # binary + path.env + shell rc
make precommit     # fmt, clippy, tests (coverage if cargo-llvm-cov is installed)
```

### Verify installation

```bash
mcp-secret-launcher --version
mcp-secret-launcher --help
```

If `mcp-secret-launcher` is not found, add `~/.local/bin` to `PATH` (or
`source ~/.config/mcp-secret-launcher/path.env`).

MCP / IDE hosts often skip shell profiles. Either set `PATH` in the host env or
use the absolute path as `command` in `mcp.json`:

```json
"command": "/home/YOU/.local/bin/mcp-secret-launcher"
```

## Managing Secrets

### Store a secret

Secrets are entered via a secure, non-echoing prompt. They are never accepted as CLI arguments (no `--value` flag) to prevent leaking into shell history or logs.

```bash
mcp-secret-launcher set --profile mcp-atlassian --key JIRA_API_TOKEN
# Enter secret value: [hidden input]
```

### Verify a secret

```bash
mcp-secret-launcher get --profile mcp-atlassian --key JIRA_API_TOKEN
# JIRA_API_TOKEN = ATATT3x...****
```

### List keys for a profile

```bash
mcp-secret-launcher list --profile mcp-atlassian
# JIRA_API_TOKEN
# CONFLUENCE_TOKEN
```

### Delete a secret

```bash
mcp-secret-launcher delete --profile mcp-atlassian --key JIRA_API_TOKEN
```

## Running an MCP Server

### Launch an MCP server

```bash
mcp-secret-launcher run --profile mcp-atlassian -- uvx mcp-atlassian
```

### Authenticate via AWS SSO and launch

To automatically authenticate via AWS SSO and inject temporary AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and `AWS_DEFAULT_REGION`):

```bash
mcp-secret-launcher aws-auth \
  --sso-url https://my-sso-portal.awsapps.com/start \
  --region us-east-1 \
  --account-id 123456789012 \
  --role-name MyDeveloperRole \
  -- uvx mcp-aws
```

You can also combine AWS SSO with standard profile secrets by passing `--profile`:

```bash
mcp-secret-launcher aws-auth \
  --sso-url https://my-sso-portal.awsapps.com/start \
  --region us-east-1 \
  --account-id 123456789012 \
  --role-name MyDeveloperRole \
  --profile custom-profile \
  -- uvx mcp-aws
```

## MCP JSON Integration

### Example: Securing `mcp-atlassian`

A typical `mcp-atlassian` config looks like this — with API tokens in plaintext:

```json
{
  "mcpServers": {
    "mcp-atlassian": {
      "command": "uvx",
      "args": ["mcp-atlassian"],
      "env": {
        "JIRA_URL": "https://mycompany.atlassian.net",
        "JIRA_USERNAME": "user@example.com",
        "JIRA_API_TOKEN": "ATATT3xFfGF0...",
        "CONFLUENCE_URL": "https://mycompany.atlassian.net/wiki",
        "CONFLUENCE_USERNAME": "user@example.com",
        "CONFLUENCE_API_TOKEN": "ATATT3xFfGF0..."
      }
    }
  }
}
```

#### Step 1 — Store the secrets in the keyring

```bash
mcp-secret-launcher set --profile mcp-atlassian --key JIRA_API_TOKEN
# Enter secret value: [hidden input]

mcp-secret-launcher set --profile mcp-atlassian --key CONFLUENCE_API_TOKEN
# Enter secret value: [hidden input]
```

#### Step 2 — Verify they were stored

```bash
mcp-secret-launcher list --profile mcp-atlassian
# JIRA_API_TOKEN
# CONFLUENCE_API_TOKEN
```

#### Step 3 — Update `mcp.json`

Replace `command` and `args`, and remove the secret values from `env`:

```json
{
  "mcpServers": {
    "mcp-atlassian": {
      "command": "mcp-secret-launcher",
      "args": ["run", "--profile", "mcp-atlassian", "--", "uvx", "mcp-atlassian"],
      "env": {
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
        "JIRA_URL": "https://mycompany.atlassian.net",
        "JIRA_USERNAME": "user@example.com",
        "CONFLUENCE_URL": "https://mycompany.atlassian.net/wiki",
        "CONFLUENCE_USERNAME": "user@example.com"
      }
    }
  }
}
```

> **Linux only:** `DBUS_SESSION_BUS_ADDRESS` is required so the launcher can reach the keyring daemon. IDEs like Kiro and VS Code often don't pass this to spawned processes. Run `echo $DBUS_SESSION_BUS_ADDRESS` in your terminal to get the correct value. On macOS and Windows this is not needed.

Non-secret env vars (URLs, usernames) stay in `mcp.json` as usual. The key names you store with `--key` must match the environment variable names the target server expects. At launch, the launcher reads all keys for the profile from the OS keyring, merges them with the static `env` block, and execs the target command. Keyring values take precedence on name collision.

### Example: Securing an AWS-based MCP Server

To use `aws-auth` in your `mcp.json`, simply invoke `mcp-secret-launcher` with the `aws-auth` subcommand, its required flags, and finally the target command.

```json
{
  "mcpServers": {
    "mcp-aws": {
      "command": "mcp-secret-launcher",
      "args": [
        "aws-auth",
        "--sso-url", "https://my-sso-portal.awsapps.com/start",
        "--region", "us-east-1",
        "--account-id", "123456789012",
        "--role-name", "MyDeveloperRole",
        "--",
        "uvx", "mcp-server-aws"
      ],
      "env": {}
    }
  }
}
```

When the MCP client starts this server, the launcher will perform the AWS SSO device authorization flow (opening a browser if necessary), securely inject `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and `AWS_DEFAULT_REGION` directly into memory, and execute `uvx mcp-server-aws`.

## Troubleshooting

### `Keyring daemon not available` / `DBUS_SESSION_BUS_ADDRESS is missing`

On Linux, the keyring backend uses D-Bus to communicate with the secret service daemon. When an IDE (Kiro, VS Code, Cursor, etc.) spawns MCP server processes, it often does **not** inherit the desktop session's `DBUS_SESSION_BUS_ADDRESS` variable.

**Symptoms:**
```
Error: Keyring daemon not available. Ensure dbus-daemon (DBUS_SESSION_BUS_ADDRESS is missing) is running.
```

**Fix:** Add `DBUS_SESSION_BUS_ADDRESS` to the `env` block in your `mcp.json`:

```bash
# Find your value
echo $DBUS_SESSION_BUS_ADDRESS
# Typical output: unix:path=/run/user/1000/bus
```

Then add it to your config:
```json
"env": {
  "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
  ...
}
```

This is not needed on macOS or Windows.
