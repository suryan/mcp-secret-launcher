# 🛡️ mcp-secret-launcher

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()

**Stop leaking API tokens!** Secure your MCP servers by fetching secrets from your OS keyring instead of storing them in plaintext `mcp.json`.

---

## 🚀 Why Use This?

MCP server configurations typically require sensitive tokens in plaintext `env` blocks. This makes them visible to anyone with file access and easy to accidentally commit. `mcp-secret-launcher` solves this by:

- 🔒 **Keyring Integration:** Uses GNOME Keyring (Linux), Keychain (macOS), or Credential Manager (Windows).
- 🔑 **AWS SSO Support:** Automatically handles AWS SSO login and injects temporary credentials.
- 💨 **Zero overhead:** Replaces itself with the target process via `execvp` on Unix.
- 🛠️ **Seamless Integration:** Works with any MCP client (Kiro, VS Code, etc.) with a simple one-line change.

---

## ⚡ Quick Start

### 1. Install

No release binaries required — build from source on the machine that will run it.
Works on **macOS** and **Linux** (including WSL2).

```bash
# Binary + ~/.local/bin on PATH (bash + zsh)
curl -fsSL https://raw.githubusercontent.com/suryan/mcp-secret-launcher/main/scripts/install.sh \
  | bash -s -- --with-path --yes
```

What that does:

1. Bootstraps [rustup](https://rustup.rs) if `cargo` is missing
2. Builds a release binary → `~/.local/bin/mcp-secret-launcher`
3. Writes `~/.config/mcp-secret-launcher/path.env` and sources it from `~/.bashrc` / `~/.zshrc` / `~/.profile` / `~/.zprofile`

```bash
# From a local clone
./scripts/install.sh --local --with-path
# or stepwise:
make setup-user
```

Open a **new shell** after install, then: `mcp-secret-launcher --help`

**Requirements:** `git`, a C linker (`build-essential` on Debian/Ubuntu, Xcode CLT on macOS),
network for crates.io on first build. Rust developers can also
`cargo install --git https://github.com/suryan/mcp-secret-launcher --locked`.

### 2. Store a Secret
```bash
mcp-secret-launcher set --profile my-server --key API_KEY
# Enter secret value: [secure input]
```

### 3. Update `mcp.json`
Update your server configuration to use the launcher:

```diff
 {
   "mcpServers": {
     "my-server": {
-      "command": "uvx",
-      "args": ["my-server-command"],
-      "env": { "API_KEY": "YOUR_SECRET_IN_PLAINTEXT" }
+      "command": "mcp-secret-launcher",
+      "args": ["run", "--profile", "my-server", "--", "uvx", "my-server-command"],
+      "env": { "NON_SECRET_VAR": "public-value" }
     }
   }
 }
```

---

## 🌟 Key Features

### 🔐 Platform Native Security
No new databases or config files. We use what's already on your machine:
- **Linux:** Secret Service API (via DBus)
- **macOS:** Apple Keychain
- **Windows:** Windows Credential Manager

### ☁️ AWS SSO Magic
Launching an AWS-based MCP server? Tired of manual `aws sso login`?
```bash
mcp-secret-launcher aws-auth \
  --sso-url https://my-sso.awsapps.com/start \
  --region us-east-1 \
  --account-id 123456789012 \
  --role-name DeveloperRole \
  -- uvx mcp-server-aws
```
The launcher will handle the browser-based auth flow and inject `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc., directly into the server's memory.

---

## 🛡️ Defense in Depth

For maximum security, combine **mcp-secret-launcher** with [**mcp-guard**](https://github.com/suryan/mcp-guard):

- **mcp-secret-launcher (Layer 3/4):** Protects your *credentials* by keeping them in the OS keyring.
- **mcp-guard (Layer 7):** Protects your *resources* by intercepting tool calls and enforcing Human-In-The-Loop (HITL) approval.

**Complete Security Stack:**
```json
"my-server": {
  "command": "mcp-guard",
  "args": [
    "--policy", "guard-policy.toml",
    "--",
    "mcp-secret-launcher", "run", "--profile", "my-server",
    "--",
    "uvx", "my-server-command"
  ]
}
```
In this setup, **mcp-guard** acts as the primary proxy, and **mcp-secret-launcher** initializes the environment before the server starts.

---

## 📖 Learn More

| Guide | Description |
| :--- | :--- |
| [📂 Usage Guide](docs/usage.md) | Install, CLI commands, and `mcp.json` examples. |
| [🏗️ Architecture](docs/architecture.md) | How the secret injection and process replacement works. |
| [👩‍💻 Development](docs/development.md) | Setup, quality gate, and contributor workflow. |

## ⚖️ License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
