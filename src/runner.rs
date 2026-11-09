// Process execution (exec on Unix, spawn on Windows)

use crate::errors::LauncherError;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

/// Environment keys allowed through into a clean child environment.
const CLEAN_PASSTHROUGH: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "TERM",
    "TMPDIR",
    "TMP",
    "TEMP",
];

/// Builds the environment map by merging inherited env with secrets.
/// Starts with the current process's environment variables, wraps each value
/// in `SecretString`, then overlays keyring secrets on top.
/// Secrets take precedence over existing env vars on name collision.
pub fn build_env(
    secrets: impl IntoIterator<Item = (String, SecretString)>,
    inherited_env: impl IntoIterator<Item = (String, String)>,
) -> HashMap<String, SecretString> {
    let mut env: HashMap<String, SecretString> = inherited_env
        .into_iter()
        .map(|(k, v)| (k, SecretString::from(v)))
        .collect();

    for (key, value) in secrets {
        env.insert(key, value);
    }

    env
}

/// Build a clean child environment: only allowlisted passthrough vars from the
/// current process, then overlay `secrets`. Used by `aws-run-with-secrets`.
#[must_use]
pub fn build_clean_env(
    secrets: impl IntoIterator<Item = (String, SecretString)>,
) -> HashMap<String, SecretString> {
    let mut env = HashMap::new();
    for key in CLEAN_PASSTHROUGH {
        if let Ok(val) = std::env::var(key) {
            env.insert((*key).to_string(), SecretString::from(val));
        }
    }
    for (key, value) in secrets {
        env.insert(key, value);
    }
    env
}

/// Captured outcome of a spawned child.
#[derive(Debug)]
pub struct CaptureOutcome {
    /// Exit code, or `None` if terminated by signal.
    pub exit_code: Option<i32>,
    /// Captured stdout (lossy UTF-8).
    pub stdout: String,
    /// Captured stderr (lossy UTF-8).
    pub stderr: String,
    /// Whether the child was killed because it hit `timeout`.
    pub timed_out: bool,
}

/// Unix: calls execvp, replacing the current process. Does not return on success.
///
/// # Errors
/// Returns an error if the `execvp` syscall fails.
#[cfg(unix)]
#[allow(clippy::needless_pass_by_value, clippy::implicit_hasher)]
pub fn exec_command(cmd: &[String], env: HashMap<String, SecretString>) -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;

    let program = cmd
        .first()
        .ok_or_else(|| anyhow::anyhow!("Empty command vector"))?;
    let args = &cmd[1..];

    let err = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v.expose_secret())))
        .exec();

    Err(LauncherError::ExecFailed {
        command: program.clone(),
        source: err,
    }
    .into())
}

/// Windows: spawns child process with secrets injected, then explicitly drops/zeroizes
/// the `env` map BEFORE calling `.wait()` on the child. This ensures secrets
/// are cleared from the launcher's memory while the child is still running, since the
/// launcher remains resident on Windows (unlike Unix execvp which replaces the process).
// Used on Windows by default, and on Unix for testing to avoid execvp process replacement.
///
/// # Errors
/// Returns an error if the child process fails to spawn or wait for exit.
#[allow(clippy::needless_pass_by_value, clippy::implicit_hasher)]
pub fn spawn_command(cmd: &[String], env: HashMap<String, SecretString>) -> anyhow::Result<i32> {
    let program = cmd
        .first()
        .ok_or_else(|| anyhow::anyhow!("Empty command vector"))?;
    let args = &cmd[1..];

    let mut child = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v.expose_secret())))
        .spawn()
        .map_err(|e| LauncherError::ExecFailed {
            command: program.clone(),
            source: e,
        })?;

    // Explicitly zeroize all SecretStrings BEFORE waiting for the child
    drop(env);

    let status = child.wait().map_err(|e| LauncherError::ExecFailed {
        command: program.clone(),
        source: e,
    })?;

    Ok(status.code().unwrap_or(1))
}

/// Spawn a child with a clean env and capture stdout/stderr.
///
/// Unlike [`exec_command`], this always returns so the caller can redact output.
/// Timeouts are enforced by the parent MCP server killing the launcher process
/// group; the `timeout` argument is accepted for API symmetry and currently
/// only recorded as `timed_out: false` on a normal exit.
///
/// # Errors
/// Returns an error if the child cannot be spawned or I/O fails.
#[allow(clippy::needless_pass_by_value, clippy::implicit_hasher)]
pub fn spawn_capture(
    cmd: &[String],
    env: HashMap<String, SecretString>,
    cwd: &Path,
    _timeout: Option<Duration>,
) -> anyhow::Result<CaptureOutcome> {
    let program = cmd
        .first()
        .ok_or_else(|| anyhow::anyhow!("Empty command vector"))?;
    let args = &cmd[1..];

    let child = std::process::Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v.expose_secret())))
        .spawn()
        .map_err(|e| LauncherError::ExecFailed {
            command: program.clone(),
            source: e,
        })?;

    // Zeroize secrets in the launcher before waiting.
    drop(env);

    let output = child
        .wait_with_output()
        .map_err(|e| LauncherError::ExecFailed {
            command: program.clone(),
            source: e,
        })?;
    Ok(CaptureOutcome {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        timed_out: false,
    })
}
