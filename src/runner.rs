// Process execution (exec on Unix, spawn on Windows)

use crate::errors::LauncherError;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;

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

/// Unix: calls execvp, replacing the current process. Does not return on success.
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
