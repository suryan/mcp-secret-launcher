//! # MCP Secret Launcher
//!
//! A library for securely managing secrets in the OS keyring and launching
//! processes with those secrets injected as environment variables.

/// Core application logic and command handlers.
pub mod app;
/// AWS SSO credential retrieval and caching.
pub mod aws_sso;
/// CLI argument definition and parsing.
pub mod cli;
/// Error types and categorization for the launcher.
pub mod errors;
/// Abstractions and implementations for OS keyring backends.
pub mod keyring_ops;
/// Utilities for masking sensitive strings in output.
pub mod masking;
/// Trait and implementations for secure user prompts.
pub mod prompter;
/// Logic for spawning and executing child processes.
pub mod runner;

/// Re-export of the main application entry point.
pub use app::run_app;

use clap::Parser;
use cli::Cli;
use keyring_ops::KeyringBackend;
use prompter::SecretPrompter;

/// Runs the CLI with the given arguments and backends.
/// This allows testing the CLI entry point without spawning a new process.
pub fn run_cli(
    args: Vec<String>,
    backend: &dyn KeyringBackend,
    prompter: &dyn SecretPrompter,
    env_vars: Vec<(String, String)>,
) -> anyhow::Result<()> {
    let cli = Cli::try_parse_from(args)?;
    run_app(cli.command, backend, prompter, env_vars)
}
