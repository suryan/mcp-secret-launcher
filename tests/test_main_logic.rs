#![allow(clippy::unwrap_used, missing_docs, clippy::items_after_statements)]
//! Tests for the main logic and exports.

use mcp_secret_launcher::keyring_ops::MockKeyring;
use mcp_secret_launcher::prompter::MockPrompter;
use secrecy::SecretString;

#[test]
fn test_run_cli_help_logic() {
    let args = vec!["mcp-secret-launcher".to_string(), "--help".to_string()];
    let backend = MockKeyring::new();
    let prompter = MockPrompter::new(SecretString::from(""));
    let res = mcp_secret_launcher::run_cli(args, &backend, &prompter, vec![]);
    // clap returns an error for --help when using try_parse_from
    assert!(res.is_err());
}

#[test]
fn test_production_backend_types() {
    // Instantiate production backends to ensure they are covered
    let _ = mcp_secret_launcher::keyring_ops::OsKeyring;
    let _ = mcp_secret_launcher::prompter::TerminalPrompter;
}

#[test]
fn test_lib_exports() {
    use mcp_secret_launcher::errors;
    let _ = format!("{:?}", errors::LauncherError::KeyringLocked);
}
