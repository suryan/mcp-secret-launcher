#![allow(clippy::unwrap_used, missing_docs, clippy::items_after_statements)]
//! Tests for the CLI module.

use anyhow::Result;
use clap::Parser;
use mcp_secret_launcher::cli::*;
use mcp_secret_launcher::keyring_ops::KeyringBackend;
use proptest::prelude::*;

/// Validates: Requirements 5.3
/// Verify that `set --profile p --key k --value v` is rejected by the CLI parser.
#[test]
fn test_set_rejects_value_flag() {
    let args = [
        "mcp-secret-launcher",
        "set",
        "--profile",
        "test-profile",
        "--key",
        "MY_KEY",
        "--value",
        "secret123",
    ];
    let result = Cli::try_parse_from(args);
    assert!(
        result.is_err(),
        "set subcommand should reject --value flag, but parsing succeeded"
    );
}

/// Validates: Requirements 5.3
/// Verify that `set --profile p --key k` (without --value) parses successfully.
#[test]
fn test_set_without_value_parses_ok() -> Result<(), anyhow::Error> {
    let args = [
        "mcp-secret-launcher",
        "set",
        "--profile",
        "test-profile",
        "--key",
        "MY_KEY",
    ];
    let Ok(parsed) = Cli::try_parse_from(args) else {
        return Err(anyhow::anyhow!(
            "set without --value should parse successfully"
        ));
    };
    match parsed.command {
        Command::Set { profile, key } => {
            assert_eq!(profile, "test-profile");
            assert_eq!(key, "MY_KEY");
        }
        _ => return Err(anyhow::anyhow!("Parsed wrong variant")),
    }
    Ok(())
}

// Feature: mcp-secret-launcher, Property 3: Argument passthrough preserves arguments
// **Validates: Requirements 3.2, 4.3**
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_argument_passthrough_preserves_arguments(
        args in prop::collection::vec("[a-zA-Z0-9]{1,20}", 1..10)
    ) {
        let mut cli_args = vec![
            "mcp-secret-launcher".to_string(),
            "run".to_string(),
            "--profile".to_string(),
            "test".to_string(),
            "--".to_string(),
        ];
        let expected = args.clone();
        cli_args.extend(args);

        let Ok(parsed) = Cli::try_parse_from(&cli_args) else { return Err(proptest::test_runner::TestCaseError::fail("CLI parsing should succeed")); };

        match parsed.command {
            Command::Run { cmd, .. } => {
                prop_assert_eq!(cmd, expected);
            }
            _ => todo!(),
        }
    }
}

#[test]
fn test_run_cli_list() {
    let backend = mcp_secret_launcher::keyring_ops::MockKeyring::new();
    let prompter =
        mcp_secret_launcher::prompter::MockPrompter::new(secrecy::SecretString::from(""));

    let args = vec![
        "mcp-secret-launcher".to_string(),
        "list".to_string(),
        "--profile".to_string(),
        "test".to_string(),
    ];
    let res = mcp_secret_launcher::run_cli(args, &backend, &prompter, vec![]);
    assert!(res.is_ok());
}

#[test]
fn test_run_cli_invalid_command() {
    let backend = mcp_secret_launcher::keyring_ops::MockKeyring::new();
    let prompter =
        mcp_secret_launcher::prompter::MockPrompter::new(secrecy::SecretString::from(""));

    let args = vec!["mcp-secret-launcher".to_string(), "invalid".to_string()];
    let res = mcp_secret_launcher::run_cli(args, &backend, &prompter, vec![]);
    assert!(res.is_err());
}

#[test]
fn test_run_cli_set() {
    let backend = mcp_secret_launcher::keyring_ops::MockKeyring::new();
    let prompter =
        mcp_secret_launcher::prompter::MockPrompter::new(secrecy::SecretString::from("xyz"));

    let args = vec![
        "mcp-secret-launcher".to_string(),
        "set".to_string(),
        "--profile".to_string(),
        "p".to_string(),
        "--key".to_string(),
        "k".to_string(),
    ];
    let res = mcp_secret_launcher::run_cli(args, &backend, &prompter, vec![]);
    assert!(res.is_ok());
    use secrecy::ExposeSecret;
    assert_eq!(backend.get_secret("p", "k").unwrap().expose_secret(), "xyz");
}

#[test]
fn test_run_cli_help() {
    let backend = mcp_secret_launcher::keyring_ops::MockKeyring::new();
    let prompter =
        mcp_secret_launcher::prompter::MockPrompter::new(secrecy::SecretString::from(""));
    let args = vec!["mcp-secret-launcher".to_string(), "--help".to_string()];
    let res = mcp_secret_launcher::run_cli(args, &backend, &prompter, vec![]);
    // Help results in a clap error with kind HelpDisplayed, but run_cli currently propagates it.
    assert!(res.is_err());
}

#[test]
fn test_get_aws_credentials_cache_race() {
    let mut server = mockito::Server::new();
    // We need a backend that returns None first, then Some after a few calls
    // to simulate another process filling the cache during the lock wait.
    struct RaceBackend {
        called: std::cell::Cell<usize>,
        data: secrecy::SecretString,
    }

    impl mcp_secret_launcher::keyring_ops::KeyringBackend for RaceBackend {
        fn get_secret(&self, _p: &str, _k: &str) -> anyhow::Result<secrecy::SecretString> {
            let c = self.called.get();
            self.called.set(c + 1);
            if c == 0 {
                Err(anyhow::anyhow!("Not found"))
            } else {
                Ok(self.data.clone())
            }
        }
        fn set_secret(&self, _p: &str, _k: &str, _v: &secrecy::SecretString) -> anyhow::Result<()> {
            Ok(())
        }
        fn delete_secret(&self, _p: &str, _k: &str) -> anyhow::Result<()> {
            Ok(())
        }
        fn get_manifest(&self, _p: &str) -> anyhow::Result<Vec<String>> {
            Ok(vec![])
        }
        fn set_manifest(&self, _p: &str, _keys: &[String]) -> anyhow::Result<()> {
            Ok(())
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let json = format!(r#"{{"accessToken": "race-ok", "expiresIn": 3600, "issuedAt": {now}}}"#);
    let backend = RaceBackend {
        called: std::cell::Cell::new(0),
        data: json.into(),
    };

    let _m4 = server
        .mock("GET", "/federation/credentials?account_id=A&role_name=R")
        .with_status(200)
        .with_body(r#"{"roleCredentials": {"accessKeyId": "ak", "secretAccessKey": "sk", "sessionToken": "st", "expiration": 2000000000}}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
        &backend,
        "https://sso.example.com",
        "us-east-1",
        "A",
        "R",
    );
    assert!(res.is_ok());
    // Should have called get_secret at least twice (first fails, second succeeds after "lock")
    assert!(backend.called.get() >= 2);
}
