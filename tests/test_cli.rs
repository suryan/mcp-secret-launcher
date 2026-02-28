//! Tests for the CLI module.

use clap::Parser;
use mcp_secret_launcher::cli::*;
use proptest::prelude::*;
use anyhow::Result;

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
    let Ok(parsed) = Cli::try_parse_from(args) else { return Err(anyhow::anyhow!("set without --value should parse successfully")); };
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
            _ => return Err(proptest::test_runner::TestCaseError::fail("Expected Run command"))
        }
    }
}
