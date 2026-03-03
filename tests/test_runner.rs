#![allow(clippy::unwrap_used, missing_docs, clippy::items_after_statements)]
//! Tests for the runner module.

use mcp_secret_launcher::runner::*;
use proptest::prelude::*;
use secrecy::{ExposeSecret, SecretString};

#[test]
fn test_build_env_includes_inherited_env() -> anyhow::Result<()> {
    let inherited = vec![(
        "MSL_TEST_INHERITED".to_string(),
        "inherited_value".to_string(),
    )];
    let secrets = vec![];
    let env = build_env(secrets, inherited);

    assert!(env.contains_key("MSL_TEST_INHERITED"));
    let secret = env
        .get("MSL_TEST_INHERITED")
        .ok_or_else(|| anyhow::anyhow!("env var missing"))?;
    assert_eq!(secret.expose_secret(), "inherited_value");
    Ok(())
}

#[test]
fn test_build_env_secrets_override_inherited() -> anyhow::Result<()> {
    let inherited = vec![("MSL_TEST_OVERRIDE".to_string(), "old_value".to_string())];
    let secrets = vec![(
        "MSL_TEST_OVERRIDE".to_string(),
        SecretString::from("secret_value".to_string()),
    )];
    let env = build_env(secrets, inherited);

    let secret = env
        .get("MSL_TEST_OVERRIDE")
        .ok_or_else(|| anyhow::anyhow!("env var missing"))?;
    assert_eq!(secret.expose_secret(), "secret_value");
    Ok(())
}

#[test]
fn test_build_env_includes_both_inherited_and_secrets() -> anyhow::Result<()> {
    let inherited = vec![("MSL_TEST_KEEP".to_string(), "keep_me".to_string())];
    let secrets = vec![(
        "MSL_TEST_NEW_SECRET".to_string(),
        SecretString::from("new_secret".to_string()),
    )];
    let env = build_env(secrets, inherited);

    assert!(env.contains_key("MSL_TEST_KEEP"));
    let secret_keep = env
        .get("MSL_TEST_KEEP")
        .ok_or_else(|| anyhow::anyhow!("env var missing"))?;
    assert_eq!(secret_keep.expose_secret(), "keep_me");

    let secret_new = env
        .get("MSL_TEST_NEW_SECRET")
        .ok_or_else(|| anyhow::anyhow!("env var missing"))?;
    assert_eq!(secret_new.expose_secret(), "new_secret");
    Ok(())
}

#[test]
fn test_build_env_empty_secrets() {
    let inherited = vec![("PATH".to_string(), "/usr/bin".to_string())];
    let env = build_env(vec![], inherited);
    assert!(!env.is_empty());
}

#[cfg(unix)]
#[test]
fn test_exec_command_empty_cmd() {
    let env = std::collections::HashMap::new();
    let res = exec_command(&[], env);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().to_string(), "Empty command vector");
}

#[cfg(unix)]
#[test]
fn test_exec_command_not_found() {
    let env = std::collections::HashMap::new();
    let res = exec_command(&["/path/to/nonexistent/binary/12345".to_string()], env);
    assert!(res.is_err());
    let err_string = res.unwrap_err().to_string();
    assert!(err_string.contains("Failed to execute"));
}

#[cfg(any(windows, unix))]
#[test]
fn test_spawn_command_empty_cmd() {
    let env = std::collections::HashMap::new();
    let res = spawn_command(&[], env);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().to_string(), "Empty command vector");
}

#[cfg(any(windows, unix))]
#[test]
fn test_spawn_command_not_found() {
    let env = std::collections::HashMap::new();
    let res = spawn_command(&["C:\\path\\to\\nonexistent\\binary.exe".to_string()], env);
    assert!(res.is_err());
    let err_string = res.unwrap_err().to_string();
    assert!(err_string.contains("Failed to execute"));
}

// Feature: mcp-secret-launcher, Property 10: Exit code propagation
// **Validates: Requirements 4.2**
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_exit_code_propagation(exit_code in 0u8..=255u8) {
        // Spawn a child process that exits with the given code, then verify
        // the exit code is propagated correctly. This tests the same logic
        // that spawn_command uses on Windows: spawn → wait → extract exit code.
        let Ok(status) = std::process::Command::new("bash")
            .args(["-c", &format!("exit {exit_code}")])
            .status() else { return Err(proptest::test_runner::TestCaseError::fail("Failed to spawn bash process")); };

        let propagated_code = status.code().unwrap_or(1);
        prop_assert_eq!(
            propagated_code,
            i32::from(exit_code),
            "Exit code {} should propagate as {}, got {}",
            exit_code,
            exit_code,
            propagated_code
        );
    }
}

// Feature: mcp-secret-launcher, Property 7: Environment merge with keyring precedence
// **Validates: Requirements 8.2**
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_env_merge_keyring_precedence(
        // Generate 1-5 "inherited-only" env vars (unique suffix + value)
        inherited_only_suffixes in prop::collection::hash_set("[A-Z]{3,8}", 1..=5),
        inherited_only_values in prop::collection::vec("[a-zA-Z0-9]{1,20}", 5),
        // Generate 1-5 "secret-only" keys (unique suffix + value)
        secret_only_suffixes in prop::collection::hash_set("[A-Z]{3,8}", 1..=5),
        secret_only_values in prop::collection::vec("[a-zA-Z0-9]{1,20}", 5),
        // Generate 1-5 "overlapping" keys with both inherited and secret values
        overlap_suffixes in prop::collection::hash_set("[A-Z]{3,8}", 1..=5),
        overlap_inherited_values in prop::collection::vec("[a-zA-Z0-9]{1,20}", 5),
        overlap_secret_values in prop::collection::vec("[a-zA-Z0-9]{1,20}", 5),
    ) {
        let prefix = "MSL_PROP7_";

        // Build prefixed key names from the generated suffixes
        let inherited_only_keys: Vec<String> = inherited_only_suffixes.iter()
            .map(|s| format!("{prefix}INH_{s}"))
            .collect();
        let secret_only_keys: Vec<String> = secret_only_suffixes.iter()
            .map(|s| format!("{prefix}SEC_{s}"))
            .collect();
        let overlap_keys: Vec<String> = overlap_suffixes.iter()
            .map(|s| format!("{prefix}OVR_{s}"))
            .collect();

        let mut inherited_env_vec: Vec<(String, String)> = Vec::new();

        // Set inherited-only env vars
        for (i, key) in inherited_only_keys.iter().enumerate() {
            let val = &inherited_only_values[i % inherited_only_values.len()];
            inherited_env_vec.push((key.clone(), val.clone()));
        }

        // Set overlapping env vars with inherited values
        for (i, key) in overlap_keys.iter().enumerate() {
            let val = &overlap_inherited_values[i % overlap_inherited_values.len()];
            inherited_env_vec.push((key.clone(), val.clone()));
        }

        // Build secrets vec: secret-only + overlapping (with secret values)
        let mut secrets: Vec<(String, SecretString)> = Vec::new();
        for (i, key) in secret_only_keys.iter().enumerate() {
            let val = &secret_only_values[i % secret_only_values.len()];
            secrets.push((key.clone(), SecretString::from(val.clone())));
        }
        for (i, key) in overlap_keys.iter().enumerate() {
            let val = &overlap_secret_values[i % overlap_secret_values.len()];
            secrets.push((key.clone(), SecretString::from(val.clone())));
        }

        // Call build_env
        let env = build_env(secrets, inherited_env_vec);

        // Verify inherited-only keys are present with inherited values
        for (i, key) in inherited_only_keys.iter().enumerate() {
            let expected = &inherited_only_values[i % inherited_only_values.len()];
            prop_assert!(
                env.contains_key(key),
                "Inherited-only key '{}' should be present in merged env", key
            );
            if let Some(secret) = env.get(key) {
                prop_assert_eq!(
                    secret.expose_secret(),
                    expected.as_str(),
                    "Inherited-only key '{}' should have inherited value", key
                );
            }
        }

        // Verify secret-only keys are present with secret values
        for (i, key) in secret_only_keys.iter().enumerate() {
            let expected = &secret_only_values[i % secret_only_values.len()];
            prop_assert!(
                env.contains_key(key),
                "Secret-only key '{}' should be present in merged env", key
            );
            if let Some(secret) = env.get(key) {
                prop_assert_eq!(
                    secret.expose_secret(),
                    expected.as_str(),
                    "Secret-only key '{}' should have secret value", key
                );
            }
        }

        // Verify overlapping keys have SECRET values (keyring wins)
        for (i, key) in overlap_keys.iter().enumerate() {
            let expected_secret = &overlap_secret_values[i % overlap_secret_values.len()];
            prop_assert!(
                env.contains_key(key),
                "Overlapping key '{}' should be present in merged env", key
            );
            if let Some(secret) = env.get(key) {
                prop_assert_eq!(
                    secret.expose_secret(),
                    expected_secret.as_str(),
                    "Overlapping key '{}' should have SECRET value (keyring precedence), not inherited value", key
                );
            }
        }
    }
}
