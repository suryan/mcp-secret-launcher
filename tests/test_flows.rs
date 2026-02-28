//! Tests for end-to-end flows.


use mcp_secret_launcher::keyring_ops::{self, KeyringBackend, MockKeyring};
use mcp_secret_launcher::masking::mask_value;
use mcp_secret_launcher::prompter::{MockPrompter, SecretPrompter};
use secrecy::{ExposeSecret, SecretString};

/// End-to-end set flow: prompt → store → manifest update
/// Validates: Requirements 5.1, 5.2
#[test]
fn test_end_to_end_set_flow() -> anyhow::Result<()> {
    let secret_value = "super-secret-token-12345";
    let profile = "test-profile";
    let key = "API_TOKEN";

    // Step 1: Create a MockPrompter with a predefined secret value
    let prompter = MockPrompter::new(SecretString::from(secret_value.to_string()));

    // Step 2: Create a MockKeyring
    let keyring = MockKeyring::new();

    // Step 3: Prompt for the secret (simulates user input)
    let value = prompter.prompt_secret("Enter secret value: ")?;

    // Step 4: Store the secret via store_secret (same as Set subcommand)
    keyring_ops::store_secret(&keyring, profile, key, &value)?;

    // Step 5: Verify the secret is stored in the keyring
    let retrieved = keyring.get_secret(profile, key)?;
    assert_eq!(retrieved.expose_secret(), secret_value);

    // Step 6: Verify the manifest is updated
    let manifest = keyring.get_manifest(profile)?;
    assert_eq!(manifest, vec![key.to_string()]);
    Ok(())
}

/// Verify that storing multiple secrets via the set flow updates the manifest correctly
/// Validates: Requirements 5.1, 5.2
#[test]
fn test_end_to_end_set_flow_multiple_keys() -> anyhow::Result<()> {
    let profile = "multi-profile";
    let keyring = MockKeyring::new();

    let entries = vec![
        ("JIRA_TOKEN", "jira-secret-abc"),
        ("CONFLUENCE_TOKEN", "confluence-secret-xyz"),
    ];

    for (key, secret_val) in &entries {
        let prompter = MockPrompter::new(SecretString::from(secret_val.to_string()));
        let value = prompter.prompt_secret("Enter secret value: ")?;
        keyring_ops::store_secret(&keyring, profile, key, &value)?;
    }

    // Verify each secret is retrievable
    for (key, expected_val) in &entries {
        let retrieved = keyring.get_secret(profile, key)?;
        assert_eq!(retrieved.expose_secret(), *expected_val);
    }

    // Verify manifest contains both keys
    let manifest = keyring.get_manifest(profile)?;
    assert_eq!(manifest.len(), 2);
    assert!(manifest.contains(&"JIRA_TOKEN".to_string()));
    assert!(manifest.contains(&"CONFLUENCE_TOKEN".to_string()));
    Ok(())
}

/// Verify that setting the same key twice updates the value but doesn't duplicate in manifest
/// Validates: Requirements 5.1, 5.2
#[test]
fn test_end_to_end_set_flow_overwrite_existing_key() -> anyhow::Result<()> {
    let profile = "overwrite-profile";
    let key = "MY_SECRET";
    let keyring = MockKeyring::new();

    // First set
    let prompter1 = MockPrompter::new(SecretString::from("old-value".to_string()));
    let value1 = prompter1.prompt_secret("Enter secret value: ")?;
    keyring_ops::store_secret(&keyring, profile, key, &value1)?;

    // Second set with a new value
    let prompter2 = MockPrompter::new(SecretString::from("new-value".to_string()));
    let value2 = prompter2.prompt_secret("Enter secret value: ")?;
    keyring_ops::store_secret(&keyring, profile, key, &value2)?;

    // Verify the secret holds the updated value
    let retrieved = keyring.get_secret(profile, key)?;
    assert_eq!(retrieved.expose_secret(), "new-value");

    // Verify manifest has no duplicates
    let manifest = keyring.get_manifest(profile)?;
    assert_eq!(manifest, vec![key.to_string()]);
    Ok(())
}

/// Empty profile with no manifest returns empty vec
/// Validates: Requirements 7.2
#[test]
fn test_empty_profile_list_returns_empty() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    // No manifest set for "empty-profile" at all
    let result = keyring_ops::list_keys_with_healing(&keyring, "empty-profile")?;
    assert!(result.is_empty());
    Ok(())
}

/// Profile with an explicitly empty manifest returns empty vec
/// Validates: Requirements 7.2
#[test]
fn test_empty_manifest_list_returns_empty() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    keyring.set_manifest("some-profile", &[])?;
    let result = keyring_ops::list_keys_with_healing(&keyring, "some-profile")?;
    assert!(result.is_empty());
    Ok(())
}

/// Masking boundary: exactly 7 characters returns "****"
#[test]
fn test_masking_boundary_exactly_7_chars() -> anyhow::Result<()> {
    assert_eq!(mask_value("1234567"), "****");
    Ok(())
}

/// Masking boundary: exactly 8 characters returns first 7 + "...****"
#[test]
fn test_masking_boundary_exactly_8_chars() -> anyhow::Result<()> {
    assert_eq!(mask_value("12345678"), "1234567...****");
    Ok(())
}

/// Deleting a key that was never set succeeds gracefully (warning printed)
/// Validates: Requirements 14.2
#[test]
fn test_delete_key_never_set() {
    let keyring = MockKeyring::new();
    // No secrets stored at all — delete should still return Ok
    let result = keyring_ops::delete_secret(&keyring, "prof", "NONEXISTENT");
    assert!(result.is_ok());
}

/// Deleting a key present in keyring store but not in manifest succeeds
#[test]
fn test_delete_key_not_in_manifest_but_in_keyring() {
    let keyring = MockKeyring::new();
    let secret = SecretString::from("orphan-value".to_string());
    // Store directly in keyring without updating manifest
    keyring.set_secret("prof", "ORPHAN_KEY", &secret).unwrap();

    let result = keyring_ops::delete_secret(&keyring, "prof", "ORPHAN_KEY");
    assert!(result.is_ok());

    // Verify the secret is gone from the keyring
    assert!(keyring.get_secret("prof", "ORPHAN_KEY").is_err());
}
