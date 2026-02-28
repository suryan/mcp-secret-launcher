//! Tests for the `keyring_ops` module.


use mcp_secret_launcher::errors::LauncherError;
use mcp_secret_launcher::keyring_ops::*;
use proptest::prelude::*;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::collections::HashSet;

#[test]
fn test_mock_keyring_set_and_get_secret() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    let secret = SecretString::from("my-token-value".to_string());
    keyring.set_secret("myprofile", "API_KEY", &secret)?;

    let retrieved = keyring.get_secret("myprofile", "API_KEY")?;
    assert_eq!(retrieved.expose_secret(), "my-token-value");
    Ok(())
}

#[test]
fn test_mock_keyring_get_secret_not_found() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    let result = keyring.get_secret("myprofile", "MISSING_KEY");
    assert!(result.is_err());
    let Err(err) = result else { return Err(anyhow::anyhow!("Expected error")) };
    let msg = err.to_string();
    assert!(msg.contains("myprofile"));
    assert!(msg.contains("MISSING_KEY"));
    Ok(())
}

#[test]
fn test_mock_keyring_delete_secret_existing() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    let secret = SecretString::from("value".to_string());
    keyring.set_secret("prof", "KEY", &secret)?;
    keyring.delete_secret("prof", "KEY")?;

    let result = keyring.get_secret("prof", "KEY");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_mock_keyring_delete_secret_nonexistent_returns_error() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    // Deleting a key that doesn't exist should return SecretNotFound
    let result = keyring.delete_secret("prof", "NOPE");
    assert!(result.is_err());
    let Err(err) = result else { return Err(anyhow::anyhow!("Expected error")) };
    assert!(
        err.downcast_ref::<LauncherError>()
            .is_some_and(|e| { matches!(e, LauncherError::SecretNotFound { .. }) })
    );
    Ok(())
}

#[test]
fn test_mock_keyring_manifest_round_trip() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    let keys = vec!["KEY_A".to_string(), "KEY_B".to_string()];
    keyring.set_manifest("myprofile", &keys)?;

    let retrieved = keyring.get_manifest("myprofile")?;
    assert_eq!(retrieved, keys);
    Ok(())
}

#[test]
fn test_mock_keyring_get_manifest_empty_when_missing() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    let result = keyring.get_manifest("nonexistent")?;
    assert!(result.is_empty());
    Ok(())
}

#[test]
fn test_mock_keyring_set_manifest_overwrites() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    keyring.set_manifest("prof", &["A".to_string()])?;
    keyring
        .set_manifest("prof", &["B".to_string(), "C".to_string()])
        ?;

    let retrieved = keyring.get_manifest("prof")?;
    assert_eq!(retrieved, vec!["B".to_string(), "C".to_string()]);
    Ok(())
}

#[test]
fn test_load_secrets_returns_all_secrets() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    let s1 = SecretString::from("val1".to_string());
    let s2 = SecretString::from("val2".to_string());
    keyring.set_secret("prof", "KEY_A", &s1)?;
    keyring.set_secret("prof", "KEY_B", &s2)?;
    keyring
        .set_manifest("prof", &["KEY_A".to_string(), "KEY_B".to_string()])
        ?;

    let secrets = load_secrets(&keyring, "prof")?;
    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[0].0, "KEY_A");
    assert_eq!(secrets[0].1.expose_secret(), "val1");
    assert_eq!(secrets[1].0, "KEY_B");
    assert_eq!(secrets[1].1.expose_secret(), "val2");
    Ok(())
}

#[test]
fn test_load_secrets_empty_when_no_manifest() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    let secrets = load_secrets(&keyring, "nonexistent")?;
    assert!(secrets.is_empty());
    Ok(())
}

#[test]
fn test_load_secrets_fails_on_missing_secret() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    // Manifest says KEY_X exists, but it's not in the store
    keyring
        .set_manifest("prof", &["KEY_X".to_string()])
        ?;

    let result = load_secrets(&keyring, "prof");
    assert!(result.is_err());
    let Err(err) = result else { return Err(anyhow::anyhow!("Expected error")) };
    let msg = err.to_string();
    assert!(msg.contains("KEY_X"));
    assert!(msg.contains("prof"));
    Ok(())
}

#[test]
fn test_delete_secret_removes_from_keyring_and_manifest() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    let secret = SecretString::from("token123".to_string());
    store_secret(&keyring, "prof", "MY_KEY", &secret)?;

    // Verify it's stored
    assert!(keyring.get_secret("prof", "MY_KEY").is_ok());
    assert!(
        keyring
            .get_manifest("prof")
            ?
            .contains(&"MY_KEY".to_string())
    );

    // Delete it
    delete_secret(&keyring, "prof", "MY_KEY")?;

    // Verify removed from keyring
    assert!(keyring.get_secret("prof", "MY_KEY").is_err());
    // Verify removed from manifest
    assert!(
        !keyring
            .get_manifest("prof")
            ?
            .contains(&"MY_KEY".to_string())
    );
    Ok(())
}

#[test]
fn test_delete_secret_already_absent_still_removes_from_manifest() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    // Manually set a manifest entry without a corresponding secret
    keyring
        .set_manifest("prof", &["GHOST_KEY".to_string()])
        ?;

    // delete_secret should succeed (warning logged to stderr) and clean up manifest
    delete_secret(&keyring, "prof", "GHOST_KEY")?;

    // Manifest should no longer contain the key
    assert!(
        !keyring
            .get_manifest("prof")
            ?
            .contains(&"GHOST_KEY".to_string())
    );
    Ok(())
}

#[test]
fn test_delete_secret_key_not_in_manifest_is_ok() -> anyhow::Result<()> {
    let keyring = MockKeyring::new();
    let secret = SecretString::from("val".to_string());
    // Store a secret directly in the keyring store (bypassing manifest)
    keyring.set_secret("prof", "ORPHAN", &secret)?;
    keyring.set_manifest("prof", &[])?;

    // Delete should remove from keyring, manifest stays empty
    delete_secret(&keyring, "prof", "ORPHAN")?;
    assert!(keyring.get_secret("prof", "ORPHAN").is_err());
    assert!(keyring.get_manifest("prof")?.is_empty());
    Ok(())
}

// Feature: mcp-secret-launcher, Property 1: Secret injection maps key names to environment variables
// **Validates: Requirements 1.1, 1.2, 2.1, 2.2**
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_secret_injection_maps_key_names_to_env_vars(
        profile in "[a-zA-Z0-9]{1,20}",
        entries in prop::collection::hash_map(
            "[a-zA-Z][a-zA-Z0-9_]{0,19}",
            "[a-zA-Z0-9]{1,30}",
            1..=10
        )
    ) {
        let keyring = MockKeyring::new();

        // Populate the MockKeyring store and manifest with the generated entries
        let key_names: Vec<String> = entries.keys().cloned().collect();
        for (key, value) in &entries {
            let secret = SecretString::from(value.clone());
            if keyring.set_secret(&profile, key, &secret).is_err() { return Err(proptest::test_runner::TestCaseError::fail("operation failed")); }
        }
        if keyring.set_manifest(&profile, &key_names).is_err() { return Err(proptest::test_runner::TestCaseError::fail("operation failed")); }

        // Call load_secrets and verify the result
        let Ok(secrets) = load_secrets(&keyring, &profile) else { return Err(proptest::test_runner::TestCaseError::fail("secrets failed")); };

        // Verify exactly N entries
        prop_assert_eq!(secrets.len(), entries.len());

        // Collect results into a HashMap for easy comparison
        let result_map: HashMap<String, String> = secrets
            .into_iter()
            .map(|(k, v)| (k, v.expose_secret().to_string()))
            .collect();

        // Verify each entry has the correct key name and value
        for (key, expected_value) in &entries {
            prop_assert!(
                result_map.contains_key(key),
                "Missing key '{}' in load_secrets result", key
            );
            if let Some(val) = result_map.get(key) {
                prop_assert_eq!(
                    val,
                    expected_value,
                    "Value mismatch for key '{}'", key
                );
            } else {
                prop_assert!(false, "result_map missing key");
            }
        }
    }

    // Feature: mcp-secret-launcher, Property 8: Missing secret error identifies the key name
    // **Validates: Requirements 1.3, 6.3**
    #[test]
    fn prop_missing_secret_error_identifies_key_name(
        profile in "[a-zA-Z][a-zA-Z0-9]{0,19}",
        key in "[a-zA-Z][a-zA-Z0-9_]{0,19}",
    ) {
        let keyring = MockKeyring::new();
        // Set up a manifest that includes the key, but do NOT store the secret
        if keyring.set_manifest(&profile, std::slice::from_ref(&key)).is_err() { return Err(proptest::test_runner::TestCaseError::fail("operation failed")); }

        // load_secrets should fail because the key is in the manifest but missing from the keyring
        let result = load_secrets(&keyring, &profile);
        prop_assert!(result.is_err(), "Expected error for missing secret, but got Ok");

        let Err(e) = result else { return Err(proptest::test_runner::TestCaseError::fail("Expected error")); };
        let err_msg = e.to_string();
        prop_assert!(
            err_msg.contains(&profile),
            "Error message '{}' should contain profile name '{}'", err_msg, profile
        );
        prop_assert!(
            err_msg.contains(&key),
            "Error message '{}' should contain key name '{}'", err_msg, key
        );
    }

    // Feature: mcp-secret-launcher, Property 2: Set-then-get round trip
    // **Validates: Requirements 5.2, 6.1**
    #[test]
    fn prop_set_then_get_round_trip(
        profile in "[a-zA-Z0-9]{1,20}",
        key in "[a-zA-Z][a-zA-Z0-9_]{0,19}",
        secret_value in "[a-zA-Z0-9]{1,30}",
    ) {
        let keyring = MockKeyring::new();
        let secret = SecretString::from(secret_value.clone());
        // Store the secret via store_secret (which also updates the manifest)
        if store_secret(&keyring, &profile, &key, &secret).is_err() { return Err(proptest::test_runner::TestCaseError::fail("operation failed")); }

        // Retrieve the secret via get_secret on the backend
        let Ok(retrieved) = keyring.get_secret(&profile, &key) else { return Err(proptest::test_runner::TestCaseError::fail("retrieved failed")); };

        // Verify the returned value matches the original
        prop_assert_eq!(
            retrieved.expose_secret(),
            &secret_value,
            "Round-trip failed: stored '{}' but got '{}'", secret_value, retrieved.expose_secret()
        );
    }

    // Feature: mcp-secret-launcher, Property 6: Manifest round trip — set updates, list reads back
    // **Validates: Requirements 7.1**
    #[test]
    fn prop_manifest_round_trip(
        profile in "[a-zA-Z0-9]{1,20}",
        key_names in prop::collection::hash_set("[a-zA-Z][a-zA-Z0-9_]{0,19}", 1..=10),
    ) {
        let keyring = MockKeyring::new();
        let dummy_secret = SecretString::from("secret_value".to_string());
        // For each key name, call store_secret (which updates the manifest)
        for key in &key_names {
            if store_secret(&keyring, &profile, key, &dummy_secret).is_err() { return Err(proptest::test_runner::TestCaseError::fail("operation failed")); }
        }

        // Read the manifest back
        let Ok(manifest) = keyring.get_manifest(&profile) else { return Err(proptest::test_runner::TestCaseError::fail("manifest failed")); };

        // Verify the manifest contains exactly those key names (same count)
        prop_assert_eq!(
            manifest.len(),
            key_names.len(),
            "Manifest has {} entries but expected {}", manifest.len(), key_names.len()
        );

        // Verify no duplicates in the manifest
        let manifest_set: HashSet<String> = manifest.iter().cloned().collect();
        prop_assert_eq!(
            manifest_set.len(),
            manifest.len(),
            "Manifest contains duplicates: {:?}", manifest
        );

        // Verify every generated key is present in the manifest
        for key in &key_names {
            prop_assert!(
                manifest_set.contains(key),
                "Key '{}' missing from manifest. Manifest: {:?}", key, manifest
            );
        }
    }

    // Feature: mcp-secret-launcher, Property 11: Delete round trip — set then delete removes from both keyring and manifest
    // **Validates: Requirements 14.1, 14.2**
    #[test]
    fn prop_delete_round_trip(
        profile in "[a-zA-Z0-9]{1,20}",
        key in "[a-zA-Z][a-zA-Z0-9_]{0,19}",
        secret_value in "[a-zA-Z0-9]{1,30}",
    ) {
        let keyring = MockKeyring::new();
        let secret = SecretString::from(secret_value);
        // Store the secret via store_secret (updates both keyring and manifest)
        if store_secret(&keyring, &profile, &key, &secret).is_err() { return Err(proptest::test_runner::TestCaseError::fail("operation failed")); }

        // Delete the secret via delete_secret (removes from both keyring and manifest)
        if delete_secret(&keyring, &profile, &key).is_err() { return Err(proptest::test_runner::TestCaseError::fail("operation failed")); }

        // Verify get_secret returns an error (key no longer in keyring)
        let get_result = keyring.get_secret(&profile, &key);
        prop_assert!(
            get_result.is_err(),
            "Expected get_secret to return error after delete, but got Ok for key '{}'", key
        );

        // Verify manifest does not contain the key
        let Ok(manifest) = keyring.get_manifest(&profile) else { return Err(proptest::test_runner::TestCaseError::fail("manifest failed")); };
        prop_assert!(
            !manifest.contains(&key),
            "Manifest should not contain key '{}' after delete, but found: {:?}", key, manifest
        );
    }

    // Feature: mcp-secret-launcher, Property 12: List self-healing removes stale manifest entries
    // **Validates: Requirements 14.3**
    #[test]
    fn prop_list_self_healing_removes_stale_manifest_entries(
        profile in "[a-zA-Z0-9]{1,20}",
        key_names in prop::collection::hash_set("[a-zA-Z][a-zA-Z0-9_]{0,19}", 2..=10),
        removal_seed in prop::collection::vec(any::<bool>(), 2..=10),
    ) {
        let keyring = MockKeyring::new();
        let dummy_value = SecretString::from("testvalue".to_string());

        let keys_vec: Vec<String> = key_names.iter().cloned().collect();
        // Step 4: For each key, call store_secret to populate both store and manifest
        for key in &keys_vec {
            if store_secret(&keyring, &profile, key, &dummy_value).is_err() { return Err(proptest::test_runner::TestCaseError::fail("operation failed")); }
        }

        // Step 5: Generate a random subset of keys to remove (at least 1, at most N-1)
        // Use the removal_seed booleans to decide which keys to remove,
        // but ensure at least 1 removed and at least 1 kept.
        let n = keys_vec.len();
        let mut to_remove: Vec<bool> = removal_seed.iter().cycle().take(n).copied().collect();

        // Count how many are marked for removal
        let remove_count = to_remove.iter().filter(|&&b| b).count();
        if remove_count == 0 {
            // Force at least one removal
            to_remove[0] = true;
        } else if remove_count == n {
            // Keep at least one key valid
            to_remove[0] = false;
        }

        let mut removed_keys: HashSet<String> = HashSet::new();
        let mut kept_keys: HashSet<String> = HashSet::new();

        for (i, key) in keys_vec.iter().enumerate() {
            if to_remove[i] {
                // Step 6: Directly remove from MockKeyring store WITHOUT updating manifest
                keyring.store.borrow_mut().remove(&(profile.clone(), key.clone()));
                removed_keys.insert(key.clone());
            } else {
                kept_keys.insert(key.clone());
            }
        }

        // Step 7: Call list_keys_with_healing
        let Ok(result) = list_keys_with_healing(&keyring, &profile) else { return Err(proptest::test_runner::TestCaseError::fail("result failed")); };

        // Step 8: Verify the returned list contains only the keys that were NOT removed
        let result_set: HashSet<String> = result.iter().cloned().collect();
        prop_assert_eq!(
            &result_set,
            &kept_keys,
            "Returned keys should match kept keys. Got: {:?}, Expected: {:?}", result_set, kept_keys
        );

        // Verify no removed keys are in the result
        for removed in &removed_keys {
            prop_assert!(
                !result_set.contains(removed),
                "Removed key '{}' should not be in the result", removed
            );
        }

        // Step 9: Verify the manifest now matches the returned list (stale entries removed)
        let Ok(manifest_after) = keyring.get_manifest(&profile) else { return Err(proptest::test_runner::TestCaseError::fail("manifest_after failed")); };
        let manifest_set: HashSet<String> = manifest_after.iter().cloned().collect();
        prop_assert_eq!(
            &manifest_set,
            &kept_keys,
            "Manifest should match kept keys after healing. Got: {:?}, Expected: {:?}", manifest_set, kept_keys
        );
    }
}
