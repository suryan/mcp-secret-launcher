//! Tests for the errors module.


use mcp_secret_launcher::errors::*;
use proptest::prelude::*;

#[test]
fn test_secret_not_found_display() {
    let err = LauncherError::SecretNotFound {
        profile: "myprofile".to_string(),
        key: "MY_KEY".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("myprofile"));
    assert!(msg.contains("MY_KEY"));
    assert!(msg.contains("mcp-secret-launcher set --profile myprofile --key MY_KEY"));
}

#[test]
fn test_keyring_locked_display() {
    let err = LauncherError::KeyringLocked;
    let msg = err.to_string();
    assert!(msg.contains("locked"));
    assert!(msg.contains("Unlock"));
}

#[test]
fn test_keyring_unavailable_display() {
    let err = LauncherError::KeyringUnavailable {
        daemon: "gnome-keyring-daemon".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("gnome-keyring-daemon"));
    assert!(msg.contains("Ensure"));
}

#[test]
fn test_insufficient_permissions_display() {
    let err = LauncherError::InsufficientPermissions;
    let msg = err.to_string();
    assert!(msg.contains("permissions"));
}

#[test]
fn test_exec_failed_display() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
    let err = LauncherError::ExecFailed {
        command: "uvx".to_string(),
        source: io_err,
    };
    let msg = err.to_string();
    assert!(msg.contains("uvx"));
    assert!(msg.contains("not found"));
}

#[test]
fn test_stale_manifest_entry_display() {
    let err = LauncherError::StaleManifestEntry {
        profile: "prod".to_string(),
        key: "API_TOKEN".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("prod"));
    assert!(msg.contains("API_TOKEN"));
    assert!(msg.contains("mcp-secret-launcher set --profile prod --key API_TOKEN"));
}

#[test]
fn test_categorize_no_entry() {
    let result = categorize(keyring::Error::NoEntry, "prof", "key1");
    match result {
        LauncherError::SecretNotFound { profile, key } => {
            assert_eq!(profile, "prof");
            assert_eq!(key, "key1");
        }
        _ => panic!("Expected SecretNotFound, got {result:?}"),
    }
}

#[test]
fn test_categorize_no_storage_access_defaults_to_locked() {
    let inner = std::io::Error::other("keyring is locked");
    let err = keyring::Error::NoStorageAccess(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::KeyringLocked));
}

#[test]
fn test_categorize_no_storage_access_permission() {
    let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
    let err = keyring::Error::NoStorageAccess(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::InsufficientPermissions));
}

#[test]
fn test_categorize_platform_failure_dbus() {
    let inner = std::io::Error::other("dbus connection failed");
    let err = keyring::Error::PlatformFailure(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::KeyringUnavailable { .. }));
}

#[test]
fn test_categorize_platform_failure_permission() {
    let inner = std::io::Error::other("permission denied by system");
    let err = keyring::Error::PlatformFailure(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::InsufficientPermissions));
}

#[test]
fn test_categorize_platform_failure_lock() {
    let inner = std::io::Error::other("auth required to unlock");
    let err = keyring::Error::PlatformFailure(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::KeyringLocked));
}

#[test]
fn test_categorize_other_errors_default_to_unavailable() {
    let err = keyring::Error::BadEncoding(vec![0xFF]);
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::KeyringUnavailable { .. }));
}

// Feature: mcp-secret-launcher, Property 9: Error messages contain structured information
// **Validates: Requirements 12.2**
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_secret_not_found_contains_context_and_remediation(
        profile in "[a-zA-Z0-9_-]{1,30}",
        key in "[a-zA-Z0-9_]{1,30}",
    ) {
        let err = LauncherError::SecretNotFound {
            profile: profile.clone(),
            key: key.clone(),
        };
        let msg = err.to_string();
        // Operation context: contains profile and key
        prop_assert!(msg.contains(&profile), "Message should contain profile '{}': {}", profile, msg);
        prop_assert!(msg.contains(&key), "Message should contain key '{}': {}", key, msg);
        // Remediation: contains the command to run
        prop_assert!(msg.contains("mcp-secret-launcher set"), "Message should contain remediation command: {}", msg);
    }

    #[test]
    fn prop_keyring_locked_contains_context_and_remediation(
        _dummy in 0..1u8,
    ) {
        let err = LauncherError::KeyringLocked;
        let msg = err.to_string();
        // Operation context: identifies the locked state
        prop_assert!(msg.to_lowercase().contains("locked"), "Message should contain 'locked': {}", msg);
        // Remediation: suggests unlocking
        prop_assert!(msg.contains("Unlock"), "Message should contain 'Unlock' remediation: {}", msg);
    }

    #[test]
    fn prop_keyring_unavailable_contains_context_and_remediation(
        daemon in "[a-zA-Z0-9_-]{1,30}",
    ) {
        let err = LauncherError::KeyringUnavailable {
            daemon: daemon.clone(),
        };
        let msg = err.to_string();
        // Operation context: contains daemon name
        prop_assert!(msg.contains(&daemon), "Message should contain daemon '{}': {}", daemon, msg);
        // Remediation: suggests ensuring daemon is running
        prop_assert!(msg.contains("Ensure"), "Message should contain 'Ensure' remediation: {}", msg);
    }

    #[test]
    fn prop_insufficient_permissions_contains_context_and_remediation(
        _dummy in 0..1u8,
    ) {
        let err = LauncherError::InsufficientPermissions;
        let msg = err.to_string();
        // Operation context and remediation: mentions permissions
        prop_assert!(msg.to_lowercase().contains("permissions"), "Message should contain 'permissions': {}", msg);
    }

    #[test]
    fn prop_exec_failed_contains_context_and_remediation(
        command in "[a-zA-Z0-9_/.-]{1,30}",
    ) {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "command not found");
        let err = LauncherError::ExecFailed {
            command: command.clone(),
            source: io_err,
        };
        let msg = err.to_string();
        // Operation context: contains the command that failed
        prop_assert!(msg.contains(&command), "Message should contain command '{}': {}", command, msg);
    }

    #[test]
    fn prop_stale_manifest_entry_contains_context_and_remediation(
        profile in "[a-zA-Z0-9_-]{1,30}",
        key in "[a-zA-Z0-9_]{1,30}",
    ) {
        let err = LauncherError::StaleManifestEntry {
            profile: profile.clone(),
            key: key.clone(),
        };
        let msg = err.to_string();
        // Operation context: contains profile and key
        prop_assert!(msg.contains(&profile), "Message should contain profile '{}': {}", profile, msg);
        prop_assert!(msg.contains(&key), "Message should contain key '{}': {}", key, msg);
        // Remediation: contains the command to run
        prop_assert!(msg.contains("mcp-secret-launcher set"), "Message should contain remediation command: {}", msg);
    }
}
