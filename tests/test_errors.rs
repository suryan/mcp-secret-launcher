#![allow(clippy::unwrap_used, missing_docs, clippy::items_after_statements, clippy::panic)]
//! Tests for the `LauncherError` enum and its categorization logic.

use mcp_secret_launcher::errors::{LauncherError, categorize};
use proptest::prelude::*;

#[test]
fn test_categorize_no_entry() {
    let err = keyring::Error::NoEntry;
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::SecretNotFound { .. }));
}

#[test]
fn test_categorize_no_storage_access_defaults_to_locked() {
    let inner = std::io::Error::other("locked");
    let err = keyring::Error::NoStorageAccess(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::KeyringLocked));
}

#[test]
fn test_categorize_no_storage_access_permission() {
    let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let err = keyring::Error::NoStorageAccess(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::InsufficientPermissions));
}

#[test]
fn test_categorize_platform_failure_gnome_keyring() {
    let inner = std::io::Error::other("gnome-keyring-daemon: not running");
    let err = keyring::Error::PlatformFailure(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::KeyringUnavailable { .. }));
}

#[test]
fn test_categorize_platform_failure_dbus() {
    let inner = std::io::Error::other("DBus error");
    let err = keyring::Error::PlatformFailure(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::KeyringUnavailable { .. }));
}

#[test]
fn test_categorize_platform_failure_generic() {
    let inner = std::io::Error::other("Generic IO error");
    let err = keyring::Error::PlatformFailure(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::KeyringUnavailable { .. }));
}

#[test]
fn test_launcher_error_display() {
    let err = LauncherError::SecretNotFound {
        profile: "p".to_string(),
        key: "k".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains('p'));
    assert!(msg.contains('k'));
}

#[test]
fn test_keyring_locked_display() {
    let err = LauncherError::KeyringLocked;
    let msg = format!("{err}");
    assert!(msg.contains("locked"));
}

#[test]
fn test_keyring_unavailable_display() {
    let err = LauncherError::KeyringUnavailable {
        daemon: "d".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains('d'));
}

#[test]
fn test_insufficient_permissions_display() {
    let err = LauncherError::InsufficientPermissions;
    let msg = format!("{err}");
    assert!(msg.contains("permissions"));
}

#[test]
fn test_exec_failed_display() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "fail");
    let err = LauncherError::ExecFailed {
        command: "cmd".to_string(),
        source: io_err,
    };
    let msg = format!("{err}");
    assert!(msg.contains("cmd"));
}

#[test]
fn test_categorize_platform_failure_auth_failed() {
    let inner = std::io::Error::other("Authentication failed");
    let err = keyring::Error::PlatformFailure(Box::new(inner));
    let res = categorize(err, "p", "k");
    assert!(matches!(res, LauncherError::KeyringLocked));
}

#[test]
fn test_categorize_platform_failure_no_daemon() {
    let inner = std::io::Error::other("Daemon not running");
    let err = keyring::Error::PlatformFailure(Box::new(inner));
    let res = categorize(err, "p", "k");
    if let LauncherError::KeyringUnavailable { daemon } = res {
        if cfg!(target_os = "linux") {
            assert!(daemon.contains("keyring-daemon"));
        } else {
            assert_eq!(daemon, "keyring service");
        }
    } else {
        panic!("Expected KeyringUnavailable error");
    }
}

#[test]
fn test_categorize_platform_failure_dbus_org_freedesktop() {
    let inner = std::io::Error::other(
        "The name org.freedesktop.secrets was not provided by any .service files",
    );
    let err = keyring::Error::PlatformFailure(Box::new(inner));
    let result = categorize(err, "prof", "key1");
    // This should match KeyringUnavailable
    assert!(matches!(result, LauncherError::KeyringUnavailable { .. }));
}

#[test]
fn test_detect_daemon_fallback() {
    // "generic error" doesn't match daemon, dbus, auth, etc., so it hits the default branch
    let err = keyring::Error::PlatformFailure(Box::new(std::io::Error::other("generic error")));
    let result = categorize(err, "prof", "key1");
    assert!(matches!(result, LauncherError::KeyringUnavailable { .. }));
}

#[test]
fn test_from_io_error_to_launcher_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "fail");
    let err = LauncherError::from(io_err);
    assert!(matches!(err, LauncherError::InsufficientPermissions));
}

#[test]
fn test_from_io_error_generic() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "fail");
    let err = LauncherError::from(io_err);
    assert!(matches!(err, LauncherError::KeyringUnavailable { .. }));
}

#[test]
fn test_from_stale_manifest_error() {
    let err = LauncherError::StaleManifestEntry {
        profile: "p".to_string(),
        key: "k".to_string(),
    };
    let _ = err.to_string();
}

#[test]
fn test_launcher_error_debug() {
    let err = LauncherError::KeyringLocked;
    let _ = format!("{err:?}");
}

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
