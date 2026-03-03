// Error types and categorization for mcp-secret-launcher

use thiserror::Error;

/// The primary error type for the secret launcher operations.
#[derive(Error, Debug)]
pub enum LauncherError {
    /// Indicates a specific secret was not found in the keyring.
    #[error(
        "Secret '{key}' not found for profile '{profile}'. Run: mcp-secret-launcher set --profile {profile} --key {key}"
    )]
    SecretNotFound {
        /// The profile the secret belongs to.
        profile: String,
        /// The key of the missing secret.
        key: String,
    },

    /// Indicates the underlying keyring is locked and user authentication is required.
    #[error("Keyring is locked or requires authentication. Unlock your keyring and retry.")]
    KeyringLocked,

    /// Indicates the keyring daemon service is not running or accessible.
    #[error("Keyring daemon not available. Ensure {daemon} is running.")]
    KeyringUnavailable {
        /// The expected daemon name based on the OS.
        daemon: String,
    },

    /// Indicates the program lacks permissions to read from the keyring.
    #[error("Insufficient permissions to access keyring. Check your user permissions.")]
    InsufficientPermissions,

    /// Indicates the target command failed to execute.
    #[error("Failed to execute '{command}': {source}")]
    ExecFailed {
        /// The command that was attempted.
        command: String,
        /// The underlying IO error.
        source: std::io::Error,
    },

    /// Indicates a discrepancy between the manifest file and the actual keyring contents.
    #[error(
        "Secret '{key}' listed in manifest for profile '{profile}' but missing from keyring. Run: mcp-secret-launcher set --profile {profile} --key {key}"
    )]
    StaleManifestEntry {
        /// The profile for the stale secret.
        profile: String,
        /// The key for the stale secret.
        key: String,
    },
}

impl From<std::io::Error> for LauncherError {
    fn from(value: std::io::Error) -> Self {
        match value.kind() {
            std::io::ErrorKind::PermissionDenied => LauncherError::InsufficientPermissions,
            _ => LauncherError::KeyringUnavailable {
                daemon: detect_daemon(),
            },
        }
    }
}

/// Maps a `keyring` crate error to the appropriate `LauncherError` variant,
/// using the provided profile and key as context for the error message.
#[allow(clippy::needless_pass_by_value)]
pub fn categorize(err: keyring::Error, profile: &str, key: &str) -> LauncherError {
    match err {
        keyring::Error::NoEntry => LauncherError::SecretNotFound {
            profile: profile.to_string(),
            key: key.to_string(),
        },
        keyring::Error::NoStorageAccess(ref inner) => {
            let msg = inner.to_string().to_lowercase();
            if msg.contains("permission") || msg.contains("denied") || msg.contains("access") {
                LauncherError::InsufficientPermissions
            } else {
                // Storage access failures typically mean the keyring is locked
                LauncherError::KeyringLocked
            }
        }
        keyring::Error::PlatformFailure(ref inner) => {
            let msg = inner.to_string().to_lowercase();
            if msg.contains("dbus")
                || msg.contains("d-bus")
                || msg.contains("daemon")
                || msg.contains("service")
                || msg.contains("connection")
            {
                LauncherError::KeyringUnavailable {
                    daemon: detect_daemon(),
                }
            } else if msg.contains("permission") || msg.contains("denied") {
                LauncherError::InsufficientPermissions
            } else if msg.contains("lock") || msg.contains("auth") || msg.contains("unlock") {
                LauncherError::KeyringLocked
            } else {
                // Default platform failures to unavailable with daemon hint
                LauncherError::KeyringUnavailable {
                    daemon: detect_daemon(),
                }
            }
        }
        // All other keyring errors map to unavailable as a safe default
        _ => LauncherError::KeyringUnavailable {
            daemon: detect_daemon(),
        },
    }
}

/// Returns the platform-appropriate keyring daemon name for error messages.
fn detect_daemon() -> String {
    if cfg!(target_os = "linux") {
        "gnome-keyring-daemon".to_string()
    } else if cfg!(target_os = "macos") {
        "security service (Keychain)".to_string()
    } else if cfg!(target_os = "windows") {
        "Credential Manager service".to_string()
    } else {
        "keyring service".to_string()
    }
}
