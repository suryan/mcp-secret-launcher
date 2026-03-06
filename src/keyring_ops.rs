// Keyring read/write/list operations + manifest management

use secrecy::{ExposeSecret, SecretString};
use std::cell::RefCell;
use std::collections::HashMap;

use crate::errors::{LauncherError, categorize};

#[cfg(target_os = "linux")]
fn check_linux_env() -> anyhow::Result<()> {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        return Err(LauncherError::KeyringUnavailable {
            daemon: "dbus-daemon (DBUS_SESSION_BUS_ADDRESS is missing)".to_string(),
        }
        .into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn check_linux_env() -> anyhow::Result<()> {
    Ok(())
}

/// Trait abstracting keyring access for testability.
pub trait KeyringBackend {
    /// Retrieves a secret from the keyring.
    fn get_secret(&self, profile: &str, key: &str) -> anyhow::Result<SecretString>;
    /// Stores an inner secret in the keyring.
    fn set_secret(&self, profile: &str, key: &str, value: &SecretString) -> anyhow::Result<()>;
    /// Deletes a secret from the keyring.
    fn delete_secret(&self, profile: &str, key: &str) -> anyhow::Result<()>;
    /// Gets the list of valid keys for a profile.
    fn get_manifest(&self, profile: &str) -> anyhow::Result<Vec<String>>;
    /// Sets the list of valid keys for a profile.
    fn set_manifest(&self, profile: &str, keys: &[String]) -> anyhow::Result<()>;
}

/// Mock implementation of `KeyringBackend` backed by `HashMap` for testing.
/// Uses `RefCell` for interior mutability since trait methods take `&self`.
pub struct MockKeyring {
    /// Mock storage for secrets map.
    pub store: RefCell<HashMap<(String, String), String>>,
    /// Mock storage for profiles manifests.
    pub manifests: RefCell<HashMap<String, Vec<String>>>,
}

impl Default for MockKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl MockKeyring {
    /// Creates a new, empty mock keyring.
    pub fn new() -> Self {
        Self {
            store: RefCell::new(HashMap::new()),
            manifests: RefCell::new(HashMap::new()),
        }
    }
}

impl KeyringBackend for MockKeyring {
    fn get_secret(&self, profile: &str, key: &str) -> anyhow::Result<SecretString> {
        let store = self.store.borrow();
        let compound_key = (profile.to_string(), key.to_string());
        match store.get(&compound_key) {
            Some(value) => Ok(SecretString::from(value.clone())),
            None => Err(LauncherError::SecretNotFound {
                profile: profile.to_string(),
                key: key.to_string(),
            }
            .into()),
        }
    }

    fn set_secret(&self, profile: &str, key: &str, value: &SecretString) -> anyhow::Result<()> {
        let mut store = self.store.borrow_mut();
        store.insert(
            (profile.to_string(), key.to_string()),
            value.expose_secret().to_string(),
        );
        Ok(())
    }

    fn delete_secret(&self, profile: &str, key: &str) -> anyhow::Result<()> {
        let mut store = self.store.borrow_mut();
        let compound_key = (profile.to_string(), key.to_string());
        if store.remove(&compound_key).is_none() {
            return Err(LauncherError::SecretNotFound {
                profile: profile.to_string(),
                key: key.to_string(),
            }
            .into());
        }
        Ok(())
    }

    fn get_manifest(&self, profile: &str) -> anyhow::Result<Vec<String>> {
        let manifests = self.manifests.borrow();
        Ok(manifests.get(profile).cloned().unwrap_or_default())
    }

    fn set_manifest(&self, profile: &str, keys: &[String]) -> anyhow::Result<()> {
        let mut manifests = self.manifests.borrow_mut();
        manifests.insert(profile.to_string(), keys.to_vec());
        Ok(())
    }
}

/// Production implementation using the `keyring` crate.
pub struct OsKeyring;

#[cfg(not(coverage))]
impl KeyringBackend for OsKeyring {
    fn get_secret(&self, profile: &str, key: &str) -> anyhow::Result<SecretString> {
        check_linux_env()?;
        let entry = keyring::Entry::new(profile, key).map_err(|e| categorize(e, profile, key))?;
        let password = entry
            .get_password()
            .map_err(|e| categorize(e, profile, key))?;
        Ok(SecretString::from(password))
    }

    fn set_secret(&self, profile: &str, key: &str, value: &SecretString) -> anyhow::Result<()> {
        check_linux_env()?;
        let entry = keyring::Entry::new(profile, key).map_err(|e| categorize(e, profile, key))?;
        entry
            .set_password(value.expose_secret())
            .map_err(|e| categorize(e, profile, key))?;
        Ok(())
    }

    fn delete_secret(&self, profile: &str, key: &str) -> anyhow::Result<()> {
        check_linux_env()?;
        let entry = keyring::Entry::new(profile, key).map_err(|e| categorize(e, profile, key))?;
        entry
            .delete_credential()
            .map_err(|e| categorize(e, profile, key))?;
        Ok(())
    }

    fn get_manifest(&self, profile: &str) -> anyhow::Result<Vec<String>> {
        check_linux_env()?;
        let user = format!("_manifest:{profile}");
        let entry = keyring::Entry::new("mcp-secret-launcher", &user)
            .map_err(|e| categorize(e, profile, "_manifest"))?;
        match entry.get_password() {
            Ok(json) => {
                let keys: Vec<String> = serde_json::from_str(&json)?;
                Ok(keys)
            }
            Err(keyring::Error::NoEntry) => Ok(Vec::new()),
            Err(e) => Err(categorize(e, profile, "_manifest").into()),
        }
    }

    fn set_manifest(&self, profile: &str, keys: &[String]) -> anyhow::Result<()> {
        check_linux_env()?;
        let user = format!("_manifest:{profile}");
        let entry = keyring::Entry::new("mcp-secret-launcher", &user)
            .map_err(|e| categorize(e, profile, "_manifest"))?;
        let json = serde_json::to_string(keys)?;
        entry
            .set_password(&json)
            .map_err(|e| categorize(e, profile, "_manifest"))?;
        Ok(())
    }
}

#[cfg(coverage)]
impl KeyringBackend for OsKeyring {
    fn get_secret(&self, _p: &str, _k: &str) -> anyhow::Result<SecretString> {
        Err(anyhow::anyhow!("dbus-daemon coverage"))
    }
    fn set_secret(&self, _p: &str, _k: &str, _v: &SecretString) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("dbus-daemon coverage"))
    }
    fn delete_secret(&self, _p: &str, _k: &str) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("dbus-daemon coverage"))
    }
    fn get_manifest(&self, _p: &str) -> anyhow::Result<Vec<String>> {
        Err(anyhow::anyhow!("dbus-daemon coverage"))
    }
    fn set_manifest(&self, _p: &str, _k: &[String]) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("dbus-daemon coverage"))
    }
}

/// Retrieves all secrets for a profile, returns vec of (`key_name`, `SecretString`).
///
/// Reads the manifest for the profile to get the list of key names, then
/// retrieves each secret from the keyring. If a manifest key is missing
/// from the keyring, the error (`SecretNotFound`) is propagated.
/// If no manifest exists, returns an empty vec (no secrets configured).
pub fn load_secrets(
    backend: &dyn KeyringBackend,
    profile: &str,
) -> anyhow::Result<Vec<(String, SecretString)>> {
    let keys = backend.get_manifest(profile)?;
    if keys.is_empty() {
        return Ok(Vec::new());
    }

    let mut secrets = Vec::with_capacity(keys.len());
    for key in keys {
        let value = backend.get_secret(profile, &key)?;
        secrets.push((key, value));
    }
    Ok(secrets)
}

/// Stores a secret in the keyring and updates the profile manifest.
///
/// Calls `set_secret` on the backend, then reads the manifest for the profile.
/// If the key is not already present in the manifest, appends it and writes
/// the updated manifest back.
pub fn store_secret(
    backend: &dyn KeyringBackend,
    profile: &str,
    key: &str,
    value: &SecretString,
) -> anyhow::Result<()> {
    backend.set_secret(profile, key, value)?;

    let mut keys = backend.get_manifest(profile)?;
    if !keys.iter().any(|k| k == key) {
        keys.push(key.to_string());
        backend.set_manifest(profile, &keys)?;
    }

    Ok(())
}

/// Removes a secret from the keyring and its key from the manifest.
///
/// Attempts to delete the secret from the keyring backend. If the keyring
/// entry is already absent (`SecretNotFound`), logs a warning to stderr
/// and continues. Any other error is propagated.
///
/// After the keyring deletion (or warning), reads the manifest, removes
/// the key name if present, and writes the updated manifest back.
pub fn delete_secret(backend: &dyn KeyringBackend, profile: &str, key: &str) -> anyhow::Result<()> {
    // Step 1: Try to delete the secret from the keyring
    match backend.delete_secret(profile, key) {
        Ok(()) => {}
        Err(err) => {
            // Check if the error is SecretNotFound (entry already absent)
            if err
                .downcast_ref::<LauncherError>()
                .is_some_and(|e| matches!(e, LauncherError::SecretNotFound { .. }))
            {
                eprintln!(
                    "Warning: keyring entry for key '{key}' in profile '{profile}' was already absent"
                );
            } else {
                return Err(err);
            }
        }
    }

    // Step 2: Read manifest, remove the key, write it back
    let mut keys = backend.get_manifest(profile)?;
    keys.retain(|k| k != key);
    backend.set_manifest(profile, &keys)?;

    Ok(())
}

/// Lists key names for a profile with self-healing: if a manifest key is missing
/// from the keyring, logs a warning and removes the stale entry from the manifest.
///
/// 1. Reads the manifest for the profile.
/// 2. If empty, prints "No keys found for profile '<profile>'" to stderr and returns empty vec.
/// 3. For each key, verifies it exists in the keyring via `get_secret`.
/// 4. If `get_secret` fails with `SecretNotFound`, logs a warning and skips the key.
/// 5. If `get_secret` fails with any other error, propagates the error.
/// 6. If any stale entries were found, writes the updated manifest (only valid keys).
/// 7. Returns the valid key names.
pub fn list_keys_with_healing(
    backend: &dyn KeyringBackend,
    profile: &str,
) -> anyhow::Result<Vec<String>> {
    let keys = backend.get_manifest(profile)?;
    if keys.is_empty() {
        eprintln!("No keys found for profile '{profile}'");
        return Ok(Vec::new());
    }

    let mut valid_keys = Vec::new();
    let mut had_stale = false;

    for key in &keys {
        match backend.get_secret(profile, key) {
            Ok(_) => {
                valid_keys.push(key.clone());
            }
            Err(err) => {
                if err
                    .downcast_ref::<LauncherError>()
                    .is_some_and(|e| matches!(e, LauncherError::SecretNotFound { .. }))
                {
                    eprintln!(
                        "Warning: stale manifest entry '{key}' for profile '{profile}' — removing"
                    );
                    had_stale = true;
                } else {
                    return Err(err);
                }
            }
        }
    }

    if had_stale {
        backend.set_manifest(profile, &valid_keys)?;
    }

    Ok(valid_keys)
}
