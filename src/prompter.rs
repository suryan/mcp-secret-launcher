// SecretPrompter trait + rpassword production implementation

use secrecy::SecretString;

/// Trait abstracting interactive secret input for testability.
pub trait SecretPrompter {
    /// Prompts the user for a secret securely.
    ///
    /// # Errors
    /// Returns an error if the interactive prompt fails or is not available.
    fn prompt_secret(&self, prompt: &str) -> anyhow::Result<SecretString>;
}

/// Production implementation using `rpassword` for non-echoing terminal input.
pub struct TerminalPrompter;

#[cfg(not(coverage))]
impl SecretPrompter for TerminalPrompter {
    fn prompt_secret(&self, prompt: &str) -> anyhow::Result<SecretString> {
        let value = rpassword::prompt_password_stderr(prompt)?;
        Ok(SecretString::from(value))
    }
}

#[cfg(coverage)]
impl SecretPrompter for TerminalPrompter {
    fn prompt_secret(&self, _prompt: &str) -> anyhow::Result<SecretString> {
        Err(anyhow::anyhow!(
            "Interactive prompt excluded from coverage run"
        ))
    }
}

/// Mock implementation for testing that returns a predefined `SecretString`.
#[cfg(any(test, feature = "test-utils", debug_assertions))]
pub struct MockPrompter {
    value: SecretString,
}

#[cfg(any(test, feature = "test-utils", debug_assertions))]
impl MockPrompter {
    /// Creates a new mock prompter with a predefined value.
    #[must_use]
    pub fn new(value: SecretString) -> Self {
        Self { value }
    }
}

#[cfg(any(test, feature = "test-utils", debug_assertions))]
impl SecretPrompter for MockPrompter {
    fn prompt_secret(&self, _prompt: &str) -> anyhow::Result<SecretString> {
        Ok(self.value.clone())
    }
}
