// SecretPrompter trait + rpassword production implementation

use secrecy::SecretString;

/// Trait abstracting interactive secret input for testability.
pub trait SecretPrompter {
    /// Prompts the user for a secret securely.
    fn prompt_secret(&self, prompt: &str) -> anyhow::Result<SecretString>;
}

/// Production implementation using `rpassword` for non-echoing terminal input.
pub struct TerminalPrompter;

impl SecretPrompter for TerminalPrompter {
    fn prompt_secret(&self, prompt: &str) -> anyhow::Result<SecretString> {
        let value = rpassword::prompt_password_stderr(prompt)?;
        Ok(SecretString::from(value))
    }
}

/// Mock implementation for testing that returns a predefined `SecretString`.
pub struct MockPrompter {
    value: SecretString,
}

impl MockPrompter {
    /// Creates a new mock prompter with a predefined value.
    pub fn new(value: SecretString) -> Self {
        Self { value }
    }
}

impl SecretPrompter for MockPrompter {
    fn prompt_secret(&self, _prompt: &str) -> anyhow::Result<SecretString> {
        Ok(self.value.clone())
    }
}
