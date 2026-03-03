#![allow(clippy::unwrap_used, missing_docs, clippy::items_after_statements)]
//! Tests for the prompter module.

//! Tests for the prompter module.

use mcp_secret_launcher::prompter::*;
use secrecy::{ExposeSecret, SecretString};

#[test]
fn test_mock_prompter_returns_predefined_value() -> anyhow::Result<()> {
    let secret = SecretString::from("test-token-123".to_string());
    let prompter = MockPrompter::new(secret);

    let result = prompter.prompt_secret("Enter secret: ")?;
    assert_eq!(result.expose_secret(), "test-token-123");
    Ok(())
}

#[test]
fn test_mock_prompter_ignores_prompt_text() -> anyhow::Result<()> {
    let secret = SecretString::from("my-secret".to_string());
    let prompter = MockPrompter::new(secret);

    let r1 = prompter.prompt_secret("Prompt A: ")?;
    let r2 = prompter.prompt_secret("Prompt B: ")?;
    assert_eq!(r1.expose_secret(), r2.expose_secret());
    Ok(())
}
