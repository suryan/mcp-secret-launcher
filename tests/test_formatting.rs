//! Integration test to ensure code is properly formatted.
//! This ensures that `cargo test` fails if `cargo fmt -- --check` fails.

use std::process::Command;

#[test]
#[allow(clippy::panic)]
fn test_code_formatting() -> anyhow::Result<()> {
    let output = Command::new("cargo")
        .arg("fmt")
        .arg("--")
        .arg("--check")
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "Code formatting check failed.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\n\nRun 'cargo fmt' to fix."
        );
    }
    Ok(())
}
