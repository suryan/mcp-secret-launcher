//! Integration tests for the main binary of mcp-secret-launcher.

use std::process::Command;

#[test]
fn test_main_cli_help() -> anyhow::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-secret-launcher"))
        .env("DBUS_SESSION_BUS_ADDRESS", "dummy:path")
        .arg("--help")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:") || stdout.contains("mcp-secret-launcher"));
    Ok(())
}

#[test]
fn test_main_cli_run_echo() -> anyhow::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-secret-launcher"))
        .env("DBUS_SESSION_BUS_ADDRESS", "dummy:path")
        .arg("run")
        .arg("--profile")
        .arg("nonexistent-profile-for-test")
        .arg("--")
        .arg("echo")
        .arg("hello-from-test")
        .output()?;

    // It might fail because the profile doesn't exist, but it will print an error
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        assert!(stdout.contains("hello-from-test"));
    } else {
        assert!(
            stderr.contains("Keyring daemon not available")
                || stderr.contains("gnome-keyring")
                || stderr.contains("keyring")
                || stderr.contains("dbus-daemon")
        );
    }
    Ok(())
}

// Added to test the access denied exit codes
#[test]
fn test_main_cli_invalid_command() -> anyhow::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-secret-launcher"))
        .env("DBUS_SESSION_BUS_ADDRESS", "dummy:path")
        .arg("invalid-command")
        .output()?;
    assert!(!output.status.success());
    Ok(())
}
