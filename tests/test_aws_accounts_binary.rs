#![allow(clippy::unwrap_used, missing_docs)]
//! Binary-level contract tests for `aws-accounts`: stdout carries only the JSON
//! document, everything human-facing goes to stderr, and failures leave stdout empty.
//!
//! The debug binary honours `__MCP_TEST_MOCK_URL` (never compiled into release
//! builds), so every OIDC and portal call goes to a local mockito server. A dummy
//! `DBUS_SESSION_BUS_ADDRESS` keeps the real keyring out of reach, which forces the
//! (mocked) device authorization flow.

use std::process::{Command, Output};

fn run(server_url: &str, sso_url: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mcp-secret-launcher"))
        .env("DBUS_SESSION_BUS_ADDRESS", "dummy:path")
        .env("__MCP_TEST_MOCK_URL", server_url)
        // Debug builds only: shrink the retry backoff so failures return fast.
        .env("__MCP_TEST_BACKOFF_MS", "1")
        .args([
            "aws-accounts",
            "--sso-url",
            sso_url,
            "--region",
            "us-east-1",
        ])
        .args(extra)
        .output()
        .unwrap()
}

fn mock_device_flow(server: &mut mockito::ServerGuard) -> Vec<mockito::Mock> {
    vec![
        server
            .mock("POST", "/client/register")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 4000000000}"#)
            .create(),
        server
            .mock("POST", "/device_authorization")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"deviceCode": "dc", "userCode": "UC-42", "verificationUri": "http://127.0.0.1/v", "expiresIn": 600, "interval": 0}"#)
            .create(),
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"accessToken": "bin-secret-token", "expiresIn": 3600}"#)
            .create(),
    ]
}

#[test]
fn test_binary_stdout_is_only_json() {
    let mut server = mockito::Server::new();
    let _flow = mock_device_flow(&mut server);
    let _a = server
        .mock("GET", "/assignment/accounts")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accountList": [{"accountId": "123456789012", "accountName": "dev", "emailAddress": "d@example.com"}]}"#)
        .create();
    let _r = server
        .mock("GET", "/assignment/roles")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"roleList": [{"accountId": "123456789012", "roleName": "read-only"}]}"#)
        .create();

    let out = run(&server.url(), "https://bin-ok.example.com/start", &[]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "stderr: {stderr}");
    // Exactly one line, and that line is the whole JSON document.
    assert_eq!(stdout.lines().count(), 1, "stdout: {stdout:?}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"accounts": [{
            "account_id": "123456789012",
            "account_name": "dev",
            "email": "d@example.com",
            "roles": ["read-only"]
        }]})
    );
    // The device-login prompt went to stderr, and the token went nowhere.
    assert!(stderr.contains("AWS SSO Device Authorization"), "{stderr}");
    assert!(stderr.contains("UC-42"));
    assert!(!stdout.contains("bin-secret-token"));
    assert!(!stderr.contains("bin-secret-token"));
}

#[test]
fn test_binary_failure_has_empty_stdout() {
    let mut server = mockito::Server::new();
    let _flow = mock_device_flow(&mut server);
    let _a = server
        .mock("GET", "/assignment/accounts")
        .match_query(mockito::Matcher::Any)
        .with_status(500)
        .create();

    let out = run(&server.url(), "https://bin-fail.example.com/start", &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert!(
        stderr.contains("Error:") && stderr.contains("ListAccounts"),
        "{stderr}"
    );
    assert!(!stderr.contains("bin-secret-token"));
}

#[test]
fn test_binary_unknown_account_id_fails() {
    let mut server = mockito::Server::new();
    let _flow = mock_device_flow(&mut server);
    let _a = server
        .mock("GET", "/assignment/accounts")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accountList": [{"accountId": "123456789012", "accountName": "dev"}]}"#)
        .create();

    let out = run(
        &server.url(),
        "https://bin-missing.example.com/start",
        &["--account-id", "999999999999"],
    );
    assert!(!out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert!(String::from_utf8_lossy(&out.stderr).contains("999999999999"));
}

#[test]
fn test_binary_partial_roles_exit_zero_with_warning() {
    let mut server = mockito::Server::new();
    let _flow = mock_device_flow(&mut server);
    let _a = server
        .mock("GET", "/assignment/accounts")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accountList": [{"accountId": "123456789012", "accountName": "dev"}, {"accountId": "210987654321", "accountName": "prod"}]}"#)
        .create();
    let _bad = server
        .mock("GET", "/assignment/roles")
        .match_query(mockito::Matcher::UrlEncoded(
            "account_id".into(),
            "210987654321".into(),
        ))
        .with_status(429)
        .create();
    let _ok = server
        .mock("GET", "/assignment/roles")
        .match_query(mockito::Matcher::UrlEncoded(
            "account_id".into(),
            "123456789012".into(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"roleList": [{"accountId": "123456789012", "roleName": "read-only"}]}"#)
        .create();

    let out = run(&server.url(), "https://bin-partial.example.com/start", &[]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "stderr: {stderr}");
    assert_eq!(stdout.lines().count(), 1, "stdout: {stdout:?}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim_end()).unwrap();
    assert_eq!(v["accounts"][0]["roles"], serde_json::json!(["read-only"]));
    assert!(v["accounts"][0].get("roles_error").is_none());
    assert_eq!(v["accounts"][1]["roles"], serde_json::json!([]));
    assert!(
        v["accounts"][1]["roles_error"]
            .as_str()
            .unwrap()
            .contains("HTTP 429"),
        "{stdout}"
    );
    assert!(
        stderr.contains("roles could not be listed for 1 of 2 account(s)"),
        "{stderr}"
    );
    assert!(!stdout.contains("bin-secret-token"));
}
