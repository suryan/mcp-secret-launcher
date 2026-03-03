#![allow(clippy::unwrap_used, missing_docs, clippy::items_after_statements)]
use mcp_secret_launcher::cli::Command;
use mcp_secret_launcher::keyring_ops::{KeyringBackend, MockKeyring};
use mcp_secret_launcher::prompter::MockPrompter;
use mcp_secret_launcher::run_app;
use secrecy::{ExposeSecret, SecretString};

#[test]
fn test_run_app_set_get_list_delete() {
    let backend = MockKeyring::new();
    let prompter = MockPrompter::new("my-secret-val".to_string().into());

    // 1. Set
    let cmd_set = Command::Set {
        profile: "default".to_string(),
        key: "MY_KEY".to_string(),
    };
    run_app(cmd_set, &backend, &prompter, Vec::new()).unwrap();
    assert_eq!(
        backend
            .get_secret("default", "MY_KEY")
            .unwrap()
            .expose_secret(),
        "my-secret-val"
    );

    // 2. Get
    let cmd_get = Command::Get {
        profile: "default".to_string(),
        key: "MY_KEY".to_string(),
    };
    // Just ensuring it doesn't panic/error
    run_app(cmd_get, &backend, &prompter, Vec::new()).unwrap();

    // 3. List
    let cmd_list = Command::List {
        profile: "default".to_string(),
    };
    run_app(cmd_list, &backend, &prompter, Vec::new()).unwrap();

    // 4. Delete
    let cmd_delete = Command::Delete {
        profile: "default".to_string(),
        key: "MY_KEY".to_string(),
    };
    run_app(cmd_delete, &backend, &prompter, Vec::new()).unwrap();

    assert!(backend.get_secret("default", "MY_KEY").is_err());
}

#[cfg(unix)]
#[test]
fn test_run_app_run_command() {
    let backend = MockKeyring::new();
    let prompter = MockPrompter::new("val".to_string().into());

    // Test Run command with a command that immediately exits 0
    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        let cmd_run = Command::Run {
            profile: "default".to_string(),
            cmd: vec!["true".to_string()],
        };
        run_app(cmd_run, &backend, &prompter, Vec::new()).unwrap();
    });
}

#[cfg(unix)]
#[test]
fn test_run_app_aws_auth_command() {
    let mut server = mockito::Server::new();
    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 2000000000}"#)
        .create();
    let _m2 = server.mock("POST", "/device_authorization").with_status(200).with_header("content-type", "application/json").with_body(r#"{"deviceCode": "dc", "userCode": "uc", "verificationUri": "http://127.0.0.1", "expiresIn": 600, "interval": 1}"#).create();
    let _m3 = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accessToken": "mt", "expiresIn": 3600}"#)
        .create();
    let _m4 = server.mock("GET", "/federation/credentials?account_id=123&role_name=MyRole").with_status(200).with_header("content-type", "application/json").with_body(r#"{"roleCredentials": {"accessKeyId": "A", "secretAccessKey": "S", "sessionToken": "T", "expiration": 1234567890}}"#).create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let backend = MockKeyring::new();

    // Add a secret to the profile to ensure the merge loop is covered
    backend
        .set_secret(
            "default",
            "EXTRA_VAR",
            &SecretString::from("val".to_string()),
        )
        .unwrap();
    backend
        .set_manifest("default", &["EXTRA_VAR".to_string()])
        .unwrap();

    let prompter = MockPrompter::new("val".to_string().into());

    let cmd_aws = Command::AwsAuth {
        sso_url: "https://sso.example.com".to_string(),
        region: "us-east-1".to_string(),
        account_id: "123".to_string(),
        role_name: "MyRole".to_string(),
        profile: Some("default".to_string()),
        cmd: vec!["true".to_string()],
    };

    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        run_app(cmd_aws, &backend, &prompter, Vec::new()).unwrap();
    });

    // Test without profile
    let cmd_aws_no_prof = Command::AwsAuth {
        sso_url: "https://sso.example.com".to_string(),
        region: "us-east-1".to_string(),
        account_id: "123".to_string(),
        role_name: "MyRole".to_string(),
        profile: None,
        cmd: vec!["true".to_string()],
    };
    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        run_app(cmd_aws_no_prof, &backend, &prompter, Vec::new()).unwrap();
    });
}
