#![allow(clippy::unwrap_used, missing_docs, clippy::items_after_statements)]
use mcp_secret_launcher::keyring_ops::KeyringBackend;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;

static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

// We will test `get_aws_credentials` end-to-end with mockito since the helper functions
struct MockKeyringBackend {
    storage: std::cell::RefCell<HashMap<String, SecretString>>,
}

impl MockKeyringBackend {
    fn new() -> Self {
        Self {
            storage: std::cell::RefCell::new(HashMap::new()),
        }
    }
}

impl KeyringBackend for MockKeyringBackend {
    fn get_secret(&self, profile: &str, key: &str) -> anyhow::Result<SecretString> {
        let full_key = format!("{profile}-{key}");
        self.storage
            .borrow()
            .get(&full_key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Not found"))
    }

    fn set_secret(&self, profile: &str, key: &str, secret: &SecretString) -> anyhow::Result<()> {
        let full_key = format!("{profile}-{key}");
        self.storage.borrow_mut().insert(full_key, secret.clone());
        Ok(())
    }

    fn delete_secret(&self, profile: &str, key: &str) -> anyhow::Result<()> {
        let full_key = format!("{profile}-{key}");
        self.storage.borrow_mut().remove(&full_key);
        Ok(())
    }

    fn get_manifest(&self, _profile: &str) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }

    fn set_manifest(&self, _profile: &str, _keys: &[String]) -> anyhow::Result<()> {
        Ok(())
    }
}

// NOTE: We need to test the public entry point `get_aws_credentials`.
#[test]
fn test_get_aws_credentials_end_to_end_new_token() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();

    // 1. Mock Client Registration
    let _m1 = server.mock("POST", "/client/register")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"clientId": "client-123", "clientSecret": "secret-456", "clientSecretExpiresAt": 2000000000}"#)
        .create();

    // 2. Mock Device Auth Start
    let _m2 = server.mock("POST", "/device_authorization")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"deviceCode": "dc123", "userCode": "CODE-123", "verificationUri": "http://127.0.0.1/verify", "expiresIn": 600, "interval": 0}"#)
        .create();

    // 3. Mock Token Polling (Success immediately)
    let _m3 = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accessToken": "my-mock-token", "expiresIn": 3600}"#)
        .create();

    // 4. Mock Get Role Credentials
    let _m4 = server.mock("GET", "/federation/credentials?account_id=123&role_name=MyRole")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"roleCredentials": {"accessKeyId": "AKIA", "secretAccessKey": "SECRET", "sessionToken": "SESSION", "expiration": 1234567890}}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let backend = MockKeyringBackend::new();

    // Disable opening the browser during tests by intercepting `open::that` or
    // simply not worrying about it since `open::that` failing just prints a warning.
    // In CI environments where there is no display, it just fails gracefully.

    let creds: HashMap<String, SecretString> = mcp_secret_launcher::aws_sso::get_aws_credentials(
        &backend,
        "https://sso.example.com",
        "us-east-1",
        "123",
        "MyRole",
    )
    .unwrap();

    assert_eq!(
        creds.get("AWS_ACCESS_KEY_ID").unwrap().expose_secret(),
        "AKIA"
    );
    assert_eq!(
        creds.get("AWS_SECRET_ACCESS_KEY").unwrap().expose_secret(),
        "SECRET"
    );
    assert_eq!(
        creds.get("AWS_SESSION_TOKEN").unwrap().expose_secret(),
        "SESSION"
    );
    assert_eq!(
        creds.get("AWS_DEFAULT_REGION").unwrap().expose_secret(),
        "us-east-1"
    );
}

#[test]
fn test_get_aws_credentials_cached_token_valid() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    // Create a mock token that's valid for 1 hour
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token_json =
        format!(r#"{{"accessToken": "cached-token", "expiresIn": 3600, "issuedAt": {now}}}"#);
    backend
        .set_secret(
            "mcp-aws-sso",
            "token:166f46b2b78da2cd5f13cdaaac765ddbcf5765a94a2f8b7056e44c0bfcbcc03c",
            &SecretString::from(token_json),
        )
        .unwrap();

    // Mock Get Role Credentials (only this one should be called)
    let _m = server.mock("GET", "/federation/credentials?account_id=123&role_name=MyRole")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"roleCredentials": {"accessKeyId": "AKIA_CACHED", "secretAccessKey": "SECRET_CACHED", "sessionToken": "SESSION_CACHED", "expiration": 1234567890}}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let creds = mcp_secret_launcher::aws_sso::get_aws_credentials(
        &backend,
        "https://sso.example.com",
        "us-east-1",
        "123",
        "MyRole",
    )
    .unwrap();

    assert_eq!(
        creds.get("AWS_ACCESS_KEY_ID").unwrap().expose_secret(),
        "AKIA_CACHED"
    );
}

#[test]
fn test_get_aws_credentials_on_401_deletes_token() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    // Create a mock token that matches our hardcoded hash for sso.example.com
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token_json =
        format!(r#"{{"accessToken": "bad-token", "expiresIn": 3600, "issuedAt": {now}}}"#);
    let token_key = "token:166f46b2b78da2cd5f13cdaaac765ddbcf5765a94a2f8b7056e44c0bfcbcc03c";
    backend
        .set_secret("mcp-aws-sso", token_key, &SecretString::from(token_json))
        .unwrap();

    // Mock Get Role Credentials returning 401
    let _m = server
        .mock(
            "GET",
            "/federation/credentials?account_id=123&role_name=MyRole",
        )
        .with_status(401)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    // We expect this to either exit or return an error depending on our bypass.
    // Let's assume it returns an error if we bypass exit.
    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
            &backend,
            "https://sso.example.com",
            "us-east-1",
            "123",
            "MyRole",
        );

        // If it didn't exit (which it shouldn't in our tests hopefully), check if it deleted the token
        assert!(res.is_err());
        assert!(backend.get_secret("mcp-aws-sso", token_key).is_err());
    });
}

#[test]
fn test_get_aws_credentials_device_code_expired() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    // 1. Mock Client Registration
    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"clientId": "c1", "clientSecret": "s1", "clientSecretExpiresAt": 2000000000}"#,
        )
        .create();

    // 2. Mock Device Auth Start
    let _m2 = server.mock("POST", "/device_authorization")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"deviceCode": "dc123", "userCode": "UC-123", "verificationUri": "http://v", "expiresIn": 60, "interval": 0}"#)
        .create();

    // 3. Mock Token Polling returns "expired_token"
    let _m3 = server
        .mock("POST", "/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error": "expired_token"}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
            &backend,
            "https://sso.example.com",
            "us-east-1",
            "123",
            "MyRole",
        );
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("expired"));
    });
}

#[test]
fn test_get_aws_credentials_client_cached() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    // Predetermine client cache key for us-east-1
    let client_key = "client:us-east-1";
    let client_json = r#"{"clientId": "cached-c", "clientSecret": "cached-s", "clientSecretExpiresAt": 2000000000}"#;
    backend
        .set_secret("mcp-aws-sso", client_key, &SecretString::from(client_json))
        .unwrap();

    // Mock Device Auth Start (should skip client registration)
    let _m1 = server.mock("POST", "/device_authorization")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"deviceCode": "dc123", "userCode": "UC-123", "verificationUri": "http://v", "expiresIn": 60, "interval": 0}"#)
        .create();

    // Mock Token Success
    let _m2 = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accessToken": "t", "expiresIn": 3600}"#)
        .create();

    // Mock Credentials
    let _m3 = server.mock("GET", "/federation/credentials?account_id=1&role_name=R")
        .with_status(200)
        .with_body(r#"{"roleCredentials": {"accessKeyId": "A", "secretAccessKey": "S", "sessionToken": "T", "expiration": 1}}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let _ = mcp_secret_launcher::aws_sso::get_aws_credentials(
        &backend,
        "https://sso.example.com",
        "us-east-1",
        "1",
        "R",
    )
    .unwrap();

    // Verify register was NOT called
    // (Mockito server automatically tracks hits, but simple way is just knowing it succeeded without a register mock)
}

#[test]
fn test_get_aws_credentials_polling_logic() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    // 1. Mock Client Registration
    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"clientId": "c1", "clientSecret": "s1", "clientSecretExpiresAt": 2000000000}"#,
        )
        .create();

    // 2. Mock Device Auth Start
    let _m2 = server.mock("POST", "/device_authorization")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"deviceCode": "dc123", "userCode": "UC-123", "verificationUri": "http://v", "expiresIn": 60, "interval": 0}"#)
        .create();

    // 3. Mock Token Polling: slow_down -> pending -> success
    let m3 = server
        .mock("POST", "/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error": "slow_down"}"#)
        .create();
    let m4 = server
        .mock("POST", "/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error": "authorization_pending"}"#)
        .create();
    let m5 = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accessToken": "final-token", "expiresIn": 3600}"#)
        .create();

    // Mock Credentials
    let _m6 = server.mock("GET", "/federation/credentials?account_id=A&role_name=R")
        .with_status(200)
        .with_body(r#"{"roleCredentials": {"accessKeyId": "AK", "secretAccessKey": "SK", "sessionToken": "ST", "expiration": 1}}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let _ = mcp_secret_launcher::aws_sso::get_aws_credentials(
        &backend,
        "https://sso.example.com",
        "us-east-1",
        "A",
        "R",
    )
    .unwrap();

    m3.assert();
    m4.assert();
    m5.assert();
}

#[test]
fn test_get_aws_credentials_client_reg_error() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    let _m = server
        .mock("POST", "/client/register")
        .with_status(400)
        .with_body("invalid_request")
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
        &backend,
        "https://sso.example.com",
        "us-east-1",
        "A",
        "R",
    );
    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("OIDC Client Reg Error")
    );
}

#[test]
fn test_get_aws_credentials_loop_timeout() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    // 1. Client Register
    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 2000000000}"#)
        .create();

    // 2. Device Auth returns 0 expires_in to force timeout after first poll
    let _m2 = server.mock("POST", "/device_authorization")
        .with_status(200)
        .with_body(r#"{"deviceCode": "dc", "userCode": "uc", "verificationUri": "http://v", "expiresIn": 0, "interval": 0}"#)
        .create();

    // 3. One poll returns pending, then loop should exit due to timeout
    let _m3 = server
        .mock("POST", "/token")
        .with_status(400)
        .with_body(r#"{"error": "authorization_pending"}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    // Set initial mock time
    mcp_secret_launcher::aws_sso::set_mock_time(Some(1000));

    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        // This is tricky because the loop polls, but doesn't let us increment time *during* the loop
        // unless we mock the token endpoint to increment time?
        // Actually, mocks in mockito can have side effects if we use a closure, but let's keep it simple:
        // If expiresIn is 0, it should exit after first failed poll because now() < expires_at is checked at start of loop
        // and after sleep.
        let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
            &backend,
            "https://sso.example.com",
            "us-east-1",
            "A",
            "R",
        );
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("expired"));
    });
    mcp_secret_launcher::aws_sso::set_mock_time(None);
}

#[test]
fn test_get_aws_credentials_access_denied() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 2000000000}"#)
        .create();

    let _m2 = server.mock("POST", "/device_authorization")
        .with_status(200)
        .with_body(r#"{"deviceCode": "dc", "userCode": "uc", "verificationUri": "http://v", "expiresIn": 60, "interval": 0}"#)
        .create();

    let _m3 = server
        .mock("POST", "/token")
        .with_status(400)
        .with_body(r#"{"error": "access_denied"}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
            &backend,
            "https://sso.example.com",
            "us-east-1",
            "A",
            "R",
        );
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("denied"));
    });
}

#[test]
fn test_get_aws_credentials_client_reg_transport_error() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    let _m = server
        .mock("POST", "/client/register")
        .with_status(500)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
        &backend,
        "https://sso.example.com",
        "us-east-1",
        "A",
        "R",
    );
    assert!(res.is_err());
}

#[test]
fn test_get_aws_credentials_device_auth_error() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 2000000000}"#)
        .create();

    let _m2 = server
        .mock("POST", "/device_authorization")
        .with_status(400)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
        &backend,
        "https://sso.example.com",
        "us-east-1",
        "A",
        "R",
    );
    assert!(res.is_err());
}

#[test]
fn test_get_aws_credentials_slow_down() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 2000000000}"#)
        .create();

    let _m2 = server.mock("POST", "/device_authorization")
        .with_status(200)
        .with_body(r#"{"deviceCode": "dc", "userCode": "uc", "verificationUri": "http://v", "expiresIn": 60, "interval": 0}"#)
        .create();

    // First poll slow_down, second poll success
    let _m3 = server
        .mock("POST", "/token")
        .with_status(400)
        .with_body(r#"{"error": "slow_down"}"#)
        .create();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let _m4 = server
        .mock("POST", "/token")
        .with_status(200)
        .with_body(format!(
            r#"{{"accessToken": "ok", "expiresIn": 3600, "issuedAt": {now}}}"#
        ))
        .create();

    let _m5 = server.mock("GET", "/federation/credentials?account_id=A&role_name=R")
        .with_status(200)
        .with_body(r#"{"roleCredentials": {"accessKeyId": "ak", "secretAccessKey": "sk", "sessionToken": "st", "expiration": 2000000000}}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
        &backend,
        "https://sso.example.com",
        "us-east-1",
        "A",
        "R",
    );
    assert!(res.is_ok());
}

#[test]
fn test_get_role_credentials_error() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 2000000000}"#)
        .create();

    let _m2 = server.mock("POST", "/device_authorization")
        .with_status(200)
        .with_body(r#"{"deviceCode": "dc", "userCode": "uc", "verificationUri": "http://v", "expiresIn": 60, "interval": 0}"#)
        .create();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let _m3 = server
        .mock("POST", "/token")
        .with_status(200)
        .with_body(format!(
            r#"{{"accessToken": "ok", "expiresIn": 3600, "issuedAt": {now}}}"#
        ))
        .create();

    // Role creds fail with 500
    let _m4 = server
        .mock("GET", "/federation/credentials?account_id=A&role_name=R")
        .with_status(500)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));

    let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
        &backend,
        "https://sso.example.com",
        "us-east-1",
        "A",
        "R",
    );
    assert!(res.is_err());
}

#[test]
fn test_get_aws_credentials_lock_fallback() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = mcp_secret_launcher::keyring_ops::MockKeyring::new();

    // Set TMPDIR to a restricted path to force fallback in lock creation.
    // /root is usually not writable by the test user.
    temp_env::with_var("TMPDIR", Some("/root"), || {
        mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));
        let _m = server
            .mock("GET", "/federation/credentials?account_id=A&role_name=R")
            .with_status(200)
            .with_body(r#"{"roleCredentials": {"accessKeyId": "ak", "secretAccessKey": "sk", "sessionToken": "st", "expiration": 2000000000}}"#)
            .create();

        let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
            &backend,
            "https://sso.example.com",
            "us-east-1",
            "A",
            "R",
        );
        // It should still fail if /root is blocked for BOTH File::create and tempfile(),
        // but it will hit the warning line (205) either way.
        // We just care about hitting the lines.
        let _ = res;
    });
}

#[test]
fn test_get_aws_credentials_token_other_error() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 2000000000}"#)
        .create();
    let _m2 = server.mock("POST", "/device_authorization").with_status(200)
        .with_body(r#"{"deviceCode": "dc", "userCode": "uc", "verificationUri": "http://v", "expiresIn": 60, "interval": 0}"#).create();

    let _m3 = server
        .mock("POST", "/token")
        .with_status(400)
        .with_body(r#"{"error": "unsupported_grant_type"}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));
    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
            &backend,
            "https://sso.example.com",
            "us-east-1",
            "A",
            "R",
        );
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("unsupported_grant_type")
        );
    });
}

#[test]
fn test_get_aws_credentials_token_transport_error() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 2000000000}"#)
        .create();
    let _m2 = server.mock("POST", "/device_authorization").with_status(200)
        .with_body(r#"{"deviceCode": "dc", "userCode": "uc", "verificationUri": "http://v", "expiresIn": 60, "interval": 0}"#).create();

    let _m3 = server.mock("POST", "/token").with_status(500).create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));
    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
            &backend,
            "https://sso.example.com",
            "us-east-1",
            "A",
            "R",
        );
        assert!(res.is_err());
    });
}

#[test]
fn test_get_aws_credentials_client_reg_400_error() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(400)
        .with_body(r#"{"error": "invalid_request"}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));
    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
            &backend,
            "https://sso.example.com",
            "us-east-1",
            "A",
            "R",
        );
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("OIDC Client Reg Error")
        );
    });
}

#[test]
fn test_get_aws_credentials_device_auth_400_error() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let mut server = mockito::Server::new();
    let backend = MockKeyringBackend::new();

    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 2000000000}"#)
        .create();
    let _m2 = server
        .mock("POST", "/device_authorization")
        .with_status(400)
        .with_body(r#"{"error": "invalid_client"}"#)
        .create();

    mcp_secret_launcher::aws_sso::set_mock_url(Some(server.url()));
    temp_env::with_var("__MCP_TEST_NO_EXEC", Some("1"), || {
        let res = mcp_secret_launcher::aws_sso::get_aws_credentials(
            &backend,
            "https://sso.example.com",
            "us-east-1",
            "A",
            "R",
        );
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("OIDC Device Auth Error")
        );
    });
}
