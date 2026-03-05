use crate::keyring_ops::{self, KeyringBackend};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fs4::fs_std::FileExt;

/// Models for AWS API requests/responses
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterClientRequest<'a> {
    client_name: &'a str,
    client_type: &'a str,
    grant_types: Vec<&'a str>,
    redirect_uris: Vec<&'a str>,
    issuer_url: &'a str,
    scopes: Vec<&'a str>,
}

#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterClientResponse {
    client_id: String,
    client_secret: String,
    client_secret_expires_at: i64,
}

#[derive(Debug, Serialize)]
struct StartDeviceAuthRequest<'a> {
    #[serde(rename = "clientId")]
    client_id: &'a str,
    #[serde(rename = "clientSecret")]
    client_secret: &'a str,
    #[serde(rename = "startUrl")]
    start_url: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartDeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: Option<String>,
    verification_uri_complete: Option<String>,
    expires_in: i64,
    interval: Option<i64>,
}

#[derive(Debug, Serialize)]
struct CreateTokenRequest<'a> {
    #[serde(rename = "clientId")]
    client_id: &'a str,
    #[serde(rename = "clientSecret")]
    client_secret: &'a str,
    #[serde(rename = "grantType")]
    grant_type: &'a str,
    #[serde(rename = "deviceCode")]
    device_code: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenResponse {
    access_token: String,
    expires_in: i64,
    // Add custom field to track when this token was issued
    #[serde(default)]
    issued_at: i64,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenErrorResponse {
    error: String,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleCredentialsResponse {
    role_credentials: RoleCredentials,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: i64,
}

const PROFILE_NAME: &str = "mcp-aws-sso";
const CLIENT_CACHE_PREFIX: &str = "client";
const TOKEN_CACHE_PREFIX: &str = "token";

/// Compute SHA-256 hex digest
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}

/// Cache keys
fn client_cache_key(region: &str) -> String {
    format!("{CLIENT_CACHE_PREFIX}:{region}")
}

fn token_cache_key(sso_url: &str) -> String {
    format!("{TOKEN_CACHE_PREFIX}:{}", sha256_hex(sso_url))
}

#[cfg(not(any(test, feature = "test-utils", debug_assertions)))]
fn get_oidc_url(region: &str) -> String {
    format!("https://oidc.{region}.amazonaws.com")
}

#[cfg(not(any(test, feature = "test-utils", debug_assertions)))]
fn get_portal_url(region: &str) -> String {
    format!("https://portal.sso.{region}.amazonaws.com")
}

#[cfg(any(test, feature = "test-utils", debug_assertions))]
thread_local! {
    /// Mock OIDC/Portal URL for testing.
    pub static MOCK_URL: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    /// Mock current time (Unix timestamp) for testing.
    pub static MOCK_TIME: std::cell::RefCell<Option<i64>> = const { std::cell::RefCell::new(None) };
}

/// Sets the mock URL used by OIDC and Portal requests.
#[cfg(any(test, feature = "test-utils", debug_assertions))]
pub fn set_mock_url(url: Option<String>) {
    MOCK_URL.with(|m| *m.borrow_mut() = url);
}

/// Sets the mock current time used for token and client expiration logic.
#[cfg(any(test, feature = "test-utils", debug_assertions))]
pub fn set_mock_time(time: Option<i64>) {
    MOCK_TIME.with(|m| *m.borrow_mut() = time);
}

#[cfg(not(any(test, feature = "test-utils", debug_assertions)))]
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(any(test, feature = "test-utils", debug_assertions))]
fn now() -> i64 {
    MOCK_TIME.with(|t| {
        t.borrow()
            .unwrap_or_else(|| time::OffsetDateTime::now_utc().unix_timestamp())
    })
}

#[cfg(any(test, feature = "test-utils", debug_assertions))]
#[cfg(any(test, feature = "test-utils", debug_assertions))]
fn get_oidc_url(region: &str) -> String {
    MOCK_URL.with(|u| {
        u.borrow()
            .clone()
            .unwrap_or_else(|| format!("https://oidc.{region}.amazonaws.com"))
    })
}

#[cfg(any(test, feature = "test-utils", debug_assertions))]
fn get_portal_url(region: &str) -> String {
    MOCK_URL.with(|u| {
        u.borrow()
            .clone()
            .unwrap_or_else(|| format!("https://portal.sso.{region}.amazonaws.com"))
    })
}

/// Retrieves AWS credentials via SSO OIDC device authorization flow.
///
/// This function handles:
/// 1. Checking for valid cached tokens in the keyring.
/// 2. Performing the device authorization flow if no valid token exists.
/// 3. Polling for the access token.
/// 4. Retrieving temporary role credentials.
/// 5. Caching credentials and tokens for future use.
pub fn get_aws_credentials(
    backend: &dyn KeyringBackend,
    sso_url: &str,
    region: &str,
    account_id: &str,
    role_name: &str,
) -> anyhow::Result<HashMap<String, SecretString>> {
    // 1. Check for valid cached token
    let token_key = token_cache_key(sso_url);
    let mut active_token = None;

    if let Ok(secret) = backend.get_secret(PROFILE_NAME, &token_key)
        && let Ok(cached_token) =
            serde_json::from_str::<CreateTokenResponse>(secret.expose_secret())
    {
        // Requirement 4.3 and edge-case 2: Token valid if > 15 mins to expiration
        let expires_at = cached_token.issued_at + cached_token.expires_in;
        if expires_at > now() + (15 * 60) {
            active_token = Some(cached_token.access_token);
        }
    }

    // 2. Perform device auth flow if no valid token
    if active_token.is_none() {
        // Use an IPC file lock to block concurrent device auth flows
        let lock_path =
            std::env::temp_dir().join(format!("mcp-aws-sso-lock-{}", sha256_hex(sso_url)));
        let lock_file = if let Ok(f) = File::create(&lock_path) {
            f
        } else {
            // Fallback to anonymous temp file if system temp dir is blocked
            let fallback = std::env::temp_dir().join("mcp-aws-sso-lock-fallback");
            File::create(fallback)
                .map_err(|e| anyhow::anyhow!("Failed to create IPC lock file: {e}"))?
        };

        // Wait for lock
        if let Err(e) = lock_file.lock_exclusive() {
            eprintln!("Warning: failed to acquire IPC lock: {e}");
        }

        // Check cache AGAIN after acquiring lock (another process may have just populated it)
        if let Ok(secret) = backend.get_secret(PROFILE_NAME, &token_key)
            && let Ok(cached_token) =
                serde_json::from_str::<CreateTokenResponse>(secret.expose_secret())
        {
            let expires_at = cached_token.issued_at + cached_token.expires_in;
            if expires_at > now() + (15 * 60) {
                active_token = Some(cached_token.access_token);
            }
        }

        // If STILL no token, perform the flow
        if active_token.is_none() {
            let client = get_or_register_client(backend, sso_url, region)?;
            let new_token_resp = perform_device_authorization(&client, sso_url, region)?;
            active_token = Some(new_token_resp.access_token.clone());

            // Cache the new token
            if let Ok(json) = serde_json::to_string(&new_token_resp) {
                let _ = keyring_ops::store_secret(backend, PROFILE_NAME, &token_key, &json.into());
            }
        }

        let _ = lock_file.unlock();
    }

    let token = active_token.ok_or_else(|| anyhow::anyhow!("Token must be present"))?;

    // 3. Get Role Credentials
    let creds = match get_role_credentials(&token, region, account_id, role_name) {
        Ok(c) => c,
        Err(e) => {
            // Requirement 10.4 / Edge Case 1: Proactively delete token on 401
            let is_401 = if let Some(ureq_err) = e.downcast_ref::<ureq::Error>() {
                matches!(ureq_err, ureq::Error::Status(401, _))
            } else {
                false
            };

            if is_401 {
                eprintln!("\n[ERROR] Cached SSO token was rejected (HTTP 401 Unauthorized).");
                eprintln!("The token may have been revoked server-side.");
                eprintln!("Deleting cached token. Please rerun the command to authenticate.");
                let _ = keyring_ops::delete_secret(backend, PROFILE_NAME, &token_key);
            }
            return Err(e);
        }
    };

    // 4. Build env map
    let mut env = HashMap::new();
    env.insert(
        "AWS_ACCESS_KEY_ID".to_string(),
        SecretString::from(creds.access_key_id),
    );
    env.insert(
        "AWS_SECRET_ACCESS_KEY".to_string(),
        SecretString::from(creds.secret_access_key),
    );
    env.insert(
        "AWS_SESSION_TOKEN".to_string(),
        SecretString::from(creds.session_token),
    );
    env.insert("AWS_DEFAULT_REGION".to_string(), SecretString::from(region));

    Ok(env)
}

#[allow(clippy::collapsible_if)]
fn get_or_register_client(
    backend: &dyn KeyringBackend,
    sso_url: &str,
    region: &str,
) -> anyhow::Result<RegisterClientResponse> {
    let client_key = client_cache_key(region);

    // Check cache
    if let Ok(secret) = backend.get_secret(PROFILE_NAME, &client_key) {
        if let Ok(client) = serde_json::from_str::<RegisterClientResponse>(secret.expose_secret()) {
            // Requirement 3.3 and edge-case 2: Valid if > 5 mins to expiration
            if client.client_secret_expires_at > now() + (5 * 60) {
                return Ok(client);
            }
        }
    }

    // Register new client using the exact shape AWS SSO expects
    let base_url = get_oidc_url(region);
    let url = format!("{base_url}/client/register");
    let req_body = RegisterClientRequest {
        client_name: "mcp-secret-launcher",
        client_type: "public",
        grant_types: vec![
            "urn:ietf:params:oauth:grant-type:device_code",
            "refresh_token",
        ],
        redirect_uris: vec!["http://127.0.0.1/oauth/callback"],
        issuer_url: sso_url,
        scopes: vec!["sso:account:access"],
    };

    let resp: ureq::Response = match ureq::post(&url)
        .set("Accept", "application/json")
        .send_json(&req_body)
    {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => {
            return Err(anyhow::anyhow!(
                "OIDC Client Reg Error: {:?}",
                r.into_string()
            ));
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to register OIDC client in region {region}: {e}"
            ));
        }
    };

    let client: RegisterClientResponse = resp.into_json()?;

    // Cache the registered client
    if let Ok(json) = serde_json::to_string(&client) {
        let _ = keyring_ops::store_secret(backend, PROFILE_NAME, &client_key, &json.into());
    }

    Ok(client)
}

#[allow(clippy::too_many_lines)]
fn perform_device_authorization(
    client: &RegisterClientResponse,
    sso_url: &str,
    region: &str,
) -> anyhow::Result<CreateTokenResponse> {
    // 1. Start Device Authorization
    let base_url = get_oidc_url(region);
    let url = format!("{base_url}/device_authorization");
    let req_body = StartDeviceAuthRequest {
        client_id: &client.client_id,
        client_secret: &client.client_secret,
        start_url: sso_url,
    };

    let resp: ureq::Response = match ureq::post(&url)
        .set("Accept", "application/json")
        .send_json(&req_body)
    {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => {
            return Err(anyhow::anyhow!(
                "OIDC Device Auth Error: {:?}",
                r.into_string()
            ));
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to start device authorization for {sso_url}. Please verify the SSO Start URL is correct. {e}"
            ));
        }
    };

    let auth_info: StartDeviceAuthResponse = resp.into_json()?;
    let verification_uri = auth_info
        .verification_uri_complete
        .as_ref()
        .or(auth_info.verification_uri.as_ref())
        .ok_or_else(|| anyhow::anyhow!("AWS OIDC must return a verification URI"))?;

    // 2. Instruct user and open browser
    eprintln!("\n=== AWS SSO Device Authorization ===");
    eprintln!("Attempting to open your browser to authorize this request...");

    #[cfg(any(test, feature = "test-utils", debug_assertions))]
    {
        let is_mocked = MOCK_URL.with(|m| m.borrow().is_some());
        if is_mocked {
            eprintln!("(Browser open bypassed in mock mode)");
        }
    }
    #[cfg(not(any(test, feature = "test-utils", debug_assertions)))]
    {
        let _ = open::that(verification_uri);
    }

    eprintln!(
        "\nIf it did not open, manually navigate to: {}",
        auth_info
            .verification_uri
            .as_deref()
            .unwrap_or(verification_uri)
    );
    eprintln!("Verify the code matches: {}\n", auth_info.user_code);

    // Setup Ctrl-C handler for graceful exit
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    #[cfg(any(test, feature = "test-utils", debug_assertions))]
    {
        let _ = ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        });
    }
    #[cfg(not(any(test, feature = "test-utils", debug_assertions)))]
    {
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .map_err(|_| anyhow::anyhow!("Error setting Ctrl-C handler"))?;
    }

    // 3. Poll for token
    let base_url = get_oidc_url(region);
    let token_url = format!("{base_url}/token");
    let mut interval = u64::try_from(auth_info.interval.unwrap_or(1)).unwrap_or(1);
    let expires_at = now() + auth_info.expires_in;

    eprintln!("Waiting for browser authorization (Ctrl+C to cancel)...");

    while running.load(Ordering::SeqCst) && now() < expires_at {
        std::thread::sleep(Duration::from_secs(interval));

        if !running.load(Ordering::SeqCst) {
            break;
        }

        let token_req = CreateTokenRequest {
            client_id: &client.client_id,
            client_secret: &client.client_secret,
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: &auth_info.device_code,
        };

        let resp: Result<ureq::Response, ureq::Error> =
            ureq::post(&token_url).send_json(&token_req);
        match resp {
            Ok(r) => {
                let mut token_resp: CreateTokenResponse = r.into_json()?;
                token_resp.issued_at = now();
                eprintln!("\nAuthorization successful!");
                return Ok(token_resp);
            }
            Err(e) => match e {
                ureq::Error::Status(_, r) => {
                    let err_resp: TokenErrorResponse = r.into_json()?;
                    match err_resp.error.as_str() {
                        "authorization_pending" => {
                            // Keep polling
                        }
                        "slow_down" => {
                            interval += 5;
                        }
                        "expired_token" => {
                            return Err(anyhow::anyhow!("The device authorization code expired"));
                        }
                        "access_denied" => {
                            eprintln!("\nAuthorization was denied by the user.");
                            return Err(anyhow::anyhow!("Authorization was denied by the user"));
                        }
                        other => {
                            return Err(anyhow::anyhow!("OIDC Token Error: {other}"));
                        }
                    }
                }
                ureq::Error::Transport(_) => return Err(e.into()),
            },
        }
    }

    if !running.load(Ordering::SeqCst) {
        eprintln!("\nAuthorization cancelled by user.");
        return Err(anyhow::anyhow!("Authorization cancelled by user"));
    }

    eprintln!("\nDevice authorization code expired.");
    Err(anyhow::anyhow!("Device authorization code expired"))
}

fn get_role_credentials(
    access_token: &str,
    region: &str,
    account_id: &str,
    role_name: &str,
) -> anyhow::Result<RoleCredentials> {
    let base_url = get_portal_url(region);
    let url =
        format!("{base_url}/federation/credentials?account_id={account_id}&role_name={role_name}");

    let resp = ureq::get(&url)
        .set("x-amz-sso_bearer_token", access_token)
        .call()?;

    let role_resp: RoleCredentialsResponse = resp.into_json()?;
    Ok(role_resp.role_credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex() {
        // Known test vector
        let input = "hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(sha256_hex(input), expected);
    }

    #[test]
    fn test_client_cache_key() {
        assert_eq!(client_cache_key("us-east-1"), "client:us-east-1");
        assert_eq!(client_cache_key("eu-west-2"), "client:eu-west-2");
    }

    #[test]
    fn test_token_cache_key() {
        let url = "https://d-12345.awsapps.com/start";
        let hash = sha256_hex(url);
        let expected = format!("token:{hash}");
        assert_eq!(token_cache_key(url), expected);
    }

    #[test]
    fn test_token_expiration_logic() {
        // Test 1: Active token with 30 mins remaining (> 15 buffer)
        let token_1 = CreateTokenResponse {
            access_token: "test_token".to_string(),
            expires_in: 3600,        // 1 hour
            issued_at: now() - 1800, // Issued 30 mins ago
        };
        let expires_at_1 = token_1.issued_at + token_1.expires_in;
        assert!(expires_at_1 > now() + (15 * 60));

        // Test 2: Token about to expire in 10 mins (< 15 buffer) => should fail check
        let token_2 = CreateTokenResponse {
            access_token: "test_token".to_string(),
            expires_in: 3600,
            issued_at: now() - 3000, // Issued 50 mins ago (10 mins left)
        };
        let expires_at_2 = token_2.issued_at + token_2.expires_in;
        assert!((expires_at_2 <= now() + (15 * 60)));

        // Test 3: Already expired token
        let token_3 = CreateTokenResponse {
            access_token: "test_token".to_string(),
            expires_in: 3600,
            issued_at: now() - 7200, // Issued 2 hours ago
        };
        let expires_at_3 = token_3.issued_at + token_3.expires_in;
        assert!((expires_at_3 <= now() + (15 * 60)));
    }

    #[test]
    fn test_client_registration_expiration_logic() {
        // 5-minute buffer requirement

        // Active client with 30 mins left
        assert!((now() + 1800) > now() + (5 * 60));

        // Client expiring in 2 mins (< 5 min buffer)
        assert!(((now() + 120) <= now() + (5 * 60)));
    }
}
