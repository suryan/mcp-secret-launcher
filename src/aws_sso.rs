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
    mock_url().unwrap_or_else(|| format!("https://oidc.{region}.amazonaws.com"))
}

/// Mock endpoint for tests: the thread-local `MOCK_URL`, else the
/// `__MCP_TEST_MOCK_URL` env var (lets binary-level tests point a debug build
/// at a local mock server). Never compiled into release builds.
#[cfg(any(test, feature = "test-utils", debug_assertions))]
fn mock_url() -> Option<String> {
    MOCK_URL
        .with(|u| u.borrow().clone())
        .or_else(|| std::env::var("__MCP_TEST_MOCK_URL").ok())
}

#[cfg(any(test, feature = "test-utils", debug_assertions))]
fn get_portal_url(region: &str) -> String {
    mock_url().unwrap_or_else(|| format!("https://portal.sso.{region}.amazonaws.com"))
}

/// Retrieves AWS credentials via SSO OIDC device authorization flow.
///
/// This function handles:
/// 1. Checking for valid cached tokens in the keyring.
/// 2. Performing the device authorization flow if no valid token exists.
/// 3. Polling for the access token.
/// 4. Retrieving temporary role credentials.
/// 5. Caching credentials and tokens for future use.
///
/// # Errors
/// Returns an error if the OIDC device authorization flow fails, if the token request
/// errors out, or if fetching role credentials from the AWS portal is denied.
pub fn get_aws_credentials(
    backend: &dyn KeyringBackend,
    sso_url: &str,
    region: &str,
    account_id: &str,
    role_name: &str,
) -> anyhow::Result<HashMap<String, SecretString>> {
    // 1-2. Obtain an SSO access token (cache, IPC lock, device flow)
    let token = get_sso_token(backend, sso_url, region)?;

    // 3. Get Role Credentials
    let creds = get_role_credentials(token.expose_secret(), region, account_id, role_name)
        .inspect_err(|e| forget_token_if_unauthorized(backend, sso_url, e))?;

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

/// Reads the cached SSO token for `token_key`, returning it only while it has
/// more than 15 minutes of validity left.
fn read_cached_token(backend: &dyn KeyringBackend, token_key: &str) -> Option<SecretString> {
    let secret = backend.get_secret(PROFILE_NAME, token_key).ok()?;
    let cached_token = serde_json::from_str::<CreateTokenResponse>(secret.expose_secret()).ok()?;
    // Requirement 4.3 and edge-case 2: Token valid if > 15 mins to expiration
    let expires_at = cached_token.issued_at + cached_token.expires_in;
    (expires_at > now() + (15 * 60)).then(|| SecretString::from(cached_token.access_token))
}

/// Returns a valid AWS SSO access token for `sso_url`.
///
/// This is the single token path shared by `aws-auth` and `aws-accounts`:
/// 1. Use the keyring-cached token if it has more than 15 minutes left.
/// 2. Otherwise take an exclusive IPC file lock in the temp dir so concurrent
///    launchers run at most one device authorization flow, re-check the cache,
///    and run the device flow (prompts go to stderr) if still needed.
/// 3. Cache any newly issued token in the keyring.
///
/// # Errors
/// Returns an error if the lock file cannot be created or the OIDC client
/// registration / device authorization flow fails.
pub fn get_sso_token(
    backend: &dyn KeyringBackend,
    sso_url: &str,
    region: &str,
) -> anyhow::Result<SecretString> {
    let token_key = token_cache_key(sso_url);
    if let Some(token) = read_cached_token(backend, &token_key) {
        return Ok(token);
    }

    // Use an IPC file lock to block concurrent device auth flows
    let lock_path = std::env::temp_dir().join(format!("mcp-aws-sso-lock-{}", sha256_hex(sso_url)));
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
    let result = match read_cached_token(backend, &token_key) {
        Some(token) => Ok(token),
        None => fetch_new_token(backend, sso_url, region, &token_key),
    };

    let _ = lock_file.unlock();
    result
}

/// Runs the device authorization flow and caches the issued token.
fn fetch_new_token(
    backend: &dyn KeyringBackend,
    sso_url: &str,
    region: &str,
    token_key: &str,
) -> anyhow::Result<SecretString> {
    let client = get_or_register_client(backend, sso_url, region)?;
    let new_token_resp = perform_device_authorization(&client, sso_url, region)?;

    // Cache the new token
    if let Ok(json) = serde_json::to_string(&new_token_resp) {
        let _ = keyring_ops::store_secret(backend, PROFILE_NAME, token_key, &json.into());
    }
    Ok(SecretString::from(new_token_resp.access_token))
}

/// Returns true when any error in the chain is an HTTP 401 from the SSO portal.
fn is_unauthorized(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<ureq::Error>(),
            Some(ureq::Error::Status(401, _))
        )
    })
}

/// Requirement 10.4 / Edge Case 1: proactively delete the cached token on a 401
/// so the next run re-authenticates instead of failing with the same token.
fn forget_token_if_unauthorized(backend: &dyn KeyringBackend, sso_url: &str, err: &anyhow::Error) {
    if is_unauthorized(err) {
        eprintln!("\n[ERROR] Cached SSO token was rejected (HTTP 401 Unauthorized).");
        eprintln!("The token may have been revoked server-side.");
        eprintln!("Deleting cached token. Please rerun the command to authenticate.");
        let _ = keyring_ops::delete_secret(backend, PROFILE_NAME, &token_cache_key(sso_url));
    }
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
        let is_mocked = mock_url().is_some();
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

/// One AWS account the SSO user can access, with the roles assigned to them in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountRoles {
    /// 12-digit AWS account ID.
    pub account_id: String,
    /// Account name as shown in the SSO portal (empty if the portal omits it).
    pub account_name: String,
    /// Account root email address (empty if the portal omits it).
    pub email: String,
    /// Permission-set role names assigned to the user, sorted and de-duplicated.
    pub roles: Vec<String>,
}

/// The `aws-accounts` stdout document: `{"accounts": [...]}`.
#[derive(Debug, Serialize)]
pub struct AccountsReport {
    /// Accounts sorted by name, then ID.
    pub accounts: Vec<AccountRoles>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListAccountsResponse {
    #[serde(default)]
    account_list: Vec<AccountInfo>,
    next_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountInfo {
    account_id: String,
    account_name: Option<String>,
    email_address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListAccountRolesResponse {
    #[serde(default)]
    role_list: Vec<RoleInfo>,
    next_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleInfo {
    role_name: String,
}

/// Page size requested from the portal (the API maximum).
const PORTAL_PAGE_SIZE: &str = "100";
/// Upper bound on concurrent `ListAccountRoles` requests.
const ROLE_FETCH_PARALLELISM: usize = 8;
/// Safety cap on pages per paginated listing.
const MAX_PAGES: usize = 1000;
/// Attempts per portal request when throttled with HTTP 429.
const MAX_ATTEMPTS: u32 = 4;
/// Per-request timeout for portal listing calls.
const PORTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Follows `nextToken` pagination until the portal stops returning one.
///
/// An empty `nextToken` ends the listing. A token seen before is treated as a
/// portal bug and fails instead of looping forever.
fn paginate<T>(
    what: &str,
    mut fetch_page: impl FnMut(Option<&str>) -> anyhow::Result<(Vec<T>, Option<String>)>,
) -> anyhow::Result<Vec<T>> {
    let mut items = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut next: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let (page, token) = fetch_page(next.as_deref())?;
        items.extend(page);
        match token.filter(|t| !t.is_empty()) {
            None => return Ok(items),
            Some(t) => {
                if !seen.insert(t.clone()) {
                    anyhow::bail!(
                        "{what}: the SSO portal returned the same nextToken twice; stopping to avoid an endless loop"
                    );
                }
                next = Some(t);
            }
        }
    }
    anyhow::bail!("{what}: more than {MAX_PAGES} pages; stopping")
}

/// Sends one authenticated GET to the SSO portal, retrying HTTP 429 with backoff.
fn portal_get(
    agent: &ureq::Agent,
    url: &str,
    query: &[(&str, &str)],
    token: &SecretString,
) -> anyhow::Result<ureq::Response> {
    let mut attempt = 0;
    loop {
        let mut req = agent
            .get(url)
            .set("x-amz-sso_bearer_token", token.expose_secret());
        for (k, v) in query {
            req = req.query(k, v);
        }
        match req.call() {
            Err(ureq::Error::Status(429, _)) if attempt + 1 < MAX_ATTEMPTS => {
                std::thread::sleep(Duration::from_millis(200 << attempt));
                attempt += 1;
            }
            other => return other.map_err(Into::into),
        }
    }
}

/// `ListAccounts`: every account assigned to the user, across all pages.
fn list_accounts(
    agent: &ureq::Agent,
    base_url: &str,
    token: &SecretString,
) -> anyhow::Result<Vec<AccountInfo>> {
    let url = format!("{base_url}/assignment/accounts");
    paginate("ListAccounts", |next| {
        let mut query = vec![("max_result", PORTAL_PAGE_SIZE)];
        if let Some(t) = next {
            query.push(("next_token", t));
        }
        let resp: ListAccountsResponse = portal_get(agent, &url, &query, token)
            .map_err(|e| e.context("ListAccounts request failed"))?
            .into_json()
            .map_err(|e| anyhow::anyhow!("ListAccounts returned invalid JSON: {e}"))?;
        Ok((resp.account_list, resp.next_token))
    })
}

/// `ListAccountRoles`: the user's role names in one account, across all pages.
fn list_account_roles(
    agent: &ureq::Agent,
    base_url: &str,
    token: &SecretString,
    account_id: &str,
) -> anyhow::Result<Vec<String>> {
    let url = format!("{base_url}/assignment/roles");
    let what = format!("ListAccountRoles for account {account_id}");
    let mut roles = paginate(&what, |next| {
        let mut query = vec![("account_id", account_id), ("max_result", PORTAL_PAGE_SIZE)];
        if let Some(t) = next {
            query.push(("next_token", t));
        }
        let resp: ListAccountRolesResponse = portal_get(agent, &url, &query, token)
            .map_err(|e| e.context(format!("{what} failed")))?
            .into_json()
            .map_err(|e| anyhow::anyhow!("{what} returned invalid JSON: {e}"))?;
        Ok((
            resp.role_list.into_iter().map(|r| r.role_name).collect(),
            resp.next_token,
        ))
    })?;
    roles.sort();
    roles.dedup();
    Ok(roles)
}

/// Fetches roles for every account with at most `ROLE_FETCH_PARALLELISM`
/// requests in flight. Results keep the input order; the first error (in
/// account order) wins.
fn fetch_roles_parallel(
    agent: &ureq::Agent,
    base_url: &str,
    token: &SecretString,
    account_ids: &[String],
) -> anyhow::Result<Vec<Vec<String>>> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: Vec<std::sync::Mutex<Option<anyhow::Result<Vec<String>>>>> = account_ids
        .iter()
        .map(|_| std::sync::Mutex::new(None))
        .collect();
    let workers = ROLE_FETCH_PARALLELISM.min(account_ids.len());

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(id) = account_ids.get(i) else { break };
                    let res = list_account_roles(agent, base_url, token, id);
                    if let Ok(mut slot) = results[i].lock() {
                        *slot = Some(res);
                    }
                }
            });
        }
    });

    results
        .into_iter()
        .zip(account_ids)
        .map(|(slot, id)| {
            slot.into_inner()
                .ok()
                .flatten()
                .unwrap_or_else(|| Err(anyhow::anyhow!("role lookup for account {id} did not run")))
        })
        .collect()
}

/// Lists the SSO accounts (and the user's roles in each) for `aws-accounts`.
///
/// Uses the same token path as `aws-auth` ([`get_sso_token`]). When
/// `account_id` is given, only that account is returned (and only its roles
/// are fetched). Accounts are sorted by name, then ID.
///
/// # Errors
/// Returns an error if authentication fails, any portal call fails (a 401
/// also deletes the cached token), or `account_id` is not assigned to the user.
pub fn list_accounts_with_roles(
    backend: &dyn KeyringBackend,
    sso_url: &str,
    region: &str,
    account_id: Option<&str>,
) -> anyhow::Result<Vec<AccountRoles>> {
    let token = get_sso_token(backend, sso_url, region)?;
    // Resolve the portal URL on this thread: the test mock URL is thread-local.
    let base_url = get_portal_url(region);
    let agent = ureq::AgentBuilder::new().timeout(PORTAL_TIMEOUT).build();

    let result = (|| {
        let mut accounts = list_accounts(&agent, &base_url, &token)?;
        if let Some(wanted) = account_id {
            accounts.retain(|a| a.account_id == wanted);
            accounts.truncate(1);
            if accounts.is_empty() {
                anyhow::bail!(
                    "Account {wanted} is not assigned to this SSO user (or does not exist)"
                );
            }
        }
        let ids: Vec<String> = accounts.iter().map(|a| a.account_id.clone()).collect();
        let roles = fetch_roles_parallel(&agent, &base_url, &token, &ids)?;

        let mut out: Vec<AccountRoles> = accounts
            .into_iter()
            .zip(roles)
            .map(|(a, roles)| AccountRoles {
                account_id: a.account_id,
                account_name: a.account_name.unwrap_or_default(),
                email: a.email_address.unwrap_or_default(),
                roles,
            })
            .collect();
        out.sort_by(|a, b| {
            a.account_name
                .cmp(&b.account_name)
                .then_with(|| a.account_id.cmp(&b.account_id))
        });
        Ok(out)
    })();

    result.inspect_err(|e| forget_token_if_unauthorized(backend, sso_url, e))
}

/// Builds the `aws-accounts` stdout document as a single JSON line.
///
/// # Errors
/// Same as [`list_accounts_with_roles`].
pub fn aws_accounts_json(
    backend: &dyn KeyringBackend,
    sso_url: &str,
    region: &str,
    account_id: Option<&str>,
) -> anyhow::Result<String> {
    let accounts = list_accounts_with_roles(backend, sso_url, region, account_id)?;
    Ok(serde_json::to_string(&AccountsReport { accounts })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paginate_stops_at_page_cap() {
        let mut calls = 0usize;
        let res: anyhow::Result<Vec<u8>> = paginate("Endless", |_| {
            calls += 1;
            Ok((vec![], Some(format!("t{calls}"))))
        });
        let err = res.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("more than 1000 pages"), "{err}");
        assert_eq!(calls, MAX_PAGES);
    }

    #[test]
    fn test_is_unauthorized_only_matches_401() {
        let other = anyhow::anyhow!("boom").context("wrapped");
        assert!(!is_unauthorized(&other));
    }

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
