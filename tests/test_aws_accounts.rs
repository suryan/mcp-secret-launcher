#![allow(clippy::unwrap_used, missing_docs, clippy::items_after_statements)]
//! Tests for the `aws-accounts` subcommand (SSO portal `ListAccounts` / `ListAccountRoles`).
//! Every HTTP call goes to a local mockito server; nothing reaches AWS.

use mcp_secret_launcher::aws_sso::{self, AccountRoles};
use mcp_secret_launcher::cli::Command;
use mcp_secret_launcher::keyring_ops::{KeyringBackend, MockKeyring};
use mcp_secret_launcher::prompter::MockPrompter;
use mockito::{Matcher, Mock, ServerGuard};
use secrecy::SecretString;

const SSO_URL: &str = "https://sso.example.com";
const TOKEN: &str = "cached-token";
// sha256("https://sso.example.com"), the keyring key aws-auth and aws-accounts share.
const TOKEN_KEY: &str = "token:166f46b2b78da2cd5f13cdaaac765ddbcf5765a94a2f8b7056e44c0bfcbcc03c";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A keyring holding a cached SSO token with an hour of validity left.
fn backend_with_token() -> MockKeyring {
    let backend = MockKeyring::new();
    let json = format!(
        r#"{{"accessToken": "{TOKEN}", "expiresIn": 3600, "issuedAt": {}}}"#,
        now()
    );
    backend
        .set_secret("mcp-aws-sso", TOKEN_KEY, &SecretString::from(json))
        .unwrap();
    backend
}

fn has_token(backend: &MockKeyring) -> bool {
    backend.get_secret("mcp-aws-sso", TOKEN_KEY).is_ok()
}

fn accounts_page(server: &mut ServerGuard, query: &str, body: &str) -> Mock {
    server
        .mock("GET", "/assignment/accounts")
        .match_query(Matcher::Exact(query.to_string()))
        .match_header("x-amz-sso_bearer_token", TOKEN)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create()
}

fn roles_page(server: &mut ServerGuard, query: &str, body: &str) -> Mock {
    server
        .mock("GET", "/assignment/roles")
        .match_query(Matcher::Exact(query.to_string()))
        .match_header("x-amz-sso_bearer_token", TOKEN)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create()
}

fn roles_body(account: &str, roles: &[&str], next: Option<&str>) -> String {
    let list: Vec<String> = roles
        .iter()
        .map(|r| format!(r#"{{"accountId": "{account}", "roleName": "{r}"}}"#))
        .collect();
    let next = next.map_or_else(|| "null".to_string(), |t| format!("\"{t}\""));
    format!(
        r#"{{"roleList": [{}], "nextToken": {next}}}"#,
        list.join(",")
    )
}

fn list(
    server: &ServerGuard,
    backend: &MockKeyring,
    id: Option<&str>,
) -> anyhow::Result<Vec<AccountRoles>> {
    aws_sso::set_mock_url(Some(server.url()));
    aws_sso::list_accounts_with_roles(backend, SSO_URL, "us-east-1", id)
}

#[test]
fn test_pagination_sorting_and_defaults() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();

    // ListAccounts: two pages. The second-page token needs URL encoding.
    let a1 = accounts_page(
        &mut server,
        "max_result=100",
        r#"{"accountList": [
            {"accountId": "222222222222", "accountName": "zeta", "emailAddress": "z@example.com"},
            {"accountId": "111111111111", "accountName": "alpha", "emailAddress": "a@example.com"}
        ], "nextToken": "p2+/="}"#,
    );
    let a2 = accounts_page(
        &mut server,
        "max_result=100&next_token=p2%2B%2F%3D",
        r#"{"accountList": [
            {"accountId": "333333333333", "accountName": null},
            {"accountId": "000000000000", "accountName": "alpha", "emailAddress": "dup@example.com"}
        ], "nextToken": ""}"#,
    );

    // ListAccountRoles: 111 paginates (with a duplicate role across pages);
    // 333 has no roles; an absent roleList is tolerated for 000.
    let r1a = roles_page(
        &mut server,
        "account_id=111111111111&max_result=100",
        &roles_body("111111111111", &["read-only", "power-user"], Some("r2")),
    );
    let r1b = roles_page(
        &mut server,
        "account_id=111111111111&max_result=100&next_token=r2",
        &roles_body("111111111111", &["admin", "read-only"], None),
    );
    let r2 = roles_page(
        &mut server,
        "account_id=222222222222&max_result=100",
        &roles_body("222222222222", &["power-user"], None),
    );
    let r3 = roles_page(
        &mut server,
        "account_id=333333333333&max_result=100",
        &roles_body("333333333333", &[], None),
    );
    let r0 = roles_page(&mut server, "account_id=000000000000&max_result=100", "{}");

    let accounts = list(&server, &backend, None).unwrap();

    let summary: Vec<(&str, &str, &str, Vec<&str>)> = accounts
        .iter()
        .map(|a| {
            (
                a.account_name.as_str(),
                a.account_id.as_str(),
                a.email.as_str(),
                a.roles.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("", "333333333333", "", vec![]),
            ("alpha", "000000000000", "dup@example.com", vec![]),
            (
                "alpha",
                "111111111111",
                "a@example.com",
                vec!["admin", "power-user", "read-only"]
            ),
            ("zeta", "222222222222", "z@example.com", vec!["power-user"]),
        ]
    );
    for m in [a1, a2, r1a, r1b, r2, r3, r0] {
        m.assert();
    }
}

#[test]
fn test_zero_accounts() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _a = accounts_page(&mut server, "max_result=100", r#"{"accountList": []}"#);
    let roles = server.mock("GET", "/assignment/roles").expect(0).create();

    aws_sso::set_mock_url(Some(server.url()));
    let json = aws_sso::aws_accounts_json(&backend, SSO_URL, "us-east-1", None).unwrap();
    assert_eq!(json, r#"{"accounts":[]}"#);
    roles.assert();
}

#[test]
fn test_json_document_shape() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _a = accounts_page(
        &mut server,
        "max_result=100",
        r#"{"accountList": [{"accountId": "123456789012", "accountName": "dev \"x\"", "emailAddress": "d@example.com"}]}"#,
    );
    let _r = roles_page(
        &mut server,
        "account_id=123456789012&max_result=100",
        &roles_body("123456789012", &["read-only", "power-user"], None),
    );

    aws_sso::set_mock_url(Some(server.url()));
    let json = aws_sso::aws_accounts_json(&backend, SSO_URL, "us-east-1", None).unwrap();
    assert!(!json.contains('\n'));
    assert!(!json.contains(TOKEN));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"accounts": [{
            "account_id": "123456789012",
            "account_name": "dev \"x\"",
            "email": "d@example.com",
            "roles": ["power-user", "read-only"]
        }]})
    );
}

#[test]
fn test_account_id_filter_fetches_only_that_account() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _a = accounts_page(
        &mut server,
        "max_result=100",
        r#"{"accountList": [
            {"accountId": "111111111111", "accountName": "a"},
            {"accountId": "222222222222", "accountName": "b"}
        ]}"#,
    );
    let wanted = roles_page(
        &mut server,
        "account_id=222222222222&max_result=100",
        &roles_body("222222222222", &["read-only"], None),
    );
    let other = server
        .mock("GET", "/assignment/roles")
        .match_query(Matcher::UrlEncoded(
            "account_id".into(),
            "111111111111".into(),
        ))
        .expect(0)
        .create();

    let accounts = list(&server, &backend, Some("222222222222")).unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].account_id, "222222222222");
    assert_eq!(accounts[0].roles, vec!["read-only".to_string()]);
    wanted.assert();
    other.assert();
}

#[test]
fn test_account_id_filter_unknown_account() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _a = accounts_page(
        &mut server,
        "max_result=100",
        r#"{"accountList": [{"accountId": "111111111111", "accountName": "a"}]}"#,
    );
    let roles = server.mock("GET", "/assignment/roles").expect(0).create();

    let err = list(&server, &backend, Some("999999999999")).unwrap_err();
    assert!(err.to_string().contains("999999999999"), "{err}");
    assert!(
        has_token(&backend),
        "a missing account must not drop the token"
    );
    roles.assert();
}

#[test]
fn test_role_fetch_error_names_account_and_keeps_token() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _a = accounts_page(
        &mut server,
        "max_result=100",
        r#"{"accountList": [
            {"accountId": "111111111111", "accountName": "a"},
            {"accountId": "222222222222", "accountName": "b"}
        ]}"#,
    );
    let _ok = roles_page(
        &mut server,
        "account_id=111111111111&max_result=100",
        &roles_body("111111111111", &["read-only"], None),
    );
    let _bad = server
        .mock("GET", "/assignment/roles")
        .match_query(Matcher::UrlEncoded(
            "account_id".into(),
            "222222222222".into(),
        ))
        .with_status(500)
        .create();

    let err = list(&server, &backend, None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("ListAccountRoles for account 222222222222"),
        "{msg}"
    );
    assert!(!msg.contains(TOKEN));
    assert!(has_token(&backend), "a 500 must not drop the token");
}

#[test]
fn test_401_on_list_accounts_deletes_token() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _a = server
        .mock("GET", "/assignment/accounts")
        .match_query(Matcher::Any)
        .with_status(401)
        .create();

    assert!(list(&server, &backend, None).is_err());
    assert!(!has_token(&backend));
}

#[test]
fn test_401_on_list_roles_deletes_token() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _a = accounts_page(
        &mut server,
        "max_result=100",
        r#"{"accountList": [{"accountId": "111111111111", "accountName": "a"}]}"#,
    );
    let _r = server
        .mock("GET", "/assignment/roles")
        .match_query(Matcher::Any)
        .with_status(401)
        .create();

    assert!(list(&server, &backend, None).is_err());
    assert!(!has_token(&backend));
}

#[test]
fn test_repeated_next_token_on_accounts_fails() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _p1 = accounts_page(
        &mut server,
        "max_result=100",
        r#"{"accountList": [], "nextToken": "loop"}"#,
    );
    let p2 = accounts_page(
        &mut server,
        "max_result=100&next_token=loop",
        r#"{"accountList": [], "nextToken": "loop"}"#,
    );

    let err = list(&server, &backend, None).unwrap_err();
    assert!(err.to_string().contains("same nextToken"), "{err}");
    p2.assert();
}

#[test]
fn test_repeated_next_token_on_roles_fails() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _a = accounts_page(
        &mut server,
        "max_result=100",
        r#"{"accountList": [{"accountId": "111111111111", "accountName": "a"}]}"#,
    );
    let _r1 = roles_page(
        &mut server,
        "account_id=111111111111&max_result=100",
        &roles_body("111111111111", &["x"], Some("t")),
    );
    let _r2 = roles_page(
        &mut server,
        "account_id=111111111111&max_result=100&next_token=t",
        &roles_body("111111111111", &["y"], Some("t")),
    );

    let err = list(&server, &backend, None).unwrap_err();
    assert!(format!("{err:#}").contains("same nextToken"), "{err:#}");
}

#[test]
fn test_invalid_json_is_an_error() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _a = accounts_page(&mut server, "max_result=100", "not json");
    let err = list(&server, &backend, None).unwrap_err();
    assert!(err.to_string().contains("invalid JSON"), "{err}");

    let mut server = mockito::Server::new();
    let _a = accounts_page(
        &mut server,
        "max_result=100",
        r#"{"accountList": [{"accountId": "111111111111"}]}"#,
    );
    let _r = roles_page(&mut server, "account_id=111111111111&max_result=100", "[");
    let err = list(&server, &backend, None).unwrap_err();
    assert!(err.to_string().contains("invalid JSON"), "{err}");
}

#[test]
fn test_throttled_request_is_retried() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let throttled = server
        .mock("GET", "/assignment/accounts")
        .match_query(Matcher::Any)
        .with_status(429)
        .expect(1)
        .create();
    let ok = accounts_page(&mut server, "max_result=100", r#"{"accountList": []}"#);

    assert_eq!(
        list(&server, &backend, None).unwrap(),
        Vec::<AccountRoles>::new()
    );
    throttled.assert();
    ok.assert();
}

#[test]
fn test_throttling_gives_up_after_max_attempts() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let throttled = server
        .mock("GET", "/assignment/accounts")
        .match_query(Matcher::Any)
        .with_status(429)
        .expect(4)
        .create();

    assert!(list(&server, &backend, None).is_err());
    assert!(has_token(&backend), "a 429 must not drop the token");
    throttled.assert();
}

#[test]
fn test_many_accounts_parallel_roles_map_to_the_right_account() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let ids: Vec<String> = (0..60).map(|i| format!("{:012}", 100 + i)).collect();
    let list_json: Vec<String> = ids
        .iter()
        .map(|id| format!(r#"{{"accountId": "{id}", "accountName": "acct-{id}"}}"#))
        .collect();
    let _a = accounts_page(
        &mut server,
        "max_result=100",
        &format!(r#"{{"accountList": [{}]}}"#, list_json.join(",")),
    );
    let mocks: Vec<Mock> = ids
        .iter()
        .map(|id| {
            let role = format!("role-{id}");
            roles_page(
                &mut server,
                &format!("account_id={id}&max_result=100"),
                &roles_body(id, &[&role], None),
            )
        })
        .collect();

    let accounts = list(&server, &backend, None).unwrap();
    assert_eq!(accounts.len(), 60);
    for a in &accounts {
        assert_eq!(a.roles, vec![format!("role-{}", a.account_id)]);
    }
    for m in mocks {
        m.assert();
    }
}

#[test]
fn test_expired_cached_token_runs_device_flow_then_lists() {
    let mut server = mockito::Server::new();
    let backend = MockKeyring::new();
    // Token with only 10 minutes left: inside the 15-minute margin, so it is refreshed.
    let stale = format!(
        r#"{{"accessToken": "stale", "expiresIn": 600, "issuedAt": {}}}"#,
        now()
    );
    backend
        .set_secret("mcp-aws-sso", TOKEN_KEY, &SecretString::from(stale))
        .unwrap();

    let _c = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"clientId": "c", "clientSecret": "s", "clientSecretExpiresAt": 4000000000}"#)
        .create();
    let _d = server
        .mock("POST", "/device_authorization")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"deviceCode": "dc", "userCode": "UC", "verificationUri": "http://127.0.0.1/v", "expiresIn": 600, "interval": 0}"#)
        .create();
    let _t = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"accessToken": "{TOKEN}", "expiresIn": 3600}}"#
        ))
        .create();
    let _a = accounts_page(&mut server, "max_result=100", r#"{"accountList": []}"#);

    assert_eq!(
        list(&server, &backend, None).unwrap(),
        Vec::<AccountRoles>::new()
    );
    // The fresh token was cached for the next caller.
    let cached = backend.get_secret("mcp-aws-sso", TOKEN_KEY).unwrap();
    assert!(secrecy::ExposeSecret::expose_secret(&cached).contains(TOKEN));
}

#[test]
fn test_run_app_aws_accounts_command() {
    let mut server = mockito::Server::new();
    let backend = backend_with_token();
    let _a = accounts_page(
        &mut server,
        "max_result=100",
        r#"{"accountList": [{"accountId": "111111111111", "accountName": "a"}]}"#,
    );
    let _r = roles_page(
        &mut server,
        "account_id=111111111111&max_result=100",
        &roles_body("111111111111", &["read-only"], None),
    );
    aws_sso::set_mock_url(Some(server.url()));

    let prompter = MockPrompter::new("unused".to_string().into());
    let cmd = Command::AwsAccounts {
        sso_url: SSO_URL.to_string(),
        region: "us-east-1".to_string(),
        account_id: Some("111111111111".to_string()),
    };
    mcp_secret_launcher::run_app(cmd, &backend, &prompter, Vec::new()).unwrap();
}

#[test]
fn test_cli_parses_aws_accounts() {
    use clap::Parser;
    let cli = mcp_secret_launcher::cli::Cli::try_parse_from([
        "mcp-secret-launcher",
        "aws-accounts",
        "--sso-url",
        SSO_URL,
        "--region",
        "ap-southeast-2",
    ])
    .unwrap();
    match cli.command {
        Command::AwsAccounts {
            sso_url,
            region,
            account_id,
        } => {
            assert_eq!(sso_url, SSO_URL);
            assert_eq!(region, "ap-southeast-2");
            assert!(account_id.is_none());
        }
        _ => unreachable!("wrong subcommand"),
    }

    // --region is required.
    assert!(
        mcp_secret_launcher::cli::Cli::try_parse_from([
            "mcp-secret-launcher",
            "aws-accounts",
            "--sso-url",
            SSO_URL,
        ])
        .is_err()
    );
}
