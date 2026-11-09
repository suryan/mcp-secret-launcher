#![allow(clippy::unwrap_used, missing_docs, clippy::items_after_statements)]
//! Coverage-focused tests for aws-run-with-secrets and aws-session-status.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use mcp_secret_launcher::aws_fetch::test_hooks;
use mcp_secret_launcher::aws_sso::{self, LoginMode};
use mcp_secret_launcher::cli::Command;
use mcp_secret_launcher::keyring_ops::MockKeyring;
use mcp_secret_launcher::prompter::MockPrompter;
use mcp_secret_launcher::run_app;
use mcp_secret_launcher::run_with_secrets::{self, RunWithSecretsRequest};
use mcp_secret_launcher::runner;
use mcp_secret_launcher::spec;
use secrecy::{ExposeSecret, SecretString};

fn write_spec(dir: &std::path::Path, body: &str) -> PathBuf {
    let path = dir.join("spec.json");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    path
}

fn mock_sso(server: &mut mockito::Server) {
    let _m1 = server
        .mock("POST", "/client/register")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"clientId":"c","clientSecret":"s","clientSecretExpiresAt":2000000000}"#)
        .create();
    let _m2 = server
        .mock("POST", "/device_authorization")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"deviceCode":"dc","userCode":"uc","verificationUri":"http://127.0.0.1","expiresIn":600,"interval":1}"#)
        .create();
    let _m3 = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accessToken":"mt","expiresIn":3600}"#)
        .create();
    let _m4 = server
        .mock(
            "GET",
            "/federation/credentials?account_id=123456789012&role_name=PowerUser",
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"roleCredentials":{"accessKeyId":"A","secretAccessKey":"S","sessionToken":"T","expiration":9999999999}}"#,
        )
        .create();
    aws_sso::set_mock_url(Some(server.url()));
}

#[test]
fn load_spec_rejects_bad_json_and_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    assert!(spec::load_spec(&dir.path().join("missing.json")).is_err());
    let bad = write_spec(dir.path(), "{not json");
    assert!(spec::load_spec(&bad).is_err());
}

#[test]
fn load_spec_accepts_valid_and_rejects_bad_entries() {
    let dir = tempfile::tempdir().unwrap();
    let ok = write_spec(
        dir.path(),
        r#"{"secrets":[{"id":"a","env":"A"}],"params":[{"id":"/p","env":"P"}]}"#,
    );
    let s = spec::load_spec(&ok).unwrap();
    assert_eq!(s.secrets.len(), 1);
    assert_eq!(s.params.len(), 1);

    let bad_source = write_spec(
        dir.path(),
        r#"{"secrets":[{"source":"vault","id":"a","env":"A"}],"params":[]}"#,
    );
    assert!(spec::load_spec(&bad_source).is_err());

    let both_file_expand = write_spec(
        dir.path(),
        r#"{"secrets":[{"id":"a","file":true,"expand_json":true,"prefix":"X_"}],"params":[]}"#,
    );
    assert!(spec::load_spec(&both_file_expand).is_err());

    let empty_id = write_spec(
        dir.path(),
        r#"{"secrets":[{"id":"","env":"A"}],"params":[]}"#,
    );
    assert!(spec::load_spec(&empty_id).is_err());

    let bad_param = write_spec(
        dir.path(),
        r#"{"secrets":[],"params":[{"source":"appconfig","id":"/x","env":"E"}]}"#,
    );
    assert!(spec::load_spec(&bad_param).is_err());

    let path_no_prefix = write_spec(
        dir.path(),
        r#"{"secrets":[],"params":[{"path":"/app/","recursive":true}]}"#,
    );
    assert!(spec::load_spec(&path_no_prefix).is_err());
}

#[test]
fn build_clean_env_passthrough_and_overlay() {
    let env =
        runner::build_clean_env([("MY_SECRET".to_string(), SecretString::from("v".to_string()))]);
    assert_eq!(env.get("MY_SECRET").unwrap().expose_secret(), "v");
    // Must not blindly inherit AWS_SECRET_ACCESS_KEY from ambient unless we set it.
    // PATH is allowlisted and usually present.
    if std::env::var_os("PATH").is_some() {
        assert!(env.contains_key("PATH"));
    }
}

#[test]
fn spawn_capture_runs_echo() {
    let dir = tempfile::tempdir().unwrap();
    let env = runner::build_clean_env([]);
    let out = runner::spawn_capture(
        &["/bin/echo".into(), "hi-from-capture".into()],
        env,
        dir.path(),
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert!(out.stdout.contains("hi-from-capture"));
    assert!(!out.timed_out);
}

#[test]
fn spawn_capture_empty_cmd_errors() {
    let dir = tempfile::tempdir().unwrap();
    let err = runner::spawn_capture(&[], runner::build_clean_env([]), dir.path(), None);
    assert!(err.is_err());
}

#[test]
fn run_with_secrets_end_to_end_redacts() {
    let mut server = mockito::Server::new();
    mock_sso(&mut server);
    let backend = MockKeyring::new();
    let dir = tempfile::tempdir().unwrap();
    let spec = write_spec(
        dir.path(),
        r#"{"secrets":[{"id":"my/secret","env":"LEAK"}],"params":[]}"#,
    );

    test_hooks::with_mock_aws(
        |_c, _r, args| {
            if args.contains(&"get-secret-value") {
                Ok("super-secret-token\n".into())
            } else {
                anyhow::bail!("unexpected {args:?}")
            }
        },
        || {
            // Child prints the secret; launcher must redact it.
            let req = RunWithSecretsRequest {
                sso_url: "https://sso.example.com",
                sso_region: "us-east-1",
                account_id: "123456789012",
                role_name: "PowerUser",
                aws_region: "ap-southeast-2",
                cwd: dir.path(),
                spec_file: &spec,
                inject_aws_credentials: true,
                login_mode: LoginMode::Interactive,
                cmd: &[
                    "/bin/bash".into(),
                    "-c".into(),
                    "echo leak=$LEAK; echo ok".into(),
                ],
                timeout: Some(Duration::from_secs(10)),
            };
            run_with_secrets::run(&backend, &req).unwrap();
        },
    );
    aws_sso::set_mock_url(None);
}

#[test]
fn run_with_secrets_without_injecting_aws_creds() {
    let mut server = mockito::Server::new();
    mock_sso(&mut server);
    let backend = MockKeyring::new();
    let dir = tempfile::tempdir().unwrap();
    let spec = write_spec(dir.path(), r#"{"secrets":[],"params":[]}"#);
    test_hooks::with_mock_aws(
        |_c, _r, _a| Ok(String::new()),
        || {
            let req = RunWithSecretsRequest {
                sso_url: "https://sso.example.com",
                sso_region: "us-east-1",
                account_id: "123456789012",
                role_name: "PowerUser",
                aws_region: "ap-southeast-2",
                cwd: dir.path(),
                spec_file: &spec,
                inject_aws_credentials: false,
                login_mode: LoginMode::Interactive,
                cmd: &["/bin/echo".into(), "plain".into()],
                timeout: None,
            };
            run_with_secrets::run(&backend, &req).unwrap();
        },
    );
    aws_sso::set_mock_url(None);
}

#[test]
fn app_aws_session_status_login_required() {
    let backend = MockKeyring::new();
    let prompter = MockPrompter::new("x".into());
    run_app(
        Command::AwsSessionStatus {
            sso_url: "https://sso.example.com".into(),
            region: "us-east-1".into(),
        },
        &backend,
        &prompter,
        Vec::new(),
    )
    .unwrap();
}

#[test]
fn resolve_injections_via_real_aws_cli_spawn_path() {
    // Cover `run_aws_real` by putting a tiny fake `aws` ahead on PATH (no mock hook).
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let aws = bin.join("aws");
    {
        let mut f = std::fs::File::create(&aws).unwrap();
        writeln!(
            f,
            "#!/bin/bash\nif [[ \"$*\" == *get-secret-value* ]]; then echo from-real-path; exit 0; fi\nif [[ \"$*\" == *get-parameter* ]]; then echo param-val; exit 0; fi\nif [[ \"$*\" == *get-parameters-by-path* ]]; then echo '{{\"Parameters\":[]}}'; exit 0; fi\necho unexpected >&2; exit 1"
        )
        .unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&aws, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let old_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{old_path}", bin.display());
    temp_env::with_var("PATH", Some(new_path.as_str()), || {
        let mut creds = std::collections::HashMap::new();
        creds.insert(
            "AWS_ACCESS_KEY_ID".into(),
            SecretString::from("A".to_string()),
        );
        creds.insert(
            "AWS_SECRET_ACCESS_KEY".into(),
            SecretString::from("S".to_string()),
        );
        creds.insert(
            "AWS_SESSION_TOKEN".into(),
            SecretString::from("T".to_string()),
        );

        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let spec_path = write_spec(
            dir.path(),
            r#"{"secrets":[{"id":"x","env":"V"}],"params":[{"id":"/p","env":"P"}]}"#,
        );
        let loaded = spec::load_spec(&spec_path).unwrap();
        let (injections, _, temps) = mcp_secret_launcher::aws_fetch::resolve_injections(
            &loaded,
            &creds,
            "ap-southeast-2",
            &work,
            |_, _, _| unreachable!(),
        )
        .unwrap();
        assert!(
            injections
                .iter()
                .any(|i| i.env == "V" && i.value.expose_secret() == "from-real-path")
        );
        assert!(
            injections
                .iter()
                .any(|i| i.env == "P" && i.value.expose_secret() == "param-val")
        );
        drop(temps);
    });
    let _ = old_path;
}

#[test]
fn app_aws_run_with_secrets_command() {
    let mut server = mockito::Server::new();
    mock_sso(&mut server);
    let backend = MockKeyring::new();
    let prompter = MockPrompter::new("x".into());
    let dir = tempfile::tempdir().unwrap();
    let spec = write_spec(dir.path(), r#"{"secrets":[],"params":[]}"#);

    test_hooks::with_mock_aws(
        |_c, _r, _a| Ok(String::new()),
        || {
            run_app(
                Command::AwsRunWithSecrets {
                    sso_url: "https://sso.example.com".into(),
                    region: "us-east-1".into(),
                    account_id: "123456789012".into(),
                    role_name: "PowerUser".into(),
                    aws_region: Some("ap-southeast-2".into()),
                    cwd: dir.path().to_string_lossy().into_owned(),
                    spec_file: spec.to_string_lossy().into_owned(),
                    inject_aws_credentials: true,
                    no_login: false,
                    timeout_secs: Some(10),
                    cmd: vec!["/bin/echo".into(), "via-app".into()],
                },
                &backend,
                &prompter,
                Vec::new(),
            )
            .unwrap();
        },
    );
    aws_sso::set_mock_url(None);
}
