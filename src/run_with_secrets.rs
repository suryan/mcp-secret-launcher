//! Orchestrate SSO → fetch secrets/params → spawn child → redact → JSON result.

use crate::aws_fetch::{self, Injection};
use crate::aws_sso::{self, LoginMode};
use crate::keyring_ops::KeyringBackend;
use crate::redact;
use crate::runner;
use crate::spec;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Result envelope printed on launcher stdout for mcp-aws-shell to parse.
#[derive(Debug, Serialize)]
pub struct RunResult {
    /// Child exit code, or `None` if killed by signal.
    pub exit_code: Option<i32>,
    /// Redacted stdout.
    pub stdout: String,
    /// Redacted stderr.
    pub stderr: String,
    /// Whether the child was killed due to timeout.
    pub timed_out: bool,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u128,
}

/// Inputs for a single `aws-run-with-secrets` invocation.
pub struct RunWithSecretsRequest<'a> {
    /// SSO start URL.
    pub sso_url: &'a str,
    /// SSO portal region.
    pub sso_region: &'a str,
    /// Primary account id.
    pub account_id: &'a str,
    /// Primary role name.
    pub role_name: &'a str,
    /// AWS region for SM/SSM fetches and child `AWS_REGION`.
    pub aws_region: &'a str,
    /// Working directory for the child.
    pub cwd: &'a Path,
    /// Path to the IDs-only JSON specification.
    pub spec_file: &'a Path,
    /// Whether to inject AWS credentials into the child.
    pub inject_aws_credentials: bool,
    /// Login behaviour when no cached SSO token exists.
    pub login_mode: LoginMode,
    /// Child argv (interpreter + args).
    pub cmd: &'a [String],
    /// Optional timeout; `None` means wait indefinitely.
    pub timeout: Option<Duration>,
}

/// Run the full aws-run-with-secrets flow and print a JSON [`RunResult`] on stdout.
///
/// # Errors
/// Returns an error if SSO, fetch, spawn, or spec loading fails.
pub fn run(backend: &dyn KeyringBackend, req: &RunWithSecretsRequest<'_>) -> anyhow::Result<()> {
    let outcome = run_inner(backend, req)?;
    // stdout is reserved for the JSON envelope (mcp-aws-shell parses it).
    println!("{}", serde_json::to_string(&outcome)?);
    Ok(())
}

fn run_inner(
    backend: &dyn KeyringBackend,
    req: &RunWithSecretsRequest<'_>,
) -> anyhow::Result<RunResult> {
    let started = Instant::now();
    let spec = spec::load_spec(req.spec_file)?;

    let base_creds = aws_sso::get_aws_credentials(
        backend,
        req.sso_url,
        req.sso_region,
        req.account_id,
        req.role_name,
        req.login_mode,
    )?;

    let temp_dir = std::env::temp_dir().join(format!(
        "mcp-aws-run-secrets-{}-{}",
        std::process::id(),
        started.elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir)?;

    let (injections, redact_values, temps) = aws_fetch::resolve_injections(
        &spec,
        &base_creds,
        req.aws_region,
        &temp_dir,
        |account, role, region| {
            // region here is the fetch region; SSO portal region stays req.sso_region.
            let _ = region;
            aws_sso::get_aws_credentials(
                backend,
                req.sso_url,
                req.sso_region,
                account,
                role,
                req.login_mode,
            )
        },
    )?;

    let env = build_child_env(
        &injections,
        if req.inject_aws_credentials {
            Some(&base_creds)
        } else {
            None
        },
        req.aws_region,
    );

    // Drop credential maps we no longer need before waiting on the child.
    drop(base_creds);

    let capture = runner::spawn_capture(req.cmd, env, req.cwd, req.timeout)?;

    // Ensure temp secret files are gone before we return output.
    drop(temps);
    let _ = std::fs::remove_dir_all(&temp_dir);

    let stdout = redact::redact_output(&capture.stdout, &redact_values);
    let stderr = redact::redact_output(&capture.stderr, &redact_values);
    drop(redact_values);
    drop(injections);

    Ok(RunResult {
        exit_code: capture.exit_code,
        stdout,
        stderr,
        timed_out: capture.timed_out,
        duration_ms: started.elapsed().as_millis(),
    })
}

fn build_child_env(
    injections: &[Injection],
    aws_creds: Option<&HashMap<String, SecretString>>,
    aws_region: &str,
) -> HashMap<String, SecretString> {
    let mut secrets = HashMap::new();
    if let Some(creds) = aws_creds {
        for (k, v) in creds {
            // Re-wrap so we don't move out of the map.
            secrets.insert(k.clone(), SecretString::from(v.expose_secret().to_string()));
        }
    }
    secrets.insert(
        "AWS_REGION".to_string(),
        SecretString::from(aws_region.to_string()),
    );
    secrets.insert(
        "AWS_DEFAULT_REGION".to_string(),
        SecretString::from(aws_region.to_string()),
    );
    secrets.insert(
        "AWS_CONFIG_FILE".to_string(),
        SecretString::from("/dev/null".to_string()),
    );
    secrets.insert(
        "AWS_SHARED_CREDENTIALS_FILE".to_string(),
        SecretString::from("/dev/null".to_string()),
    );
    secrets.insert("AWS_PAGER".to_string(), SecretString::from(String::new()));

    for inj in injections {
        secrets.insert(
            inj.env.clone(),
            SecretString::from(inj.value.expose_secret().to_string()),
        );
    }

    runner::build_clean_env(secrets)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    fn expand_json_local(raw: &str, prefix: &str) -> Vec<(String, String)> {
        let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(raw).unwrap();
        obj.into_iter()
            .map(|(k, v)| {
                let text = match v {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                };
                (format!("{prefix}{}", aws_fetch::to_env_key(&k)), text)
            })
            .collect()
    }

    #[test]
    fn build_child_env_is_clean_plus_injections() {
        let injections = vec![Injection {
            env: "FOO".to_string(),
            value: SecretString::from("bar".to_string()),
            temp_path: None,
        }];
        let env = build_child_env(&injections, None, "ap-southeast-2");
        assert_eq!(env.get("FOO").unwrap().expose_secret(), "bar");
        assert_eq!(
            env.get("AWS_REGION").unwrap().expose_secret(),
            "ap-southeast-2"
        );
        assert!(env.contains_key("AWS_CONFIG_FILE"));
    }

    #[test]
    fn load_and_run_echo_with_local_spec() {
        // End-to-end without AWS: empty secrets, just echo.
        let dir = std::env::temp_dir().join(format!("rws-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let spec_path = dir.join("spec.json");
        {
            let mut f = std::fs::File::create(&spec_path).unwrap();
            f.write_all(br#"{"secrets":[],"params":[]}"#).unwrap();
        }

        let env = build_child_env(&[], None, "ap-southeast-2");
        let capture = runner::spawn_capture(
            &["/bin/echo".to_string(), "hello-rws".to_string()],
            env,
            &dir,
            Some(Duration::from_secs(5)),
        )
        .unwrap();
        assert_eq!(capture.exit_code, Some(0));
        assert!(capture.stdout.contains("hello-rws"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expand_json_local_prefixes() {
        let pairs = expand_json_local(r#"{"clientId":"abc","jwtSigningKey":"pem"}"#, "SF_");
        assert!(pairs.iter().any(|(k, v)| k == "SF_CLIENTID" && v == "abc"));
        assert!(
            pairs
                .iter()
                .any(|(k, v)| k == "SF_JWTSIGNINGKEY" && v == "pem")
        );
    }
}
