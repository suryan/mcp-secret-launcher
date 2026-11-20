//! Fetch Secrets Manager / SSM values via the AWS CLI using temporary credentials.

use crate::spec::{ParamEntry, RunSpec, SecretEntry};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A value ready to inject: either an env binding or a temp-file path binding.
#[derive(Debug)]
pub struct Injection {
    /// Environment variable name.
    pub env: String,
    /// Value placed in the environment (secret text, or path to a temp file).
    pub value: SecretString,
    /// When set, `value` is a filesystem path that must be deleted after the run.
    pub temp_path: Option<PathBuf>,
}

/// Hold temp files and delete them on drop.
#[derive(Debug, Default)]
pub struct TempFiles {
    paths: Vec<PathBuf>,
}

impl TempFiles {
    /// Track a path for later deletion.
    pub fn track(&mut self, path: PathBuf) {
        self.paths.push(path);
    }
}

impl Drop for TempFiles {
    fn drop(&mut self) {
        for p in &self.paths {
            let _ = std::fs::remove_file(p);
        }
        self.paths.clear();
    }
}

/// Resolve all secrets and params in `spec` into injections.
///
/// `base_creds` are SSO role credentials for the primary account/role.
/// `cred_factory` obtains credentials for an (account, role, region) override.
///
/// # Errors
/// Returns an error if the AWS CLI fails, JSON parsing fails, or an entry is malformed.
#[allow(clippy::implicit_hasher)]
pub fn resolve_injections<F>(
    spec: &RunSpec,
    base_creds: &HashMap<String, SecretString>,
    default_region: &str,
    temp_dir: &Path,
    mut cred_factory: F,
) -> anyhow::Result<(Vec<Injection>, Vec<SecretString>, TempFiles)>
where
    F: FnMut(&str, &str, &str) -> anyhow::Result<HashMap<String, SecretString>>,
{
    let mut injections = Vec::new();
    let mut redact_values = Vec::new();
    let mut temps = TempFiles::default();
    let mut override_cache: HashMap<(String, String, String), HashMap<String, SecretString>> =
        HashMap::new();

    for (i, entry) in spec.secrets.iter().enumerate() {
        let region = entry.region.as_deref().unwrap_or(default_region);
        let creds = select_creds(
            base_creds,
            &mut override_cache,
            &mut cred_factory,
            entry.account.as_deref(),
            entry.role.as_deref(),
            region,
        )?;
        let raw = get_secret_string(creds, region, &entry.id)
            .map_err(|e| anyhow::anyhow!("secrets[{i}] id={}: {e}", entry.id))?;
        apply_secret_entry(
            entry,
            &raw,
            temp_dir,
            &mut injections,
            &mut redact_values,
            &mut temps,
        )?;
    }

    for (i, entry) in spec.params.iter().enumerate() {
        let region = entry.region.as_deref().unwrap_or(default_region);
        let creds = select_creds(
            base_creds,
            &mut override_cache,
            &mut cred_factory,
            entry.account.as_deref(),
            entry.role.as_deref(),
            region,
        )?;
        apply_param_entry(entry, creds, region, i, &mut injections, &mut redact_values)?;
    }

    Ok((injections, redact_values, temps))
}

fn select_creds<'a, F>(
    base_creds: &'a HashMap<String, SecretString>,
    cache: &'a mut HashMap<(String, String, String), HashMap<String, SecretString>>,
    factory: &mut F,
    account: Option<&str>,
    role: Option<&str>,
    region: &str,
) -> anyhow::Result<&'a HashMap<String, SecretString>>
where
    F: FnMut(&str, &str, &str) -> anyhow::Result<HashMap<String, SecretString>>,
{
    match (account, role) {
        (None, None) => Ok(base_creds),
        (Some(a), Some(r)) => {
            let key = (a.to_string(), r.to_string(), region.to_string());
            if let std::collections::hash_map::Entry::Vacant(e) = cache.entry(key.clone()) {
                e.insert(factory(a, r, region)?);
            }
            cache
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("credential cache miss after insert"))
        }
        _ => anyhow::bail!(
            "secret/param account and role overrides must both be set or both omitted"
        ),
    }
}

fn apply_secret_entry(
    entry: &SecretEntry,
    raw: &str,
    temp_dir: &Path,
    injections: &mut Vec<Injection>,
    redact_values: &mut Vec<SecretString>,
    temps: &mut TempFiles,
) -> anyhow::Result<()> {
    if entry.expand_json {
        let prefix = entry.prefix.as_deref().unwrap_or("");
        let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(raw)
            .map_err(|e| anyhow::anyhow!("expand_json: secret is not a JSON object: {e}"))?;
        for (k, v) in obj {
            let text = json_value_to_string(&v);
            let env_name = format!("{prefix}{}", to_env_key(&k));
            redact_values.push(SecretString::from(text.clone()));
            injections.push(Injection {
                env: env_name,
                value: SecretString::from(text),
                temp_path: None,
            });
        }
        // Also redact the raw JSON blob if it leaks.
        redact_values.push(SecretString::from(raw.to_string()));
        return Ok(());
    }

    let value = if let Some(key) = entry.json_key.as_deref() {
        extract_json_key(raw, key)?
    } else {
        raw.to_string()
    };
    redact_values.push(SecretString::from(value.clone()));

    let env_name = entry
        .env
        .clone()
        .ok_or_else(|| anyhow::anyhow!("env is required"))?;

    if entry.file {
        let path = write_temp_secret(temp_dir, &value)?;
        temps.track(path.clone());
        injections.push(Injection {
            env: env_name,
            value: SecretString::from(path.to_string_lossy().into_owned()),
            temp_path: Some(path),
        });
    } else {
        injections.push(Injection {
            env: env_name,
            value: SecretString::from(value),
            temp_path: None,
        });
    }
    Ok(())
}

fn apply_param_entry(
    entry: &ParamEntry,
    creds: &HashMap<String, SecretString>,
    region: &str,
    index: usize,
    injections: &mut Vec<Injection>,
    redact_values: &mut Vec<SecretString>,
) -> anyhow::Result<()> {
    if let Some(id) = entry.id.as_deref() {
        let value = get_parameter(creds, region, id)
            .map_err(|e| anyhow::anyhow!("params[{index}] id={id}: {e}"))?;
        redact_values.push(SecretString::from(value.clone()));
        let env_name = entry
            .env
            .clone()
            .ok_or_else(|| anyhow::anyhow!("params[{index}]: env required"))?;
        injections.push(Injection {
            env: env_name,
            value: SecretString::from(value),
            temp_path: None,
        });
        return Ok(());
    }

    let path = entry
        .path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("params[{index}]: path required"))?;
    let prefix = entry.prefix.as_deref().unwrap_or("");
    let pairs = get_parameters_by_path(creds, region, path, entry.recursive)
        .map_err(|e| anyhow::anyhow!("params[{index}] path={path}: {e}"))?;
    for (name, value) in pairs {
        let suffix = name
            .strip_prefix(path)
            .unwrap_or(name.as_str())
            .trim_start_matches('/');
        let env_name = format!("{prefix}{}", to_env_key(suffix));
        redact_values.push(SecretString::from(value.clone()));
        injections.push(Injection {
            env: env_name,
            value: SecretString::from(value),
            temp_path: None,
        });
    }
    Ok(())
}

fn get_secret_string(
    creds: &HashMap<String, SecretString>,
    region: &str,
    secret_id: &str,
) -> anyhow::Result<String> {
    let out = run_aws(
        creds,
        region,
        &[
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            secret_id,
            "--query",
            "SecretString",
            "--output",
            "text",
        ],
    )?;
    Ok(out.trim_end_matches('\n').to_string())
}

fn get_parameter(
    creds: &HashMap<String, SecretString>,
    region: &str,
    name: &str,
) -> anyhow::Result<String> {
    let out = run_aws(
        creds,
        region,
        &[
            "ssm",
            "get-parameter",
            "--name",
            name,
            "--with-decryption",
            "--query",
            "Parameter.Value",
            "--output",
            "text",
        ],
    )?;
    Ok(out.trim_end_matches('\n').to_string())
}

#[derive(Debug, Deserialize)]
struct SsmParameter {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Debug, Deserialize)]
struct SsmByPathOut {
    #[serde(rename = "Parameters")]
    parameters: Vec<SsmParameter>,
}

fn get_parameters_by_path(
    creds: &HashMap<String, SecretString>,
    region: &str,
    path: &str,
    recursive: bool,
) -> anyhow::Result<Vec<(String, String)>> {
    let mut args = vec![
        "ssm",
        "get-parameters-by-path",
        "--path",
        path,
        "--with-decryption",
        "--output",
        "json",
    ];
    if recursive {
        args.push("--recursive");
    }
    let out = run_aws(creds, region, &args)?;
    let parsed: SsmByPathOut = serde_json::from_str(&out)
        .map_err(|e| anyhow::anyhow!("ssm get-parameters-by-path JSON: {e}"))?;
    Ok(parsed
        .parameters
        .into_iter()
        .map(|p| (p.name, p.value))
        .collect())
}

fn run_aws(
    creds: &HashMap<String, SecretString>,
    region: &str,
    args: &[&str],
) -> anyhow::Result<String> {
    #[cfg(any(test, feature = "test-utils"))]
    if let Some(result) = test_hooks::try_mock(creds, region, args) {
        return result;
    }
    run_aws_real(creds, region, args)
}

fn run_aws_real(
    creds: &HashMap<String, SecretString>,
    region: &str,
    args: &[&str],
) -> anyhow::Result<String> {
    let mut cmd = Command::new("aws");
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for key in ["PATH", "HOME", "LANG", "LC_ALL"] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    for (k, v) in creds {
        cmd.env(k, v.expose_secret());
    }
    cmd.env("AWS_REGION", region);
    cmd.env("AWS_DEFAULT_REGION", region);
    cmd.env("AWS_CONFIG_FILE", "/dev/null");
    cmd.env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null");
    cmd.env("AWS_PAGER", "");

    let output = cmd
        .output()
        .map_err(|e| anyhow::anyhow!("failed to spawn aws CLI: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "aws {} failed (exit {:?}): {stderr}",
            args.first().unwrap_or(&""),
            output.status.code()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Test-only hooks so unit/integration tests can exercise fetch/inject without a real AWS CLI.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_hooks {
    use secrecy::SecretString;
    use std::cell::RefCell;
    use std::collections::HashMap;

    type AwsMockFn =
        Box<dyn Fn(&HashMap<String, SecretString>, &str, &[&str]) -> anyhow::Result<String>>;

    thread_local! {
        static MOCK: RefCell<Option<AwsMockFn>> = const { RefCell::new(None) };
    }

    /// Install a mock AWS CLI for the duration of `body`.
    pub fn with_mock_aws<R>(
        mock: impl Fn(&HashMap<String, SecretString>, &str, &[&str]) -> anyhow::Result<String> + 'static,
        body: impl FnOnce() -> R,
    ) -> R {
        MOCK.with(|c| {
            *c.borrow_mut() = Some(Box::new(mock));
        });
        let result = body();
        MOCK.with(|c| {
            *c.borrow_mut() = None;
        });
        result
    }

    pub(super) fn try_mock(
        creds: &HashMap<String, SecretString>,
        region: &str,
        args: &[&str],
    ) -> Option<anyhow::Result<String>> {
        MOCK.with(|c| c.borrow().as_ref().map(|f| f(creds, region, args)))
    }
}

fn extract_json_key(raw: &str, key: &str) -> anyhow::Result<String> {
    let v: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| anyhow::anyhow!("secret is not JSON (needed for json_key): {e}"))?;
    let val = v
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("json_key '{key}' not found in secret"))?;
    Ok(json_value_to_string(val))
}

fn json_value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Map a JSON/SSM key to an env-safe suffix: non-alnum → `_`, uppercased.
#[must_use]
pub fn to_env_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn write_temp_secret(temp_dir: &Path, value: &str) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(temp_dir)?;
    let name = format!("mcp-secret-{}-{}", std::process::id(), random_suffix());
    let path = temp_dir.join(name);
    {
        let mut f = std::fs::File::create(&path)?;
        f.write_all(value.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

fn random_suffix() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    h.finish()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::spec::{ParamEntry, RunSpec, SecretEntry};
    use secrecy::ExposeSecret;

    fn base_creds() -> HashMap<String, SecretString> {
        let mut m = HashMap::new();
        m.insert(
            "AWS_ACCESS_KEY_ID".into(),
            SecretString::from("AKIATEST".to_string()),
        );
        m.insert(
            "AWS_SECRET_ACCESS_KEY".into(),
            SecretString::from("secret".to_string()),
        );
        m.insert(
            "AWS_SESSION_TOKEN".into(),
            SecretString::from("token".to_string()),
        );
        m
    }

    #[test]
    fn env_key_sanitizes() {
        assert_eq!(to_env_key("clientId"), "CLIENTID");
        assert_eq!(to_env_key("jwt-signing-key"), "JWT_SIGNING_KEY");
        assert_eq!(to_env_key("a/b/c"), "A_B_C");
    }

    #[test]
    fn extract_json_key_works() {
        let raw = r#"{"clientId":"abc","n":1}"#;
        assert_eq!(extract_json_key(raw, "clientId").unwrap(), "abc");
        assert_eq!(extract_json_key(raw, "n").unwrap(), "1");
        assert!(extract_json_key("not-json", "x").is_err());
        assert!(extract_json_key(r#"{"a":1}"#, "missing").is_err());
    }

    #[test]
    fn write_temp_is_0600() {
        let dir = std::env::temp_dir().join(format!("mcp-secret-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_temp_secret(&dir, "secret-bytes").unwrap();
        let read = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read, "secret-bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_json_key_env_and_file_and_expand() {
        test_hooks::with_mock_aws(
            |_creds, _region, args| {
                if args.contains(&"get-secret-value") {
                    let id = args
                        .iter()
                        .position(|a| *a == "--secret-id")
                        .map_or("", |i| args[i + 1]);
                    match id {
                        "plain" => Ok("plain-value\n".into()),
                        "json-one" => Ok(r#"{"clientId":"cid-1"}"#.into()),
                        "json-all" => Ok(r#"{"clientId":"cid","jwtSigningKey":"pem"}"#.into()),
                        "file-secret" => Ok("file-bytes".into()),
                        other => anyhow::bail!("unknown secret {other}"),
                    }
                } else {
                    anyhow::bail!("unexpected aws args: {args:?}")
                }
            },
            || {
                let dir = std::env::temp_dir().join(format!("rws-inj-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                let spec = RunSpec {
                    secrets: vec![
                        SecretEntry {
                            source: "secretsmanager".into(),
                            id: "plain".into(),
                            json_key: None,
                            env: Some("PLAIN".into()),
                            file: false,
                            expand_json: false,
                            prefix: None,
                            account: None,
                            role: None,
                            region: None,
                        },
                        SecretEntry {
                            source: "secretsmanager".into(),
                            id: "json-one".into(),
                            json_key: Some("clientId".into()),
                            env: Some("SF_CLIENT_ID".into()),
                            file: false,
                            expand_json: false,
                            prefix: None,
                            account: None,
                            role: None,
                            region: None,
                        },
                        SecretEntry {
                            source: "secretsmanager".into(),
                            id: "json-all".into(),
                            json_key: None,
                            env: None,
                            file: false,
                            expand_json: true,
                            prefix: Some("SF_".into()),
                            account: None,
                            role: None,
                            region: None,
                        },
                        SecretEntry {
                            source: "secretsmanager".into(),
                            id: "file-secret".into(),
                            json_key: None,
                            env: Some("SF_KEY_FILE".into()),
                            file: true,
                            expand_json: false,
                            prefix: None,
                            account: None,
                            role: None,
                            region: None,
                        },
                    ],
                    params: vec![],
                };
                let (injections, redacts, temps) =
                    resolve_injections(&spec, &base_creds(), "ap-southeast-2", &dir, |_, _, _| {
                        unreachable!("no overrides")
                    })
                    .unwrap();
                assert!(
                    injections
                        .iter()
                        .any(|i| i.env == "PLAIN" && i.value.expose_secret() == "plain-value")
                );
                assert!(
                    injections
                        .iter()
                        .any(|i| i.env == "SF_CLIENT_ID" && i.value.expose_secret() == "cid-1")
                );
                assert!(injections.iter().any(|i| i.env == "SF_CLIENTID"));
                assert!(injections.iter().any(|i| i.env == "SF_JWTSIGNINGKEY"));
                let file_inj = injections.iter().find(|i| i.env == "SF_KEY_FILE").unwrap();
                let path = std::path::Path::new(file_inj.value.expose_secret());
                assert!(path.is_file());
                assert_eq!(std::fs::read_to_string(path).unwrap(), "file-bytes");
                assert!(!redacts.is_empty());
                drop(temps);
                let _ = std::fs::remove_dir_all(&dir);
            },
        );
    }

    #[test]
    fn resolve_ssm_id_and_path() {
        test_hooks::with_mock_aws(
            |_creds, _region, args| {
                if args.contains(&"get-parameter") {
                    Ok("https://app.example\n".into())
                } else if args.contains(&"get-parameters-by-path") {
                    Ok(r#"{"Parameters":[
                        {"Name":"/app/sit/url","Value":"u1"},
                        {"Name":"/app/sit/token","Value":"t1"}
                    ]}"#
                    .into())
                } else {
                    anyhow::bail!("unexpected {args:?}")
                }
            },
            || {
                let dir = std::env::temp_dir().join(format!("rws-ssm-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                let spec = RunSpec {
                    secrets: vec![],
                    params: vec![
                        ParamEntry {
                            source: "ssm".into(),
                            id: Some("/app/url".into()),
                            path: None,
                            recursive: false,
                            env: Some("APP_URL".into()),
                            prefix: None,
                            account: None,
                            role: None,
                            region: None,
                        },
                        ParamEntry {
                            source: "ssm".into(),
                            id: None,
                            path: Some("/app/sit/".into()),
                            recursive: true,
                            env: None,
                            prefix: Some("APP_".into()),
                            account: None,
                            role: None,
                            region: None,
                        },
                    ],
                };
                let (injections, _, temps) = resolve_injections(
                    &spec,
                    &base_creds(),
                    "ap-southeast-2",
                    &dir,
                    |_, _, _| unreachable!(),
                )
                .unwrap();
                assert!(injections.iter().any(
                    |i| i.env == "APP_URL" && i.value.expose_secret() == "https://app.example"
                ));
                assert!(
                    injections
                        .iter()
                        .any(|i| i.env == "APP_URL" || i.env.starts_with("APP_"))
                );
                assert!(injections.iter().any(|i| i.env == "APP_TOKEN"));
                drop(temps);
                let _ = std::fs::remove_dir_all(&dir);
            },
        );
    }

    #[test]
    fn account_role_override_uses_factory() {
        test_hooks::with_mock_aws(
            |creds, _region, args| {
                assert!(creds.contains_key("AWS_ACCESS_KEY_ID"));
                if args.contains(&"get-secret-value") {
                    Ok("from-other-account".into())
                } else {
                    anyhow::bail!("bad args")
                }
            },
            || {
                let dir = std::env::temp_dir().join(format!("rws-ovr-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                let spec = RunSpec {
                    secrets: vec![SecretEntry {
                        source: "secretsmanager".into(),
                        id: "x".into(),
                        json_key: None,
                        env: Some("X".into()),
                        file: false,
                        expand_json: false,
                        prefix: None,
                        account: Some("999999999999".into()),
                        role: Some("OtherRole".into()),
                        region: Some("us-east-1".into()),
                    }],
                    params: vec![],
                };
                let mut calls = 0_u32;
                let (injections, _, temps) = resolve_injections(
                    &spec,
                    &base_creds(),
                    "ap-southeast-2",
                    &dir,
                    |account, role, region| {
                        calls += 1;
                        assert_eq!(account, "999999999999");
                        assert_eq!(role, "OtherRole");
                        assert_eq!(region, "us-east-1");
                        let mut c = base_creds();
                        c.insert(
                            "AWS_ACCESS_KEY_ID".into(),
                            SecretString::from("OTHER".to_string()),
                        );
                        Ok(c)
                    },
                )
                .unwrap();
                assert_eq!(calls, 1);
                assert_eq!(injections[0].value.expose_secret(), "from-other-account");
                drop(temps);
                let _ = std::fs::remove_dir_all(&dir);
            },
        );
    }

    #[test]
    fn partial_account_override_errors() {
        let dir = std::env::temp_dir().join(format!("rws-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let spec = RunSpec {
            secrets: vec![SecretEntry {
                source: "secretsmanager".into(),
                id: "x".into(),
                json_key: None,
                env: Some("X".into()),
                file: false,
                expand_json: false,
                prefix: None,
                account: Some("1".into()),
                role: None,
                region: None,
            }],
            params: vec![],
        };
        let err = resolve_injections(
            &spec,
            &base_creds(),
            "ap-southeast-2",
            &dir,
            |_, _, _| unreachable!(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("both"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn aws_cli_failure_surfaces() {
        test_hooks::with_mock_aws(
            |_c, _r, _a| anyhow::bail!("aws boom"),
            || {
                let dir = std::env::temp_dir().join(format!("rws-fail-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                let spec = RunSpec {
                    secrets: vec![SecretEntry {
                        source: "secretsmanager".into(),
                        id: "x".into(),
                        json_key: None,
                        env: Some("X".into()),
                        file: false,
                        expand_json: false,
                        prefix: None,
                        account: None,
                        role: None,
                        region: None,
                    }],
                    params: vec![],
                };
                assert!(
                    resolve_injections(&spec, &base_creds(), "ap-southeast-2", &dir, |_, _, _| {
                        unreachable!()
                    })
                    .is_err()
                );
                let _ = std::fs::remove_dir_all(&dir);
            },
        );
    }

    #[test]
    fn temp_files_drop_deletes() {
        let dir = std::env::temp_dir().join(format!("rws-drop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_temp_secret(&dir, "bye").unwrap();
        {
            let mut temps = TempFiles::default();
            temps.track(path.clone());
            assert!(path.exists());
        }
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
