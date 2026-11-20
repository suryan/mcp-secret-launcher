//! JSON run-with-secrets specification (IDs and mappings only — never values).

use serde::Deserialize;

/// Top-level fetch/inject specification written by mcp-aws-shell.
#[derive(Debug, Clone, Deserialize)]
pub struct RunSpec {
    /// Secrets Manager entries to fetch and inject.
    #[serde(default)]
    pub secrets: Vec<SecretEntry>,
    /// SSM Parameter Store entries to fetch and inject.
    #[serde(default)]
    pub params: Vec<ParamEntry>,
}

/// One Secrets Manager fetch instruction.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretEntry {
    /// Must be `"secretsmanager"` (reserved for future sources).
    #[serde(default = "default_sm_source")]
    pub source: String,
    /// Secret id or ARN.
    pub id: String,
    /// Optional JSON object key to extract.
    #[serde(default)]
    pub json_key: Option<String>,
    /// Environment variable name for a single value (required unless `expand_json`).
    #[serde(default)]
    pub env: Option<String>,
    /// When true, write the value to a mode-0600 temp file and set `env` to its path.
    #[serde(default)]
    pub file: bool,
    /// When true, parse the secret as JSON and export every key with `prefix`.
    #[serde(default)]
    pub expand_json: bool,
    /// Prefix for `expand_json` keys (e.g. `SF_`).
    #[serde(default)]
    pub prefix: Option<String>,
    /// Optional account override for this entry.
    #[serde(default)]
    pub account: Option<String>,
    /// Optional role override for this entry.
    #[serde(default)]
    pub role: Option<String>,
    /// Optional AWS region override for this fetch.
    #[serde(default)]
    pub region: Option<String>,
}

/// One SSM Parameter Store fetch instruction.
#[derive(Debug, Clone, Deserialize)]
pub struct ParamEntry {
    /// Must be `"ssm"`.
    #[serde(default = "default_ssm_source")]
    pub source: String,
    /// Single parameter name (mutually exclusive with `path`).
    #[serde(default)]
    pub id: Option<String>,
    /// Parameter path prefix for recursive fetch.
    #[serde(default)]
    pub path: Option<String>,
    /// When true with `path`, fetch recursively.
    #[serde(default)]
    pub recursive: bool,
    /// Environment variable for a single parameter.
    #[serde(default)]
    pub env: Option<String>,
    /// Prefix for path-expanded parameter names.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Optional account override.
    #[serde(default)]
    pub account: Option<String>,
    /// Optional role override.
    #[serde(default)]
    pub role: Option<String>,
    /// Optional AWS region override.
    #[serde(default)]
    pub region: Option<String>,
}

fn default_sm_source() -> String {
    "secretsmanager".to_string()
}

fn default_ssm_source() -> String {
    "ssm".to_string()
}

/// Load and parse a run specification from a JSON file.
///
/// # Errors
/// Returns an error if the file cannot be read or is not valid JSON for [`RunSpec`].
pub fn load_spec(path: &std::path::Path) -> anyhow::Result<RunSpec> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read spec file {}: {e}", path.display()))?;
    let spec: RunSpec = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("invalid run-with-secrets spec: {e}"))?;
    validate_spec(&spec)?;
    Ok(spec)
}

fn validate_spec(spec: &RunSpec) -> anyhow::Result<()> {
    for (i, s) in spec.secrets.iter().enumerate() {
        if s.source != "secretsmanager" {
            anyhow::bail!("secrets[{i}]: unsupported source '{}'", s.source);
        }
        if s.id.is_empty() {
            anyhow::bail!("secrets[{i}]: id is required");
        }
        if s.expand_json {
            if s.prefix.as_deref().unwrap_or("").is_empty() {
                anyhow::bail!("secrets[{i}]: expand_json requires prefix");
            }
        } else if s.env.as_deref().unwrap_or("").is_empty() {
            anyhow::bail!("secrets[{i}]: env is required unless expand_json is true");
        }
        if s.file && s.expand_json {
            anyhow::bail!("secrets[{i}]: file and expand_json cannot both be true");
        }
    }
    for (i, p) in spec.params.iter().enumerate() {
        if p.source != "ssm" {
            anyhow::bail!("params[{i}]: unsupported source '{}'", p.source);
        }
        let has_id = p.id.as_deref().is_some_and(|s| !s.is_empty());
        let has_path = p.path.as_deref().is_some_and(|s| !s.is_empty());
        if has_id == has_path {
            anyhow::bail!("params[{i}]: exactly one of id or path is required");
        }
        if has_id && p.env.as_deref().unwrap_or("").is_empty() {
            anyhow::bail!("params[{i}]: env is required for a single parameter id");
        }
        if has_path && p.prefix.as_deref().unwrap_or("").is_empty() {
            anyhow::bail!("params[{i}]: prefix is required for a path fetch");
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_secret() {
        let spec: RunSpec = serde_json::from_str(
            r#"{
              "secrets": [{"id": "my/secret", "env": "FOO"}],
              "params": []
            }"#,
        )
        .unwrap();
        validate_spec(&spec).unwrap();
        assert_eq!(spec.secrets[0].source, "secretsmanager");
        assert_eq!(spec.secrets[0].env.as_deref(), Some("FOO"));
    }

    #[test]
    fn rejects_expand_without_prefix() {
        let spec: RunSpec = serde_json::from_str(
            r#"{"secrets": [{"id": "x", "expand_json": true}], "params": []}"#,
        )
        .unwrap();
        assert!(validate_spec(&spec).is_err());
    }

    #[test]
    fn rejects_param_without_id_or_path() {
        let spec: RunSpec =
            serde_json::from_str(r#"{"secrets": [], "params": [{"env": "X"}]}"#).unwrap();
        assert!(validate_spec(&spec).is_err());
    }
}
