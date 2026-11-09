use clap::{Parser, Subcommand};

/// Command-line arguments for the MCP Secret Launcher.
#[derive(Parser)]
#[command(
    name = "mcp-secret-launcher",
    version,
    about = "Secure MCP server launcher"
)]
pub struct Cli {
    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands.
#[derive(Subcommand)]
pub enum Command {
    /// Retrieve secrets and launch the target command
    Run {
        /// The profile to use for retrieving secrets.
        #[arg(long)]
        profile: String,
        /// Target command and arguments (after --)
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Authenticate via AWS SSO and launch the target command
    AwsAuth {
        /// The AWS SSO start URL
        #[arg(long = "sso-url")]
        sso_url: String,
        /// The AWS region for the SSO portal
        #[arg(long)]
        region: String,
        /// The AWS account ID
        #[arg(long = "account-id")]
        account_id: String,
        /// The IAM role name to assume
        #[arg(long = "role-name")]
        role_name: String,
        /// Optional profile to load standard secrets alongside AWS credentials
        #[arg(long)]
        profile: Option<String>,
        /// Never start the interactive device-authorization flow: if no valid
        /// cached SSO token exists, fail fast instead of opening a browser.
        /// Intended for headless callers such as a stdio MCP server. A
        /// non-interactive stdin (not a TTY) implies this automatically.
        #[arg(long = "no-login")]
        no_login: bool,
        /// Target command and arguments (after --)
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// List the AWS SSO accounts and roles you can access, as JSON on stdout
    AwsAccounts {
        /// The AWS SSO start URL
        #[arg(long = "sso-url")]
        sso_url: String,
        /// The AWS region for the SSO portal
        #[arg(long)]
        region: String,
        /// Only return this AWS account ID
        #[arg(long = "account-id")]
        account_id: Option<String>,
        /// Never start the interactive device-authorization flow: if no valid
        /// cached SSO token exists, fail fast instead of opening a browser.
        /// Intended for headless callers such as a stdio MCP server. A
        /// non-interactive stdin (not a TTY) implies this automatically.
        #[arg(long = "no-login")]
        no_login: bool,
    },
    /// Fetch Secrets Manager / SSM values, inject as env or temp files, run a
    /// command, redact secret values from captured output, and print a JSON
    /// result envelope on stdout. Never prints secret values.
    AwsRunWithSecrets {
        /// The AWS SSO start URL
        #[arg(long = "sso-url")]
        sso_url: String,
        /// The AWS region for the SSO portal
        #[arg(long)]
        region: String,
        /// The AWS account ID used for SSO role credentials
        #[arg(long = "account-id")]
        account_id: String,
        /// The IAM role name to assume
        #[arg(long = "role-name")]
        role_name: String,
        /// Region for Secrets Manager / SSM fetches and the child's `AWS_REGION`
        #[arg(long = "aws-region")]
        aws_region: Option<String>,
        /// Working directory for the child process
        #[arg(long)]
        cwd: String,
        /// Path to a JSON specification of secret/param IDs (never values)
        #[arg(long = "spec-file")]
        spec_file: String,
        /// Inject `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` into the child
        #[arg(long = "inject-aws-credentials", default_value_t = true, action = clap::ArgAction::Set)]
        inject_aws_credentials: bool,
        /// Never start the interactive device-authorization flow
        #[arg(long = "no-login")]
        no_login: bool,
        /// Optional timeout hint in seconds (enforced by the MCP parent)
        #[arg(long = "timeout-secs")]
        timeout_secs: Option<u64>,
        /// Target command and arguments (after --)
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Probe whether a cached SSO token is still valid. Never starts device login.
    /// Prints JSON: `{"status":"ok","expires_at":...}` or
    /// `{"status":"login_required","login_url":"..."}`.
    AwsSessionStatus {
        /// The AWS SSO start URL
        #[arg(long = "sso-url")]
        sso_url: String,
        /// The AWS region for the SSO portal (accepted for symmetry; unused)
        #[arg(long)]
        region: String,
    },
    /// Store a secret in the keyring (interactive prompt)
    Set {
        /// The profile to store the secret under.
        #[arg(long)]
        profile: String,
        /// The key identifying the secret.
        #[arg(long)]
        key: String,
    },
    /// Retrieve and display a masked secret
    Get {
        /// The profile to retrieve the secret from.
        #[arg(long)]
        profile: String,
        /// The key identifying the secret.
        #[arg(long)]
        key: String,
    },
    /// List all key names for a profile
    List {
        /// The profile to list keys for.
        #[arg(long)]
        profile: String,
    },
    /// Remove a secret from the keyring and manifest
    Delete {
        /// The profile to delete the secret from.
        #[arg(long)]
        profile: String,
        /// The key identifying the secret to delete.
        #[arg(long)]
        key: String,
    },
}
