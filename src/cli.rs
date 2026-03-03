use clap::{Parser, Subcommand};

/// Command-line arguments for the MCP Secret Launcher.
#[derive(Parser)]
#[command(name = "mcp-secret-launcher", about = "Secure MCP server launcher")]
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
        /// Target command and arguments (after --)
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
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
