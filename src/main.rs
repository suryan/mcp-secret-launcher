//! Main entry point for the MCP Secret Launcher.

use clap::Parser;
use mcp_secret_launcher::cli::{Cli, Command};
use mcp_secret_launcher::keyring_ops::{self, KeyringBackend, OsKeyring};
use mcp_secret_launcher::masking::mask_value;
use mcp_secret_launcher::prompter::{SecretPrompter, TerminalPrompter};
use secrecy::ExposeSecret;

use mcp_secret_launcher::runner;
fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let backend = OsKeyring;

    match cli.command {
        Command::Run { profile, cmd } => {
            let secrets = keyring_ops::load_secrets(&backend, &profile)?;
            let env = runner::build_env(secrets, std::env::vars());

            #[cfg(unix)]
            {
                runner::exec_command(&cmd, env)?;
            }

            #[cfg(windows)]
            {
                let code = runner::spawn_command(&cmd, env)?;
                std::process::exit(code);
            }
        }

        Command::Set { profile, key } => {
            let prompter = TerminalPrompter;
            let value = prompter.prompt_secret("Enter secret value: ")?;
            keyring_ops::store_secret(&backend, &profile, &key, &value)?;
            eprintln!("Secret '{key}' stored for profile '{profile}'");
        }

        Command::Get { profile, key } => {
            let secret = backend.get_secret(&profile, &key)?;
            let masked = mask_value(secret.expose_secret());
            println!("{key} = {masked}");
        }

        Command::List { profile } => {
            let keys = keyring_ops::list_keys_with_healing(&backend, &profile)?;
            for key in keys {
                println!("{key}");
            }
        }

        Command::Delete { profile, key } => {
            keyring_ops::delete_secret(&backend, &profile, &key)?;
            eprintln!("Secret '{key}' deleted from profile '{profile}'");
        }
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}
