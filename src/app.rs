use crate::cli::Command;
use crate::keyring_ops::{self, KeyringBackend};
use crate::prompter::SecretPrompter;
use crate::{aws_sso, masking, runner};
use secrecy::ExposeSecret;

/// Core execution logic for the MCP Secret Launcher.
/// Extracted from `main.rs` to allow unit testing of the CLI logic.
///
/// # Errors
/// Returns an error if secret retrieval, prompting, or child process execution fails.
pub fn run_app(
    command: Command,
    backend: &dyn KeyringBackend,
    prompter: &dyn SecretPrompter,
    env_vars: Vec<(String, String)>,
) -> anyhow::Result<()> {
    match command {
        Command::Run { profile, cmd } => {
            let secrets = keyring_ops::load_secrets(backend, &profile)?;
            let env = runner::build_env(secrets, env_vars);

            #[cfg(unix)]
            {
                if std::env::var("__MCP_TEST_NO_EXEC").is_ok() {
                    let _ = runner::spawn_command(&cmd, env)?;
                } else {
                    runner::exec_command(&cmd, env)?;
                }
            }

            #[cfg(windows)]
            {
                let code = runner::spawn_command(&cmd, env)?;
                if std::env::var("__MCP_TEST_NO_EXEC").is_err() {
                    std::process::exit(code);
                }
            }
        }

        Command::Set { profile, key } => {
            let value = prompter.prompt_secret("Enter secret value: ")?;
            keyring_ops::store_secret(backend, &profile, &key, &value)?;
            eprintln!("Secret '{key}' stored for profile '{profile}'");
        }

        Command::Get { profile, key } => {
            let secret = backend.get_secret(&profile, &key)?;
            let masked = masking::mask_value(secret.expose_secret());
            println!("{key} = {masked}");
        }

        Command::List { profile } => {
            let keys = keyring_ops::list_keys_with_healing(backend, &profile)?;
            for key in keys {
                println!("{key}");
            }
        }

        Command::Delete { profile, key } => {
            keyring_ops::delete_secret(backend, &profile, &key)?;
            eprintln!("Secret '{key}' deleted from profile '{profile}'");
        }

        Command::AwsAuth {
            sso_url,
            region,
            account_id,
            role_name,
            profile,
            cmd,
        } => {
            // First load AWS credentials
            let mut secrets =
                aws_sso::get_aws_credentials(backend, &sso_url, &region, &account_id, &role_name)?;

            // Then merge with profile secrets if specified
            if let Some(p) = profile {
                let profile_secrets = keyring_ops::load_secrets(backend, &p)?;
                for (k, v) in profile_secrets {
                    secrets.insert(k, v);
                }
            }

            let env = runner::build_env(secrets, env_vars);

            #[cfg(unix)]
            {
                if std::env::var("__MCP_TEST_NO_EXEC").is_ok() {
                    let _ = runner::spawn_command(&cmd, env)?;
                } else {
                    runner::exec_command(&cmd, env)?;
                }
            }

            #[cfg(windows)]
            {
                let code = runner::spawn_command(&cmd, env)?;
                if std::env::var("__MCP_TEST_NO_EXEC").is_err() {
                    std::process::exit(code);
                }
            }
        }
    }

    Ok(())
}
