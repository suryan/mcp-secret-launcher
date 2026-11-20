use crate::cli::Command;
use crate::keyring_ops::{self, KeyringBackend};
use crate::prompter::SecretPrompter;
use crate::{aws_sso, masking, run_with_secrets, runner};
use secrecy::ExposeSecret;
use std::path::Path;
use std::time::Duration;

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

        Command::AwsAccounts {
            sso_url,
            region,
            account_id,
            no_login,
        } => {
            // stdout carries only the JSON document; prompts and errors go to stderr.
            let login_mode = aws_sso::LoginMode::resolve(no_login);
            let json = aws_sso::aws_accounts_json(
                backend,
                &sso_url,
                &region,
                account_id.as_deref(),
                login_mode,
            )?;
            println!("{json}");
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
            no_login,
            cmd,
        } => {
            // First load AWS credentials
            let login_mode = aws_sso::LoginMode::resolve(no_login);
            let mut secrets = aws_sso::get_aws_credentials(
                backend,
                &sso_url,
                &region,
                &account_id,
                &role_name,
                login_mode,
            )?;

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

        Command::AwsRunWithSecrets {
            sso_url,
            region,
            account_id,
            role_name,
            aws_region,
            cwd,
            spec_file,
            inject_aws_credentials,
            no_login,
            timeout_secs,
            cmd,
        } => {
            let aws_region = aws_region.unwrap_or_else(|| region.clone());
            let login_mode = aws_sso::LoginMode::resolve(no_login);
            let req = run_with_secrets::RunWithSecretsRequest {
                sso_url: &sso_url,
                sso_region: &region,
                account_id: &account_id,
                role_name: &role_name,
                aws_region: &aws_region,
                cwd: Path::new(&cwd),
                spec_file: Path::new(&spec_file),
                inject_aws_credentials,
                login_mode,
                cmd: &cmd,
                timeout: timeout_secs.map(Duration::from_secs),
            };
            run_with_secrets::run(backend, &req)?;
        }

        Command::AwsSessionStatus { sso_url, region: _ } => {
            let status = aws_sso::aws_session_status(backend, &sso_url);
            println!("{}", serde_json::to_string(&status)?);
        }
    }

    Ok(())
}
