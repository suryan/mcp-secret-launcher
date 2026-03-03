//! Main entry point for the MCP Secret Launcher.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Err(err) = mcp_secret_launcher::run_cli(
        args,
        &mcp_secret_launcher::keyring_ops::OsKeyring,
        &mcp_secret_launcher::prompter::TerminalPrompter,
        std::env::vars().collect(),
    ) {
        if let Some(clap_err) = err.downcast_ref::<clap::Error>() {
            clap_err.exit();
        }
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}
