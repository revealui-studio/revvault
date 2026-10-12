mod commands;
pub mod tui_editor;

use clap::{Parser, Subcommand};

const AFTER_HELP: &str = "\
Examples:
  revvault init                                  create the store and age identity
  revvault set revealui/prod/stripe/secret-key   store a secret (hidden prompt)
  revvault get revealui/prod/stripe/secret-key   metadata on a TTY; value when piped
  revvault get --reveal <path>                   print the value on a TTY
  revvault list --prefix revealui/prod           filter paths by prefix
  revvault set <path> --value slug               one-shot set (not for credentials)
  revvault list --tree                           browse the whole store
  revvault export-env revealui/dev/electric      KEY=VALUE lines for shell eval
  revvault run --env KEY=path -- cmd…            secrets in child env only (stream-safe)

Secret paths follow <project>/<subsystem>/<name>, all lower-kebab.
Scripts can pipe instead of prompting:  printf %s \"$VALUE\" | revvault set <path>
Stream-safe: STREAM_SAFE=1 blocks TTY print/clip of values unless REVVAULT_ALLOW_PRINT=1
(use a vault-private terminal for full keys). Prefer `run` / with-secrets on camera.";

#[derive(Parser)]
#[command(
    name = "revvault",
    version,
    about = "Age-encrypted secret vault",
    arg_required_else_help = true,
    after_help = AFTER_HELP
)]
struct Cli {
    /// Output structured JSON instead of human-readable text
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault (create store directory and age identity)
    Init(commands::init::InitArgs),
    /// Decrypt and print a secret
    Get(commands::get::GetArgs),
    /// Load secrets into the child environment only, then exec a command (stream-safe)
    Run(commands::run::RunArgs),
    /// Store a secret (hidden prompt on a terminal, or piped stdin)
    Set(commands::set::SetArgs),
    /// Generate a strong random password (optionally store under a path)
    Generate(commands::generate::GenerateArgs),
    /// List secrets in the store
    List(commands::list::ListArgs),
    /// Fuzzy search for secrets
    Search(commands::search::SearchArgs),
    /// Output KEY=VALUE lines for shell eval
    ExportEnv(commands::export_env::ExportEnvArgs),
    /// Decrypt → $EDITOR → re-encrypt
    Edit(commands::edit::EditArgs),
    /// Delete a secret
    Delete(commands::delete::DeleteArgs),
    /// Generate shell completions
    Completions(commands::completions::CompletionsArgs),
    /// Migrate secrets from external sources
    Migrate(commands::migrate::MigrateArgs),
    /// Rotate API keys for a provider
    Rotate(commands::rotate::RotateArgs),
    /// Promote dual-slot next → live for a rotation.toml provider (GAP-261)
    RotationPromote(commands::rotation_promote::RotationPromoteArgs),
    /// Verify dual-slot next leaves (presence + kid match; no promote)
    RotationVerify(commands::rotation_verify::RotationVerifyArgs),
    /// Show rotation status
    RotationStatus,
    /// Sync vault secrets with external services (e.g., Vercel env vars)
    Sync(commands::sync::SyncArgs),
    /// Vault-only health check: read every manifest entry, validate shape
    Doctor(commands::doctor::DoctorArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let json = cli.json;

    // Service principals can invoke only policy-bound child delivery.
    if revvault_core::service::ServicePolicy::current()?.is_some()
        && !service_command_allowed(&cli.command)
    {
        anyhow::bail!("revvault_service_capability_denied");
    }

    let result = match cli.command {
        Commands::Init(args) => commands::init::run(args, json),
        Commands::Get(args) => commands::get::run(args, json),
        Commands::Run(args) => commands::run::run(args),
        Commands::Set(args) => commands::set::run(args, json),
        Commands::Generate(args) => commands::generate::run(args, json),
        Commands::List(args) => commands::list::run(args, json),
        Commands::Search(args) => commands::search::run(args, json),
        Commands::ExportEnv(args) => commands::export_env::run(args, json),
        Commands::Edit(args) => commands::edit::run(args),
        Commands::Delete(args) => commands::delete::run(args, json),
        Commands::Completions(args) => {
            commands::completions::run(args);
            Ok(())
        }
        Commands::Migrate(args) => commands::migrate::run(args),
        Commands::Rotate(args) => commands::rotate::run(args).await,
        Commands::RotationPromote(args) => commands::rotation_promote::run(args),
        Commands::RotationVerify(args) => commands::rotation_verify::run(args),
        Commands::RotationStatus => commands::rotate::status(),
        Commands::Sync(args) => commands::sync::run(args, json).await,
        Commands::Doctor(args) => commands::doctor::run(args),
    };

    if let Err(ref e) = result {
        if json {
            println!("{}", serde_json::json!({"error": e.to_string()}));
            std::process::exit(1);
        }
    }

    result
}

fn service_command_allowed(command: &Commands) -> bool {
    matches!(command, Commands::Run(_))
}

#[cfg(test)]
mod service_dispatch_tests {
    use super::*;
    #[test]
    fn service_import_cannot_force_rotation_or_print_multiline_input() {
        for option in ["--force", "--multiline"] {
            assert!(Cli::try_parse_from([
                "revvault",
                "set",
                "--service-uid",
                "19001",
                option,
                "revealfleet/publisher/synthetic-key",
            ])
            .is_err());
        }
        assert!(Cli::try_parse_from([
            "revvault",
            "set",
            "--service-uid",
            "19001",
            "revealfleet/publisher/synthetic-key",
        ])
        .is_ok());
    }
    #[test]
    fn service_initialization_cannot_select_personal_paths_or_implicitly_preview() {
        for args in [
            vec![
                "revvault",
                "init",
                "--service-policy",
                "/policy.toml",
                "--store-dir",
                "/personal",
            ],
            vec![
                "revvault",
                "init",
                "--service-policy",
                "/policy.toml",
                "--identity-file",
                "/personal/key",
            ],
            vec!["revvault", "init", "--dry-run"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(Cli::try_parse_from([
            "revvault",
            "init",
            "--service-policy",
            "/policy.toml",
            "--dry-run"
        ])
        .is_ok());
    }
    #[test]
    fn services_cannot_print_export_mutate_or_call_providers() {
        for args in [
            vec!["revvault", "list"],
            vec!["revvault", "get", "revealfleet/publisher/app-key"],
            vec!["revvault", "set", "revealfleet/publisher/app-key"],
            vec!["revvault", "delete", "revealfleet/publisher/app-key"],
            vec!["revvault", "export-env", "revealfleet/publisher/env"],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(!service_command_allowed(&cli.command));
        }
        let cli = Cli::try_parse_from([
            "revvault",
            "run",
            "--",
            "/usr/local/bin/node",
            "/app/dist/publisher-run.js",
        ])
        .unwrap();
        assert!(service_command_allowed(&cli.command));
    }
}
