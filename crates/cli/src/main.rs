mod commands;
pub mod tui_editor;

use clap::{Parser, Subcommand};

const AFTER_HELP: &str = "\
Examples:
  revvault init                                  create the store and age identity
  revvault set revealui/prod/stripe/secret-key   store a secret (hidden prompt)
  revvault get revealui/prod/stripe/secret-key   decrypt and print a secret
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
    /// Create a root-only independently encrypted fixed service custody checkpoint
    Backup(commands::backup::BackupArgs),
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
    /// Show rotation status
    RotationStatus,
    /// Sync vault secrets with external services (e.g., Vercel env vars)
    Sync(commands::sync::SyncArgs),
    /// Vault-only health check: read every manifest entry, validate shape
    Doctor(commands::doctor::DoctorArgs),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Arm before capability/configuration reads and keep alive through output.
    let deadline = if is_service_receiver(&cli.command) {
        Some(revvault_core::service::receiver::ServiceReceiverDeadline::start()?)
    } else {
        None
    };

    // Services receive only the maintained delivery capability. Reject every
    // other command before provider I/O, plaintext printing or a mutation.
    if revvault_core::service::ServicePolicy::current()?.is_some()
        && !service_command_allowed(&cli.command)
    {
        anyhow::bail!("revvault_service_capability_denied");
    }

    // Construct no Tokio runtime or worker threads on the service receiver
    // path, including its failures. Keep ordinary commands on the same
    // multi-thread/all-drivers runtime previously supplied by tokio::main.
    dispatch_command(
        cli,
        deadline.as_ref(),
        run_service_receiver,
        |command, json| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(run_ordinary_command(command, json))
        },
    )
}

fn command_result(result: anyhow::Result<()>, json: bool) -> anyhow::Result<()> {
    if let Err(ref e) = result {
        if json {
            println!("{}", serde_json::json!({"error": e.to_string()}));
            std::process::exit(1);
        }
    }

    result
}

fn is_service_receiver(command: &Commands) -> bool {
    match command {
        Commands::Init(args) => args.service_policy.is_some() && !args.dry_run,
        Commands::Set(args) => args.service_uid.is_some(),
        _ => false,
    }
}

/// The one command-routing boundary. Both production executors are passed
/// lazily so a failed receiver can never construct or fall through to a runtime.
fn dispatch_command<D>(
    cli: Cli,
    deadline: Option<&D>,
    receiver: impl FnOnce(Commands, bool, &D) -> anyhow::Result<()>,
    ordinary: impl FnOnce(Commands, bool) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if is_service_receiver(&cli.command) {
        let deadline =
            deadline.ok_or_else(|| anyhow::anyhow!("revvault_service_request_denied"))?;
        receiver(cli.command, cli.json, deadline)
    } else {
        ordinary(cli.command, cli.json)
    }
}

fn run_service_receiver(
    command: Commands,
    json: bool,
    deadline: &revvault_core::service::receiver::ServiceReceiverDeadline,
) -> anyhow::Result<()> {
    let result = match command {
        Commands::Init(args) => commands::init::run(args, json, Some(deadline)),
        Commands::Set(args) => commands::set::run(args, json, Some(deadline)),
        _ => anyhow::bail!("revvault_service_request_denied"),
    };
    command_result(result, json)
}

async fn run_ordinary_command(command: Commands, json: bool) -> anyhow::Result<()> {
    let result = match command {
        Commands::Init(args) => commands::init::run(args, json, None),
        Commands::Backup(args) => commands::backup::run(args, json),
        Commands::Get(args) => commands::get::run(args, json),
        Commands::Run(args) => commands::run::run(args),
        Commands::Set(args) => commands::set::run(args, json, None),
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
        Commands::RotationPromote(args) => commands::rotation_promote::run(args).await,
        Commands::RotationStatus => commands::rotate::status(),
        Commands::Sync(args) => commands::sync::run(args, json).await,
        Commands::Doctor(args) => commands::doctor::run(args),
    };
    // Preserve JSON error exit before the ordinary runtime is dropped, just as
    // in the former tokio::main body. The receiver uses the same result owner.
    command_result(result, json)
}

fn service_command_allowed(command: &Commands) -> bool {
    matches!(command, Commands::Run(_))
}

#[cfg(test)]
mod service_dispatch_tests {
    use super::*;
    use std::cell::Cell;

    fn receiver_commands() -> Vec<Vec<&'static str>> {
        vec![
            vec![
                "revvault",
                "init",
                "--service-policy",
                "/policy.toml",
                "--service-request",
                "/request.json",
            ],
            vec![
                "revvault",
                "init",
                "--service-policy",
                "/policy.toml",
                "--service-request",
                "/request.json",
                "--resume",
            ],
            vec![
                "revvault",
                "init",
                "--service-policy",
                "/policy.toml",
                "--service-request",
                "/request.json",
                "--restore-archive",
                "/checkpoint.age",
                "--expected-sha256",
                "digest",
            ],
            vec![
                "revvault",
                "init",
                "--service-policy",
                "/policy.toml",
                "--service-request",
                "/request.json",
                "--request-status",
            ],
            vec![
                "revvault",
                "set",
                "--service-uid",
                "19001",
                "--service-request",
                "/request.json",
                "revealfleet/publisher/synthetic-key",
            ],
        ]
    }

    #[test]
    fn every_receiver_routes_synchronously_without_constructing_async_runtime() {
        for args in receiver_commands() {
            for json in [false, true] {
                let mut cli = Cli::try_parse_from(args.clone()).unwrap();
                cli.json = json;
                let called = Cell::new(false);
                dispatch_command(
                    cli,
                    Some(&()),
                    |command, actual_json, _deadline| {
                        assert!(is_service_receiver(&command));
                        assert_eq!(actual_json, json);
                        assert!(tokio::runtime::Handle::try_current().is_err());
                        called.set(true);
                        Ok(())
                    },
                    |_command, _json| panic!("receiver constructed ordinary async runtime"),
                )
                .unwrap();
                assert!(called.get(), "receiver was not executed: {args:?}");
            }
        }
    }

    #[test]
    fn receiver_errors_never_fall_through_to_async_runtime() {
        for args in receiver_commands() {
            let cli = Cli::try_parse_from(args.clone()).unwrap();
            let called = Cell::new(false);
            let error = dispatch_command(
                cli,
                Some(&()),
                |_command, _json, _deadline| {
                    called.set(true);
                    anyhow::bail!("synthetic receiver admission denied")
                },
                |_command, _json| panic!("denied receiver constructed ordinary async runtime"),
            )
            .unwrap_err();
            assert!(called.get(), "receiver denial was not executed: {args:?}");
            assert_eq!(error.to_string(), "synthetic receiver admission denied");
        }
    }

    #[test]
    fn receiver_missing_deadline_denies_without_either_executor() {
        for args in receiver_commands() {
            let cli = Cli::try_parse_from(args).unwrap();
            let error = dispatch_command::<()>(
                cli,
                None,
                |_command, _json, _deadline| panic!("receiver started without deadline"),
                |_command, _json| panic!("receiver missing deadline constructed async runtime"),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "revvault_service_request_denied");
        }
    }

    #[test]
    fn ordinary_commands_keep_the_runtime_executor_including_service_preview() {
        for args in [
            vec!["revvault", "list"],
            vec!["revvault", "set", "revealfleet/publisher/synthetic-key"],
            vec!["revvault", "rotate", "synthetic", "--dry-run"],
            vec!["revvault", "rotation-promote", "synthetic"],
            vec!["revvault", "sync", "fly"],
            vec![
                "revvault",
                "init",
                "--service-policy",
                "/policy.toml",
                "--dry-run",
            ],
        ] {
            let cli = Cli::try_parse_from(args.clone()).unwrap();
            let called = Cell::new(false);
            let error = dispatch_command::<()>(
                cli,
                None,
                |_command, _json, _deadline| panic!("ordinary command entered service receiver"),
                |command, _json| {
                    assert!(!is_service_receiver(&command));
                    called.set(true);
                    anyhow::bail!("synthetic ordinary runtime result")
                },
            )
            .unwrap_err();
            assert!(called.get(), "ordinary runtime was not selected: {args:?}");
            assert_eq!(error.to_string(), "synthetic ordinary runtime result");
        }
    }

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
            vec![
                "revvault",
                "backup",
                "--service-uid",
                "19001",
                "--recipient",
                "public",
                "--output",
                "/root/checkpoint.age",
            ],
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

    #[test]
    fn service_restore_requires_pinned_archive_and_cannot_resume_or_override_store() {
        let valid = [
            "revvault",
            "init",
            "--service-policy",
            "/policy.toml",
            "--restore-archive",
            "/checkpoint.age",
            "--expected-sha256",
            "digest",
        ];
        assert!(Cli::try_parse_from(valid).is_ok());
        for extra in ["--resume", "--dry-run"] {
            let mut args = valid.to_vec();
            args.push(extra);
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(Cli::try_parse_from(&valid[..6]).is_err());
        assert!(Cli::try_parse_from([
            "revvault",
            "init",
            "--restore-archive",
            "/checkpoint.age",
            "--expected-sha256",
            "digest",
        ])
        .is_err());
        let mut args = valid.to_vec();
        args.extend(["--store-dir", "/owner"]);
        assert!(Cli::try_parse_from(args).is_err());
    }
}
