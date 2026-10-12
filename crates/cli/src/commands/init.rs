use clap::Args;
use serde_json::json;

use revvault_core::init::{
    init_service_vault, init_vault, resume_service_vault, service_init_plan, InitOptions,
};
use revvault_core::service::ServicePolicy;

#[derive(Args)]
pub struct InitArgs {
    /// Provision a fixed kernel-UID service vault from a reviewed policy (root only).
    #[arg(long, value_name = "FILE", conflicts_with_all = ["store_dir", "identity_file"])]
    pub service_policy: Option<std::path::PathBuf>,

    /// Preview service paths and secret selectors without creating keys or files.
    #[arg(long, requires = "service_policy")]
    pub dry_run: bool,

    /// Resume an unchanged interrupted service initialization (root only).
    #[arg(long, requires = "service_policy", conflicts_with = "dry_run")]
    pub resume: bool,

    /// Override the store directory (default: ~/.revealui/passage-store)
    #[arg(long, value_name = "DIR")]
    pub store_dir: Option<std::path::PathBuf>,

    /// Override the identity file (default: ~/.config/age/keys.txt)
    #[arg(long, value_name = "FILE")]
    pub identity_file: Option<std::path::PathBuf>,
}

pub fn run(args: InitArgs, json_output: bool) -> anyhow::Result<()> {
    if let Some(path) = args.service_policy {
        let plan = if args.dry_run {
            let policy: ServicePolicy = toml::from_str(&std::fs::read_to_string(&path)?)?;
            service_init_plan(&policy)?
        } else if args.resume {
            resume_service_vault(&path)?
        } else {
            init_service_vault(&path)?
        };
        let output = serde_json::json!({
            "status": if args.dry_run { "service_preview" } else if args.resume { "service_resumed" } else { "service_initialized" },
            "plan": plan,
            "credentialDelivery": "not performed",
        });
        if json_output {
            println!("{}", serde_json::to_string(&output)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        return Ok(());
    }
    let summary = init_vault(InitOptions {
        store_dir: args.store_dir,
        identity_file: args.identity_file,
    })?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "status": "initialized",
                "store": summary.store_dir.to_string_lossy(),
                "identity": summary.identity_file.to_string_lossy(),
                "public_key": summary.public_key,
            }))?
        );
        return Ok(());
    }

    if summary.store_existed && summary.identity_existed {
        eprintln!(
            "Vault already initialized.\n  Store:    {}\n  Identity: {}",
            summary.store_dir.display(),
            summary.identity_file.display(),
        );
        return Ok(());
    }

    if !summary.store_existed {
        eprintln!("✓ Created store:    {}", summary.store_dir.display());
    } else {
        eprintln!("  Store exists:     {}", summary.store_dir.display());
    }

    if !summary.identity_existed {
        eprintln!("✓ Generated identity: {}", summary.identity_file.display());
        eprintln!("  Public key:         {}", summary.public_key);
    } else {
        eprintln!("  Identity exists:  {}", summary.identity_file.display());
    }

    eprintln!();
    eprintln!(
        "WARNING: Back up your identity file — if you lose it, all secrets are unrecoverable."
    );
    eprintln!("         Store a copy in a password manager or secure offline location.");
    eprintln!("         Identity: {}", summary.identity_file.display());
    eprintln!();
    eprintln!("Your vault is ready. Try:");
    eprintln!("  revvault set credentials/example/api-key   # store a secret");
    eprintln!("  revvault list                              # list secrets");

    Ok(())
}
