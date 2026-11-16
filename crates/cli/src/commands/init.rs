use clap::Args;
use serde_json::json;

use revvault_core::init::{init_vault, service_init_plan, InitOptions};
use revvault_core::service::receiver::{
    ServiceInvocation, ServiceMutationGuard, ServiceMutationOutcome, ServiceReceiverDeadline,
};
use revvault_core::service::ServicePolicy;

#[derive(Args)]
pub struct InitArgs {
    /// Provision a fixed kernel-UID service vault from a reviewed policy (root only).
    #[arg(long, value_name = "FILE", conflicts_with_all = ["store_dir", "identity_file"])]
    pub service_policy: Option<std::path::PathBuf>,

    /// Immutable nonsecret request descriptor, mandatory for every service write.
    #[arg(
        long,
        value_name = "FILE",
        requires = "service_policy",
        conflicts_with = "dry_run"
    )]
    pub service_request: Option<std::path::PathBuf>,

    /// Observe an original request's local records; never retries or grants admission.
    #[arg(long, requires_all = ["service_policy", "service_request"], conflicts_with_all = ["dry_run", "resume", "restore_archive", "expected_sha256"])]
    pub request_status: bool,

    /// Preview service paths and secret selectors without creating keys or files.
    #[arg(long, requires = "service_policy")]
    pub dry_run: bool,

    /// Include root-only immutable source fingerprints in a service preview.
    /// Does not create a vault or authorize remote execution or credential import.
    #[arg(long, requires_all = ["service_policy", "dry_run"])]
    pub source_check: bool,

    /// Resume an unchanged interrupted service initialization (root only).
    #[arg(long, requires = "service_policy", conflicts_with = "dry_run")]
    pub resume: bool,

    /// Restore a pinned encrypted service checkpoint onto an absent fixed namespace.
    /// Dedicated recovery identity is read from stdin only; never argv/environment.
    #[arg(long, requires_all = ["service_policy", "expected_sha256"], conflicts_with_all = ["resume", "dry_run"])]
    pub restore_archive: Option<std::path::PathBuf>,

    /// Independently accepted archive digest from the original backup receipt.
    #[arg(long, requires = "restore_archive")]
    pub expected_sha256: Option<String>,

    /// Override the store directory (default: ~/.revealui/passage-store)
    #[arg(long, value_name = "DIR")]
    pub store_dir: Option<std::path::PathBuf>,

    /// Override the identity file (default: ~/.config/age/keys.txt)
    #[arg(long, value_name = "FILE")]
    pub identity_file: Option<std::path::PathBuf>,
}

pub fn run(
    args: InitArgs,
    json_output: bool,
    deadline: Option<&ServiceReceiverDeadline>,
) -> anyhow::Result<()> {
    if let Some(path) = args.service_policy {
        if args.request_status {
            let request = args
                .service_request
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("revvault_service_request_denied"))?;
            let deadline =
                deadline.ok_or_else(|| anyhow::anyhow!("revvault_service_request_denied"))?;
            let report = ServiceMutationGuard::status(deadline, request, &path)?;
            if json_output {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            return Ok(());
        }
        let sources = if args.source_check {
            Some(revvault_core::service::service_source_contract(&path)?)
        } else {
            None
        };
        let restoring = args.restore_archive.is_some();
        let plan = if args.dry_run {
            let policy: ServicePolicy = toml::from_str(&std::fs::read_to_string(&path)?)?;
            service_init_plan(&policy)?
        } else {
            let request = args
                .service_request
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("revvault_service_request_denied"))?;
            let deadline =
                deadline.ok_or_else(|| anyhow::anyhow!("revvault_service_request_denied"))?;
            let invocation = if let Some(archive) = args.restore_archive {
                ServiceInvocation::Restore {
                    policy: path,
                    archive,
                    archive_sha256: args
                        .expected_sha256
                        .ok_or_else(|| anyhow::anyhow!("revvault_service_request_denied"))?,
                }
            } else if args.resume {
                ServiceInvocation::Resume { policy: path }
            } else {
                ServiceInvocation::Initialize { policy: path }
            };
            let guard = ServiceMutationGuard::begin(deadline, request, invocation)?;
            let secret = if restoring {
                Some(read_recovery_identity()?)
            } else {
                None
            };
            match guard.execute(secret)? {
                ServiceMutationOutcome::Initialized(plan)
                | ServiceMutationOutcome::Resumed(plan)
                | ServiceMutationOutcome::Restored(plan) => plan,
                _ => anyhow::bail!("revvault_service_request_denied"),
            }
        };
        let mut output = serde_json::json!({
            "status": if restoring { "service_restored" } else if args.dry_run { "service_preview" } else if args.resume { "service_resumed" } else { "service_initialized" },
            "plan": plan,
            "credentialDelivery": "not performed",
            "provider_admission": "held",
        });
        if let Some(sources) = sources {
            output["source_contract_sha256"] = serde_json::json!(sources.sha256()?);
            output["source_contract"] = serde_json::to_value(sources)?;
            output["provider_admission"] = serde_json::json!("held");
        }
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

fn read_recovery_identity() -> anyhow::Result<secrecy::SecretString> {
    use std::io::{IsTerminal, Read};
    if std::io::stdin().is_terminal() {
        anyhow::bail!("revvault_service_backup_restore_denied");
    }
    let mut key = zeroize::Zeroizing::new(vec![0_u8; 4097]);
    let mut count = 0;
    loop {
        match std::io::stdin().read(&mut key[count..]) {
            Ok(0) => break,
            Ok(n) => {
                count += n;
                if count > 4096 {
                    anyhow::bail!("revvault_service_backup_restore_denied");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => anyhow::bail!("revvault_service_backup_restore_denied"),
        }
    }
    let value = std::str::from_utf8(&key[..count])
        .map_err(|_| anyhow::anyhow!("revvault_service_backup_restore_denied"))?;
    Ok(secrecy::SecretString::from(value.to_owned()))
}
