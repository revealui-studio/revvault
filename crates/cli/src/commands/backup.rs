use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct BackupArgs {
    /// Fixed service UID; personal store fallback is never supported.
    #[arg(long)]
    pub service_uid: u32,
    /// Approved dedicated public age recovery recipient (never a private key).
    #[arg(long)]
    pub recipient: String,
    /// Create-only encrypted checkpoint in an immutable root-private directory.
    #[arg(long)]
    pub output: PathBuf,
}

pub fn run(args: BackupArgs, json_output: bool) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let receipt = revvault_core::service::backup::backup_service_vault(
            args.service_uid,
            &args.recipient,
            &args.output,
        )?;
        let output = serde_json::json!({"status": "service_backed_up", "receipt": receipt,
            "providerUpload": "not performed", "ownerAcceptance": "not inferred"});
        if json_output {
            println!("{}", serde_json::to_string(&output)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (args, json_output);
        anyhow::bail!("revvault_service_backup_restore_denied")
    }
}
