use std::path::PathBuf;

use clap::Args;

use revvault_core::import::PlaintextImporter;
use revvault_core::Config;
use revvault_core::PassageStore;

#[derive(Args)]
pub struct MigrateArgs {
    /// Directory containing plaintext secret files
    #[arg(long)]
    pub plaintext_dir: PathBuf,

    /// Preview only, don't write anything
    #[arg(long)]
    pub dry_run: bool,

    /// Delete original files after successful import
    #[arg(long)]
    pub delete_originals: bool,

    /// Skip confirmation prompts
    #[arg(long)]
    pub force: bool,

    /// Only import files that match a known service (skip uncategorized)
    #[arg(long)]
    pub secrets_only: bool,
}

pub fn run(args: MigrateArgs) -> anyhow::Result<()> {
    let importer = PlaintextImporter::new(args.plaintext_dir.clone());
    let records = importer.scan()?;

    let records: Vec<_> = if args.secrets_only {
        records
            .into_iter()
            .filter(|r| r.categorized_by != "uncategorized")
            .collect()
    } else {
        records
    };

    if records.is_empty() {
        eprintln!("No files found to migrate.");
        return Ok(());
    }

    eprintln!("Found {} files to migrate:\n", records.len());
    for record in &records {
        eprintln!(
            "  {} → {} ({})",
            record.source_path.display(),
            record.target_path,
            record.categorized_by
        );
    }

    if args.dry_run {
        eprintln!("\n(dry run — no changes made)");
        return Ok(());
    }

    if !args.force {
        eprint!("\nProceed? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    if args.delete_originals {
        for record in &records {
            revvault_core::service::assert_personal_path(&record.source_path)?;
        }
    }

    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    let manifest = importer.execute(&store, &records)?;

    // Write manifest
    let manifest_dir = store.store_dir().join(".revvault/migrations");
    revvault_core::service::assert_personal_path(&manifest_dir)?;
    std::fs::create_dir_all(&manifest_dir)?;
    let manifest_path = manifest_dir.join(format!("{}.json", manifest.timestamp.replace(':', "-")));
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    revvault_core::service::assert_personal_path(&manifest_path)?;
    std::fs::write(&manifest_path, manifest_json)?;
    eprintln!("\nMigrated {} secrets.", records.len());
    eprintln!("Manifest: {}", manifest_path.display());

    if args.delete_originals {
        for record in &records {
            revvault_core::service::assert_personal_path(&record.source_path)?;
            std::fs::remove_file(&record.source_path)?;
        }
        eprintln!("Deleted {} original files.", records.len());
    }

    Ok(())
}
