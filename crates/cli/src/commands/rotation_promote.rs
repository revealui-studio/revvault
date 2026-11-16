use clap::Args;

use revvault_core::rotation::{executor, RotationConfig};
use revvault_core::store::PassageStore;
use revvault_core::Config;

/// Flip dual-slot `{path}-next` → live for a rotation.toml provider (GAP-261).
#[derive(Args)]
pub struct RotationPromoteArgs {
    /// Provider name matching a `[providers.<name>]` block with dual_slot = true
    pub provider: String,
}

pub async fn run(args: RotationPromoteArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;
    let rotation_config = RotationConfig::load(&config.store_dir)?;

    let provider_config = rotation_config
        .providers
        .get(&args.provider)
        .ok_or_else(|| {
            anyhow::anyhow!("provider '{}' not found in rotation.toml", args.provider)
        })?;

    let store = PassageStore::open(config)?;
    executor::promote(&store, &args.provider, provider_config).await
}
