use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Result, RevvaultError};
use crate::rotation::sync_hook::SyncConfig;
use crate::sync::shape::Shape;

/// Rotation configuration loaded from `<store>/.revvault/rotation.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
}

/// Configuration for a single rotation provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Secret path in the store containing the current API key.
    pub secret_path: String,
    /// Provider-specific settings.
    #[serde(default)]
    pub settings: HashMap<String, String>,
    /// Optional post-rotation sync block. When present, the
    /// executor pushes the new value to the configured external
    /// secret stores (today: Vercel) after the vault write
    /// succeeds. See [`crate::rotation::sync_hook`] for shape +
    /// failure semantics.
    #[serde(default)]
    pub sync: Option<SyncConfig>,
    /// User-configurable shell commands to run after the vault
    /// write + sync hook complete. Executed sequentially with
    /// `sh -c`. Failure prevents HTTP credential revocation and returns
    /// an error when `revoke_url` is configured; otherwise it is warn-only.
    /// HTTP promotion retries these hooks before verification and revocation.
    #[serde(default)]
    pub post_rotate: Vec<String>,
    /// Optional strict verification command. When set, runs after
    /// the `post_rotate` hooks. Exit-zero records `verified: true`
    /// in the rotation log; **non-zero records `verified: false`
    /// AND causes the executor to return Err** (cli exits non-zero).
    /// Vault state is unchanged either way — the rotation already
    /// landed.
    #[serde(default)]
    pub verify: Option<String>,
    /// When `true`, a `verify` command **must** be configured
    /// (GAP-261). Crown jewels never rotate without a post-rotation
    /// readback. Default `false` keeps non-crown providers optional.
    #[serde(default)]
    pub require_verify: bool,
    /// When `true`, any failed post-rotation sync target makes the
    /// executor return `Err` (GAP-261). Default `false` keeps the
    /// historical best-effort sync for non-crown providers.
    #[serde(default)]
    pub sync_must_succeed: bool,
    /// When `true` (GAP-261 dual-slot residual), `rotate` writes the new
    /// material to `{secret_path}-next` (and companion `-next` paths) and
    /// copies the outgoing live value to `-previous` **without** overwriting
    /// the live leaf. Operators flip with `revvault rotation promote`.
    /// Default `false` keeps in-place rotation for non-crown providers.
    #[serde(default)]
    pub dual_slot: bool,
    /// Optional expected output shape of the rotated value. When set,
    /// the executor validates the fresh rotation outcome against this
    /// shape **before** writing it to the vault. A mismatch aborts the
    /// rotation — the old key remains in place.
    ///
    /// The universal structural checks (empty / null-literal /
    /// Vercel-envelope) always apply regardless of whether
    /// `output_shape` is declared.
    ///
    /// TOML form:
    /// ```toml
    /// [providers.my-stripe-key]
    /// secret_path = "revealui/prod/stripe/secret-key"
    /// output_shape = "stripe-key-live-only"
    /// ```
    #[serde(default)]
    pub output_shape: Option<Shape>,
}

impl ProviderConfig {
    /// Fail-closed crown-jewel checks (GAP-261 §3.2): `require_verify`
    /// without a `verify` command is a hard config error.
    pub fn validate(&self, name: &str) -> Result<()> {
        if self.require_verify && self.verify.is_none() {
            return Err(RevvaultError::Other(anyhow::anyhow!(
                "provider '{name}': require_verify=true but no verify command configured"
            )));
        }
        Ok(())
    }
}

impl RotationConfig {
    /// Load rotation config from the store's `.revvault/rotation.toml`.
    pub fn load(store_dir: &Path) -> Result<Self> {
        let config_path = store_dir.join(".revvault/rotation.toml");

        if !config_path.exists() {
            return Ok(Self {
                providers: HashMap::new(),
            });
        }

        let contents = std::fs::read_to_string(&config_path)?;
        let config: Self = toml::from_str(&contents)
            .map_err(|e| RevvaultError::Other(anyhow::anyhow!("invalid rotation.toml: {e}")))?;
        for (name, provider) in &config.providers {
            provider.validate(name)?;
        }
        Ok(config)
    }
}
