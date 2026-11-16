use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::rotation::sync_hook::SyncLogEntry;

/// Outcome returned by a rotation provider after a successful rotation.
/// Contains the new secret value; the executor writes it to the vault.
#[derive(Debug)]
pub struct RotationOutcome {
    /// New secret value to store in the vault.
    pub new_value: SecretString,
    /// Opaque identifier for the new key (e.g. numeric token ID).
    /// Stored in the vault for use as `old_key_id` in the next rotation.
    pub new_key_id: Option<String>,
    /// Extra vault paths written in the same rotation as `new_value`
    /// (e.g. SPKI public PEM for `ed25519-keypair`). Empty for providers
    /// that only rotate a single leaf.
    pub companion_writes: Vec<(String, SecretString)>,
}

impl RotationOutcome {
    /// Convenience for single-value providers (http / neon / local).
    pub fn single(new_value: SecretString, new_key_id: Option<String>) -> Self {
        Self {
            new_value,
            new_key_id,
            companion_writes: Vec::new(),
        }
    }
}

/// Append-only log entry written to `<store>/.revvault/rotation-log.jsonl`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RotationLogEntry {
    pub timestamp: String,
    pub provider: String,
    pub secret_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_key_id: Option<String>,
    pub status: String,
    /// Per-target sync rows when `[providers.<name>.sync.*]` is
    /// configured. `None` when no sync block was set; an empty
    /// vector when sync ran but nothing to do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync: Option<Vec<SyncLogEntry>>,
    /// Whether the post-rotation `verify` command passed.
    /// `None` when no verify command was configured;
    /// `Some(true)` when verify exited zero;
    /// `Some(false)` when verify failed (the executor also
    /// returns Err in that case so the cli exits non-zero).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

/// Trait for secret rotation providers.
///
/// Each provider is constructed with the current key value (read from the
/// vault by the executor) and is responsible only for API interactions.
/// Vault I/O (storing the new value, updating the key-ID record) is handled
/// by the executor after `rotate()` returns.
#[async_trait]
pub trait RotationProvider: Send + Sync {
    /// Provider name (e.g. "stripe", "vercel", "github").
    fn name(&self) -> &str;

    /// Validate configuration — check URLs parse, required fields present.
    /// Should NOT make network requests.
    async fn preflight(&self) -> Result<()>;

    /// Return a human-readable description of what `rotate` would do.
    async fn dry_run(&self) -> Result<String>;

    /// Create the replacement key. The current key must remain usable.
    /// Returns the new secret value and optional key ID; does not touch the vault.
    async fn rotate(&self) -> Result<RotationOutcome>;

    /// Revoke the old key only after the replacement is persisted and verified.
    async fn revoke_old(&self) -> Result<()> {
        Ok(())
    }
}
