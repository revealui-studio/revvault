use revvault_core::{Config, PassageStore, RevvaultError};

/// Resolve configuration and open the store, pointing first-run users at
/// `revvault init` when the store or identity does not exist yet.
pub(crate) fn open_store() -> anyhow::Result<PassageStore> {
    let result = Config::resolve().and_then(PassageStore::open);
    result.map_err(|e| match e {
        RevvaultError::StoreNotFound(_)
        | RevvaultError::IdentityNotFound(_)
        | RevvaultError::RecipientsNotFound(_) => anyhow::Error::new(e).context(
            "vault not initialized (run `revvault init` to create the store and identity)",
        ),
        other => other.into(),
    })
}

pub mod backup;
pub mod completions;
pub mod delete;
pub mod doctor;
pub mod edit;
pub mod export_env;
pub mod generate;
pub mod get;
pub mod init;
pub mod list;
pub mod migrate;
pub mod rotate;
pub mod rotation_promote;
pub mod run;
pub mod search;
pub mod set;
pub mod stream_safe;
pub mod sync;
