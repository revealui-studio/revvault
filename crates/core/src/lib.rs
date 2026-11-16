// Workaround: rustc 1.93.1 ICE in early_lint_checks (StyledBuffer::replace panic).
// Any lint warning triggers the crash. Keep blanket allow until rustc is updated.
// See: https://github.com/rust-lang/rust/issues
#![allow(unused)]

pub mod config;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod import;
pub mod init;
pub mod namespace;
pub mod rotation;
pub mod service;
pub mod store;
pub mod sync;

pub use config::Config;
pub use error::RevvaultError;
pub use identity::Identity;
pub use namespace::Namespace;
pub use store::PassageStore;
