use std::env;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{Result, RevvaultError};

/// Optional config file at `~/.config/revvault/config.toml`.
#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    /// Override default store path.
    store_path: Option<PathBuf>,
    /// Override default identity file path.
    identity: Option<PathBuf>,
    /// Editor command, or "builtin" to use the built-in TUI editor.
    editor: Option<String>,
    /// Directory for temporary plaintext files during edit.
    tmpdir: Option<PathBuf>,
}

impl ConfigFile {
    /// Load `~/.config/revvault/config.toml`.
    ///
    /// Returns `Default::default()` silently if the file does not exist.
    /// Returns an error if the file exists but cannot be parsed.
    fn load() -> Result<Self> {
        let Some(home) = dirs::home_dir() else {
            return Ok(Self::default());
        };
        let path = home.join(".config/revvault/config.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path).map_err(RevvaultError::Io)?;
        toml::from_str(&raw).map_err(|e| {
            RevvaultError::Other(anyhow::anyhow!(
                "malformed config file {}: {e}",
                path.display()
            ))
        })
    }
}

/// Cross-platform configuration for store, identity, editor, and tmpdir.
#[derive(Clone)]
pub struct Config {
    pub store_dir: PathBuf,
    pub identity_file: PathBuf,
    pub recipients_file: PathBuf,
    /// Editor command, or "builtin" to use the built-in TUI editor (may include arguments, e.g. `"zed --wait"`).
    pub editor: Option<String>,
    /// Directory for temporary plaintext files during edit.
    pub tmpdir: Option<PathBuf>,
}

impl Config {
    /// Resolve configuration from config file, environment, and platform defaults.
    ///
    /// Resolution order (later overrides earlier):
    ///   config file → env var → platform default
    ///
    /// Store:
    ///   1. `~/.config/revvault/config.toml` `store_path`
    ///   2. `REVVAULT_STORE` env var
    ///   3. `PASSAGE_DIR` env var (backwards compat)
    ///   4. `~/.revealui/passage-store`
    ///
    /// Identity:
    ///   1. `~/.config/revvault/config.toml` `identity`
    ///   2. `REVVAULT_IDENTITY` env var
    ///   3. `~/.config/age/keys.txt`
    ///   4. `~/.age-identity/keys.txt`
    ///
    /// Editor:
    ///   1. `~/.config/revvault/config.toml` `editor`
    ///   2. `EDITOR` env var
    ///
    /// Tmpdir:
    ///   1. `~/.config/revvault/config.toml` `tmpdir`
    ///   2. `TMPDIR` env var
    pub fn resolve() -> Result<Self> {
        if let Some(policy) = crate::service::ServicePolicy::current()? {
            return Ok(policy.config());
        }
        let file = ConfigFile::load()?;
        let store_dir = Self::resolve_store_dir(&file)?;
        let identity_file = Self::resolve_identity_file(&file)?;
        let recipients_file = store_dir.join(".age-recipients");
        let editor = Self::resolve_editor(&file);
        let tmpdir = Self::resolve_tmpdir(&file);

        Ok(Self {
            store_dir,
            identity_file,
            recipients_file,
            editor,
            tmpdir,
        })
    }

    fn resolve_store_dir(file: &ConfigFile) -> Result<PathBuf> {
        // Config file wins first (only if path exists)
        if let Some(ref p) = file.store_path {
            if p.is_dir() {
                return Ok(p.clone());
            }
        }

        // Env vars next
        if let Ok(path) = env::var("REVVAULT_STORE") {
            let p = PathBuf::from(path);
            if p.is_dir() {
                return Ok(p);
            }
        }

        if let Ok(path) = env::var("PASSAGE_DIR") {
            let p = PathBuf::from(path);
            if p.is_dir() {
                return Ok(p);
            }
        }

        // Platform-aware default
        let home = home_dir()?;

        let mut candidates = vec![home.join(".revealui/passage-store")];
        if cfg!(target_os = "linux") {
            if let Ok(win_user) = env::var("WINDOWS_USERNAME") {
                candidates.push(
                    PathBuf::from("/mnt/c/Users")
                        .join(&win_user)
                        .join(".revealui/passage-store"),
                );
            }
        }

        for candidate in &candidates {
            if candidate.is_dir() {
                return Ok(candidate.clone());
            }
        }

        Err(RevvaultError::StoreNotFound(
            candidates
                .first()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("~/.revealui/passage-store")),
        ))
    }

    fn resolve_identity_file(file: &ConfigFile) -> Result<PathBuf> {
        // Config file wins first (only if file exists)
        if let Some(ref p) = file.identity {
            if p.is_file() {
                return Ok(p.clone());
            }
        }

        // Env var next
        if let Ok(path) = env::var("REVVAULT_IDENTITY") {
            let p = PathBuf::from(path);
            if p.is_file() {
                return Ok(p);
            }
        }

        let home = home_dir()?;

        let mut candidates = vec![
            home.join(".config/age/keys.txt"), // XDG standard location (checked first)
            home.join(".age-identity/keys.txt"), // legacy location
        ];
        if cfg!(target_os = "linux") {
            if let Ok(win_user) = env::var("WINDOWS_USERNAME") {
                candidates.push(
                    PathBuf::from("/mnt/c/Users")
                        .join(&win_user)
                        .join(".age-identity/keys.txt"),
                );
            }
        }

        for candidate in &candidates {
            if candidate.is_file() {
                return Ok(candidate.clone());
            }
        }

        Err(RevvaultError::IdentityNotFound(
            candidates
                .first()
                .cloned()
                .unwrap_or_else(|| PathBuf::from("~/.config/age/keys.txt")),
        ))
    }

    fn resolve_editor(file: &ConfigFile) -> Option<String> {
        // Config file wins, then EDITOR env var
        if let Some(ref e) = file.editor {
            if !e.trim().is_empty() {
                return Some(e.clone());
            }
        }
        env::var("EDITOR").ok()
    }

    fn resolve_tmpdir(file: &ConfigFile) -> Option<PathBuf> {
        // Config file wins, then TMPDIR env var
        if let Some(ref p) = file.tmpdir {
            return Some(p.clone());
        }
        env::var("TMPDIR").ok().map(PathBuf::from)
    }
}

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| {
        RevvaultError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine home directory",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_respects_env_vars() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();

        let id_file = dir.path().join("keys.txt");
        std::fs::write(&id_file, "# fake identity\n").unwrap();

        let recip_file = store.join(".age-recipients");
        std::fs::write(&recip_file, "age1fake\n").unwrap();

        unsafe {
            env::set_var("REVVAULT_STORE", &store);
            env::set_var("REVVAULT_IDENTITY", &id_file);
        }

        let config = Config::resolve().unwrap();
        assert_eq!(config.store_dir, store);
        assert_eq!(config.identity_file, id_file);

        unsafe {
            env::remove_var("REVVAULT_STORE");
            env::remove_var("REVVAULT_IDENTITY");
        }
    }
}
