use std::io::Write;
use std::path::{Path, PathBuf};

use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use secrecy::{ExposeSecret, SecretString};

mod operation;
pub use operation::{ExpectedCurrent, OperationReceipt};
use walkdir::WalkDir;

use crate::config::Config;
use crate::crypto;
use crate::error::{Result, RevvaultError};
use crate::identity::Identity;
use crate::namespace::Namespace;

/// Entry in the secret store.
#[derive(Debug, Clone)]
pub struct SecretEntry {
    /// Relative path from store root (e.g., "revealui/stripe/secret-key")
    pub path: String,
    /// Parsed namespace from the first path segment
    pub namespace: Namespace,
    /// Full filesystem path to the .age file
    pub file_path: PathBuf,
}

/// The main passage-compatible secret store.
pub struct PassageStore {
    config: Config,
    identity: Identity,
    recipients: Vec<age::x25519::Recipient>,
    service: Option<crate::service::ServicePolicy>,
    service_import_path: Option<String>,
}

impl PassageStore {
    /// Open an existing store using resolved configuration.
    pub fn open(config: Config) -> Result<Self> {
        let service = crate::service::ServicePolicy::current()?;
        if let Some(policy) = &service {
            policy.assert_configuration(&config)?;
        }
        let identity = Identity::from_file(&config.identity_file)?;
        let recipients = crypto::load_recipients(&config.recipients_file)?;

        let store = Self {
            config,
            identity,
            recipients,
            service,
            service_import_path: None,
        };
        store.assert_service_recipients()?;
        Ok(store)
    }

    /// Root-only, create-only import bound to one approved secret in the same
    /// immutable service capability. No personal configuration is consulted.
    pub fn open_service_import(uid: u32, path: &str) -> Result<Self> {
        let policy = crate::service::ServicePolicy::for_import(uid)?;
        if !policy.allows_read(path) {
            return Err(RevvaultError::Other(anyhow::anyhow!(
                "revvault_service_capability_denied"
            )));
        }
        let mut store = Self::open(policy.config())?;
        store.service = Some(policy);
        store.service_import_path = Some(path.into());
        store.assert_service_recipients()?;
        Ok(store)
    }

    fn assert_service_recipients(&self) -> Result<()> {
        if self.service.is_some()
            && (self.identity.as_identities().len() != 1
                || self.recipients.len() != 1
                || self.recipients[0].to_string() != self.identity.default_recipient().to_string())
        {
            return Err(RevvaultError::Other(anyhow::anyhow!(
                "revvault_service_capability_denied"
            )));
        }
        Ok(())
    }

    /// Get (decrypt) a secret by its path.
    pub fn get(&self, path: &str) -> Result<SecretString> {
        let _lock = self.operation_lock(false)?;
        self.require_no_pending()?;
        self.read_secret(path)
    }

    fn read_secret(&self, path: &str) -> Result<SecretString> {
        validate_path(path)?;
        let file_path = self.checked_secret_path(path)?;
        let ciphertext = match std::fs::read(&file_path) {
            Ok(value) => value,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(RevvaultError::SecretNotFound(path.to_string()))
            }
            Err(e) => return Err(e.into()),
        };
        crypto::decrypt(&ciphertext, &self.identity).map_err(|e| match e {
            RevvaultError::DecryptionFailed(reason) => RevvaultError::DecryptionFailedForPath {
                path: path.to_string(),
                reason,
            },
            other => other,
        })
    }

    /// Create under the shared writer lock; never race a conditional write.
    pub fn set(&self, path: &str, plaintext: &[u8]) -> Result<()> {
        let _custody_lock = if let Some(selected) = &self.service_import_path {
            if selected != path || !root_import_caller() {
                return Err(RevvaultError::Other(anyhow::anyhow!(
                    "revvault_service_capability_denied"
                )));
            }
            Some(crate::service::lock_custody(
                self.service
                    .as_ref()
                    .ok_or_else(|| {
                        RevvaultError::Other(anyhow::anyhow!("revvault_service_capability_denied"))
                    })?
                    .uid,
            )?)
        } else {
            self.assert_write()?;
            None
        };
        let _lock = self.operation_lock(true)?;
        self.require_no_pending()?;
        let file_path = self.checked_secret_path(path)?;
        match std::fs::metadata(&file_path) {
            Ok(_) => return Err(RevvaultError::SecretAlreadyExists(path.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if self.service_import_path.is_some() {
            self.create_secret_parent(file_path.parent().unwrap())?;
            let ciphertext = crypto::encrypt(plaintext, &self.recipients)?;
            self.write_ciphertext(&file_path, &ciphertext, false)?;
            operation::sync_directory(file_path.parent().unwrap())
        } else {
            self.write_secret(path, plaintext)
        }
    }

    /// Atomic overwrite under the same writer lock as conditional promotion.
    pub fn upsert(&self, path: &str, plaintext: &[u8]) -> Result<()> {
        self.assert_write()?;
        let _lock = self.operation_lock(true)?;
        self.require_no_pending()?;
        self.write_secret(path, plaintext)
    }

    fn prepare_write_path(&self, path: &str) -> Result<PathBuf> {
        let file_path = self.checked_secret_path(path)?;
        match std::fs::metadata(&file_path) {
            Ok(metadata) if metadata.permissions().readonly() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "existing secret is read-only",
                )
                .into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let parent = file_path.parent().unwrap();
        self.ensure_parent(parent)?;
        if std::fs::metadata(parent)?.permissions().readonly() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "secret directory is read-only",
            )
            .into());
        }
        Ok(file_path)
    }

    fn write_secret(&self, path: &str, plaintext: &[u8]) -> Result<()> {
        let file_path = self.prepare_write_path(path)?;
        let ciphertext = crypto::encrypt(plaintext, &self.recipients)?;
        operation::atomic_write(&file_path, &ciphertext)
    }

    fn write_ciphertext(
        &self,
        destination: &Path,
        ciphertext: &[u8],
        overwrite: bool,
    ) -> Result<()> {
        let parent = destination
            .parent()
            .ok_or_else(|| RevvaultError::InvalidPath("missing parent".into()))?;
        let mut pending = tempfile::NamedTempFile::new_in(parent)?;
        pending.write_all(ciphertext)?;
        #[cfg(unix)]
        if self.service_import_path.is_some() {
            let uid = self
                .service
                .as_ref()
                .ok_or_else(|| {
                    RevvaultError::Other(anyhow::anyhow!("revvault_service_capability_denied"))
                })?
                .uid;
            set_import_permissions(pending.as_file(), uid, 0o640)?;
        }
        pending.as_file().sync_all()?;
        if overwrite {
            pending.persist(destination).map_err(|error| error.error)?;
        } else {
            pending
                .persist_noclobber(destination)
                .map_err(|error| error.error)?;
        }
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn create_secret_parent(&self, parent: &Path) -> Result<()> {
        if self.service_import_path.is_none() {
            std::fs::create_dir_all(parent)?;
            return Ok(());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let uid = self
                .service
                .as_ref()
                .ok_or_else(|| {
                    RevvaultError::Other(anyhow::anyhow!("revvault_service_capability_denied"))
                })?
                .uid;
            let relative = parent
                .strip_prefix(&self.config.store_dir)
                .map_err(|_| RevvaultError::InvalidPath("foreign service parent".into()))?;
            let mut current = self.config.store_dir.clone();
            crate::service::immutable_path(&current)?;
            crate::service::private_service_path(&current, uid)?;
            for part in relative.components() {
                if !matches!(part, std::path::Component::Normal(_)) {
                    return Err(RevvaultError::InvalidPath("foreign service parent".into()));
                }
                current.push(part);
                match std::fs::symlink_metadata(&current) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        std::fs::DirBuilder::new().mode(0o700).create(&current)?;
                        set_import_permissions(&std::fs::File::open(&current)?, uid, 0o750)?;
                    }
                    Err(error) => return Err(error.into()),
                    Ok(_) => {}
                }
                crate::service::immutable_path(&current)?;
                crate::service::private_service_path(&current, uid)?;
                if !std::fs::metadata(&current)?.is_dir() {
                    return Err(RevvaultError::InvalidPath(
                        "non-directory service parent".into(),
                    ));
                }
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(RevvaultError::Other(anyhow::anyhow!(
                "revvault_service_capability_denied"
            )))
        }
    }

    /// List all secret entries, optionally filtered by a path prefix.
    pub fn list(&self, prefix: Option<&str>) -> Result<Vec<SecretEntry>> {
        let _lock = self.operation_lock(false)?;
        self.require_no_pending()?;
        let mut entries = Vec::new();

        for entry in WalkDir::new(&self.config.store_dir)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| e.path() != self.config.store_dir.join(".revvault"))
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Skip non-.age files and hidden files
            let ext = path.extension().and_then(|e| e.to_str());
            if ext != Some("age") {
                continue;
            }

            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if file_name.starts_with('.') {
                continue;
            }

            let relative = path.strip_prefix(&self.config.store_dir).unwrap_or(path);

            // Remove .age extension from the logical path
            let logical_path = relative
                .with_extension("")
                .to_string_lossy()
                .replace('\\', "/");

            if self
                .service
                .as_ref()
                .is_some_and(|policy| !policy.allows_read(&logical_path))
            {
                continue;
            }
            if let Some(prefix) = prefix {
                if !logical_path.starts_with(prefix) {
                    continue;
                }
            }

            let namespace = logical_path
                .split('/')
                .next()
                .map(Namespace::from_path_segment)
                .unwrap_or(Namespace::Misc);

            entries.push(SecretEntry {
                path: logical_path,
                namespace,
                file_path: path.to_path_buf(),
            });
        }

        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    /// Fuzzy search for secrets by path.
    pub fn search(&self, query: &str) -> Result<Vec<SecretEntry>> {
        let matcher = SkimMatcherV2::default();
        let mut entries = self.list(None)?;

        let mut scored: Vec<(i64, SecretEntry)> = entries
            .drain(..)
            .filter_map(|entry| {
                matcher
                    .fuzzy_match(&entry.path, query)
                    .map(|score| (score, entry))
            })
            .collect();

        scored.sort_by_key(|b| std::cmp::Reverse(b.0));
        Ok(scored.into_iter().map(|(_, entry)| entry).collect())
    }

    /// Fuzzy search for secrets by path, returning match scores.
    pub fn search_scored(&self, query: &str) -> Result<Vec<(i64, SecretEntry)>> {
        let matcher = SkimMatcherV2::default();
        let mut entries = self.list(None)?;

        let mut scored: Vec<(i64, SecretEntry)> = entries
            .drain(..)
            .filter_map(|entry| {
                matcher
                    .fuzzy_match(&entry.path, query)
                    .map(|score| (score, entry))
            })
            .collect();

        scored.sort_by_key(|b| std::cmp::Reverse(b.0));
        Ok(scored)
    }

    /// Delete a secret by its path.
    pub fn delete(&self, path: &str) -> Result<()> {
        self.assert_write()?;
        let _lock = self.operation_lock(true)?;
        self.require_no_pending()?;
        let file_path = self.checked_secret_path(path)?;
        std::fs::remove_file(&file_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                RevvaultError::SecretNotFound(path.to_string())
            } else {
                e.into()
            }
        })?;
        operation::sync_directory(file_path.parent().unwrap())?;

        // Clean up empty parent directories
        if let Some(parent) = file_path.parent() {
            Self::cleanup_empty_dirs(parent, &self.config.store_dir);
        }

        Ok(())
    }

    /// Get the store root directory.
    pub fn store_dir(&self) -> &Path {
        &self.config.store_dir
    }

    fn assert_write(&self) -> Result<()> {
        if self.service.is_some() {
            return Err(RevvaultError::Other(anyhow::anyhow!(
                "revvault_service_capability_denied"
            )));
        }
        Ok(())
    }

    fn checked_secret_path(&self, path: &str) -> Result<PathBuf> {
        if self
            .service
            .as_ref()
            .is_some_and(|policy| !policy.allows_read(path))
        {
            return Err(RevvaultError::Other(anyhow::anyhow!(
                "revvault_service_capability_denied"
            )));
        }
        validate_path(path)?;
        if path.split('/').next() == Some(".revvault") {
            return Err(RevvaultError::InvalidPath(
                "reserved store metadata path".into(),
            ));
        }
        let file_path = self.config.store_dir.join(format!("{path}.age"));
        operation::check_path(&self.config.store_dir, &file_path)?;
        operation::check_regular(&file_path)?;
        #[cfg(unix)]
        if let Some(policy) = &self.service {
            if self.service_import_path.is_none() {
                crate::service::immutable_path(&file_path)?;
                crate::service::private_service_path(&file_path, policy.uid)?;
            }
        }
        Ok(file_path)
    }

    fn cleanup_empty_dirs(dir: &Path, stop_at: &Path) {
        let mut current = dir.to_path_buf();
        while current != stop_at {
            if std::fs::read_dir(&current)
                .map(|mut d| d.next().is_none())
                .unwrap_or(false)
            {
                let _ = std::fs::remove_dir(&current);
            } else {
                break;
            }
            if let Some(parent) = current.parent() {
                current = parent.to_path_buf();
            } else {
                break;
            }
        }
    }
}

fn root_import_caller() -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(unix)]
fn set_import_permissions(file: &std::fs::File, uid: u32, mode: u32) -> Result<()> {
    use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
    if !root_import_caller() || unsafe { libc::fchown(file.as_raw_fd(), 0, uid) } != 0 {
        return Err(RevvaultError::Other(anyhow::anyhow!(
            "revvault_service_capability_denied"
        )));
    }
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Validate a secret path to prevent directory traversal and other attacks.
fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(RevvaultError::InvalidPath("path is empty".into()));
    }
    if path.contains('\0') {
        return Err(RevvaultError::InvalidPath("path contains null byte".into()));
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err(RevvaultError::InvalidPath("path must be relative".into()));
    }
    for segment in path.split(['/', '\\']) {
        if segment.is_empty() || segment == ".." || segment == "." {
            return Err(RevvaultError::InvalidPath(
                "path traversal not allowed".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    /// Create a temp store with a generated identity and recipients file.
    pub(crate) fn setup_temp_store() -> (tempfile::TempDir, PassageStore) {
        let dir = tempfile::tempdir().unwrap();
        let store_dir = dir.path().join("store");
        std::fs::create_dir_all(&store_dir).unwrap();

        let id = age::x25519::Identity::generate();
        let recipient = id.to_public();

        let id_file = dir.path().join("keys.txt");
        std::fs::write(
            &id_file,
            format!(
                "# test key\n{}\n",
                secrecy::ExposeSecret::expose_secret(&id.to_string())
            ),
        )
        .unwrap();

        let recip_file = store_dir.join(".age-recipients");
        std::fs::write(&recip_file, format!("{}\n", recipient)).unwrap();

        let config = Config {
            store_dir,
            identity_file: id_file,
            recipients_file: recip_file,
            editor: None,
            tmpdir: None,
        };

        let store = PassageStore::open(config).unwrap();
        (dir, store)
    }

    #[test]
    fn set_and_get_roundtrip() {
        let (_dir, store) = setup_temp_store();

        store
            .set("credentials/stripe/secret-key", b"sk_live_123")
            .unwrap();
        let secret = store.get("credentials/stripe/secret-key").unwrap();
        assert_eq!(secret.expose_secret(), "sk_live_123");
    }

    #[test]
    fn set_rejects_duplicate() {
        let (_dir, store) = setup_temp_store();

        store.set("misc/token", b"value1").unwrap();
        let err = store.set("misc/token", b"value2").unwrap_err();
        assert!(matches!(err, RevvaultError::SecretAlreadyExists(_)));
    }

    #[test]
    fn upsert_overwrites_existing() {
        let (_dir, store) = setup_temp_store();

        store.set("misc/token", b"old_value").unwrap();
        store.upsert("misc/token", b"new_value").unwrap();

        let secret = store.get("misc/token").unwrap();
        assert_eq!(secret.expose_secret(), "new_value");
    }

    #[test]
    fn upsert_creates_new() {
        let (_dir, store) = setup_temp_store();

        store.upsert("misc/fresh", b"brand_new").unwrap();
        let secret = store.get("misc/fresh").unwrap();
        assert_eq!(secret.expose_secret(), "brand_new");
    }

    #[test]
    fn list_with_nested_directories() {
        let (_dir, store) = setup_temp_store();

        store.set("credentials/stripe/secret-key", b"sk1").unwrap();
        store
            .set("credentials/stripe/publishable-key", b"pk1")
            .unwrap();
        store.set("ssh/github", b"key1").unwrap();
        store.set("misc/note", b"hello").unwrap();

        let entries = store.list(None).unwrap();
        assert_eq!(entries.len(), 4);

        // Sorted alphabetically
        assert_eq!(entries[0].path, "credentials/stripe/publishable-key");
        assert_eq!(entries[1].path, "credentials/stripe/secret-key");
        assert_eq!(entries[2].path, "misc/note");
        assert_eq!(entries[3].path, "ssh/github");
    }

    #[test]
    fn list_with_prefix_filter() {
        let (_dir, store) = setup_temp_store();

        store.set("credentials/stripe/sk", b"v1").unwrap();
        store.set("credentials/neon/db", b"v2").unwrap();
        store.set("ssh/github", b"v3").unwrap();

        let entries = store.list(Some("credentials")).unwrap();
        assert_eq!(entries.len(), 2);

        let entries = store.list(Some("ssh")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "ssh/github");
    }

    #[test]
    fn search_returns_fuzzy_matches() {
        let (_dir, store) = setup_temp_store();

        store.set("credentials/stripe/secret-key", b"v1").unwrap();
        store
            .set("credentials/stripe/publishable-key", b"v2")
            .unwrap();
        store.set("ssh/github", b"v3").unwrap();

        let results = store.search("stripe").unwrap();
        assert_eq!(results.len(), 2);
        // Both stripe entries should match
        assert!(results.iter().all(|e| e.path.contains("stripe")));
    }

    #[test]
    fn delete_removes_file_and_cleans_dirs() {
        let (_dir, store) = setup_temp_store();

        store.set("deep/nested/secret", b"value").unwrap();
        assert!(store.get("deep/nested/secret").is_ok());

        store.delete("deep/nested/secret").unwrap();

        // Secret should be gone
        assert!(matches!(
            store.get("deep/nested/secret").unwrap_err(),
            RevvaultError::SecretNotFound(_)
        ));

        // Empty parent directories should be cleaned up
        let nested_dir = store.store_dir().join("deep/nested");
        assert!(!nested_dir.exists());
        let deep_dir = store.store_dir().join("deep");
        assert!(!deep_dir.exists());
    }

    #[test]
    fn delete_nonexistent_returns_error() {
        let (_dir, store) = setup_temp_store();

        let err = store.delete("does/not/exist").unwrap_err();
        assert!(matches!(err, RevvaultError::SecretNotFound(_)));
    }

    #[test]
    fn get_nonexistent_returns_error() {
        let (_dir, store) = setup_temp_store();

        let err = store.get("no/such/secret").unwrap_err();
        assert!(matches!(err, RevvaultError::SecretNotFound(_)));
    }

    #[test]
    fn validate_rejects_empty_path() {
        assert!(matches!(
            validate_path(""),
            Err(RevvaultError::InvalidPath(_))
        ));
    }

    #[test]
    fn validate_rejects_absolute_path() {
        assert!(matches!(
            validate_path("/etc/passwd"),
            Err(RevvaultError::InvalidPath(_))
        ));
    }

    #[test]
    fn validate_rejects_traversal() {
        assert!(matches!(
            validate_path("../../etc/passwd"),
            Err(RevvaultError::InvalidPath(_))
        ));
        assert!(matches!(
            validate_path("foo/../../../etc/shadow"),
            Err(RevvaultError::InvalidPath(_))
        ));
        assert!(matches!(
            validate_path("./hidden"),
            Err(RevvaultError::InvalidPath(_))
        ));
    }

    #[test]
    fn validate_rejects_null_bytes() {
        assert!(matches!(
            validate_path("foo\0bar"),
            Err(RevvaultError::InvalidPath(_))
        ));
    }

    #[test]
    fn validate_rejects_backslash_traversal() {
        assert!(matches!(
            validate_path("foo\\..\\..\\etc\\passwd"),
            Err(RevvaultError::InvalidPath(_))
        ));
    }

    #[test]
    fn validate_accepts_valid_paths() {
        assert!(validate_path("credentials/stripe/secret-key").is_ok());
        assert!(validate_path("ssh/github").is_ok());
        assert!(validate_path("single-level").is_ok());
        assert!(validate_path("deep/nested/path/to/secret").is_ok());
    }

    #[test]
    fn store_rejects_traversal_on_set() {
        let (_dir, store) = setup_temp_store();
        assert!(matches!(
            store.set("../../etc/passwd", b"hacked"),
            Err(RevvaultError::InvalidPath(_))
        ));
    }

    #[test]
    fn store_rejects_traversal_on_get() {
        let (_dir, store) = setup_temp_store();
        assert!(matches!(
            store.get("../../../etc/shadow"),
            Err(RevvaultError::InvalidPath(_))
        ));
    }

    #[test]
    fn namespace_parsed_from_list() {
        let (_dir, store) = setup_temp_store();

        store.set("credentials/test", b"v1").unwrap();
        store.set("ssh/key", b"v2").unwrap();
        store.set("revealui/config", b"v3").unwrap();

        let entries = store.list(None).unwrap();
        assert_eq!(entries.len(), 3);

        let cred = entries
            .iter()
            .find(|e| e.path == "credentials/test")
            .unwrap();
        assert_eq!(cred.namespace, Namespace::Credentials);

        let ssh = entries.iter().find(|e| e.path == "ssh/key").unwrap();
        assert_eq!(ssh.namespace, Namespace::Ssh);

        let rui = entries
            .iter()
            .find(|e| e.path == "revealui/config")
            .unwrap();
        assert_eq!(rui.namespace, Namespace::RevealUI);
    }

    #[test]
    fn secret_files_have_age_extension() {
        let (_dir, store) = setup_temp_store();

        store.set("misc/token", b"value").unwrap();
        let entries = store.list(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].file_path.extension().unwrap() == "age");
    }
}
