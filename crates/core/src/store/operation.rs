//! Conditional single-leaf mutations owned by PassageStore.
use super::*;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};

pub(super) struct StoreLock(File);

impl Drop for StoreLock {
    fn drop(&mut self) {
        // Explicitly release the owned flock, including transient descriptors
        // inherited by a concurrently forked child before its exec. Closing
        // the file remains the OS crash-release mechanism.
        let _ = FileExt::unlock(&self.0);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExpectedCurrent {
    Absent,
    Sha256(String),
}

#[derive(Debug, Serialize)]
pub struct OperationReceipt {
    pub operation_id: String,
    pub path: String,
    pub status: &'static str,
    pub current_matches: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u8,
    operation_id: String,
    path: String,
    expected: ExpectedCurrent,
    desired: Vec<u8>,
    committed: bool,
}

fn fingerprint(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

pub(super) fn check_path(root: &Path, path: &Path) -> Result<()> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| RevvaultError::InvalidPath("outside store".into()))?;
    let root_metadata = std::fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(RevvaultError::InvalidPath(
            "store root must be a real directory".into(),
        ));
    }
    let mut current = root.to_path_buf();
    for part in rel.components() {
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(RevvaultError::InvalidPath("symlink in store path".into()))
            }
            Ok(meta) if !meta.is_dir() && !meta.is_file() => {
                return Err(RevvaultError::InvalidPath("nonregular store entry".into()));
            }
            Ok(meta) if current != path && !meta.is_dir() => {
                return Err(RevvaultError::InvalidPath(
                    "store parent must be a directory".into(),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(super) fn check_regular(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => Err(
            RevvaultError::InvalidPath("store leaf must be a regular file".into()),
        ),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub(super) fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    // Ordinary atomic setters remain supported elsewhere. Conditional commits
    // reject before preparing intent when durable directory syncing is absent.
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_write_with_sync(path, bytes, sync_directory)
}

fn atomic_write_with_sync(
    path: &Path,
    bytes: &[u8],
    sync: impl Fn(&Path) -> Result<()>,
) -> Result<()> {
    let mut options = atomic_write_file::AtomicWriteFile::options();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(path)?;
    output.write_all(bytes)?;
    output.commit()?;
    sync(path.parent().unwrap())
}

impl PassageStore {
    pub(super) fn ensure_parent(&self, path: &Path) -> Result<()> {
        check_path(&self.config.store_dir, path)?;
        let mut missing = Vec::new();
        let mut cursor = path;
        while !cursor.try_exists()? {
            missing.push(cursor.to_path_buf());
            cursor = cursor
                .parent()
                .ok_or_else(|| RevvaultError::InvalidPath("no parent".into()))?;
        }
        for dir in missing.iter().rev() {
            std::fs::create_dir(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
            sync_directory(dir.parent().unwrap())?;
        }
        Ok(())
    }

    pub(super) fn operation_lock(&self, exclusive: bool) -> Result<StoreLock> {
        let state = self.config.store_dir.join(".revvault");
        let path = state.join("store.lock");
        check_path(&self.config.store_dir, &state)?;
        check_path(&self.config.store_dir, &path)?;
        check_regular(&path)?;

        if let Some(policy) = &self.service {
            if exclusive && self.service_import_path.is_none() {
                return Err(RevvaultError::Other(anyhow::anyhow!(
                    "revvault_service_capability_denied"
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                for (entry, mode, directory) in [
                    (state.as_path(), 0o750, true),
                    (path.as_path(), 0o640, false),
                ] {
                    crate::service::immutable_path(entry)?;
                    crate::service::private_service_path(entry, policy.uid)?;
                    let metadata = std::fs::symlink_metadata(entry)?;
                    if metadata.mode() & 0o7777 != mode
                        || metadata.is_dir() != directory
                        || (!directory
                            && (!metadata.is_file()
                                || metadata.nlink() != 1
                                || metadata.len() != 0))
                    {
                        return Err(RevvaultError::Other(anyhow::anyhow!(
                            "revvault_service_capability_denied"
                        )));
                    }
                }
            }
            #[cfg(not(unix))]
            return Err(RevvaultError::Other(anyhow::anyhow!(
                "revvault_service_capability_denied"
            )));
        } else {
            // Personal stores retain lazy coordination initialization.
            match std::fs::create_dir(&state) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
                    }
                    sync_directory(&self.config.store_dir)?;
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }

        let mut options = OpenOptions::new();
        options.read(true);
        if self.service.is_some() {
            options.write(exclusive);
        } else if exclusive || !path.try_exists()? {
            options.write(true).create(true).truncate(false);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path)?;
        let result = if exclusive {
            FileExt::try_lock_exclusive(&lock)
        } else {
            FileExt::try_lock_shared(&lock)
        };
        if let Err(e) = result {
            if e.kind() == ErrorKind::WouldBlock {
                return Err(RevvaultError::OperationPending);
            }
            return Err(e.into());
        }
        Ok(StoreLock(lock))
    }

    fn pending_path(&self) -> PathBuf {
        self.config.store_dir.join(".revvault/pending.age")
    }

    pub(super) fn require_no_pending(&self) -> Result<()> {
        let path = self.pending_path();
        check_path(&self.config.store_dir, &path)?;
        match std::fs::symlink_metadata(path) {
            Ok(_) => Err(RevvaultError::OperationPending),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn read_intent(&self, path: &Path) -> Result<Option<Intent>> {
        check_path(&self.config.store_dir, path)?;
        check_regular(path)?;
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let value = crypto::decrypt(&bytes, &self.identity)?;
        let intent: Intent = serde_json::from_str(value.expose_secret())
            .map_err(|_| RevvaultError::OperationConflict)?;
        if intent.version != 1 || uuid::Uuid::parse_str(&intent.operation_id).is_err() {
            return Err(RevvaultError::OperationConflict);
        }
        self.checked_secret_path(&intent.path)?;
        Ok(Some(intent))
    }

    fn write_intent(&self, path: &Path, intent: &Intent) -> Result<()> {
        self.ensure_parent(path.parent().unwrap())?;
        let bytes = serde_json::to_vec(intent).map_err(|_| RevvaultError::OperationConflict)?;
        let ciphertext = crypto::encrypt(&bytes, &self.recipients)?;
        // Refuse an unrecoverable journal before creating its reader fence.
        // Recipient-only writers cannot implement conditional replay.
        crypto::decrypt(&ciphertext, &self.identity)?;
        atomic_write(path, &ciphertext)
    }

    fn current_fingerprint(&self, path: &str) -> Result<ExpectedCurrent> {
        match self.read_secret(path) {
            Ok(value) => Ok(ExpectedCurrent::Sha256(fingerprint(
                value.expose_secret().as_bytes(),
            ))),
            Err(RevvaultError::SecretNotFound(_)) => Ok(ExpectedCurrent::Absent),
            Err(e) => Err(e),
        }
    }

    /// Retry the same immutable single-leaf operation after an interrupted ack.
    /// A committed replay reports historical success without restoring a value
    /// overwritten later. No multi-leaf or hosted-containment guarantee.
    pub fn compare_and_upsert(
        &self,
        path: &str,
        expected: ExpectedCurrent,
        desired: &[u8],
        operation_id: &str,
    ) -> Result<OperationReceipt> {
        self.assert_write()?;
        self.conditional_with_checkpoint(path, expected, desired, operation_id, |_| Ok(()))
    }

    fn conditional_with_checkpoint(
        &self,
        path: &str,
        expected: ExpectedCurrent,
        desired: &[u8],
        operation_id: &str,
        checkpoint: impl Fn(&str) -> Result<()>,
    ) -> Result<OperationReceipt> {
        if !cfg!(unix) {
            return Err(RevvaultError::DurabilityUnsupported);
        }
        let id =
            uuid::Uuid::parse_str(operation_id).map_err(|_| RevvaultError::OperationConflict)?;
        if id.to_string() != operation_id {
            return Err(RevvaultError::OperationConflict);
        }
        if let ExpectedCurrent::Sha256(ref hash) = expected {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(RevvaultError::OperationConflict);
            }
        }
        std::str::from_utf8(desired).map_err(|_| RevvaultError::OperationConflict)?;
        self.checked_secret_path(path)?;
        let _lock = self.operation_lock(true)?;
        sync_directory(&self.config.store_dir)?;
        let pending = self.pending_path();
        let receipt = self
            .config
            .store_dir
            .join(format!(".revvault/operations/{operation_id}.age"));
        let request = Intent {
            version: 1,
            operation_id: operation_id.to_string(),
            path: path.to_string(),
            expected,
            desired: desired.to_vec(),
            committed: false,
        };
        let same = |other: &Intent| {
            other.operation_id == request.operation_id
                && other.path == request.path
                && other.expected == request.expected
                && other.desired == request.desired
        };
        let prepared = self.read_intent(&pending)?;
        if let Some(ref intent) = prepared {
            if !same(intent) || intent.committed {
                return Err(RevvaultError::OperationConflict);
            }
        }
        let completed = self.read_intent(&receipt)?;
        if let Some(ref intent) = completed {
            if !same(intent) || !intent.committed {
                return Err(RevvaultError::OperationConflict);
            }
            if prepared.is_some()
                && self.current_fingerprint(path)? != ExpectedCurrent::Sha256(fingerprint(desired))
            {
                // Maintained writers cannot replace a leaf while its fence is
                // pending. Preserve evidence of nonparticipating interference.
                return Err(RevvaultError::OperationConflict);
            }
            // A previous receipt rename may have returned a directory-sync
            // error. Re-establish durable receipt before clearing its fence.
            File::open(&receipt)?.sync_all()?;
            sync_directory(receipt.parent().unwrap())?;
        } else {
            let current = self.current_fingerprint(path)?;
            let desired_hash = ExpectedCurrent::Sha256(fingerprint(desired));
            if prepared.is_none() {
                if current != request.expected {
                    return Err(RevvaultError::OperationConflict);
                }
                if current != desired_hash {
                    self.prepare_write_path(path)?;
                }
                checkpoint("before_prepare")?;
                self.write_intent(&pending, &request)?;
            } else if current != request.expected && current != desired_hash {
                return Err(RevvaultError::OperationConflict);
            }
            checkpoint("prepared")?;
            if current != desired_hash {
                self.write_secret(path, desired)?;
            } else {
                // Resume after a live rename whose directory sync failed.
                let live = self.checked_secret_path(path)?;
                File::open(&live)?.sync_all()?;
                sync_directory(live.parent().unwrap())?;
            }
            checkpoint("replaced")?;
            let committed = Intent {
                committed: true,
                ..request
            };
            self.write_intent(&receipt, &committed)?;
            checkpoint("receipted")?;
        }
        if self.read_intent(&pending)?.is_some() {
            std::fs::remove_file(&pending)?;
            sync_directory(pending.parent().unwrap())?;
        }
        let matches =
            self.current_fingerprint(path)? == ExpectedCurrent::Sha256(fingerprint(desired));
        Ok(OperationReceipt {
            operation_id: operation_id.to_string(),
            path: path.to_string(),
            status: "committed",
            current_matches: matches,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::tests::setup_temp_store;
    use super::*;

    fn id() -> String {
        uuid::Uuid::new_v4().to_string()
    }
    fn expected(bytes: &[u8]) -> ExpectedCurrent {
        ExpectedCurrent::Sha256(fingerprint(bytes))
    }
    fn interrupted(stage: &str, stop: &str) -> Result<()> {
        if stage == stop {
            Err(std::io::Error::other("synthetic interruption").into())
        } else {
            Ok(())
        }
    }

    #[test]
    fn rejects_conflicting_prior_and_changed_request_without_overwrite() {
        let (_dir, store) = setup_temp_store();
        store.set("credentials/license", b"old\n").unwrap();
        let operation = id();
        assert!(matches!(
            store.compare_and_upsert("credentials/license", expected(b"old"), b"new", &operation),
            Err(RevvaultError::OperationConflict)
        ));
        let receipt = store
            .compare_and_upsert(
                "credentials/license",
                expected(b"old\n"),
                b"new\n",
                &operation,
            )
            .unwrap();
        assert!(receipt.current_matches);
        assert_eq!(
            store.get("credentials/license").unwrap().expose_secret(),
            "new\n"
        );
        assert!(matches!(
            store.compare_and_upsert(
                "credentials/license",
                expected(b"old\n"),
                b"different",
                &operation
            ),
            Err(RevvaultError::OperationConflict)
        ));
        assert!(matches!(
            store.compare_and_upsert("other/path", expected(b"old\n"), b"new\n", &operation),
            Err(RevvaultError::OperationConflict)
        ));
    }

    #[test]
    fn committed_retry_never_restores_over_later_legitimate_write() {
        let (_dir, store) = setup_temp_store();
        let operation = id();
        store
            .compare_and_upsert(
                "credentials/license",
                ExpectedCurrent::Absent,
                b"first",
                &operation,
            )
            .unwrap();
        store.upsert("credentials/license", b"later").unwrap();
        let receipt = store
            .compare_and_upsert(
                "credentials/license",
                ExpectedCurrent::Absent,
                b"first",
                &operation,
            )
            .unwrap();
        assert_eq!(receipt.status, "committed");
        assert!(!receipt.current_matches);
        assert_eq!(
            store.get("credentials/license").unwrap().expose_secret(),
            "later"
        );
        assert_eq!(store.list(None).unwrap().len(), 1);
        store.delete("credentials/license").unwrap();
        assert!(
            !store
                .compare_and_upsert(
                    "credentials/license",
                    ExpectedCurrent::Absent,
                    b"first",
                    &operation
                )
                .unwrap()
                .current_matches
        );
        assert!(matches!(
            store.get("credentials/license"),
            Err(RevvaultError::SecretNotFound(_))
        ));
    }

    #[test]
    fn interrupted_stages_are_encrypted_fenced_and_retryable() {
        for stop in ["before_prepare", "prepared", "replaced", "receipted"] {
            let (_dir, store) = setup_temp_store();
            let operation = id();
            store
                .set("credentials/license", b"prior-sensitive")
                .unwrap();
            assert!(store
                .conditional_with_checkpoint(
                    "credentials/license",
                    expected(b"prior-sensitive"),
                    b"desired-sensitive",
                    &operation,
                    |stage| interrupted(stage, stop)
                )
                .is_err());
            if stop == "before_prepare" {
                assert_eq!(
                    store.get("credentials/license").unwrap().expose_secret(),
                    "prior-sensitive"
                );
            } else {
                assert!(matches!(
                    store.get("credentials/license"),
                    Err(RevvaultError::OperationPending)
                ));
                assert!(matches!(
                    store.list(None),
                    Err(RevvaultError::OperationPending)
                ));
                assert!(matches!(
                    store.set("other", b"x"),
                    Err(RevvaultError::OperationPending)
                ));
                assert!(matches!(
                    store.upsert("credentials/license", b"x"),
                    Err(RevvaultError::OperationPending)
                ));
                assert!(matches!(
                    store.delete("credentials/license"),
                    Err(RevvaultError::OperationPending)
                ));
                let journal = std::fs::read(store.pending_path()).unwrap();
                assert!(!journal
                    .windows(b"desired-sensitive".len())
                    .any(|w| w == b"desired-sensitive"));
                assert!(!journal
                    .windows(b"prior-sensitive".len())
                    .any(|w| w == b"prior-sensitive"));
                assert!(matches!(
                    store.compare_and_upsert(
                        "credentials/license",
                        expected(b"prior-sensitive"),
                        b"other",
                        &operation
                    ),
                    Err(RevvaultError::OperationConflict)
                ));
            }
            let receipt = store
                .compare_and_upsert(
                    "credentials/license",
                    expected(b"prior-sensitive"),
                    b"desired-sensitive",
                    &operation,
                )
                .unwrap();
            assert!(receipt.current_matches);
            assert_eq!(
                store.get("credentials/license").unwrap().expose_secret(),
                "desired-sensitive"
            );
            assert!(!store.pending_path().exists());
            let raw_receipt = std::fs::read(
                store
                    .config
                    .store_dir
                    .join(format!(".revvault/operations/{operation}.age")),
            )
            .unwrap();
            assert!(!raw_receipt.windows(17).any(|w| w == b"desired-sensitive"));
        }
    }

    #[test]
    fn damaged_current_and_pending_are_never_treated_as_absent() {
        let (_dir, store) = setup_temp_store();
        std::fs::write(store.config.store_dir.join("damaged.age"), b"not age").unwrap();
        assert!(matches!(
            store.compare_and_upsert("damaged", ExpectedCurrent::Absent, b"new", &id()),
            Err(RevvaultError::DecryptionFailedForPath { .. })
        ));
        let _lock = store.operation_lock(true).unwrap();
        std::fs::write(store.pending_path(), b"not age").unwrap();
        drop(_lock);
        assert!(matches!(
            store.get("missing"),
            Err(RevvaultError::OperationPending)
        ));
        assert!(store
            .compare_and_upsert("missing", ExpectedCurrent::Absent, b"new", &id())
            .is_err());
    }

    #[test]
    fn encryption_and_directory_failure_preserve_previous_value() {
        let (_dir, mut store) = setup_temp_store();
        store.set("credentials/license", b"prior").unwrap();
        let recipients = std::mem::take(&mut store.recipients);
        assert!(matches!(
            store.compare_and_upsert("credentials/license", expected(b"prior"), b"new", &id()),
            Err(RevvaultError::EncryptionFailed(_))
        ));
        store.recipients = vec![age::x25519::Identity::generate().to_public()];
        assert!(matches!(
            store.compare_and_upsert("missing", ExpectedCurrent::Absent, b"new", &id()),
            Err(RevvaultError::DecryptionFailed(_))
        ));
        assert!(!store.pending_path().exists());
        store.recipients = recipients;
        assert_eq!(
            store.get("credentials/license").unwrap().expose_secret(),
            "prior"
        );
        std::fs::write(
            store.config.store_dir.join(".revvault/operations"),
            b"blocked directory",
        )
        .unwrap();
        assert!(store
            .compare_and_upsert("credentials/license", expected(b"prior"), b"new", &id())
            .is_err());
        assert_eq!(
            store.get("credentials/license").unwrap().expose_secret(),
            "prior"
        );
    }

    #[test]
    fn filesystem_atomic_writer_failure_is_not_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("destination");
        std::fs::create_dir(&destination).unwrap();
        assert!(atomic_write(&destination, b"encrypted synthetic data").is_err());
        assert!(destination.is_dir());
        let replaced = dir.path().join("replaced");
        let error = atomic_write_with_sync(&replaced, b"ciphertext", |_| {
            Err(std::io::Error::other("synthetic directory fsync failure").into())
        });
        assert!(error.is_err());
        assert_eq!(std::fs::read(&replaced).unwrap(), b"ciphertext");
        assert!(sync_directory(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn aliases_and_symlinks_cannot_change_request_identity() {
        let (_dir, store) = setup_temp_store();
        for path in ["a//b", "a/./b", "a/../b", "a\\b", ".revvault/operations/x"] {
            assert!(matches!(
                store.compare_and_upsert(path, ExpectedCurrent::Absent, b"new", &id()),
                Err(RevvaultError::InvalidPath(_))
            ));
        }
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), store.config.store_dir.join("escape")).unwrap();
        assert!(matches!(
            store.compare_and_upsert("escape/secret", ExpectedCurrent::Absent, b"new", &id()),
            Err(RevvaultError::InvalidPath(_))
        ));
        assert!(!outside.path().join("secret.age").exists());
        assert!(matches!(
            store.compare_and_upsert("secret", ExpectedCurrent::Absent, &[255], &id()),
            Err(RevvaultError::OperationConflict)
        ));
    }

    #[test]
    fn nonregular_entries_and_symlink_root_are_rejected_without_reading() {
        let (_dir, mut store) = setup_temp_store();
        let socket_path = store.config.store_dir.join("socket.age");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        assert!(matches!(
            store.get("socket"),
            Err(RevvaultError::InvalidPath(_))
        ));
        assert!(matches!(
            store.compare_and_upsert("socket", ExpectedCurrent::Absent, b"new", &id()),
            Err(RevvaultError::InvalidPath(_))
        ));
        drop(store.operation_lock(true).unwrap());
        let control = store.config.store_dir.join(".revvault/pending.age");
        let _control_listener = std::os::unix::net::UnixListener::bind(&control).unwrap();
        assert!(matches!(
            store.compare_and_upsert("secret", ExpectedCurrent::Absent, b"new", &id()),
            Err(RevvaultError::InvalidPath(_))
        ));
        let outside = tempfile::tempdir().unwrap();
        let alias = outside.path().join("alias");
        std::os::unix::fs::symlink(&store.config.store_dir, &alias).unwrap();
        store.config.store_dir = alias;
        assert!(matches!(
            store.get("secret"),
            Err(RevvaultError::InvalidPath(_))
        ));
    }

    #[test]
    fn read_only_uninitialized_coordination_metadata_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = setup_temp_store();
        let root = &store.config.store_dir;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o500)).unwrap();
        // Privileged test runners bypass Unix permissions. Establish denial
        // with a synthetic probe before asserting this platform condition.
        let probe = root.join("permission-probe");
        let denied = match std::fs::create_dir(&probe) {
            Ok(()) => {
                std::fs::remove_dir(&probe).unwrap();
                false
            }
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::PermissionDenied);
                true
            }
        };
        let read = store.get("missing");
        let list = store.list(None);
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        if denied {
            assert!(
                matches!(read, Err(RevvaultError::Io(ref error)) if error.kind() == ErrorKind::PermissionDenied)
            );
            assert!(
                matches!(list, Err(RevvaultError::Io(ref error)) if error.kind() == ErrorKind::PermissionDenied)
            );
        }
    }

    #[test]
    fn initialized_shared_readers_use_readonly_lock_and_store() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = setup_temp_store();
        store.set("secret", b"synthetic").unwrap();
        let state = store.config.store_dir.join(".revvault");
        let lock = state.join("store.lock");
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::set_permissions(
            &store.config.store_dir,
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        let read = store.get("secret");
        let list = store.list(None);
        std::fs::set_permissions(
            &store.config.store_dir,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(read.unwrap().expose_secret(), "synthetic");
        assert_eq!(list.unwrap().len(), 1);
    }

    #[test]
    fn nested_metadata_named_directory_remains_visible() {
        let (_dir, store) = setup_temp_store();
        store
            .set("credentials/.revvault/license", b"synthetic")
            .unwrap();
        assert_eq!(
            store.list(None).unwrap()[0].path,
            "credentials/.revvault/license"
        );
    }

    #[test]
    fn readonly_destination_rejected_before_intent_and_history_needs_no_write() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = setup_temp_store();
        store.set("secret", b"prior").unwrap();
        let leaf = store.config.store_dir.join("secret.age");
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(
            matches!(store.compare_and_upsert("secret", expected(b"prior"), b"new", &id()), Err(RevvaultError::Io(ref e)) if e.kind() == ErrorKind::PermissionDenied)
        );
        assert!(!store.pending_path().exists());
        assert_eq!(store.get("secret").unwrap().expose_secret(), "prior");
        let parent = store.config.store_dir.join("readonly-parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
        let rejected = store.compare_and_upsert(
            "readonly-parent/new",
            ExpectedCurrent::Absent,
            b"new",
            &id(),
        );
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            matches!(rejected, Err(RevvaultError::Io(ref e)) if e.kind() == ErrorKind::PermissionDenied)
        );
        assert!(!store.pending_path().exists());
        let operation = id();
        assert!(
            store
                .compare_and_upsert("secret", expected(b"prior"), b"prior", &operation)
                .unwrap()
                .current_matches
        );
        assert!(
            store
                .compare_and_upsert("secret", expected(b"prior"), b"prior", &operation)
                .unwrap()
                .current_matches
        );
    }

    #[test]
    fn third_value_after_preparation_keeps_conflict_fenced() {
        for stop in ["prepared", "replaced", "receipted"] {
            let (_dir, store) = setup_temp_store();
            store.set("secret", b"prior").unwrap();
            let operation = id();
            assert!(store
                .conditional_with_checkpoint(
                    "secret",
                    expected(b"prior"),
                    b"desired",
                    &operation,
                    |stage| interrupted(stage, stop)
                )
                .is_err());
            // Synthetic nonparticipating writer models interference, not an API.
            let ciphertext = crypto::encrypt(b"third", &store.recipients).unwrap();
            std::fs::write(store.config.store_dir.join("secret.age"), ciphertext).unwrap();
            assert!(matches!(
                store.compare_and_upsert("secret", expected(b"prior"), b"desired", &operation),
                Err(RevvaultError::OperationConflict)
            ));
            assert!(matches!(
                store.compare_and_upsert("secret", expected(b"third"), b"desired", &id()),
                Err(RevvaultError::OperationConflict)
            ));
            assert!(store.pending_path().exists());
            assert!(matches!(
                store.get("secret"),
                Err(RevvaultError::OperationPending)
            ));
            assert!(matches!(
                store.upsert("secret", b"other"),
                Err(RevvaultError::OperationPending)
            ));
        }
    }

    #[test]
    fn corrupt_committed_receipt_cannot_fabricate_retry_success() {
        let (_dir, store) = setup_temp_store();
        let operation = id();
        store
            .compare_and_upsert("secret", ExpectedCurrent::Absent, b"desired", &operation)
            .unwrap();
        let receipt = store
            .config
            .store_dir
            .join(format!(".revvault/operations/{operation}.age"));
        std::fs::write(receipt, b"corrupted synthetic receipt").unwrap();
        assert!(store
            .compare_and_upsert("secret", ExpectedCurrent::Absent, b"desired", &operation)
            .is_err());
        assert_eq!(store.get("secret").unwrap().expose_secret(), "desired");
    }

    // A subprocess holds the exact maintained lock, then exits without cleanup.
    // These environment values are synthetic test fixtures, never runtime options.
    #[test]
    fn lock_process_fixture() {
        let Ok(path) = std::env::var("REVVAULT_TEST_LOCK_PATH") else {
            return;
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        FileExt::lock_exclusive(&file).unwrap();
        std::fs::write(std::env::var("REVVAULT_TEST_LOCK_READY").unwrap(), b"ready").unwrap();
        loop {
            std::thread::park();
        }
    }

    #[test]
    fn independent_process_competes_and_crash_releases_os_lock() {
        let (dir, store) = setup_temp_store();
        drop(store.operation_lock(true).unwrap());
        let ready = dir.path().join("ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::operation::tests::lock_process_fixture",
                "--nocapture",
            ])
            .env(
                "REVVAULT_TEST_LOCK_PATH",
                store.config.store_dir.join(".revvault/store.lock"),
            )
            .env("REVVAULT_TEST_LOCK_READY", &ready)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !ready.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let started = ready.exists();
        let blocked = store.compare_and_upsert(
            "credentials/license",
            ExpectedCurrent::Absent,
            b"new",
            &id(),
        );
        let ordinary = [
            store.set("other", b"x"),
            store.upsert("other", b"x"),
            store.delete("other"),
        ];
        let read_blocked = matches!(store.get("other"), Err(RevvaultError::OperationPending));
        let list_blocked = matches!(store.list(None), Err(RevvaultError::OperationPending));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(ordinary
            .into_iter()
            .all(|result| matches!(result, Err(RevvaultError::OperationPending))));
        assert!(read_blocked && list_blocked);
        assert!(started, "synthetic child failed to acquire lock");
        assert!(matches!(blocked, Err(RevvaultError::OperationPending)));
        assert!(
            store
                .compare_and_upsert(
                    "credentials/license",
                    ExpectedCurrent::Absent,
                    b"new",
                    &id()
                )
                .unwrap()
                .current_matches
        );
    }
}
