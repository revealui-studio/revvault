//! Independent encrypted checkpoints for fixed service custody. Root admission,
//! scoped file inventory and no-clobber publication extend service provisioning.
//! Storage transport and owner acceptance of checkpoint receipts are separate.
use super::{immutable_path, lock_custody, ServicePolicy};
use crate::error::{Result, RevvaultError};
use crate::init::{self, ServiceInitPlan};
use age::x25519;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const LIMIT: usize = 16 * 1024 * 1024;
const FILE_LIMIT: usize = 1024 * 1024;

fn denied() -> RevvaultError {
    RevvaultError::Other(anyhow::anyhow!("revvault_service_backup_restore_denied"))
}

/// Nonsecret receipt. Its archive digest must be independently accepted and
/// retained: age recipient encryption alone does not authenticate a sender.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReceipt {
    pub version: u32,
    pub uid: u32,
    pub checkpoint: String,
    pub archive_sha256: String,
    pub recovery_recipient: String,
    pub policy_sha256: String,
    pub commands: BTreeMap<String, String>,
    pub files: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    uid: u32,
    checkpoint: String,
    recovery_recipient: String,
    commands: BTreeMap<String, String>,
    files: BTreeMap<String, CustodyBytes>,
}

// Each entry erases itself even if deserialization fails before the complete
// checkpoint is constructed. Never derive Debug for private custody bytes.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct CustodyBytes(Vec<u8>);

impl Drop for CustodyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl std::ops::Deref for CustodyBytes {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for CustodyBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl From<Vec<u8>> for CustodyBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

fn root_only() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(denied());
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn command_digests(policy: &ServicePolicy) -> Result<BTreeMap<String, String>> {
    policy
        .command
        .iter()
        .filter(|part| Path::new(part).is_absolute())
        .map(|part| Ok((part.clone(), init::file_digest(Path::new(part))?)))
        .collect()
}

fn file_names(policy: &ServicePolicy) -> Vec<String> {
    let mut names = vec![
        "policy.toml".into(),
        "identity.txt".into(),
        "store/.age-recipients".into(),
    ];
    names.extend(
        policy
            .secrets
            .values()
            .map(|path| format!("store/{path}.age")),
    );
    names.sort();
    names.dedup();
    names
}

fn directories(names: &[String]) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("store"), PathBuf::from("store/.revvault")];
    for name in names {
        for parent in Path::new(name).ancestors().skip(1) {
            if !parent.as_os_str().is_empty() {
                dirs.push(parent.to_path_buf());
            }
        }
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

fn private_file(path: &Path, gid: u32, mode: u32) -> Result<()> {
    immutable_path(path)?;
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.nlink() != 1 || m.gid() != gid || m.mode() & 0o7777 != mode {
        return Err(denied());
    }
    Ok(())
}

fn read_limited(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(denied());
    }
    Ok(bytes)
}

fn validate_payload(checkpoint: &Checkpoint, policy: &ServicePolicy) -> Result<()> {
    if checkpoint.version != 1
        || checkpoint.uid != policy.uid
        || uuid::Uuid::parse_str(&checkpoint.checkpoint).is_err()
        || checkpoint.commands != command_digests(policy)?
        || checkpoint.files.len() > 35
    {
        return Err(denied());
    }
    let names = file_names(policy);
    if checkpoint.files.len() != names.len()
        || checkpoint.files.keys().any(|name| !names.contains(name))
        || checkpoint
            .files
            .values()
            .any(|bytes| bytes.len() > FILE_LIMIT)
    {
        return Err(denied());
    }
    for name in ["policy.toml", "identity.txt", "store/.age-recipients"] {
        if !checkpoint.files.contains_key(name) {
            return Err(denied());
        }
    }
    let policy_bytes = toml::to_string(policy).map_err(|_| denied())?;
    if checkpoint.files["policy.toml"].as_slice() != policy_bytes.as_bytes() {
        return Err(denied());
    }
    let text = std::str::from_utf8(&checkpoint.files["identity.txt"]).map_err(|_| denied())?;
    let identity = crate::Identity::from_text(text).map_err(|_| denied())?;
    if identity.as_identities().len() != 1 {
        return Err(denied());
    }
    let recipient_text =
        std::str::from_utf8(&checkpoint.files["store/.age-recipients"]).map_err(|_| denied())?;
    let recipients = crate::crypto::parse_recipients(recipient_text).map_err(|_| denied())?;
    let service_recipient = identity.default_recipient().to_string();
    if recipients.len() != 1
        || recipients[0].to_string() != service_recipient
        || checkpoint.recovery_recipient == service_recipient
        || checkpoint
            .recovery_recipient
            .parse::<x25519::Recipient>()
            .is_err()
    {
        return Err(denied());
    }
    // Validate ciphertext against its preserved service identity without printing
    // plaintext or writing a temporary identity file.
    for (name, bytes) in &checkpoint.files {
        if name.ends_with(".age") {
            let plaintext = crate::crypto::decrypt(bytes, &identity).map_err(|_| denied())?;
            if plaintext.expose_secret().len() > FILE_LIMIT {
                return Err(denied());
            }
        }
    }
    Ok(())
}

/// Create an independently encrypted checkpoint without plaintext disk output.
/// Requires an active fixed service capability and a distinct recovery recipient.
/// The create-only encrypted output must be in an immutable root-private directory.
pub fn backup_service_vault(uid: u32, recipient: &str, output: &Path) -> Result<BackupReceipt> {
    root_only()?;
    let _lock = lock_custody(uid)?;
    let policy = ServicePolicy::for_import(uid)?;
    init::validate_service_account_and_commands(&policy)?;
    let recovery = recipient
        .parse::<x25519::Recipient>()
        .map_err(|_| denied())?;
    let root = policy
        .config()
        .store_dir
        .parent()
        .ok_or_else(denied)?
        .to_path_buf();
    let parent = output.parent().ok_or_else(denied)?;
    immutable_path(parent)?;
    let m = fs::symlink_metadata(parent)?;
    if !m.is_dir()
        || m.gid() != 0
        || m.mode() & 0o7777 != 0o700
        || !output.is_absolute()
        || output.starts_with(&root)
    {
        return Err(denied());
    }
    match fs::symlink_metadata(output) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(denied()),
    }
    let names = file_names(&policy);
    let dirs = directories(&names);
    let mut checkpoint = Checkpoint {
        version: 1,
        uid,
        checkpoint: uuid::Uuid::new_v4().to_string(),
        recovery_recipient: recovery.to_string(),
        commands: command_digests(&policy)?,
        files: BTreeMap::new(),
    };
    // Reject pending initialization, metadata extras, unexpected selectors,
    // symlinks, hardlinks and unsafe ownership anywhere in the namespace.
    for (index, entry) in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        if index > 1024 {
            return Err(denied());
        }
        let entry = entry.map_err(|_| denied())?;
        let path = entry.path();
        let relative = path.strip_prefix(&root).map_err(|_| denied())?;
        let m = fs::symlink_metadata(path)?;
        immutable_path(path)?;
        if m.is_dir() {
            if (!relative.as_os_str().is_empty() && !dirs.contains(&relative.to_path_buf()))
                || m.gid() != uid
                || m.mode() & 0o7777 != 0o750
            {
                return Err(denied());
            }
        } else {
            let name = relative.to_str().ok_or_else(denied)?;
            if !names.iter().any(|allowed| allowed == name) {
                return Err(denied());
            }
            let (gid, mode) = if name == "policy.toml" {
                (0, 0o644)
            } else {
                (uid, 0o640)
            };
            private_file(path, gid, mode)?;
            checkpoint
                .files
                .insert(name.into(), read_limited(path, FILE_LIMIT)?.to_vec().into());
        }
    }
    validate_payload(&checkpoint, &policy)?;
    let bytes = Zeroizing::new(serde_json::to_vec(&checkpoint).map_err(|_| denied())?);
    if bytes.len() > LIMIT {
        return Err(denied());
    }
    let encrypted = crate::crypto::encrypt(&bytes, &[recovery])?;
    let receipt = BackupReceipt {
        version: 1,
        uid,
        checkpoint: checkpoint.checkpoint.clone(),
        archive_sha256: digest(&encrypted),
        recovery_recipient: checkpoint.recovery_recipient.clone(),
        policy_sha256: digest(&checkpoint.files["policy.toml"]),
        commands: checkpoint.commands.clone(),
        files: checkpoint
            .files
            .iter()
            .map(|(name, bytes)| (name.clone(), digest(bytes)))
            .collect(),
    };
    let mut pending = tempfile::NamedTempFile::new_in(parent)?;
    init::set_service_permissions(pending.path(), 0, 0o600)?;
    pending.write_all(&encrypted)?;
    pending.as_file().sync_all()?;
    pending.persist_noclobber(output).map_err(|_| denied())?;
    fs::File::open(parent)?.sync_all()?;
    Ok(receipt)
}

/// Restore a pinned independently encrypted checkpoint onto an absent fixed
/// service namespace. Never adopts an existing store or regenerates an identity.
/// The digest must come from an independently accepted backup receipt; policy
/// and absolute command hashes must match the accepted restore source exactly.
pub(crate) fn restore_service_vault(
    policy_file: &Path,
    archive: &Path,
    expected_sha256: &str,
    recovery_identity: &str,
    admission: Option<&super::receiver::ServiceMutationGuard<'_>>,
) -> Result<ServiceInitPlan> {
    restore_checkpoint(
        policy_file,
        archive,
        expected_sha256,
        recovery_identity,
        false,
        admission,
    )
}

/// Disposable native fixture only: fail after fully staging recovery, before
/// atomic capability publication. No production CLI or environment fault route.
#[cfg(feature = "native-service-tests")]
pub fn interrupt_restore_before_publication(
    policy_file: &Path,
    archive: &Path,
    expected_sha256: &str,
    recovery_identity: &str,
) -> Result<ServiceInitPlan> {
    restore_checkpoint(
        policy_file,
        archive,
        expected_sha256,
        recovery_identity,
        true,
        None,
    )
}

/// Lower primitive for disposable native fixtures; unavailable in production builds.
#[cfg(feature = "native-service-tests")]
pub fn native_restore_service_vault(
    policy_file: &Path,
    archive: &Path,
    expected_sha256: &str,
    recovery_identity: &str,
) -> Result<ServiceInitPlan> {
    restore_checkpoint(
        policy_file,
        archive,
        expected_sha256,
        recovery_identity,
        false,
        None,
    )
}

fn restore_checkpoint(
    policy_file: &Path,
    archive: &Path,
    expected_sha256: &str,
    recovery_identity: &str,
    interrupt: bool,
    admission: Option<&super::receiver::ServiceMutationGuard<'_>>,
) -> Result<ServiceInitPlan> {
    root_only()?;
    immutable_path(policy_file)?;
    let policy: ServicePolicy =
        toml::from_str(&fs::read_to_string(policy_file)?).map_err(|_| denied())?;
    init::validate_service_account_and_commands(&policy)?;
    let plan = init::service_init_plan(&policy)?;
    let target = plan.policy_file.parent().ok_or_else(denied)?;
    match fs::symlink_metadata(target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(denied()),
    }
    private_file(archive, 0, 0o600)?;
    let encrypted = read_limited(archive, LIMIT + 1024 * 1024)?;
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
        || digest(&encrypted) != expected_sha256
    {
        return Err(denied());
    }
    let key = crate::Identity::from_text(recovery_identity).map_err(|_| denied())?;
    if key.as_identities().len() != 1 {
        return Err(denied());
    }
    // Age is not a compressed container: bounded ciphertext also bounds this
    // shared strict UTF-8 decrypt path. Never materialize a private key file.
    let plaintext = crate::crypto::decrypt(&encrypted, &key).map_err(|_| denied())?;
    if plaintext.expose_secret().len() > LIMIT {
        return Err(denied());
    }
    let checkpoint: Checkpoint =
        serde_json::from_str(plaintext.expose_secret()).map_err(|_| denied())?;
    validate_payload(&checkpoint, &policy)?;
    if checkpoint.recovery_recipient != key.default_recipient().to_string() {
        return Err(denied());
    }
    if let Some(guard) = admission {
        guard.recheck()?;
    }
    // All authority, source, archive and payload checks precede target creation.
    let parent = target.parent().ok_or_else(denied)?;
    init::ensure_service_parent(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".service-restore-")
        .tempdir_in(parent)?;
    let names = checkpoint.files.keys().cloned().collect::<Vec<_>>();
    let dirs = directories(&names);
    for dir in &dirs {
        let path = staging.path().join(dir);
        fs::create_dir(&path)?;
        init::set_service_permissions(&path, policy.uid, 0o750)?;
    }
    for (name, bytes) in &checkpoint.files {
        let path = staging.path().join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(bytes)?;
        let (gid, mode) = if name == "policy.toml" {
            (0, 0o644)
        } else {
            (policy.uid, 0o640)
        };
        init::set_service_permissions(&path, gid, mode)?;
        file.sync_all()?;
    }
    for dir in dirs.iter().rev() {
        fs::File::open(staging.path().join(dir))?.sync_all()?;
    }
    init::set_service_permissions(staging.path(), policy.uid, 0o750)?;
    fs::File::open(staging.path())?.sync_all()?;
    if interrupt {
        return Err(denied());
    }
    // One atomic no-replace publication of the fully validated, fsynced store
    // and capability. Partial staging is never an active runtime capability.
    if let Some(guard) = admission {
        guard.recheck()?;
    }
    init::publish_new_service_store(staging.path(), target)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn fixture() -> (ServicePolicy, Checkpoint) {
        let policy = ServicePolicy {
            version: 1,
            uid: 19001,
            command: vec!["/usr/bin/env".into()],
            environment: BTreeMap::new(),
            secrets: BTreeMap::from([(
                "REVEALFLEET_TEST_SECRET".into(),
                "revealfleet/publisher/synthetic-key".into(),
            )]),
        };
        let key = x25519::Identity::generate();
        let recovery = x25519::Identity::generate();
        let files: BTreeMap<String, CustodyBytes> = [
            (
                "policy.toml".into(),
                toml::to_string(&policy).unwrap().into_bytes(),
            ),
            (
                "identity.txt".into(),
                key.to_string().expose_secret().as_bytes().to_vec(),
            ),
            (
                "store/.age-recipients".into(),
                format!("{}\n", key.to_public()).into_bytes(),
            ),
            (
                "store/revealfleet/publisher/synthetic-key.age".into(),
                crate::crypto::encrypt(b"synthetic", &[key.to_public()]).unwrap(),
            ),
        ]
        .into_iter()
        .map(|(name, bytes)| (name, bytes.into()))
        .collect();
        let checkpoint = Checkpoint {
            version: 1,
            uid: policy.uid,
            checkpoint: uuid::Uuid::new_v4().to_string(),
            recovery_recipient: recovery.to_public().to_string(),
            commands: command_digests(&policy).unwrap(),
            files,
        };
        (policy, checkpoint)
    }

    #[test]
    fn payload_requires_exact_policy_source_identity_and_scoped_ciphertext() {
        let (policy, mut checkpoint) = fixture();
        validate_payload(&checkpoint, &policy).unwrap();
        checkpoint
            .files
            .insert("../owner/identity".into(), b"foreign".to_vec().into());
        assert!(validate_payload(&checkpoint, &policy).is_err());
        checkpoint.files.remove("../owner/identity");
        checkpoint.uid += 1;
        assert!(validate_payload(&checkpoint, &policy).is_err());
        checkpoint.uid -= 1;
        checkpoint
            .commands
            .insert("/usr/bin/env".into(), "changed".into());
        assert!(validate_payload(&checkpoint, &policy).is_err());
        checkpoint.commands = command_digests(&policy).unwrap();
        checkpoint.files.insert(
            "store/revealfleet/publisher/synthetic-key.age".into(),
            b"bad ciphertext".to_vec().into(),
        );
        assert!(validate_payload(&checkpoint, &policy).is_err());
    }

    #[test]
    fn payload_denies_changed_policy_recipients_and_recovery_identity_reuse() {
        let (policy, mut checkpoint) = fixture();
        checkpoint.recovery_recipient =
            String::from_utf8(checkpoint.files["store/.age-recipients"].to_vec())
                .unwrap()
                .trim()
                .into();
        assert!(validate_payload(&checkpoint, &policy).is_err());
        let (policy, mut checkpoint) = fixture();
        checkpoint.files.insert(
            "store/.age-recipients".into(),
            format!("{}\n", x25519::Identity::generate().to_public())
                .into_bytes()
                .into(),
        );
        assert!(validate_payload(&checkpoint, &policy).is_err());
        let (policy, mut checkpoint) = fixture();
        checkpoint
            .files
            .get_mut("policy.toml")
            .unwrap()
            .extend(b"\n#changed");
        assert!(validate_payload(&checkpoint, &policy).is_err());
    }

    #[test]
    fn payload_denies_unknown_version_missing_identity_and_oversized_files() {
        let (policy, mut checkpoint) = fixture();
        checkpoint.version = 2;
        assert!(validate_payload(&checkpoint, &policy).is_err());
        checkpoint.version = 1;
        checkpoint
            .files
            .insert("identity.txt".into(), vec![0; FILE_LIMIT + 1].into());
        assert!(validate_payload(&checkpoint, &policy).is_err());
        checkpoint.files.remove("identity.txt");
        assert!(validate_payload(&checkpoint, &policy).is_err());
    }

    #[test]
    fn incomplete_secret_checkpoint_cannot_be_admitted_for_restore() {
        let (policy, mut checkpoint) = fixture();
        checkpoint
            .files
            .remove("store/revealfleet/publisher/synthetic-key.age");
        assert!(validate_payload(&checkpoint, &policy).is_err());
    }

    #[test]
    fn unprivileged_backup_and_restore_deny_without_reading_paths() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let absent = Path::new("/nonexistent/revealfleet-custody");
        assert_eq!(
            backup_service_vault(19001, "invalid", absent)
                .unwrap_err()
                .to_string(),
            "revvault_service_backup_restore_denied"
        );
        assert_eq!(
            restore_service_vault(absent, absent, "invalid", "invalid", None)
                .unwrap_err()
                .to_string(),
            "revvault_service_backup_restore_denied"
        );
    }
}
