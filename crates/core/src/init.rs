//! Vault initialization — create store directory, generate age identity.

use std::path::{Path, PathBuf};

use age::x25519;
use chrono::Utc;
use secrecy::ExposeSecret as _;

use crate::error::{Result, RevvaultError};
use crate::service::ServicePolicy;

/// Nonsecret preview of the fixed kernel-bound service provisioning target.
/// Unlike personal initialization this never accepts store/identity overrides.
#[derive(Debug, serde::Serialize)]
pub struct ServiceInitPlan {
    pub uid: u32,
    pub gid: u32,
    pub policy_file: PathBuf,
    pub store_dir: PathBuf,
    pub identity_file: PathBuf,
    pub recipients_file: PathBuf,
    pub command: Vec<String>,
    pub environment: std::collections::BTreeMap<String, String>,
    pub secrets: std::collections::BTreeMap<String, String>,
}

pub fn service_init_plan(policy: &ServicePolicy) -> Result<ServiceInitPlan> {
    policy.validate(policy.uid)?;
    let config = policy.config();
    Ok(ServiceInitPlan {
        uid: policy.uid,
        gid: policy.uid,
        policy_file: ServicePolicy::fixed_policy_path(policy.uid),
        store_dir: config.store_dir,
        identity_file: config.identity_file,
        recipients_file: config.recipients_file,
        command: policy.command.clone(),
        environment: policy.environment.clone(),
        secrets: policy.secrets.clone(),
    })
}

fn service_init_denied() -> RevvaultError {
    RevvaultError::Other(anyhow::anyhow!("revvault_service_provisioning_denied"))
}

/// Provision a new independent age identity and store, publishing the service
/// capability last. Requires a reviewed immutable policy and an existing OS
/// account with matching primary GID and no supplementary group memberships.
/// Never adopts or overwrites existing service paths or personal vault data.
pub fn init_service_vault(policy_file: &Path) -> Result<ServiceInitPlan> {
    provision_service_vault(policy_file, false, 0)
}

/// Resume only an initializer-produced, unchanged, unbound fresh store.
/// Never rotate an identity, adopt a foreign store or repair unsafe ownership.
pub fn resume_service_vault(policy_file: &Path) -> Result<ServiceInitPlan> {
    provision_service_vault(policy_file, true, 0)
}

/// Fault injection exists only in the explicit disposable native test feature.
/// Production CLI builds have no environment or argument route to this fault.
#[cfg(feature = "native-service-tests")]
pub fn interrupt_service_vault_after_store(policy_file: &Path) -> Result<ServiceInitPlan> {
    provision_service_vault(policy_file, false, 1)
}

/// Native-only interruption after durable capability publication, before finalization.
#[cfg(feature = "native-service-tests")]
pub fn interrupt_service_vault_after_capability(policy_file: &Path) -> Result<ServiceInitPlan> {
    provision_service_vault(policy_file, false, 2)
}

fn provision_service_vault(
    policy_file: &Path,
    resume: bool,
    interruption: u8,
) -> Result<ServiceInitPlan> {
    #[cfg(target_os = "linux")]
    {
        use crate::service::immutable_path;
        if unsafe { libc::geteuid() } != 0 {
            return Err(service_init_denied());
        }
        immutable_path(policy_file)?;
        let policy: ServicePolicy = toml::from_str(&std::fs::read_to_string(policy_file)?)
            .map_err(|_| service_init_denied())?;
        let plan = service_init_plan(&policy)?;
        ServicePolicy::reject_legacy(plan.uid)?;
        validate_service_account_and_commands(&policy)?;
        let policy_parent = plan.policy_file.parent().ok_or_else(service_init_denied)?;
        let service_root = plan.store_dir.parent().ok_or_else(service_init_denied)?;
        let store_parent = service_root.parent().ok_or_else(service_init_denied)?;
        // Create only the fixed maintained service namespace, checking every
        // existing ancestor before descending. Never repair/adopt a mutable
        // path or accept a caller-selected privileged store location.
        if resume {
            immutable_path(store_parent)?;
        } else {
            ensure_service_parent(store_parent)?;
        }
        if !std::fs::metadata(store_parent)?.is_dir() {
            return Err(service_init_denied());
        }
        if resume {
            immutable_path(service_root)?;
        } else {
            match std::fs::symlink_metadata(service_root) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(service_init_denied()),
            }
            let staging = tempfile::Builder::new()
                .prefix(".service-init-")
                .tempdir_in(store_parent)?;
            create_service_store(staging.path(), plan.gid)?;
            write_service_intent(staging.path(), &policy)?;
            // The completed store and root-only provenance are durable before
            // publication. Service-group access never includes write access.
            set_service_permissions(staging.path(), plan.gid, 0o750)?;
            std::fs::File::open(staging.path())?.sync_all()?;
            publish_new_service_store(staging.path(), service_root)?;
        }
        // Serialize create/resume finalization on immutable root-only provenance.
        let _lock = lock_service_intent(service_root)?;
        if resume {
            verify_service_recovery(service_root, &policy)?;
        }
        let published = match std::fs::symlink_metadata(&plan.policy_file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Ok(_) if resume => true,
            _ => return Err(service_init_denied()),
        };
        // A crash here leaves durable, bound recovery evidence, no capability.
        std::fs::File::open(store_parent)?.sync_all()?;
        if interruption == 1 {
            return Err(service_init_denied());
        }
        if !published {
            let mut capability = tempfile::NamedTempFile::new_in(policy_parent)?;
            use std::io::Write;
            capability.write_all(
                toml::to_string(&policy)
                    .map_err(|_| service_init_denied())?
                    .as_bytes(),
            )?;
            set_service_permissions(capability.path(), 0, 0o644)?;
            capability.as_file().sync_all()?;
            // No-clobber capability publication is last. Active or concurrent
            // capabilities cannot be overwritten by either create or resume.
            capability
                .persist_noclobber(&plan.policy_file)
                .map_err(|_| service_init_denied())?;
            std::fs::File::open(policy_parent)?.sync_all()?;
        }
        if interruption == 2 {
            return Err(service_init_denied());
        }
        std::fs::remove_file(service_root.join(".provisioning.toml"))?;
        std::fs::File::open(service_root)?.sync_all()?;
        Ok(plan)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (policy_file, resume, interruption);
        Err(service_init_denied())
    }
}

/// Shared root provisioning admission for fresh initialization and restoration.
#[cfg(target_os = "linux")]
pub(crate) fn validate_service_account_and_commands(policy: &ServicePolicy) -> Result<()> {
    use crate::service::immutable_path;
    if unsafe { libc::geteuid() } != 0 {
        return Err(service_init_denied());
    }
    let plan = service_init_plan(policy)?;
    ServicePolicy::reject_legacy(plan.uid)?;
    // getpwuid/getgrouplist are used only during root provisioning, before
    // any filesystem changes. The runtime separately checks kernel groups.
    unsafe {
        let account = libc::getpwuid(plan.uid);
        if account.is_null() || (*account).pw_gid != plan.gid {
            return Err(service_init_denied());
        }
        let mut count = 0;
        libc::getgrouplist(
            (*account).pw_name,
            plan.gid,
            std::ptr::null_mut(),
            &mut count,
        );
        if count <= 0 || count > 1024 {
            return Err(service_init_denied());
        }
        let mut groups = vec![0; count as usize];
        if libc::getgrouplist(
            (*account).pw_name,
            plan.gid,
            groups.as_mut_ptr(),
            &mut count,
        ) < 0
            || groups.iter().any(|group| *group != plan.gid)
        {
            return Err(service_init_denied());
        }
    }
    for part in &policy.command {
        if Path::new(part).is_absolute() {
            immutable_path(Path::new(part))?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceProvisioningIntent {
    version: u32,
    policy: String,
    files: std::collections::BTreeMap<String, String>,
    commands: std::collections::BTreeMap<String, String>,
}

#[cfg(target_os = "linux")]
pub(crate) fn file_digest(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(service_init_denied());
    }
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = zeroize::Zeroizing::new([0; 8192]);
    loop {
        let count = file.read(&mut *buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(target_os = "linux")]
fn service_intent(root: &Path, policy: &ServicePolicy) -> Result<ServiceProvisioningIntent> {
    Ok(ServiceProvisioningIntent {
        version: 1,
        policy: toml::to_string(policy).map_err(|_| service_init_denied())?,
        files: [
            "identity.txt",
            "store/.age-recipients",
            "store/.revvault/store.lock",
        ]
        .into_iter()
        .map(|name| Ok((name.to_string(), file_digest(&root.join(name))?)))
        .collect::<Result<_>>()?,
        commands: policy
            .command
            .iter()
            .filter(|part| Path::new(part).is_absolute())
            .map(|part| Ok((part.clone(), file_digest(Path::new(part))?)))
            .collect::<Result<_>>()?,
    })
}

#[cfg(target_os = "linux")]
fn write_service_intent(root: &Path, policy: &ServicePolicy) -> Result<()> {
    use std::io::Write;
    let intent = service_intent(root, policy)?;
    let mut file = tempfile::NamedTempFile::new_in(root)?;
    file.write_all(
        toml::to_string(&intent)
            .map_err(|_| service_init_denied())?
            .as_bytes(),
    )?;
    set_service_permissions(file.path(), 0, 0o600)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(root.join(".provisioning.toml"))
        .map_err(|_| service_init_denied())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn lock_service_intent(root: &Path) -> Result<std::fs::File> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    let path = root.join(".provisioning.toml");
    crate::service::immutable_path(&path)?;
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(service_init_denied());
    }
    let file = std::fs::File::open(path)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(service_init_denied());
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn verify_service_recovery(root: &Path, policy: &ServicePolicy) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // Exactly the fresh maintained layout; never absorb ciphertext, aliases,
    // metadata additions or incomplete/foreign storage into a new capability.
    for (name, mode, directory, gid) in [
        ("", 0o750, true, policy.uid),
        ("store", 0o750, true, policy.uid),
        ("store/.revvault", 0o750, true, policy.uid),
        ("store/.revvault/store.lock", 0o640, false, policy.uid),
        ("identity.txt", 0o640, false, policy.uid),
        ("store/.age-recipients", 0o640, false, policy.uid),
        (".provisioning.toml", 0o600, false, 0),
    ] {
        let path = if name.is_empty() {
            root.to_path_buf()
        } else {
            root.join(name)
        };
        crate::service::immutable_path(&path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.gid() != gid
            || metadata.mode() & 0o7777 != mode
            || metadata.is_dir() != directory
            || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        {
            return Err(service_init_denied());
        }
    }
    let capability = ServicePolicy::fixed_policy_path(policy.uid);
    let published = match std::fs::symlink_metadata(&capability) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Ok(metadata) => {
            crate::service::immutable_path(&capability)?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.gid() != 0
                || metadata.mode() & 0o7777 != 0o644
                || std::fs::read_to_string(&capability)?
                    != toml::to_string(policy).map_err(|_| service_init_denied())?
            {
                return Err(service_init_denied());
            }
            true
        }
        Err(_) => return Err(service_init_denied()),
    };
    let mut root_entries = vec![".provisioning.toml", "identity.txt", "store"];
    if published {
        root_entries.push("policy.toml");
    }
    for (name, allowed) in [
        ("", root_entries),
        ("store", vec![".age-recipients", ".revvault"]),
        ("store/.revvault", vec!["store.lock"]),
    ] {
        let entries = std::fs::read_dir(root.join(name))?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        if entries.len() != allowed.len()
            || entries
                .iter()
                .any(|entry| !allowed.iter().any(|name| entry == name))
        {
            return Err(service_init_denied());
        }
    }
    let recorded: ServiceProvisioningIntent =
        toml::from_str(&std::fs::read_to_string(root.join(".provisioning.toml"))?)
            .map_err(|_| service_init_denied())?;
    let expected = service_intent(root, policy)?;
    if recorded.version != 1
        || recorded.policy != expected.policy
        || recorded.files != expected.files
        || recorded.commands != expected.commands
    {
        return Err(service_init_denied());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_service_parent(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::service::immutable_path(ancestor.parent().ok_or_else(service_init_denied)?)?;
                std::fs::DirBuilder::new().mode(0o755).create(ancestor)?;
                std::fs::set_permissions(ancestor, std::fs::Permissions::from_mode(0o755))?;
                std::fs::File::open(ancestor)?.sync_all()?;
                std::fs::File::open(ancestor.parent().ok_or_else(service_init_denied)?)?
                    .sync_all()?;
            }
            Err(_) => return Err(service_init_denied()),
        }
        crate::service::immutable_path(ancestor)?;
        if !std::fs::metadata(ancestor)?.is_dir() {
            return Err(service_init_denied());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn publish_new_service_store(source: &Path, destination: &Path) -> Result<()> {
    let destination = std::ffi::CString::new(destination.as_os_str().as_encoded_bytes())
        .map_err(|_| service_init_denied())?;
    let source = std::ffi::CString::new(source.as_os_str().as_encoded_bytes())
        .map_err(|_| service_init_denied())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(service_init_denied());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_service_permissions(path: &Path, gid: u32, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let file = std::fs::File::open(path)?;
    use std::os::fd::AsRawFd;
    if unsafe { libc::fchown(file.as_raw_fd(), !0, gid) } != 0 {
        return Err(service_init_denied());
    }
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(unix)]
fn create_service_store(root: &Path, gid: u32) -> Result<()> {
    let summary = init_vault(InitOptions {
        store_dir: Some(root.join("store")),
        identity_file: Some(root.join("identity.txt")),
    })?;
    set_service_permissions(&summary.store_dir, gid, 0o750)?;
    set_service_permissions(&summary.store_dir.join(".revvault"), gid, 0o750)?;

    let lock_path = summary.store_dir.join(".revvault/store.lock");
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)?;
    set_service_permissions(&lock_path, gid, 0o640)?;
    lock.sync_all()?;
    std::fs::File::open(summary.store_dir.join(".revvault"))?.sync_all()?;
    set_service_permissions(&summary.identity_file, gid, 0o640)?;
    set_service_permissions(&summary.store_dir.join(".age-recipients"), gid, 0o640)?;
    for directory in [root, summary.store_dir.as_path()] {
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_file() {
                std::fs::File::open(path)?.sync_all()?;
            }
        }
        std::fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

/// Summary returned after a successful `init_vault` call.
#[derive(Debug, Clone)]
pub struct InitSummary {
    /// Path to the created store directory.
    pub store_dir: PathBuf,
    /// Path to the identity (private key) file.
    pub identity_file: PathBuf,
    /// Age public key written to `.age-recipients`.
    pub public_key: String,
    /// True if the store directory already existed before this call.
    pub store_existed: bool,
    /// True if the identity file already existed before this call.
    pub identity_existed: bool,
}

/// Options for `init_vault`.
#[derive(Debug, Default)]
pub struct InitOptions {
    /// Override the default store location (`~/.revealui/passage-store`).
    pub store_dir: Option<PathBuf>,
    /// Override the default identity location (`~/.config/age/keys.txt`).
    pub identity_file: Option<PathBuf>,
}

/// Initialize a new vault.
///
/// - Creates the store directory if it does not exist.
/// - Generates a new age X25519 identity and writes it to `identity_file`
///   **only if the file does not already exist** (never overwrites).
/// - Writes the identity's public key to `<store_dir>/.age-recipients`
///   if the file does not already exist.
///
/// Safe to call on an already-initialized vault — it will not overwrite
/// existing keys.
pub fn init_vault(options: InitOptions) -> Result<InitSummary> {
    let store_dir = options.store_dir.unwrap_or_else(default_store_dir);

    let identity_file = options.identity_file.unwrap_or_else(default_identity_file);

    // --- Store directory ---
    let store_existed = store_dir.exists();
    if !store_existed {
        std::fs::create_dir_all(&store_dir)?;
        // Create the .revvault metadata directory too
        std::fs::create_dir_all(store_dir.join(".revvault"))?;
    }

    // --- Identity file ---
    let identity_existed = identity_file.exists();
    let public_key = if identity_existed {
        // Read the existing public key from the recipients file if available,
        // otherwise re-derive it from the identity file.
        read_existing_public_key(&store_dir, &identity_file)?
    } else {
        generate_and_write_identity(&identity_file)?
    };

    // --- Recipients file ---
    let recipients_file = store_dir.join(".age-recipients");
    if !recipients_file.exists() {
        std::fs::write(&recipients_file, format!("{}\n", public_key))?;
    }

    Ok(InitSummary {
        store_dir,
        identity_file,
        public_key,
        store_existed,
        identity_existed,
    })
}

/// Generate a fresh X25519 identity, write it to disk, return the public key.
fn generate_and_write_identity(path: &Path) -> Result<String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let identity = x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let created_at = Utc::now().to_rfc3339();

    let contents = format!(
        "# created: {created_at}\n# public key: {public_key}\n{}\n",
        identity.to_string().expose_secret(),
    );

    std::fs::write(path, &contents)?;

    // Restrict permissions to owner-read-only on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(public_key)
}

/// Extract the public key from an existing setup.
/// Prefers the `.age-recipients` file; falls back to parsing the identity file.
fn read_existing_public_key(store_dir: &Path, identity_file: &Path) -> Result<String> {
    let recipients_file = store_dir.join(".age-recipients");

    // Try the recipients file first — it's already the public key.
    if recipients_file.exists() {
        let contents = std::fs::read_to_string(&recipients_file)?;
        if let Some(key) = contents
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            return Ok(key.trim().to_string());
        }
    }

    // Fall back to parsing the identity file.
    let contents = std::fs::read_to_string(identity_file)?;

    // Try the `# public key:` comment first (written by revvault init).
    for line in contents.lines() {
        if let Some(key) = line.strip_prefix("# public key: ") {
            return Ok(key.trim().to_string());
        }
    }

    // Last resort: parse a secret key line and re-derive the public key.
    if let Some(identity) = contents
        .lines()
        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        .and_then(|l| l.trim().parse::<x25519::Identity>().ok())
    {
        return Ok(identity.to_public().to_string());
    }

    Err(RevvaultError::Other(anyhow::anyhow!(
        "cannot determine public key from existing identity file — \
         file may be corrupt or use an unsupported format"
    )))
}

fn default_store_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".revealui/passage-store")
}

fn default_identity_file() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/age/keys.txt")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_policy() -> ServicePolicy {
        ServicePolicy {
            version: 1,
            uid: 1001,
            command: vec![
                "/usr/local/bin/node".into(),
                "/app/dist/publisher-run.js".into(),
            ],
            environment: std::collections::BTreeMap::new(),
            secrets: std::collections::BTreeMap::from([(
                "REVEALFLEET_PUBLISHER_DATABASE_URL".into(),
                "revealfleet/publisher/database-url".into(),
            )]),
        }
    }

    #[cfg(windows)]
    #[test]
    fn service_preview_rejects_unix_command_paths_on_windows() {
        let policy = service_policy();
        assert!(policy.validate(policy.uid).is_err());
        assert!(service_init_plan(&policy).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn service_preview_has_fixed_paths_without_identity_or_ciphertext() {
        let policy = service_policy();
        let plan = service_init_plan(&policy).unwrap();
        assert_eq!(
            plan.store_dir,
            Path::new("/var/lib/revvault/services/1001/store")
        );
        assert_eq!(
            plan.identity_file,
            Path::new("/var/lib/revvault/services/1001/identity.txt")
        );
        assert_eq!(
            plan.policy_file,
            Path::new("/var/lib/revvault/services/1001/policy.toml")
        );
        assert_eq!(plan.uid, plan.gid);
        let encoded = serde_json::to_string(&plan).unwrap();
        assert!(!encoded.contains("AGE-SECRET-KEY-"));
        assert!(encoded.contains("revealfleet/publisher/database-url"));
        let mut invalid = policy;
        invalid.uid = 0;
        assert!(service_init_plan(&invalid).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn service_staging_creates_independent_identity_and_group_read_only_store() {
        use std::os::unix::fs::MetadataExt;
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let gid = unsafe { libc::getegid() };
        create_service_store(first.path(), gid).unwrap();
        create_service_store(second.path(), gid).unwrap();
        let recipients =
            std::fs::read_to_string(first.path().join("store/.age-recipients")).unwrap();
        let other = std::fs::read_to_string(second.path().join("store/.age-recipients")).unwrap();
        assert_ne!(recipients, other);
        let identity = std::fs::read_to_string(first.path().join("identity.txt")).unwrap();
        let key: x25519::Identity = identity
            .lines()
            .find(|line| line.starts_with("AGE-SECRET-KEY-"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(recipients.trim(), key.to_public().to_string());
        let ciphertext =
            crate::crypto::encrypt(b"synthetic-service-only", &[key.to_public()]).unwrap();
        let own = crate::Identity::from_file(&first.path().join("identity.txt")).unwrap();
        let foreign = crate::Identity::from_file(&second.path().join("identity.txt")).unwrap();
        assert_eq!(
            crate::crypto::decrypt(&ciphertext, &own)
                .unwrap()
                .expose_secret(),
            "synthetic-service-only"
        );
        assert!(crate::crypto::decrypt(&ciphertext, &foreign).is_err());
        for (path, mode) in [
            ("store", 0o750),
            ("store/.revvault", 0o750),
            ("identity.txt", 0o640),
            ("store/.age-recipients", 0o640),
        ] {
            let metadata = std::fs::metadata(first.path().join(path)).unwrap();
            assert_eq!(metadata.gid(), gid);
            assert_eq!(metadata.mode() & 0o777, mode);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unprivileged_service_provisioning_denies_before_reading_or_writing() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("policy.toml");
        std::fs::write(&source, toml::to_string(&service_policy()).unwrap()).unwrap();
        let before = std::fs::read(&source).unwrap();
        let error = init_service_vault(&source).unwrap_err().to_string();
        assert_eq!(error, "revvault_service_provisioning_denied");
        assert_eq!(
            resume_service_vault(&source).unwrap_err().to_string(),
            "revvault_service_provisioning_denied"
        );
        assert_eq!(std::fs::read(&source).unwrap(), before);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn service_store_publication_never_replaces_existing_directory_or_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let staging = temp.path().join("staging");
        let destination = temp.path().join("destination");
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(staging.join("synthetic-marker"), "candidate").unwrap();
        std::fs::create_dir(&destination).unwrap();
        assert!(publish_new_service_store(&staging, &destination).is_err());
        assert!(staging.join("synthetic-marker").exists());
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
        std::fs::remove_dir(&destination).unwrap();
        std::os::unix::fs::symlink(&staging, &destination).unwrap();
        assert!(publish_new_service_store(&staging, &destination).is_err());
        assert!(std::fs::symlink_metadata(&destination)
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_file(&destination).unwrap();
        publish_new_service_store(&staging, &destination).unwrap();
        assert!(!staging.exists());
        assert_eq!(
            std::fs::read_to_string(destination.join("synthetic-marker")).unwrap(),
            "candidate"
        );
    }
    use secrecy::ExposeSecret as _;

    fn opts(dir: &tempfile::TempDir) -> InitOptions {
        InitOptions {
            store_dir: Some(dir.path().join("store")),
            identity_file: Some(dir.path().join("keys.txt")),
        }
    }

    // ── fresh init ────────────────────────────────────────────────────────────

    #[test]
    fn fresh_init_creates_store_and_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = init_vault(opts(&tmp)).unwrap();

        assert!(!summary.store_existed);
        assert!(!summary.identity_existed);
        assert!(summary.store_dir.is_dir());
        assert!(summary.identity_file.is_file());
        assert!(summary.store_dir.join(".revvault").is_dir());
        assert!(summary.store_dir.join(".age-recipients").is_file());
        assert!(summary.public_key.starts_with("age1"));
    }

    #[test]
    fn fresh_init_recipients_file_contains_public_key() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = init_vault(opts(&tmp)).unwrap();

        let recipients =
            std::fs::read_to_string(summary.store_dir.join(".age-recipients")).unwrap();
        assert!(recipients.contains(&summary.public_key));
    }

    #[test]
    fn fresh_init_identity_file_has_correct_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = init_vault(opts(&tmp)).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&summary.identity_file)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "identity file must be owner-read-only");
        }
    }

    // ── idempotency ───────────────────────────────────────────────────────────

    #[test]
    fn second_init_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let first = init_vault(opts(&tmp)).unwrap();
        let second = init_vault(opts(&tmp)).unwrap();

        assert!(second.store_existed);
        assert!(second.identity_existed);
        // Public key must be stable across calls.
        assert_eq!(first.public_key, second.public_key);
    }

    #[test]
    fn second_init_does_not_overwrite_identity_file() {
        let tmp = tempfile::tempdir().unwrap();
        init_vault(opts(&tmp)).unwrap();

        let identity_path = tmp.path().join("keys.txt");
        let before = std::fs::read_to_string(&identity_path).unwrap();
        init_vault(opts(&tmp)).unwrap();
        let after = std::fs::read_to_string(&identity_path).unwrap();

        assert_eq!(before, after);
    }

    // ── partial state: identity exists, store does not ────────────────────────

    #[test]
    fn init_with_existing_identity_no_store_reads_pubkey_from_comment() {
        let tmp = tempfile::tempdir().unwrap();

        // Pre-write an identity file with the `# public key:` comment.
        let identity = x25519::Identity::generate();
        let pubkey = identity.to_public().to_string();
        std::fs::write(
            tmp.path().join("keys.txt"),
            format!(
                "# public key: {pubkey}\n{}\n",
                identity.to_string().expose_secret()
            ),
        )
        .unwrap();

        let summary = init_vault(opts(&tmp)).unwrap();

        assert!(!summary.store_existed);
        assert!(summary.identity_existed);
        assert_eq!(summary.public_key, pubkey);
    }

    #[test]
    fn init_with_identity_missing_comment_derives_pubkey_from_secret_key() {
        let tmp = tempfile::tempdir().unwrap();

        // Write an identity file without the `# public key:` comment line.
        let identity = x25519::Identity::generate();
        let expected_pubkey = identity.to_public().to_string();
        std::fs::write(
            tmp.path().join("keys.txt"),
            format!(
                "# created: 2024-01-01\n{}\n",
                identity.to_string().expose_secret()
            ),
        )
        .unwrap();

        let summary = init_vault(opts(&tmp)).unwrap();

        assert_eq!(summary.public_key, expected_pubkey);
    }

    // ── partial state: store exists with recipients, identity exists ──────────

    #[test]
    fn init_with_existing_recipients_file_reads_pubkey_from_it() {
        let tmp = tempfile::tempdir().unwrap();

        // Create a store with a recipients file but no identity comment.
        let store = tmp.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let identity = x25519::Identity::generate();
        let pubkey = identity.to_public().to_string();
        std::fs::write(store.join(".age-recipients"), format!("{pubkey}\n")).unwrap();

        // Write identity without the public key comment.
        std::fs::write(
            tmp.path().join("keys.txt"),
            format!("{}\n", identity.to_string().expose_secret()),
        )
        .unwrap();

        let summary = init_vault(opts(&tmp)).unwrap();

        assert_eq!(summary.public_key, pubkey);
    }
}
