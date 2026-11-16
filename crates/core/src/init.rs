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
pub(crate) fn init_service_vault(
    policy_file: &Path,
    guard: &crate::service::receiver::ServiceMutationGuard<'_>,
) -> Result<ServiceInitPlan> {
    provision_service_vault(policy_file, false, 0, Some(guard))
}

/// Resume only an initializer-produced, unchanged, unbound fresh store.
/// Never rotate an identity, adopt a foreign store or repair unsafe ownership.
pub(crate) fn resume_service_vault(
    policy_file: &Path,
    guard: &crate::service::receiver::ServiceMutationGuard<'_>,
) -> Result<ServiceInitPlan> {
    provision_service_vault(policy_file, true, 0, Some(guard))
}

// Explicit native primitive proof only, alongside the existing fault injectors.
// The production public API cannot bypass receiver request admission.
#[cfg(feature = "native-service-tests")]
pub fn native_init_service_vault(policy_file: &Path) -> Result<ServiceInitPlan> {
    provision_service_vault(policy_file, false, 0, None)
}
#[cfg(feature = "native-service-tests")]
pub fn native_resume_service_vault(policy_file: &Path) -> Result<ServiceInitPlan> {
    provision_service_vault(policy_file, true, 0, None)
}

/// Fault injection exists only in the explicit disposable native test feature.
/// Production CLI builds have no environment or argument route to this fault.
#[cfg(feature = "native-service-tests")]
pub fn interrupt_service_vault_after_store(policy_file: &Path) -> Result<ServiceInitPlan> {
    provision_service_vault(policy_file, false, 1, None)
}

/// Native-only interruption after durable capability publication, before finalization.
#[cfg(feature = "native-service-tests")]
pub fn interrupt_service_vault_after_capability(policy_file: &Path) -> Result<ServiceInitPlan> {
    provision_service_vault(policy_file, false, 2, None)
}

fn provision_service_vault(
    policy_file: &Path,
    resume: bool,
    interruption: u8,
    admission: Option<&crate::service::receiver::ServiceMutationGuard<'_>>,
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
        if let Some(guard) = admission {
            guard.recheck()?;
        }
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
            if let Some(guard) = admission {
                guard.recheck()?;
            }
            publish_new_service_store(staging.path(), service_root)?;
        }
        // Serialize create/resume finalization on immutable root-only provenance.
        let _lock = lock_service_intent(service_root)?;
        if let Some(guard) = admission {
            guard.recheck()?;
        }
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
            set_service_descriptor_permissions(capability.as_file(), 0, 0o644)?;
            capability.as_file().sync_all()?;
            // No-clobber capability publication is last. Active or concurrent
            // capabilities cannot be overwritten by either create or resume.
            if let Some(guard) = admission {
                guard.recheck()?;
            }
            publish_noreplace(capability, &plan.policy_file).map_err(|_| service_init_denied())?;
            // Shared publication syncs the same held parent used by rename.
        }
        if interruption == 2 {
            return Err(service_init_denied());
        }
        if let Some(guard) = admission {
            guard.recheck()?;
        }
        std::fs::remove_file(service_root.join(".provisioning.toml"))?;
        std::fs::File::open(service_root)?.sync_all()?;
        Ok(plan)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (policy_file, resume, interruption, admission);
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
        files: ["identity.txt", "store/.age-recipients"]
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
    set_service_descriptor_permissions(file.as_file(), 0, 0o600)?;
    file.as_file().sync_all()?;
    publish_noreplace(file, &root.join(".provisioning.toml")).map_err(|_| service_init_denied())?;
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
        ("store/.revvault", vec![]),
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
    let file = std::fs::File::open(path)?;
    set_service_descriptor_permissions(&file, gid, mode)
}

#[cfg(unix)]
fn set_service_descriptor_permissions(file: &std::fs::File, gid: u32, mode: u32) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::fchown(file.as_raw_fd(), !0, gid) } != 0 {
        return Err(service_init_denied());
    }
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(unix)]
fn create_service_store(root: &Path, gid: u32) -> Result<()> {
    let summary = initialize_paths(root.join("store"), root.join("identity.txt"))?;
    set_service_permissions(&summary.store_dir, gid, 0o750)?;
    set_service_permissions(&summary.store_dir.join(".revvault"), gid, 0o750)?;
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
    crate::service::assert_personal_path(&store_dir)?;
    crate::service::assert_personal_path(&identity_file)?;
    for relative in [".age-recipients", ".revvault"] {
        crate::service::assert_personal_path(&store_dir.join(relative))?;
    }
    initialize_paths(store_dir, identity_file)
}

// The guarded service initializer and personal initializer share the same
// creation primitive; only the former may select the reserved custody paths.
fn initialize_paths(store_dir: PathBuf, identity_file: PathBuf) -> Result<InitSummary> {
    #[cfg(target_os = "linux")]
    {
        initialize_linux_paths(store_dir, identity_file)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let store_existed = store_dir.try_exists()?;
        std::fs::create_dir_all(&store_dir)?;
        std::fs::create_dir_all(store_dir.join(".revvault"))?;
        let mut identity_existed = init_file_present(&identity_file)?;
        if !identity_existed {
            match generate_and_write_identity(&identity_file) {
                Ok(_) => {}
                Err(RevvaultError::Io(error))
                    if error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    // A concurrent initializer won. Never use our discarded key or
                    // trust a public-key comment; parse the actual published bytes.
                    identity_existed = true;
                }
                Err(error) => return Err(error),
            }
        }
        let keys = actual_public_keys(&identity_file)?;
        let recipients_file = store_dir.join(".age-recipients");
        if !init_file_present(&recipients_file)? {
            match publish_init_file(&recipients_file, format!("{}\n", keys[0]).as_bytes()) {
                Ok(()) => {}
                Err(RevvaultError::Io(error))
                    if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        let public_key = read_existing_public_key(&store_dir, &identity_file)?;
        // Exact replay also completes directory durability after a lost success.
        sync_init_parent(&identity_file)?;
        sync_init_parent(&recipients_file)?;
        Ok(InitSummary {
            store_dir,
            identity_file,
            public_key,
            store_existed,
            identity_existed,
        })
    }
}

#[cfg(target_os = "linux")]
struct InitDirectory {
    // Each name belongs to the preceding descriptor, never to a reopened path.
    chain: Vec<(std::fs::File, Option<std::ffi::CString>)>,
}

#[cfg(target_os = "linux")]
impl InitDirectory {
    fn open(path: &Path, create: bool) -> Result<(Self, bool)> {
        use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
        let relative = !path.is_absolute();
        let cwd = if relative {
            Some(std::fs::File::open(".")?)
        } else {
            None
        };
        let cwd_path = if relative {
            Some(std::env::current_dir()?)
        } else {
            None
        };
        let absolute = if let Some(cwd) = &cwd_path {
            cwd.join(path)
        } else {
            path.to_path_buf()
        };
        if absolute.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::Prefix(_)
            ) || c.as_os_str().as_bytes().contains(&0)
        }) {
            return Err(init_denied());
        }
        let root = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut held = Self {
            chain: vec![(unsafe { std::fs::File::from_raw_fd(root) }, None)],
        };
        let mut existed = true;
        let cwd_depth = cwd_path.as_ref().map(|p| {
            p.components()
                .filter(|c| matches!(c, std::path::Component::Normal(_)))
                .count()
        });
        if cwd_depth == Some(0) && !same_init_inode(cwd.as_ref().unwrap(), &held.chain[0].0)? {
            return Err(init_denied());
        }
        for component in absolute.components() {
            match component {
                std::path::Component::RootDir | std::path::Component::CurDir => continue,
                std::path::Component::Normal(name) => {
                    let name =
                        std::ffi::CString::new(name.as_bytes()).map_err(|_| init_denied())?;
                    existed = held.descend(&name, create)?;
                    if cwd_depth == Some(held.chain.len() - 1)
                        && !same_init_inode(cwd.as_ref().unwrap(), &held.chain.last().unwrap().0)?
                    {
                        return Err(init_denied());
                    }
                }
                _ => return Err(init_denied()),
            }
        }
        held.sync_chain()?;
        held.check_attached()?;
        Ok((held, existed))
    }

    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            chain: self
                .chain
                .iter()
                .map(|(file, name)| Ok((file.try_clone()?, name.clone())))
                .collect::<std::io::Result<_>>()?,
        })
    }

    fn resolve(&self, path: &Path, create: bool) -> Result<(Self, bool)> {
        use std::os::unix::ffi::OsStrExt;
        if path.is_absolute() {
            return Self::open(path, create);
        }
        if path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::Prefix(_)
            ) || c.as_os_str().as_bytes().contains(&0)
        }) {
            return Err(init_denied());
        }
        let mut held = self.try_clone()?;
        let mut existed = true;
        for component in path.components() {
            if let std::path::Component::Normal(name) = component {
                let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| init_denied())?;
                existed = held.descend(&name, create)?;
            }
        }
        held.sync_chain()?;
        held.check_attached()?;
        Ok((held, existed))
    }

    fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.chain.last().unwrap().0.as_raw_fd()
    }

    fn descend(&mut self, name: &std::ffi::CStr, create: bool) -> Result<bool> {
        use std::os::fd::FromRawFd;
        let mut existed = true;
        let mut fd = unsafe {
            libc::openat(
                self.fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        if fd < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
            && create
        {
            let created = unsafe { libc::mkdirat(self.fd(), name.as_ptr(), 0o700) };
            if created != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(std::io::Error::last_os_error().into());
            }
            existed = created != 0;
            fd = unsafe {
                libc::openat(
                    self.fd(),
                    name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_DIRECTORY
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK,
                )
            };
        }
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let child = unsafe { std::fs::File::from_raw_fd(fd) };
        #[cfg(test)]
        init_descriptor_hook(14);
        #[cfg(test)]
        init_publication_fault(4)?;
        // Sync even an existing link: this may be replay after interrupted mkdir.
        child.sync_all()?;
        self.chain.last().unwrap().0.sync_all()?;
        self.chain.push((child, Some(name.to_owned())));
        Ok(existed)
    }

    fn child(&self, name: &std::ffi::CStr, create: bool) -> Result<Self> {
        let mut held = Self {
            chain: self
                .chain
                .iter()
                .map(|(file, name)| Ok((file.try_clone()?, name.clone())))
                .collect::<std::io::Result<_>>()?,
        };
        held.descend(name, create)?;
        held.check_attached()?;
        Ok(held)
    }

    fn entry<'a>(&'a self, name: &std::ffi::OsStr) -> Result<InitEntry<'a>> {
        use std::os::unix::ffi::OsStrExt;
        let raw = name.as_bytes();
        if raw.is_empty() || raw == b"." || raw == b".." || raw.contains(&b'/') {
            return Err(init_denied());
        }
        Ok(InitEntry {
            directory: self,
            name: std::ffi::CString::new(raw).map_err(|_| init_denied())?,
        })
    }

    fn sync_chain(&self) -> Result<()> {
        for (file, _) in self.chain.iter().rev() {
            file.sync_all()?;
        }
        Ok(())
    }

    fn check_attached(&self) -> Result<()> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        for pair in self.chain.windows(2) {
            let info = init_stat_at(pair[0].0.as_raw_fd(), pair[1].1.as_ref().unwrap())?
                .ok_or_else(init_denied)?;
            let actual = pair[1].0.metadata()?;
            if info.st_mode & libc::S_IFMT != libc::S_IFDIR
                || info.st_dev != actual.dev()
                || info.st_ino != actual.ino()
            {
                return Err(init_denied());
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn same_init_inode(a: &std::fs::File, b: &std::fs::File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let a = a.metadata()?;
    let b = b.metadata()?;
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

#[cfg(target_os = "linux")]
fn init_stat_at(fd: std::os::fd::RawFd, name: &std::ffi::CStr) -> Result<Option<libc::stat>> {
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            fd,
            name.as_ptr(),
            info.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error.into());
    }
    Ok(Some(unsafe { info.assume_init() }))
}

#[cfg(target_os = "linux")]
struct InitEntry<'a> {
    directory: &'a InitDirectory,
    name: std::ffi::CString,
}

#[cfg(target_os = "linux")]
impl InitEntry<'_> {
    fn open(&self) -> Result<Option<std::fs::File>> {
        use std::os::{fd::FromRawFd, unix::fs::MetadataExt};
        let fd = unsafe {
            libc::openat(
                self.directory.fd(),
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error.into());
        }
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let info = file.metadata()?;
        if !info.is_file() || info.nlink() != 1 || info.len() > 65_536 {
            return Err(init_denied());
        }
        self.check_file(&file)?;
        Ok(Some(file))
    }

    fn check_file(&self, file: &std::fs::File) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let actual = file.metadata()?;
        let named = init_stat_at(self.directory.fd(), &self.name)?.ok_or_else(init_denied)?;
        if named.st_mode & libc::S_IFMT != libc::S_IFREG
            || named.st_nlink != 1
            || named.st_dev != actual.dev()
            || named.st_ino != actual.ino()
        {
            return Err(init_denied());
        }
        Ok(())
    }

    fn rename_file(&self, source_name: &std::ffi::CStr, file: &std::fs::File) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let named = init_stat_at(self.directory.fd(), source_name)?.ok_or_else(init_denied)?;
        let actual = file.metadata()?;
        if !actual.is_file()
            || named.st_nlink != 1
            || named.st_dev != actual.dev()
            || named.st_ino != actual.ino()
        {
            return Err(init_denied());
        }
        #[cfg(test)]
        init_publication_fault(3)?;
        if unsafe {
            libc::renameat2(
                self.directory.fd(),
                source_name.as_ptr(),
                self.directory.fd(),
                self.name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn publish(&self, bytes: &[u8]) -> Result<std::fs::File> {
        use std::io::{Seek, Write};
        #[cfg(test)]
        init_descriptor_hook(10);
        let mut temporary = InitTemporary::create(self.directory)?;
        temporary.file.write_all(bytes)?;
        temporary.file.sync_all()?;
        #[cfg(test)]
        init_publication_fault(1)?;
        #[cfg(test)]
        init_descriptor_hook(11);
        self.rename_file(&temporary.name, &temporary.file)?;
        temporary.published = true;
        #[cfg(test)]
        init_descriptor_hook(15);
        #[cfg(test)]
        init_publication_fault(2)?;
        self.directory.chain.last().unwrap().0.sync_all()?;
        temporary.file.rewind()?;
        self.check_file(&temporary.file)?;
        temporary.file.try_clone().map_err(Into::into)
    }
}

#[cfg(target_os = "linux")]
struct InitTemporary<'a> {
    directory: &'a InitDirectory,
    name: std::ffi::CString,
    file: std::fs::File,
    published: bool,
}

#[cfg(target_os = "linux")]
impl<'a> InitTemporary<'a> {
    fn create(directory: &'a InitDirectory) -> Result<Self> {
        use std::os::fd::FromRawFd;
        for _ in 0..16 {
            let name = init_temporary_name();
            let fd = unsafe {
                libc::openat(
                    directory.fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd >= 0 {
                use std::os::unix::fs::PermissionsExt;
                let temporary = Self {
                    directory,
                    name,
                    file: unsafe { std::fs::File::from_raw_fd(fd) },
                    published: false,
                };
                temporary
                    .file
                    .set_permissions(std::fs::Permissions::from_mode(0o600))?;
                return Ok(temporary);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error.into());
            }
        }
        Err(init_denied())
    }
}

#[cfg(target_os = "linux")]
impl Drop for InitTemporary<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if self.published {
            return;
        }
        // Check the observed inode before best-effort cleanup. This is not an
        // atomic inode-CAS unlink; the parent must exclude untrusted writers.
        if let (Ok(Some(named)), Ok(actual)) = (
            init_stat_at(self.directory.fd(), &self.name),
            self.file.metadata(),
        ) {
            if named.st_dev == actual.dev() && named.st_ino == actual.ino() {
                unsafe {
                    libc::unlinkat(self.directory.fd(), self.name.as_ptr(), 0);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn read_init_descriptor(mut file: &std::fs::File) -> Result<zeroize::Zeroizing<String>> {
    use std::io::Read;
    let mut text = zeroize::Zeroizing::new(String::new());
    (&mut file).take(65_537).read_to_string(&mut text)?;
    if text.len() > 65_536 {
        return Err(init_denied());
    }
    Ok(text)
}

#[cfg(target_os = "linux")]
fn initialize_linux_paths(store_dir: PathBuf, identity_file: PathBuf) -> Result<InitSummary> {
    // One cwd anchor for the complete operation, including both relative paths.
    let (initial_cwd, _) = InitDirectory::open(Path::new("."), false)?;
    let relative = !store_dir.is_absolute() || !identity_file.is_absolute();
    let (store, store_existed) = initial_cwd.resolve(&store_dir, true)?;
    #[cfg(test)]
    init_descriptor_hook(16);
    let metadata = store.child(c".revvault", true)?;
    let parent = identity_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (identity_parent, _) = initial_cwd.resolve(parent, true)?;
    let identity_entry =
        identity_parent.entry(identity_file.file_name().ok_or_else(init_denied)?)?;
    let recipients_entry = store.entry(std::ffi::OsStr::new(".age-recipients"))?;
    let mut identity_existed = true;
    let identity = match identity_entry.open()? {
        Some(file) => file,
        None => {
            identity_existed = false;
            let (contents, _) = new_init_identity();
            match identity_entry.publish(contents.as_bytes()) {
                Ok(file) => file,
                Err(RevvaultError::Io(error))
                    if error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    identity_existed = true;
                    identity_entry.open()?.ok_or_else(init_denied)?
                }
                Err(error) => return Err(error),
            }
        }
    };
    #[cfg(test)]
    init_descriptor_hook(12);
    let key_text = read_init_descriptor(&identity)?;
    let keys = crate::identity::Identity::from_text(&key_text).map_err(|_| init_denied())?;
    let keys: Vec<_> = keys
        .as_identities()
        .iter()
        .map(|key| key.to_public().to_string())
        .collect();
    let recipients = match recipients_entry.open()? {
        Some(file) => file,
        None => match recipients_entry.publish(format!("{}\n", keys[0]).as_bytes()) {
            Ok(file) => file,
            Err(RevvaultError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                recipients_entry.open()?.ok_or_else(init_denied)?
            }
            Err(error) => return Err(error),
        },
    };
    let recipient_text = read_init_descriptor(&recipients)?;
    let public_key = recipient_text
        .lines()
        .map(str::trim)
        .find(|line| keys.iter().any(|key| key == line))
        .ok_or_else(init_denied)?
        .to_string();
    #[cfg(test)]
    init_descriptor_hook(13);
    store.sync_chain()?;
    identity_parent.sync_chain()?;
    metadata.sync_chain()?;
    identity_entry.check_file(&identity)?;
    recipients_entry.check_file(&recipients)?;
    store.check_attached()?;
    identity_parent.check_attached()?;
    metadata.check_attached()?;
    if relative
        && !same_init_inode(
            &initial_cwd.chain.last().unwrap().0,
            &std::fs::File::open(".")?,
        )?
    {
        return Err(init_denied());
    }
    Ok(InitSummary {
        store_dir,
        identity_file,
        public_key,
        store_existed,
        identity_existed,
    })
}

fn new_init_identity() -> (zeroize::Zeroizing<String>, String) {
    let identity = x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let created_at = Utc::now().to_rfc3339();
    let contents = zeroize::Zeroizing::new(format!(
        "# created: {created_at}\n# public key: {public_key}\n{}\n",
        identity.to_string().expose_secret()
    ));
    (contents, public_key)
}

fn init_denied() -> RevvaultError {
    RevvaultError::Other(anyhow::anyhow!("revvault_initialization_inconsistent"))
}

#[cfg(not(target_os = "linux"))]
fn init_file_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(info) if info.is_file() => Ok(true),
        Ok(_) => Err(init_denied()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(target_os = "linux"))]
fn read_init_file(path: &Path) -> Result<zeroize::Zeroizing<String>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 65_536 {
        return Err(init_denied());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(init_denied());
        }
    }
    let mut text = zeroize::Zeroizing::new(String::new());
    file.take(65_537).read_to_string(&mut text)?;
    if text.len() > 65_536 {
        return Err(init_denied());
    }
    Ok(text)
}

#[cfg(not(target_os = "linux"))]
fn sync_init_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(path.parent().ok_or_else(init_denied)?)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Atomic no-clobber publication, private from its first byte. This repairs
/// creation races; complete hostile ancestor custody requires held directory FDs.
#[cfg(not(target_os = "linux"))]
fn publish_init_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().ok_or_else(init_denied)?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    #[cfg(test)]
    init_publication_fault(1)?;
    publish_noreplace(staged, path)?;
    #[cfg(test)]
    init_publication_fault(2)?;
    sync_init_parent(path)
}

/// Linux custody must never fall back to link/unlink publication: a crash in
/// that gap leaves an ambiguous multi-linked identity or service record.
fn publish_noreplace(staged: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let (directory, _) = InitDirectory::open(parent, false)?;
        let entry = directory.entry(path.file_name().ok_or_else(init_denied)?)?;
        let source = std::ffi::CString::new(
            staged
                .path()
                .file_name()
                .ok_or_else(init_denied)?
                .as_bytes(),
        )
        .map_err(|_| init_denied())?;
        entry.rename_file(&source, staged.as_file())?;
        directory.sync_chain()?;
        entry.check_file(staged.as_file())?;
        directory.check_attached()?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        staged
            .persist_noclobber(path)
            .map_err(|failure| RevvaultError::Io(failure.error))?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn init_temporary_name() -> std::ffi::CString {
    #[cfg(test)]
    if let Some(name) = INIT_TEMPORARY_NAMES.with(|names| names.borrow_mut().pop()) {
        return name;
    }
    std::ffi::CString::new(format!(
        ".revvault-init-{}",
        hex::encode(rand::random::<[u8; 16]>())
    ))
    .unwrap()
}

#[cfg(all(test, target_os = "linux"))]
type InitDescriptorHook = (u8, Box<dyn FnOnce()>);

#[cfg(all(test, target_os = "linux"))]
std::thread_local! {
    static INIT_DESCRIPTOR_HOOK: std::cell::RefCell<Option<InitDescriptorHook>> = const { std::cell::RefCell::new(None) };
    static INIT_TEMPORARY_NAMES: std::cell::RefCell<Vec<std::ffi::CString>> = const { std::cell::RefCell::new(Vec::new()) };
}
#[cfg(all(test, target_os = "linux"))]
fn init_descriptor_hook(stage: u8) {
    let hook = INIT_DESCRIPTOR_HOOK.with(|slot| {
        let mut hook = slot.borrow_mut();
        if hook
            .as_ref()
            .is_some_and(|(expected, _)| *expected == stage)
        {
            hook.take()
        } else {
            None
        }
    });
    if let Some((_, hook)) = hook {
        hook();
    }
}

// Faults are confined to synthetic unit fixtures and absent from CLI builds.
#[cfg(test)]
std::thread_local! { static INIT_PUBLICATION_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
fn init_publication_fault(stage: u8) -> Result<()> {
    INIT_PUBLICATION_FAULT.with(|fault| {
        if fault.get() == stage {
            fault.set(0);
            return Err(std::io::Error::new(
                if stage == 3 {
                    std::io::ErrorKind::Unsupported
                } else {
                    std::io::ErrorKind::Other
                },
                "synthetic initialization interruption",
            )
            .into());
        }
        Ok(())
    })
}

/// Generate a fresh X25519 identity; an existing destination is never replaced.
#[cfg(any(not(target_os = "linux"), test))]
fn generate_and_write_identity(path: &Path) -> Result<String> {
    let (contents, public_key) = new_init_identity();
    #[cfg(target_os = "linux")]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let (directory, _) = InitDirectory::open(parent, true)?;
        directory
            .entry(path.file_name().ok_or_else(init_denied)?)?
            .publish(contents.as_bytes())?;
        directory.check_attached()?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        publish_init_file(path, contents.as_bytes())?;
    }
    Ok(public_key)
}

#[cfg(not(target_os = "linux"))]
fn actual_public_keys(identity_file: &Path) -> Result<Vec<String>> {
    let contents = read_init_file(identity_file)?;
    let identity = crate::identity::Identity::from_text(&contents).map_err(|_| init_denied())?;
    Ok(identity
        .as_identities()
        .iter()
        .map(|key| key.to_public().to_string())
        .collect())
}

/// Use actual private identities, never public-key comments. Existing personal
/// multi-recipient files remain byte-for-byte intact if a real identity matches.
#[cfg(not(target_os = "linux"))]
fn read_existing_public_key(store_dir: &Path, identity_file: &Path) -> Result<String> {
    let keys = actual_public_keys(identity_file)?;
    let recipients = read_init_file(&store_dir.join(".age-recipients"))?;
    for line in recipients
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if keys.iter().any(|key| key == line) {
            return Ok(line.to_string());
        }
    }
    Err(init_denied())
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
        let error = provision_service_vault(&source, false, 0, None)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "revvault_service_provisioning_denied");
        assert_eq!(
            provision_service_vault(&source, true, 0, None)
                .unwrap_err()
                .to_string(),
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

    #[test]
    #[cfg(target_os = "linux")]
    fn personal_init_denies_reserved_paths_before_creating_either_input() {
        let dir = tempfile::tempdir().unwrap();
        for identity_reserved in [false, true] {
            let personal = dir.path().join("untouched");
            let reserved = PathBuf::from("/var/lib/revvault/services/19001/foreign");
            let options = if identity_reserved {
                InitOptions {
                    store_dir: Some(personal.clone()),
                    identity_file: Some(reserved),
                }
            } else {
                InitOptions {
                    store_dir: Some(reserved),
                    identity_file: Some(personal.clone()),
                }
            };
            assert_eq!(
                init_vault(options).unwrap_err().to_string(),
                "revvault_service_capability_denied"
            );
            assert!(!personal.exists());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn personal_init_rejects_derived_custody_aliases_without_creating_identity() {
        for relative in [".age-recipients", ".revvault"] {
            let dir = tempfile::tempdir().unwrap();
            let store = dir.path().join("store");
            std::fs::create_dir(&store).unwrap();
            let alias = store.join(relative);
            std::os::unix::fs::symlink("/var/lib/revvault/nonexistent", &alias).unwrap();
            let identity = dir.path().join("identity");
            assert!(init_vault(InitOptions {
                store_dir: Some(store.clone()),
                identity_file: Some(identity.clone())
            })
            .is_err());
            assert!(!identity.exists());
            assert!(alias.is_symlink());
            assert_eq!(std::fs::read_dir(&store).unwrap().count(), 1);
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
    #[test]
    fn identity_publication_never_replaces_an_existing_winner() {
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("keys.txt");
        generate_and_write_identity(&key).unwrap();
        let before = std::fs::read(&key).unwrap();
        assert!(generate_and_write_identity(&key).is_err());
        assert_eq!(std::fs::read(&key).unwrap(), before);
    }

    #[test]
    fn concurrent_initializers_recover_the_same_actual_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let children: Vec<_> = (0..16)
            .map(|_| {
                let root = tmp.path().to_path_buf();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    init_vault(InitOptions {
                        store_dir: Some(root.join("store")),
                        identity_file: Some(root.join("keys.txt")),
                    })
                    .unwrap()
                    .public_key
                })
            })
            .collect();
        let keys: Vec<_> = children
            .into_iter()
            .map(|child| child.join().unwrap())
            .collect();
        assert!(keys.iter().all(|key| key == &keys[0]));
        let identity = std::fs::read_to_string(tmp.path().join("keys.txt")).unwrap();
        let actual = identity
            .lines()
            .find(|line| !line.starts_with('#') && !line.trim().is_empty())
            .unwrap()
            .parse::<x25519::Identity>()
            .unwrap()
            .to_public()
            .to_string();
        assert_eq!(keys[0], actual);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("store/.age-recipients")).unwrap(),
            format!("{actual}\n")
        );
    }

    #[test]
    fn stale_public_comment_cannot_choose_an_unrelated_recipient() {
        let tmp = tempfile::tempdir().unwrap();
        let actual = x25519::Identity::generate();
        let stale = x25519::Identity::generate().to_public().to_string();
        std::fs::write(
            tmp.path().join("keys.txt"),
            format!(
                "# public key: {stale}\n{}\n",
                actual.to_string().expose_secret()
            ),
        )
        .unwrap();
        assert_eq!(
            init_vault(opts(&tmp)).unwrap().public_key,
            actual.to_public().to_string()
        );
    }

    #[test]
    fn recipients_mismatch_is_denied_without_rewriting_existing_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let first = init_vault(opts(&tmp)).unwrap();
        let path = first.store_dir.join(".age-recipients");
        let wrong = format!("{}\n", x25519::Identity::generate().to_public());
        std::fs::write(&path, &wrong).unwrap();
        let identity = std::fs::read(&first.identity_file).unwrap();
        assert!(init_vault(opts(&tmp)).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), wrong);
        assert_eq!(std::fs::read(&first.identity_file).unwrap(), identity);
    }

    #[test]
    fn personal_multiple_recipients_are_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let first = init_vault(opts(&tmp)).unwrap();
        let recipients = format!(
            "# retained collaborator\n{}\n{}\n",
            x25519::Identity::generate().to_public(),
            first.public_key
        );
        std::fs::write(first.store_dir.join(".age-recipients"), &recipients).unwrap();
        assert_eq!(init_vault(opts(&tmp)).unwrap().public_key, first.public_key);
        assert_eq!(
            std::fs::read_to_string(first.store_dir.join(".age-recipients")).unwrap(),
            recipients
        );
    }

    #[test]
    fn published_identity_without_recipients_recovers_without_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("keys.txt");
        let public = generate_and_write_identity(&key).unwrap();
        let before = std::fs::read(&key).unwrap();
        let summary = init_vault(opts(&tmp)).unwrap();
        assert_eq!(summary.public_key, public);
        assert_eq!(std::fs::read(key).unwrap(), before);
        assert_eq!(init_vault(opts(&tmp)).unwrap().public_key, public);
    }

    #[test]
    fn comment_only_identity_is_not_accepted_as_a_private_key() {
        let tmp = tempfile::tempdir().unwrap();
        let bogus = format!(
            "# public key: {}\n",
            x25519::Identity::generate().to_public()
        );
        std::fs::write(tmp.path().join("keys.txt"), &bogus).unwrap();
        assert!(init_vault(opts(&tmp)).is_err());
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("keys.txt")).unwrap(),
            bogus
        );
        assert!(!tmp.path().join("store/.age-recipients").exists());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_identity_symlink_is_not_followed_or_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        let key = tmp.path().join("keys.txt");
        std::os::unix::fs::symlink(&victim, &key).unwrap();
        assert!(init_vault(opts(&tmp)).is_err());
        assert!(key.is_symlink());
        assert!(!victim.exists());
    }

    #[test]
    fn failed_prepublication_sync_boundary_never_exposes_partial_key() {
        let tmp = tempfile::tempdir().unwrap();
        INIT_PUBLICATION_FAULT.with(|fault| fault.set(1));
        assert!(init_vault(opts(&tmp)).is_err());
        assert!(!tmp.path().join("keys.txt").exists());
        // The private staging file is removed when publication fails.
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
        init_vault(opts(&tmp)).unwrap();
    }

    #[test]
    fn lost_success_before_directory_sync_recovers_without_key_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        INIT_PUBLICATION_FAULT.with(|fault| fault.set(2));
        assert!(init_vault(opts(&tmp)).is_err());
        let before = std::fs::read(tmp.path().join("keys.txt")).unwrap();
        assert!(!tmp.path().join("store/.age-recipients").exists());
        let recovered = init_vault(opts(&tmp)).unwrap();
        assert_eq!(std::fs::read(tmp.path().join("keys.txt")).unwrap(), before);
        assert_eq!(
            init_vault(opts(&tmp)).unwrap().public_key,
            recovered.public_key
        );
    }
    #[test]
    fn personal_multiple_identities_may_match_a_nonfirst_recipient() {
        let tmp = tempfile::tempdir().unwrap();
        let first = x25519::Identity::generate();
        let second = x25519::Identity::generate();
        std::fs::create_dir(tmp.path().join("store")).unwrap();
        std::fs::write(
            tmp.path().join("keys.txt"),
            format!(
                "{}\n{}\n",
                first.to_string().expose_secret(),
                second.to_string().expose_secret()
            ),
        )
        .unwrap();
        let recipients = format!("{}\n", second.to_public());
        std::fs::write(tmp.path().join("store/.age-recipients"), &recipients).unwrap();
        assert_eq!(
            init_vault(opts(&tmp)).unwrap().public_key,
            second.to_public().to_string()
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("store/.age-recipients")).unwrap(),
            recipients
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn unsupported_atomic_rename_fails_without_link_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("keys.txt");
        INIT_PUBLICATION_FAULT.with(|fault| fault.set(3));
        let error = generate_and_write_identity(&key).unwrap_err();
        assert!(
            matches!(error, RevvaultError::Io(ref error) if error.kind() == std::io::ErrorKind::Unsupported)
        );
        assert!(!key.exists());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
        generate_and_write_identity(&key).unwrap();
        let before = std::fs::read(&key).unwrap();
        INIT_PUBLICATION_FAULT.with(|fault| fault.set(3));
        assert!(generate_and_write_identity(&key).is_err());
        assert_eq!(std::fs::read(&key).unwrap(), before);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn initializer_refuses_symlinked_store_ancestor_without_writing_through_it() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::os::unix::fs::symlink(&victim, tmp.path().join("alias")).unwrap();
        let result = init_vault(InitOptions {
            store_dir: Some(tmp.path().join("alias/store")),
            identity_file: Some(tmp.path().join("keys.txt")),
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0);
        assert!(!tmp.path().join("keys.txt").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn initializer_refuses_symlinked_identity_ancestor_without_writing_through_it() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::os::unix::fs::symlink(&victim, tmp.path().join("alias")).unwrap();
        let result = init_vault(InitOptions {
            store_dir: Some(tmp.path().join("store")),
            identity_file: Some(tmp.path().join("alias/keys.txt")),
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn initializer_refuses_parent_traversal_components() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("existing")).unwrap();
        let result = init_vault(InitOptions {
            store_dir: Some(tmp.path().join("existing/../store")),
            identity_file: Some(tmp.path().join("keys.txt")),
        });
        assert!(result.is_err());
        assert!(!tmp.path().join("store").exists());
        assert!(!tmp.path().join("keys.txt").exists());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn held_directory_publication_cannot_follow_replaced_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        let original = tmp.path().join("original");
        let saved = tmp.path().join("saved");
        let victim = tmp.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        let (held, _) = InitDirectory::open(&original, true).unwrap();
        std::fs::rename(&original, &saved).unwrap();
        std::os::unix::fs::symlink(&victim, &original).unwrap();
        held.entry(std::ffi::OsStr::new("fixture"))
            .unwrap()
            .publish(b"synthetic fixture")
            .unwrap();
        assert!(held.check_attached().is_err());
        assert_eq!(
            std::fs::read(saved.join("fixture")).unwrap(),
            b"synthetic fixture"
        );
        assert_eq!(std::fs::read_dir(victim).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn initializer_detects_ancestor_replacement_at_creation_read_rename_and_sync() {
        for stage in [10, 11, 12, 13] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("owner");
            std::fs::create_dir(&root).unwrap();
            let moved = tmp.path().join("moved");
            let replace = root.clone();
            INIT_DESCRIPTOR_HOOK.with(|slot| {
                *slot.borrow_mut() = Some((
                    stage,
                    Box::new(move || {
                        std::fs::rename(&replace, &moved).unwrap();
                        std::fs::create_dir(&replace).unwrap();
                        std::fs::write(replace.join("keep"), b"unrelated active work").unwrap();
                    }),
                ))
            });
            let result = init_vault(InitOptions {
                store_dir: Some(root.join("store")),
                identity_file: Some(root.join("keys.txt")),
            });
            assert!(
                result.is_err(),
                "must not acknowledge detached paths at stage {stage}"
            );
            assert_eq!(
                std::fs::read(root.join("keep")).unwrap(),
                b"unrelated active work"
            );
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_directory_replacement_after_open_is_detected_before_return() {
        let tmp = tempfile::tempdir().unwrap();
        let (held, _) = InitDirectory::open(tmp.path(), false).unwrap();
        let path = tmp.path().join("child");
        let moved = tmp.path().join("moved");
        let victim = tmp.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        let original = path.clone();
        let planted = victim.clone();
        INIT_DESCRIPTOR_HOOK.with(|slot| {
            *slot.borrow_mut() = Some((
                14,
                Box::new(move || {
                    std::fs::rename(&original, &moved).unwrap();
                    std::os::unix::fs::symlink(&planted, &original).unwrap();
                }),
            ))
        });
        assert!(held.child(c"child", true).is_err());
        assert!(path.is_symlink());
        assert_eq!(std::fs::read_dir(victim).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_identity_and_recipients_reject_final_name_substitution() {
        for (stage, filename) in [(12, "keys.txt"), (13, "store/.age-recipients")] {
            let tmp = tempfile::tempdir().unwrap();
            let victim = tmp.path().join("victim");
            std::fs::write(&victim, b"unrelated active work").unwrap();
            let selected = tmp.path().join(filename);
            let moved = tmp.path().join("saved");
            let redirect = victim.clone();
            INIT_DESCRIPTOR_HOOK.with(|slot| {
                *slot.borrow_mut() = Some((
                    stage,
                    Box::new(move || {
                        std::fs::rename(&selected, &moved).unwrap();
                        std::os::unix::fs::symlink(&redirect, &selected).unwrap();
                    }),
                ))
            });
            assert!(init_vault(opts(&tmp)).is_err());
            assert_eq!(std::fs::read(&victim).unwrap(), b"unrelated active work");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn temporary_collision_and_replacement_preserve_unrelated_inodes() {
        let tmp = tempfile::tempdir().unwrap();
        let (held, _) = InitDirectory::open(tmp.path(), false).unwrap();
        std::fs::write(tmp.path().join("collision"), b"active").unwrap();
        INIT_TEMPORARY_NAMES
            .with(|slot| *slot.borrow_mut() = vec![c"fresh".to_owned(), c"collision".to_owned()]);
        let staged = InitTemporary::create(&held).unwrap();
        assert_eq!(staged.name.as_c_str(), c"fresh");
        std::fs::rename(tmp.path().join("fresh"), tmp.path().join("moved")).unwrap();
        std::fs::write(tmp.path().join("fresh"), b"replacement active work").unwrap();
        drop(staged);
        assert_eq!(
            std::fs::read(tmp.path().join("fresh")).unwrap(),
            b"replacement active work"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("collision")).unwrap(),
            b"active"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn directory_sync_failure_retains_existing_links_for_safe_retry() {
        let tmp = tempfile::tempdir().unwrap();
        let (held, _) = InitDirectory::open(tmp.path(), false).unwrap();
        INIT_DESCRIPTOR_HOOK.with(|slot| {
            *slot.borrow_mut() = Some((
                14,
                Box::new(|| {
                    INIT_PUBLICATION_FAULT.with(|fault| fault.set(4));
                }),
            ))
        });
        assert!(held.child(c"created", true).is_err());
        assert!(tmp.path().join("created").is_dir());
        let retried = held.child(c"created", true).unwrap();
        retried.sync_chain().unwrap();
        retried.check_attached().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn initializer_denies_hardlinked_files_and_non_directory_ancestors() {
        let tmp = tempfile::tempdir().unwrap();
        let first = init_vault(opts(&tmp)).unwrap();
        for original in [
            &first.identity_file,
            &first.store_dir.join(".age-recipients"),
        ] {
            let copy = tmp.path().join("linked");
            std::fs::hard_link(original, &copy).unwrap();
            assert!(init_vault(opts(&tmp)).is_err());
            std::fs::remove_file(copy).unwrap();
        }
        let fifo =
            std::ffi::CString::new(tmp.path().join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(InitDirectory::open(&tmp.path().join("fifo/child"), true).is_err());
        assert!(InitDirectory::open(&first.identity_file.join("child"), true).is_err());
        assert!(InitDirectory::open(&tmp.path().join("new/../invalid"), true).is_err());
        assert!(!tmp.path().join("new").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn initializer_process_boundary_recovery_and_relative_paths() {
        for mode in [
            "mkdir",
            "published",
            "relative",
            "relative-change",
            "umask",
            "descriptors",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "init::tests::initializer_subprocess_fixture",
                    "--ignored",
                    "--nocapture",
                ])
                .env("REVEALFLEET_INIT_PROCESS_FIXTURE", mode)
                .current_dir(tmp.path())
                .output()
                .unwrap();
            let expected = match mode {
                "mkdir" => 71,
                "published" => 72,
                _ => 0,
            };
            assert_eq!(
                child.status.code(),
                Some(expected),
                "fixture {mode}: {}",
                String::from_utf8_lossy(&child.stderr)
            );
            if mode == "mkdir" {
                assert!(tmp.path().join("created").is_dir());
                init_vault(InitOptions {
                    store_dir: Some(tmp.path().join("created/store")),
                    identity_file: Some(tmp.path().join("created/keys.txt")),
                })
                .unwrap();
            } else if mode == "published" {
                let before = std::fs::read(tmp.path().join("keys.txt")).unwrap();
                assert!(!tmp.path().join("store/.age-recipients").exists());
                init_vault(opts(&tmp)).unwrap();
                assert_eq!(std::fs::read(tmp.path().join("keys.txt")).unwrap(), before);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "subprocess-only fixture, exercised by initializer_process_boundary_recovery_and_relative_paths"]
    fn initializer_subprocess_fixture() {
        match std::env::var("REVEALFLEET_INIT_PROCESS_FIXTURE")
            .unwrap()
            .as_str()
        {
            "mkdir" => {
                let (held, _) = InitDirectory::open(Path::new("."), false).unwrap();
                INIT_DESCRIPTOR_HOOK.with(|slot| {
                    *slot.borrow_mut() = Some((
                        14,
                        Box::new(|| unsafe {
                            libc::_exit(71);
                        }),
                    ))
                });
                let _ = held.child(c"created", true);
                panic!("mkdir exit hook did not execute");
            }
            "published" => {
                INIT_DESCRIPTOR_HOOK.with(|slot| {
                    *slot.borrow_mut() = Some((
                        15,
                        Box::new(|| unsafe {
                            libc::_exit(72);
                        }),
                    ))
                });
                let _ = init_vault(InitOptions {
                    store_dir: Some("store".into()),
                    identity_file: Some("keys.txt".into()),
                });
                panic!("publication exit hook did not execute");
            }
            "relative" => {
                let first = init_vault(InitOptions {
                    store_dir: Some("store".into()),
                    identity_file: Some("./keys.txt".into()),
                })
                .unwrap();
                let second = init_vault(InitOptions {
                    store_dir: Some("./store".into()),
                    identity_file: Some("keys.txt".into()),
                })
                .unwrap();
                assert_eq!(first.public_key, second.public_key);
            }
            "relative-change" => {
                let original = std::env::current_dir().unwrap();
                let elsewhere = original.join("elsewhere");
                std::fs::create_dir(&elsewhere).unwrap();
                let changed = elsewhere.clone();
                INIT_DESCRIPTOR_HOOK.with(|slot| {
                    *slot.borrow_mut() = Some((
                        16,
                        Box::new(move || {
                            std::env::set_current_dir(&changed).unwrap();
                        }),
                    ))
                });
                let initialized = init_vault(InitOptions {
                    store_dir: Some("store".into()),
                    identity_file: Some("keys.txt".into()),
                });
                assert!(initialized.is_err());
                assert!(original.join("keys.txt").exists());
                assert_eq!(std::fs::read_dir(elsewhere).unwrap().count(), 0);
            }
            "umask" => {
                use std::os::unix::fs::PermissionsExt;
                unsafe {
                    libc::umask(0o077);
                }
                let initialized = init_vault(InitOptions {
                    store_dir: Some("private/store".into()),
                    identity_file: Some("private/keys.txt".into()),
                })
                .unwrap();
                for path in [
                    &initialized.identity_file,
                    &initialized.store_dir.join(".age-recipients"),
                ] {
                    assert_eq!(
                        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                        0o600
                    );
                }
                assert_eq!(
                    std::fs::metadata("private").unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
            "descriptors" => {
                let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
                let before = count();
                for _ in 0..64 {
                    init_vault(InitOptions {
                        store_dir: Some("store".into()),
                        identity_file: Some("keys.txt".into()),
                    })
                    .unwrap();
                    assert!(InitDirectory::open(Path::new("missing/../invalid"), true).is_err());
                }
                assert_eq!(count(), before);
            }
            other => panic!("unknown synthetic fixture {other}"),
        }
    }
}
