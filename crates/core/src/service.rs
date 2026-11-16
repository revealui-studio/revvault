//! Kernel-UID capabilities for service callers. Fixed root-owned policy and a
//! dedicated read-only encrypted store; no home/env/machine override fallback.
use crate::error::Result;
use crate::{Config, RevvaultError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
pub mod backup;
pub mod receiver;

/// Public build evidence only. It binds the canonical policy and each immutable
/// absolute command input to the running RevVault executable; never vault data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceSourceContract {
    pub version: u32,
    pub uid: u32,
    pub policy_sha256: String,
    pub revvault_sha256: String,
    pub command_sha256: BTreeMap<String, String>,
}

impl ServiceSourceContract {
    pub fn sha256(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| denied())?,
        )))
    }
}

/// Root-only, read-only evidence for a reviewed image. This is not a capability
/// grant and does not prove provider identity, mounts, execution fencing or custody.
pub fn service_source_contract(policy_file: &Path) -> Result<ServiceSourceContract> {
    #[cfg(target_os = "linux")]
    {
        use sha2::{Digest, Sha256};
        if unsafe { libc::geteuid() } != 0 {
            return Err(denied());
        }
        let measure = || -> Result<ServiceSourceContract> {
            immutable_path(policy_file)?;
            let metadata = std::fs::metadata(policy_file)?;
            if !metadata.is_file() || metadata.len() > 65_536 {
                return Err(denied());
            }
            use std::io::Read;
            let mut source = String::new();
            std::fs::File::open(policy_file)?
                .take(65_537)
                .read_to_string(&mut source)?;
            if source.len() > 65_536 {
                return Err(denied());
            }
            let policy: ServicePolicy = toml::from_str(&source).map_err(|_| denied())?;
            policy.validate(policy.uid)?;
            let executable = std::env::current_exe()?;
            immutable_path(&executable)?;
            let commands = policy
                .command
                .iter()
                .filter(|command| Path::new(command).is_absolute())
                .map(|command| {
                    let path = Path::new(command);
                    immutable_path(path)?;
                    Ok((command.clone(), crate::init::file_digest(path)?))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            Ok(ServiceSourceContract {
                version: 1,
                uid: policy.uid,
                policy_sha256: hex::encode(Sha256::digest(
                    toml::to_string(&policy).map_err(|_| denied())?.as_bytes(),
                )),
                revvault_sha256: crate::init::file_digest(&executable)?,
                command_sha256: commands,
            })
        };
        // File/parser errors can contain paths or source fragments. Only a fixed
        // error crosses the preview boundary, just as with service admission.
        measure().map_err(|_| denied())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy_file;
        Err(denied())
    }
}

/// Serialize maintained service imports and custody snapshots on the fixed
/// directory inode. No lock file, environment override or runtime write grant.
pub(crate) fn lock_custody(uid: u32) -> Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::geteuid() } != 0 || uid == 0 {
            return Err(denied());
        }
        let root = ServicePolicy::fixed_policy_path(uid);
        let root = root.parent().ok_or_else(denied)?;
        immutable_path(root)?;
        private_service_path(root, uid)?;
        let file = std::fs::File::open(root)?;
        if !file.metadata()?.is_dir()
            || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0
        {
            return Err(denied());
        }
        Ok(file)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = uid;
        Err(denied())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicy {
    pub version: u32,
    pub uid: u32,
    pub command: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, String>,
}

fn denied() -> RevvaultError {
    RevvaultError::Other(anyhow::anyhow!("revvault_service_capability_denied"))
}

/// Personal APIs must never adopt the reserved service custody namespace,
/// including an alias reached through an existing symlink. This guards maintained
/// API use and accidental configuration; it does not constrain arbitrary root IO.
pub fn assert_personal_path(path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        assert_outside_custody(path, Path::new("/var/lib/revvault"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn assert_outside_custody(path: &Path, custody: &Path) -> Result<()> {
    use std::path::Component;
    let absolute = std::path::absolute(path).map_err(|_| denied())?;
    let canonical_custody = std::fs::canonicalize(custody).ok();
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                current.pop();
            }
            Component::CurDir => continue,
            other => current.push(other.as_os_str()),
        }
        let reserved = |candidate: &Path| {
            candidate.starts_with(custody)
                || canonical_custody
                    .as_ref()
                    .is_some_and(|root| candidate.starts_with(root))
        };
        if reserved(&current) {
            return Err(denied());
        }
        match std::fs::canonicalize(&current) {
            Ok(resolved) => {
                if reserved(&resolved) {
                    return Err(denied());
                }
                current = resolved;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A missing suffix is valid for initialization. A dangling link
                // has an unverified destination and must not be adopted instead.
                match std::fs::symlink_metadata(&current) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(denied()),
                }
            }
            Err(_) => return Err(denied()),
        }
    }
    Ok(())
}

impl ServicePolicy {
    /// One fixed persistent custody namespace; no caller-selected relocation.
    pub fn fixed_policy_path(uid: u32) -> PathBuf {
        PathBuf::from(format!("/var/lib/revvault/services/{uid}/policy.toml"))
    }

    /// Old split-root capabilities require reviewed migration, never fallback/adoption.
    pub(crate) fn reject_legacy(uid: u32) -> Result<()> {
        match std::fs::symlink_metadata(format!("/etc/revvault/services/{uid}.toml")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(denied()),
        }
    }

    /// Unix kernel identity selects the policy; callers cannot select another
    /// principal through HOME, config files, CLI options or environment variables.
    pub fn current() -> Result<Option<Self>> {
        #[cfg(unix)]
        {
            let uid = unsafe { libc::geteuid() };
            let Some(policy) = Self::load_fixed(uid)? else {
                return Ok(None);
            };
            if unsafe { libc::getegid() } != uid {
                return Err(denied());
            }
            let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
            if count < 0 {
                return Err(denied());
            }
            let mut groups = vec![0; count as usize];
            if unsafe { libc::getgroups(count, groups.as_mut_ptr()) } != count
                || groups.iter().any(|group| *group != uid)
            {
                return Err(denied());
            }
            Ok(Some(policy))
        }
        #[cfg(not(unix))]
        {
            Ok(None)
        }
    }

    /// The same fixed policy/store loader, restricted to root provisioning.
    /// A coding/service caller cannot choose a foreign UID or personal store.
    pub(crate) fn for_import(uid: u32) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            if unsafe { libc::geteuid() } != 0 || uid == 0 {
                return Err(denied());
            }
            Self::load_fixed(uid)?.ok_or_else(denied)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = uid;
            Err(denied())
        }
    }

    #[cfg(unix)]
    fn load_fixed(uid: u32) -> Result<Option<Self>> {
        Self::reject_legacy(uid)?;
        let path = Self::fixed_policy_path(uid);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(denied()),
            Ok(_) => {}
        }
        // Pending provisioning closes runtime admission even after policy publication.
        match std::fs::symlink_metadata(
            path.parent().ok_or_else(denied)?.join(".provisioning.toml"),
        ) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(denied()),
        }
        immutable_path(&path)?;
        let policy: Self = toml::from_str(&std::fs::read_to_string(&path).map_err(|_| denied())?)
            .map_err(|_| denied())?;
        policy.validate(uid)?;
        let config = policy.config();
        for file in [
            &config.store_dir,
            &config.identity_file,
            &config.recipients_file,
        ] {
            immutable_path(file)?;
            private_service_path(file, uid)?;
        }
        private_service_path(config.store_dir.parent().ok_or_else(denied)?, uid)?;
        for part in &policy.command {
            if Path::new(part).is_absolute() {
                immutable_path(Path::new(part))?;
            }
        }
        Ok(Some(policy))
    }

    pub fn config(&self) -> Config {
        let root = PathBuf::from(format!("/var/lib/revvault/services/{}", self.uid));
        Config {
            store_dir: root.join("store"),
            identity_file: root.join("identity.txt"),
            recipients_file: root.join("store/.age-recipients"),
            editor: None,
            tmpdir: None,
        }
    }

    pub fn validate(&self, uid: u32) -> Result<()> {
        let safe_key = |key: &str| {
            !key.is_empty()
                && key.bytes().enumerate().all(|(i, ch)| {
                    ch == b'_' || ch.is_ascii_uppercase() || (i > 0 && ch.is_ascii_digit())
                })
        };
        let safe_path = |path: &str| {
            !path.is_empty()
                && path.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part.bytes().all(|ch| {
                            ch.is_ascii_lowercase()
                                || ch.is_ascii_digit()
                                || matches!(ch, b'-' | b'_')
                        })
                })
        };
        if self.version != 1
            || uid == 0
            || self.uid != uid
            || self.command.is_empty()
            || !Path::new(&self.command[0]).is_absolute()
            || self.command.iter().any(|part| part.contains('\0'))
            || self.secrets.is_empty()
            || self.secrets.len() > 32
            || self.secrets.keys().any(|key| {
                [
                    "PATH",
                    "HOME",
                    "NODE_ENV",
                    "PORT",
                    "LANG",
                    "NODE_OPTIONS",
                    "LD_PRELOAD",
                    "LD_LIBRARY_PATH",
                ]
                .contains(&key.as_str())
            })
            || self
                .secrets
                .iter()
                .any(|(key, path)| !safe_key(key) || !safe_path(path))
            || self
                .environment
                .keys()
                .any(|key| !["PATH", "HOME", "NODE_ENV", "PORT", "LANG"].contains(&key.as_str()))
            || self.environment.values().any(|value| value.contains('\0'))
            || self
                .environment
                .keys()
                .any(|key| self.secrets.contains_key(key))
        {
            return Err(denied());
        }
        Ok(())
    }

    pub fn allows_read(&self, path: &str) -> bool {
        self.secrets.values().any(|allowed| allowed == path)
    }

    pub fn assert_configuration(&self, config: &Config) -> Result<()> {
        let expected = self.config();
        if config.store_dir != expected.store_dir
            || config.identity_file != expected.identity_file
            || config.recipients_file != expected.recipients_file
            || config.editor.is_some()
            || config.tmpdir.is_some()
        {
            return Err(denied());
        }
        Ok(())
    }
}

/// Every ancestor is immutable to service callers; symlink substitutions and
/// group/world-writable parents cannot turn scoped paths into the shared vault.
#[cfg(unix)]
pub fn immutable_path(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| denied())?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.file_type().is_symlink()
        {
            return Err(denied());
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn private_service_path(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| denied())?;
    if metadata.gid() != uid || metadata.mode() & 0o007 != 0 {
        return Err(denied());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(target_os = "linux")]
    fn personal_paths_reject_reserved_custody_and_preserve_other_paths() {
        for path in [
            "/var/lib/revvault",
            "/var/lib/revvault/services/19001/store",
            "/var/lib/revvault/../elsewhere",
        ] {
            assert_eq!(
                assert_personal_path(Path::new(path))
                    .unwrap_err()
                    .to_string(),
                "revvault_service_capability_denied"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        assert_personal_path(&dir.path().join("new/personal-store")).unwrap();
        assert_personal_path(Path::new("/var/lib/revvault-personal/new")).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn personal_paths_resolve_aliases_before_parent_components_and_missing_suffixes() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let custody = dir.path().join("reserved");
        std::fs::create_dir_all(custody.join("services/19001")).unwrap();
        let alias = dir.path().join("alias");
        symlink(custody.join("services"), &alias).unwrap();
        for path in [alias.join("19001/new"), alias.join("../new")] {
            assert!(assert_outside_custody(&path, &custody).is_err());
        }
        let personal = dir.path().join("personal");
        std::fs::create_dir(&personal).unwrap();
        let personal_alias = dir.path().join("personal-alias");
        symlink(&personal, &personal_alias).unwrap();
        assert_outside_custody(&personal_alias.join("new"), &custody).unwrap();
        let dangling = dir.path().join("dangling");
        symlink(custody.join("missing"), &dangling).unwrap();
        assert!(assert_outside_custody(&dangling.join("new"), &custody).is_err());
    }

    #[test]
    fn source_contract_digest_binds_every_source_and_declared_principal() {
        let original = ServiceSourceContract {
            version: 1,
            uid: 1001,
            policy_sha256: "a".repeat(64),
            revvault_sha256: "b".repeat(64),
            command_sha256: BTreeMap::from([
                ("/usr/local/bin/node".into(), "c".repeat(64)),
                ("/app/dist/publisher-run.js".into(), "d".repeat(64)),
            ]),
        };
        let encoded = serde_json::to_string(&original).unwrap();
        let roundtrip: ServiceSourceContract = serde_json::from_str(&encoded).unwrap();
        assert_eq!(original.sha256().unwrap(), roundtrip.sha256().unwrap());
        for field in [
            "version",
            "uid",
            "policy_sha256",
            "revvault_sha256",
            "command_sha256",
        ] {
            let mut changed = serde_json::to_value(&original).unwrap();
            changed[field] = match field {
                "version" => serde_json::json!(2),
                "uid" => serde_json::json!(1002),
                "command_sha256" => serde_json::json!({"/usr/local/bin/node": "e".repeat(64)}),
                _ => serde_json::json!("e".repeat(64)),
            };
            let changed: ServiceSourceContract = serde_json::from_value(changed).unwrap();
            assert_ne!(
                original.sha256().unwrap(),
                changed.sha256().unwrap(),
                "{field}"
            );
        }
    }

    #[test]
    fn source_contract_denial_does_not_reveal_paths_or_read_a_personal_store() {
        let error = service_source_contract(Path::new("/nonexistent/synthetic-private-policy"))
            .unwrap_err();
        assert_eq!(error.to_string(), "revvault_service_capability_denied");
    }

    fn policy() -> ServicePolicy {
        ServicePolicy {
            version: 1,
            uid: 1001,
            command: vec![
                "/usr/local/bin/node".into(),
                "/app/dist/publisher-run.js".into(),
            ],
            environment: BTreeMap::from([
                ("HOME".into(), "/var/lib/revealfleet/publisher".into()),
                ("NODE_ENV".into(), "production".into()),
            ]),
            secrets: BTreeMap::from([
                (
                    "REVEALFLEET_PUBLISHER_DATABASE_URL".into(),
                    "revealfleet/publisher/database-url".into(),
                ),
                (
                    "REVEALFLEET_PUBLISHER_GITHUB_APP_PRIVATE_KEY".into(),
                    "revealfleet/publisher/app-key".into(),
                ),
            ]),
        }
    }
    #[test]
    fn service_policy_binds_kernel_uid_exact_paths_and_dedicated_store() {
        let p = policy();
        p.validate(1001).unwrap();
        assert!(p.validate(1000).is_err());
        assert!(p.validate(0).is_err());
        assert!(p.allows_read("revealfleet/publisher/app-key"));
        for path in [
            "revealfleet/controller/app-key",
            "revealfleet/reviewer/app-key",
            "credentials/github/personal-token",
            "revealfleet/publisher/app-key/child",
        ] {
            assert!(!p.allows_read(path));
        }
        let mut config = p.config();
        p.assert_configuration(&config).unwrap();
        config.identity_file = "/synthetic/operator/identity.txt".into();
        assert!(p.assert_configuration(&config).is_err());
    }
    #[test]
    fn service_policy_rejects_injection_and_traversal() {
        for key in [
            "NODE_OPTIONS",
            "LD_PRELOAD",
            "REVVAULT_IDENTITY",
            "SSH_AUTH_SOCK",
            "GH_TOKEN",
        ] {
            let mut p = policy();
            p.environment.insert(key.into(), "denied".into());
            assert!(p.validate(1001).is_err());
        }
        for path in [
            "../controller/key",
            "/credentials/key",
            "revealfleet//key",
            "revealfleet/publisher/../key",
            "revealfleet\\key",
        ] {
            let mut p = policy();
            p.secrets.insert("KEY".into(), path.into());
            assert!(p.validate(1001).is_err());
        }
        let mut p = policy();
        p.command[0] = "node".into();
        assert!(p.validate(1001).is_err());
        assert!(toml::from_str::<ServicePolicy>("version=1\nuid=1001\nunknown=true").is_err());
    }
}
