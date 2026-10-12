//! Kernel-UID capabilities for service callers. Fixed root-owned policy and a
//! dedicated read-only encrypted store; no home/env/machine override fallback.
use crate::error::Result;
use crate::{Config, RevvaultError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    #[cfg(unix)]
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
        config.identity_file = "/tmp/foreign-vault/identity.txt".into();
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
