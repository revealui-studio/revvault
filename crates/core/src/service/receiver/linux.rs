//! Dedicated-process service mutation admission. The volume-local nonce ledger
//! is not a provider execution fence or an independently nonrollback authority.
use super::{
    ServiceInvocation, ServiceMutationOutcome, ServiceMutationRequest, ServiceOperation,
    ServiceRequestState, ServiceRequestStatus,
};
use crate::service::{immutable_path, service_source_contract, ServicePolicy};
use crate::{error::Result, PassageStore, RevvaultError};
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

const LIMIT: u64 = 65_536;
// A canonical claim adds a fixed wrapper and explicit nullable metadata.
const RECORD_LIMIT: u64 = LIMIT + 1024;
const CUSTODY: &str = "/var/lib/revvault";
const SECONDS: i64 = 30;

fn denied() -> RevvaultError {
    RevvaultError::Other(anyhow::anyhow!("revvault_service_request_denied"))
}

/// A hard deadline for a dedicated, in-process receiver invocation. SIGKILL
/// affects the entire calling process; never construct this in a shared daemon.
/// Timers do not survive exec or bound descendants/pending kernel I/O. The current
/// receiver executes no children. Provider fencing/termination remains separate.
pub struct ServiceReceiverDeadline {
    timer: libc::timer_t,
}

impl ServiceReceiverDeadline {
    pub fn start() -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(crate::service::denied());
        }
        Self::arm(Duration::from_secs(SECONDS as u64))
    }

    fn arm(duration: Duration) -> Result<Self> {
        // No handler, global alarm, environment selector or adjustable production
        // budget: this timer can only kill this receiver process.
        let mut event: libc::sigevent = unsafe { std::mem::zeroed() };
        event.sigev_notify = libc::SIGEV_SIGNAL;
        event.sigev_signo = libc::SIGKILL;
        let mut timer = std::ptr::null_mut();
        if unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut event, &mut timer) } != 0 {
            return Err(denied());
        }
        let guard = Self { timer };
        let specification = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: duration.as_secs() as libc::time_t,
                tv_nsec: duration.subsec_nanos() as libc::c_long,
            },
        };
        if unsafe { libc::timer_settime(timer, 0, &specification, std::ptr::null_mut()) } != 0 {
            return Err(denied());
        }
        Ok(guard)
    }
}

impl Drop for ServiceReceiverDeadline {
    fn drop(&mut self) {
        // Deletes only this timer. Process exit also destroys its owned timers.
        unsafe {
            libc::timer_delete(self.timer);
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct MountIdentity {
    id: String,
    device: String,
    root: String,
}

fn mount_identity(text: &str) -> Result<MountIdentity> {
    let mut matches = text.lines().filter_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.get(4).copied() != Some(CUSTODY) {
            return None;
        }
        Some(fields)
    });
    let fields = matches.next().ok_or_else(denied)?;
    if matches.next().is_some()
        || fields.len() < 10
        || !fields[5].split(',').any(|option| option == "rw")
        || !fields.contains(&"-")
    {
        return Err(denied());
    }
    Ok(MountIdentity {
        id: fields[0].into(),
        device: fields[2].into(),
        root: fields[3].into(),
    })
}

fn current_mount() -> Result<MountIdentity> {
    let mut text = String::new();
    fs::File::open("/proc/self/mountinfo")?
        .take(1_048_577)
        .read_to_string(&mut text)?;
    if text.len() > 1_048_576 {
        return Err(denied());
    }
    let mount = mount_identity(&text)?;
    immutable_path(Path::new(CUSTODY))?;
    let metadata = fs::metadata(CUSTODY)?;
    let actual = format!(
        "{}:{}",
        libc::major(metadata.dev()),
        libc::minor(metadata.dev())
    );
    if !metadata.is_dir() || actual != mount.device {
        return Err(denied());
    }
    Ok(mount)
}

fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ServiceMutationRequest {
    fn validate_binding(
        &self,
        uid: u32,
        operation: ServiceOperation,
        selector: Option<&str>,
        archive: Option<&str>,
    ) -> Result<()> {
        if self.version != 1
            || self.uid == 0
            || self.uid != uid
            || self.operation != operation
            || self.selector.as_deref() != selector
            || self.archive_sha256.as_deref() != archive
            || !hex(&self.request_id, 32)
            || !hex(&self.source_contract_sha256, 64)
            || !hex(&self.expected_target_sha256, 64)
            || self
                .archive_sha256
                .as_deref()
                .is_some_and(|value| !hex(value, 64))
            || self.expires_at <= 0
            || chrono::DateTime::from_timestamp(self.expires_at, 0).is_none()
        {
            return Err(denied());
        }
        Ok(())
    }

    fn validate(
        &self,
        uid: u32,
        operation: ServiceOperation,
        selector: Option<&str>,
        archive: Option<&str>,
        now: i64,
    ) -> Result<()> {
        self.validate_binding(uid, operation, selector, archive)?;
        if self.expires_at.saturating_sub(now) < SECONDS
            || self.expires_at.saturating_sub(now) > 300
        {
            return Err(denied());
        }
        Ok(())
    }
}

fn read_request(request_file: &Path) -> Result<ServiceMutationRequest> {
    immutable_path(request_file)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(request_file)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() > LIMIT
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(denied());
    }
    let mut input = String::new();
    file.take(LIMIT + 1).read_to_string(&mut input)?;
    if input.len() as u64 > LIMIT {
        return Err(denied());
    }
    serde_json::from_str(&input).map_err(|_| denied())
}

fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

struct Journal {
    directory: PathBuf,
    owner: u32,
    request_id: String,
    claim: Vec<u8>,
}

impl Journal {
    fn for_request(directory: PathBuf, request: &ServiceMutationRequest) -> Result<Self> {
        let claim =
            serde_json::to_vec(&serde_json::json!({"version":1,"state":"held","request":request}))
                .map_err(|_| denied())?;
        if claim.len() as u64 > RECORD_LIMIT {
            return Err(denied());
        }
        Ok(Self {
            directory,
            owner: 0,
            request_id: request.request_id.clone(),
            claim,
        })
    }

    fn observation(
        &self,
        request: ServiceMutationRequest,
        state: ServiceRequestState,
    ) -> ServiceRequestStatus {
        ServiceRequestStatus {
            version: 1,
            request_id: request.request_id,
            request_sha256: hex::encode(Sha256::digest(&self.claim)),
            uid: request.uid,
            operation: request.operation,
            source_contract_sha256: request.source_contract_sha256,
            expected_target_sha256: request.expected_target_sha256,
            observed_at: Utc::now().timestamp(),
            state,
            record_durability: "unverified",
            provider_admission: "held",
            process_termination: "unverified",
            execution_fencing: "unverified",
            rollback_protection: "unverified",
            retry_authorized: false,
        }
    }

    fn check_directory(&self) -> Result<()> {
        let m = fs::symlink_metadata(&self.directory)?;
        if !m.is_dir()
            || m.uid() != self.owner
            || m.gid() != self.owner
            || m.mode() & 0o7777 != 0o700
        {
            return Err(denied());
        }
        Ok(())
    }

    fn write_new(&self, path: &Path, value: &[u8]) -> Result<()> {
        self.check_directory()?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.write_all(value)?;
        file.sync_all()?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    fn require_incomplete(&self) -> Result<()> {
        match fs::symlink_metadata(self.complete_path()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(denied()),
        }
    }

    fn claim(&self) -> Result<()> {
        self.check_directory()?;
        // Even an orphaned/truncated completion record forbids request reuse.
        self.require_incomplete()?;
        self.write_new(&self.claim_path(), &self.claim)
    }

    fn claim_path(&self) -> PathBuf {
        self.directory
            .join(format!("{}.held.json", self.request_id))
    }
    fn complete_path(&self) -> PathBuf {
        self.directory
            .join(format!("{}.complete.json", self.request_id))
    }

    fn read_record(&self, path: &Path) -> Result<Vec<u8>> {
        self.check_directory()?;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != self.owner
            || m.gid() != self.owner
            || m.nlink() != 1
            || m.mode() & 0o7777 != 0o600
            || m.len() > RECORD_LIMIT
        {
            return Err(denied());
        }
        let mut value = Vec::new();
        file.take(RECORD_LIMIT + 1).read_to_end(&mut value)?;
        if value.len() as u64 != m.len() || value.len() as u64 > RECORD_LIMIT {
            return Err(denied());
        }
        Ok(value)
    }

    fn verify_claim(&self) -> Result<()> {
        if self.read_record(&self.claim_path())? != self.claim {
            return Err(denied());
        }
        Ok(())
    }

    fn verify(&self) -> Result<()> {
        self.require_incomplete()?;
        self.verify_claim()
    }

    fn completion_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&serde_json::json!({
            "version": 1, "request_sha256": hex::encode(Sha256::digest(&self.claim)),
            "status": "local_complete", "provider_admission": "held"
        }))
        .map_err(|_| denied())
    }

    fn complete(&self) -> Result<()> {
        self.verify()?;
        self.write_new(&self.complete_path(), &self.completion_bytes()?)
    }

    fn status(&self) -> Result<ServiceRequestState> {
        // A missing namespace is only an observation: dispatch may still be
        // running, delayed, or on a different/rolled-back volume. Never retry.
        if !present(&self.directory)? {
            return Ok(ServiceRequestState::Unobserved);
        }
        self.check_directory()?;
        let claim = present(&self.claim_path())?;
        let complete = present(&self.complete_path())?;
        if !claim {
            if complete {
                return Err(denied());
            }
            return Ok(ServiceRequestState::Unobserved);
        }
        self.verify_claim()?;
        if !complete {
            return Ok(ServiceRequestState::Held);
        }
        if self.read_record(&self.complete_path())? != self.completion_bytes()? {
            return Err(denied());
        }
        // Visible exact bytes do not prove the original writer's fsync returned.
        Ok(ServiceRequestState::LocalCompletionObserved)
    }
}

/// Owns one durable consumed nonce; only execute() can publish local completion.
/// Must borrow a deadline that stays alive through the calling receiver's output.
pub struct ServiceMutationGuard<'a> {
    _deadline: &'a ServiceReceiverDeadline,
    request: ServiceMutationRequest,
    invocation: ServiceInvocation,
    policy: PathBuf,
    mount: MountIdentity,
    journal: Journal,
}

impl<'a> ServiceMutationGuard<'a> {
    pub fn begin(
        deadline: &'a ServiceReceiverDeadline,
        request_file: &Path,
        invocation: ServiceInvocation,
    ) -> Result<Self> {
        let begin = || -> Result<Self> {
            if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
                return Err(denied());
            }
            let mount = current_mount()?;
            let request = read_request(request_file)?;
            let (policy, operation, selector, archive) = match &invocation {
                ServiceInvocation::Initialize { policy } => {
                    (policy.clone(), ServiceOperation::Initialize, None, None)
                }
                ServiceInvocation::Resume { policy } => {
                    (policy.clone(), ServiceOperation::Resume, None, None)
                }
                ServiceInvocation::Restore {
                    policy,
                    archive_sha256,
                    ..
                } => (
                    policy.clone(),
                    ServiceOperation::Restore,
                    None,
                    Some(archive_sha256.as_str()),
                ),
                ServiceInvocation::Import { uid, selector } => (
                    ServicePolicy::fixed_policy_path(*uid),
                    ServiceOperation::Import,
                    Some(selector.as_str()),
                    None,
                ),
            };
            let sources = service_source_contract(&policy)?;
            request.validate(
                sources.uid,
                operation,
                selector,
                archive,
                Utc::now().timestamp(),
            )?;
            if let ServiceInvocation::Import { uid, selector } = &invocation {
                if *uid != request.uid || !ServicePolicy::for_import(*uid)?.allows_read(selector) {
                    return Err(denied());
                }
            }
            if sources.sha256()? != request.source_contract_sha256 {
                return Err(denied());
            }
            let directory = PathBuf::from(CUSTODY).join("requests");
            match fs::symlink_metadata(&directory) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::DirBuilder::new().mode(0o700).create(&directory)?;
                    fs::File::open(CUSTODY)?.sync_all()?;
                }
                Err(_) => return Err(denied()),
                Ok(_) => {}
            }
            immutable_path(&directory)?;
            let journal = Journal::for_request(directory, &request)?;
            journal.claim()?;
            let guard = Self {
                _deadline: deadline,
                request,
                invocation,
                policy,
                mount,
                journal,
            };
            guard.recheck()?;
            Ok(guard)
        };
        begin().map_err(|_| denied())
    }

    /// Observe an exact original request without creating, repairing or retrying
    /// any state. Expiry restricts mutation admission; it never hides old evidence.
    /// Source upgrades, missing mounts and ambiguous records deny reconciliation.
    pub fn status(
        _deadline: &ServiceReceiverDeadline,
        request_file: &Path,
        policy_file: &Path,
    ) -> Result<ServiceRequestStatus> {
        let inspect = || -> Result<ServiceRequestStatus> {
            if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
                return Err(denied());
            }
            let mount = current_mount()?;
            let request = read_request(request_file)?;
            let sources = service_source_contract(policy_file)?;
            let (selector, archive) = match request.operation {
                ServiceOperation::Import => {
                    (Some(request.selector.as_deref().ok_or_else(denied)?), None)
                }
                ServiceOperation::Restore => (
                    None,
                    Some(request.archive_sha256.as_deref().ok_or_else(denied)?),
                ),
                _ => (None, None),
            };
            request.validate_binding(sources.uid, request.operation, selector, archive)?;
            if request.operation == ServiceOperation::Import
                && !ServicePolicy::for_import(request.uid)?
                    .allows_read(selector.ok_or_else(denied)?)
            {
                return Err(denied());
            }
            if sources.sha256()? != request.source_contract_sha256 {
                return Err(denied());
            }
            let journal = Journal::for_request(PathBuf::from(CUSTODY).join("requests"), &request)?;
            let state = journal.status()?;
            if current_mount()? != mount
                || service_source_contract(policy_file)?.sha256()? != request.source_contract_sha256
            {
                return Err(denied());
            }
            Ok(journal.observation(request, state))
        };
        inspect().map_err(|_| denied())
    }

    /// Rechecked after custody locks and immediately before protected writes.
    pub(crate) fn recheck(&self) -> Result<()> {
        let verify = || -> Result<()> {
            if Utc::now().timestamp() >= self.request.expires_at
                || current_mount()? != self.mount
                || service_source_contract(&self.policy)?.sha256()?
                    != self.request.source_contract_sha256
            {
                return Err(denied());
            }
            self.journal.verify()
        };
        verify().map_err(|_| denied())
    }

    pub fn execute(self, secret: Option<SecretString>) -> Result<ServiceMutationOutcome> {
        self.recheck()?;
        let result = match &self.invocation {
            ServiceInvocation::Initialize { policy } if secret.is_none() => {
                ServiceMutationOutcome::Initialized(crate::init::init_service_vault(policy, &self)?)
            }
            ServiceInvocation::Resume { policy } if secret.is_none() => {
                ServiceMutationOutcome::Resumed(crate::init::resume_service_vault(policy, &self)?)
            }
            ServiceInvocation::Import { uid, selector } => {
                let value = secret.as_ref().ok_or_else(denied)?.expose_secret().trim();
                if value.is_empty() || value.len() > LIMIT as usize || value.contains('\0') {
                    return Err(denied());
                }
                PassageStore::open_service_import(*uid, selector)?.import_guarded(
                    selector,
                    value.as_bytes(),
                    &self,
                )?;
                ServiceMutationOutcome::Imported(selector.clone())
            }
            ServiceInvocation::Restore {
                policy,
                archive,
                archive_sha256,
            } => {
                let identity = secret.as_ref().ok_or_else(denied)?.expose_secret();
                if identity.is_empty() || identity.len() > 4096 {
                    return Err(denied());
                }
                ServiceMutationOutcome::Restored(crate::service::backup::restore_service_vault(
                    policy,
                    archive,
                    archive_sha256,
                    identity,
                    Some(&self),
                )?)
            }
            _ => return Err(denied()),
        };
        // The initializer publishes its canonical policy only after validation;
        // fingerprints remain equal to the candidate's canonical source contract.
        self.recheck()?;
        self.journal.complete().map_err(|_| denied())?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
