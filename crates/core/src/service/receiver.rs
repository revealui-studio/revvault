//! Dedicated-process, durable service mutation admission; never provider acceptance.
use crate::init::ServiceInitPlan;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOperation {
    Initialize,
    Resume,
    Import,
    Restore,
}

/// Nonsecret, immutable automation input, not a provider or credential grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceMutationRequest {
    pub version: u32,
    pub request_id: String,
    pub uid: u32,
    pub operation: ServiceOperation,
    pub selector: Option<String>,
    pub source_contract_sha256: String,
    pub expected_target_sha256: String,
    pub expires_at: i64,
    pub archive_sha256: Option<String>,
}

/// Constructed from actual invocation arguments, never from the request's action.
pub enum ServiceInvocation {
    Initialize {
        policy: PathBuf,
    },
    Resume {
        policy: PathBuf,
    },
    Import {
        uid: u32,
        selector: String,
    },
    Restore {
        policy: PathBuf,
        archive: PathBuf,
        archive_sha256: String,
    },
}

pub enum ServiceMutationOutcome {
    Initialized(ServiceInitPlan),
    Resumed(ServiceInitPlan),
    Imported(String),
    Restored(ServiceInitPlan),
}

/// Observations never authorize replay, admission, or a trusted completion claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRequestState {
    Unobserved,
    Held,
    LocalCompletionObserved,
}

/// Nonsecret local observation, deliberately not deserializable as an authority.
#[derive(Debug, Serialize)]
pub struct ServiceRequestStatus {
    version: u32,
    request_id: String,
    request_sha256: String,
    uid: u32,
    operation: ServiceOperation,
    source_contract_sha256: String,
    expected_target_sha256: String,
    observed_at: i64,
    state: ServiceRequestState,
    record_durability: &'static str,
    provider_admission: &'static str,
    process_termination: &'static str,
    execution_fencing: &'static str,
    rollback_protection: &'static str,
    retry_authorized: bool,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{ServiceMutationGuard, ServiceReceiverDeadline};

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use super::*;
    use crate::{error::Result, RevvaultError};
    use secrecy::SecretString;
    use std::path::Path;
    fn denied() -> RevvaultError {
        RevvaultError::Other(anyhow::anyhow!("revvault_service_request_denied"))
    }
    pub struct ServiceReceiverDeadline;
    impl ServiceReceiverDeadline {
        pub fn start() -> Result<Self> {
            Err(denied())
        }
    }
    pub struct ServiceMutationGuard<'a> {
        _deadline: &'a ServiceReceiverDeadline,
    }
    impl<'a> ServiceMutationGuard<'a> {
        pub fn begin(
            _deadline: &'a ServiceReceiverDeadline,
            _request: &Path,
            _invocation: ServiceInvocation,
        ) -> Result<Self> {
            Err(denied())
        }
        pub fn status(
            _deadline: &ServiceReceiverDeadline,
            _request: &Path,
            _policy: &Path,
        ) -> Result<ServiceRequestStatus> {
            Err(denied())
        }
        pub fn execute(self, _secret: Option<SecretString>) -> Result<ServiceMutationOutcome> {
            Err(denied())
        }
        pub(crate) fn recheck(&self) -> Result<()> {
            Err(denied())
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub use unsupported::{ServiceMutationGuard, ServiceReceiverDeadline};
