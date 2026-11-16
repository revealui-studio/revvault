//! Read-only provider evidence for the existing service provisioning boundary.
//! Configuration equality is deliberately separate from remote execution/custody
//! admission. This module has no exec, lease, secret import or deployment method.
use super::FlyClient;
use anyhow::{bail, Result};
use chrono::Utc;
use reqwest::{redirect::Policy, Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use zeroize::Zeroizing;

const MACHINES_API: &str = "https://api.machines.dev/v1";
const MAX_RESPONSE: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);
const DENIED: &str = "revvault_service_target_unverified";

/// Reviewed nonsecret expectations, not a second inventory or a capability.
/// Callers derive these from accepted artifacts and the canonical fleet registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlyServiceTarget {
    pub version: u32,
    pub app: String,
    pub machine_id: String,
    pub instance_id: String,
    /// Exact digest reference; a floating tag is never an accepted target.
    pub image: String,
    pub volume_id: String,
    pub service_uid: u32,
    pub source_contract_sha256: String,
    pub expires_at: i64,
}

impl FlyServiceTarget {
    fn validate(&self, now: i64) -> Result<()> {
        let hex = |value: &str, length: usize| {
            value.len() == length
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        let name = !self.app.is_empty()
            && self.app.len() <= 63
            && self
                .app
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && self.app.as_bytes()[0].is_ascii_alphanumeric()
            && self.app.as_bytes()[self.app.len() - 1].is_ascii_alphanumeric();
        let image_prefix = format!("registry.fly.io/{}@sha256:", self.app);
        let image_digest = self.image.strip_prefix(&image_prefix);
        if self.version != 1
            || !name
            || !(12..=32).contains(&self.machine_id.len())
            || !hex(&self.machine_id, self.machine_id.len())
            || self.instance_id.len() != 26
            || !self
                .instance_id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            || !self.volume_id.starts_with("vol_")
            || !(8..=40).contains(&self.volume_id.len())
            || !self.volume_id[4..]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || !image_digest.is_some_and(|value| hex(value, 64))
            || !hex(&self.source_contract_sha256, 64)
            || self.service_uid == 0
            || self.service_uid == u32::MAX
            || self.expires_at.saturating_sub(now) < 10
            || self.expires_at.saturating_sub(now) > 600
        {
            bail!(DENIED);
        }
        Ok(())
    }

    fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}

/// Public configuration observation. A fresh matching Machine cannot establish
/// the receiver's root identity, source, replay protection or execution fencing.
#[derive(Debug, Serialize)]
pub struct FlyServiceTargetEvidence {
    pub version: u32,
    pub target_sha256: String,
    pub observed_at: i64,
    pub expires_at: i64,
    pub app: String,
    pub machine_id: String,
    pub instance_id: String,
    pub image: String,
    pub volume_id: String,
    pub expected_service_uid: u32,
    pub expected_source_contract_sha256: String,
    pub provider_configuration_matches: bool,
    // Private fields cannot be constructed by a caller as an admission grant.
    receiver_identity: &'static str,
    receiver_sources: &'static str,
    execution_fencing: &'static str,
    provisioning: &'static str,
}

#[derive(Deserialize)]
struct Machine {
    id: String,
    instance_id: String,
    state: String,
    image_ref: Image,
    config: Configuration,
}

#[derive(Deserialize)]
struct Image {
    digest: String,
}

#[derive(Deserialize)]
struct Configuration {
    image: String,
    mounts: Vec<Mount>,
}

#[derive(Deserialize)]
struct Mount {
    volume: String,
    path: String,
}

impl FlyClient {
    /// Explicit caller-supplied read credential only: no environment, Fly CLI,
    /// operator login or personal vault fallback. GraphQL endpoint overrides do
    /// not affect the fixed Machines endpoint. Never emits raw provider output.
    pub async fn verify_service_target(
        &self,
        target: &FlyServiceTarget,
    ) -> Result<FlyServiceTargetEvidence> {
        self.verify_service_target_at(target, MACHINES_API, TIMEOUT)
            .await
    }

    // Endpoint and short timeout injection are private to this implementation's
    // tests. There is no runtime option for an arbitrary provider/proxy endpoint.
    async fn verify_service_target_at(
        &self,
        target: &FlyServiceTarget,
        base: &str,
        timeout: Duration,
    ) -> Result<FlyServiceTargetEvidence> {
        target.validate(Utc::now().timestamp())?;
        if self.token.trim().is_empty() {
            bail!(DENIED);
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|_| anyhow::anyhow!(DENIED))?;
        let operation = async {
            let mut response = client
                .get(format!(
                    "{base}/apps/{}/machines/{}",
                    target.app, target.machine_id
                ))
                .bearer_auth(self.token.as_str())
                .send()
                .await?;
            if !response.status().is_success()
                || response
                    .content_length()
                    .is_some_and(|length| length > MAX_RESPONSE as u64)
            {
                bail!(DENIED);
            }
            // Preallocate once and erase raw provider bytes on every exit. Only
            // selected public identity fields survive deserialization; arbitrary
            // config environment, metadata and response bodies are never returned.
            let mut bytes = Zeroizing::new(vec![0_u8; MAX_RESPONSE]);
            let mut size = 0_usize;
            while let Some(chunk) = response.chunk().await? {
                if chunk.len() > MAX_RESPONSE - size {
                    bail!(DENIED);
                }
                bytes[size..size + chunk.len()].copy_from_slice(&chunk);
                size += chunk.len();
            }
            let machine: Machine = serde_json::from_slice(&bytes[..size])?;
            if machine.id != target.machine_id
                || machine.instance_id != target.instance_id
                || machine.state != "started"
                || machine.config.image != target.image
                || !target
                    .image
                    .ends_with(&format!("@{}", machine.image_ref.digest))
                || machine.config.mounts.len() != 1
                || machine.config.mounts[0].volume != target.volume_id
                || machine.config.mounts[0].path != "/var/lib/revvault"
            {
                bail!(DENIED);
            }
            let now = Utc::now().timestamp();
            target.validate(now)?;
            Ok::<_, anyhow::Error>(FlyServiceTargetEvidence {
                version: 1,
                target_sha256: target.digest()?,
                observed_at: now,
                // Evidence is short-lived even if the proposed plan lasts longer.
                expires_at: target.expires_at.min(now + 30),
                app: target.app.clone(),
                machine_id: target.machine_id.clone(),
                instance_id: target.instance_id.clone(),
                image: target.image.clone(),
                volume_id: target.volume_id.clone(),
                expected_service_uid: target.service_uid,
                expected_source_contract_sha256: target.source_contract_sha256.clone(),
                provider_configuration_matches: true,
                receiver_identity: "unverified",
                receiver_sources: "unverified",
                execution_fencing: "unverified",
                provisioning: "held",
            })
        };
        tokio::time::timeout(timeout, operation)
            .await
            .map_err(|_| anyhow::anyhow!(DENIED))?
            .map_err(|_| anyhow::anyhow!(DENIED))
    }
}

#[cfg(test)]
mod tests;
