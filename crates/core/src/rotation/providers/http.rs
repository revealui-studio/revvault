//! Generic HTTP rotation provider.
//!
//! Rotates any API key whose lifecycle can be driven by two HTTP endpoints:
//! one to create a new key and one to revoke the old key.
//!
//! # Rotation TOML example
//!
//! ```toml
//! [providers.vercel]
//! secret_path = "credentials/vercel/token"
//!
//! [providers.vercel.settings]
//! create_url    = "https://api.vercel.com/v3/user/tokens"
//! response_field = "token"
//! id_field      = "tokenId"
//! revoke_url    = "https://api.vercel.com/v2/user/tokens/{old_key_id}"
//! revoke_method = "DELETE"
//! ```
//!
//! # Available settings
//!
//! | Key | Required | Default | Description |
//! |-----|----------|---------|-------------|
//! | `create_url` | yes | — | Endpoint to POST (or PUT) for a new key |
//! | `response_field` | yes | — | Dot-path into JSON response to extract new key value (`"token"`, `"data.key"`) |
//! | `id_field` | no | — | Dot-path to extract new key ID for future revocations (`"id"`, `"tokenId"`) |
//! | `revoke_url` | no | — | Endpoint to revoke old key; supports `{old_key}` and `{old_key_id}` |
//! | `revoke_method` | no | `DELETE` | HTTP verb for revoke (`DELETE` \| `POST`) |
//! | `create_method` | no | `POST` | HTTP verb for create (`POST` \| `PUT`) |
//! | `create_body` | no | `{}` | JSON body for create; `{current_key}` is substituted |
//! | `auth_type` | no | `bearer` | `bearer` \| `header` \| `none` |
//! | `auth_header_name` | no | `X-Api-Key` | Header name when `auth_type = "header"` |

use std::collections::HashMap;

use async_trait::async_trait;
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

use crate::error::{Result, RevvaultError};
use crate::rotation::provider::{RotationOutcome, RotationProvider};

#[derive(Debug)]
enum AuthType {
    Bearer,
    Header,
    None,
}

#[derive(Debug)]
pub struct GenericHttpProvider {
    name: String,
    /// Current key value — read from the vault by the executor.
    current_key: SecretString,
    /// Key ID from the *previous* rotation — used in `{old_key_id}` revoke substitution.
    old_key_id: Option<String>,
    create_url: String,
    create_method: String,
    create_body: String,
    response_field: String,
    id_field: Option<String>,
    revoke_url: Option<String>,
    revoke_method: String,
    auth_type: AuthType,
    auth_header_name: String,
}

impl GenericHttpProvider {
    /// Build a provider from `ProviderConfig::settings`.
    ///
    /// `current_key` — decrypted value read from the vault.
    /// `old_key_id`  — ID stored from the previous rotation (may be absent for first run).
    pub fn from_config(
        name: String,
        current_key: SecretString,
        old_key_id: Option<String>,
        settings: &HashMap<String, String>,
    ) -> Result<Self> {
        let require = |key: &str| -> Result<String> {
            settings.get(key).cloned().ok_or_else(|| {
                RevvaultError::Other(anyhow::anyhow!(
                    "provider '{}': missing required setting '{}'",
                    name,
                    key
                ))
            })
        };

        let create_url = require("create_url")?;
        let response_field = require("response_field")?;

        let auth_type = match settings.get("auth_type").map(String::as_str) {
            Some("header") => AuthType::Header,
            Some("none") => AuthType::None,
            _ => AuthType::Bearer,
        };

        Ok(Self {
            name,
            current_key,
            old_key_id,
            create_url,
            create_method: settings
                .get("create_method")
                .cloned()
                .unwrap_or_else(|| "POST".into()),
            create_body: settings
                .get("create_body")
                .cloned()
                .unwrap_or_else(|| "{}".into()),
            response_field,
            id_field: settings.get("id_field").cloned(),
            revoke_url: settings.get("revoke_url").cloned(),
            revoke_method: settings
                .get("revoke_method")
                .cloned()
                .unwrap_or_else(|| "DELETE".into()),
            auth_type,
            auth_header_name: settings
                .get("auth_header_name")
                .cloned()
                .unwrap_or_else(|| "X-Api-Key".into()),
        })
    }

    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.auth_type {
            AuthType::Bearer => builder.bearer_auth(self.current_key.expose_secret()),
            AuthType::Header => {
                builder.header(&self.auth_header_name, self.current_key.expose_secret())
            }
            AuthType::None => builder,
        }
    }

    /// Walk a dot-separated path through a JSON value.
    fn extract_field<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
        let mut current = value;
        for segment in path.split('.') {
            current = current.get(segment)?;
        }
        Some(current)
    }

    fn rotation_failed(&self, reason: impl Into<String>) -> RevvaultError {
        RevvaultError::RotationFailed {
            provider: self.name.clone(),
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl RotationProvider for GenericHttpProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn preflight(&self) -> Result<()> {
        // Validate URLs parse without making any network requests.
        reqwest::Url::parse(&self.create_url).map_err(|e| {
            RevvaultError::Other(anyhow::anyhow!(
                "provider '{}': invalid create_url '{}': {e}",
                self.name,
                self.create_url
            ))
        })?;

        if let Some(ref url_template) = self.revoke_url {
            let url_clean = url_template
                .replace("{old_key}", "placeholder")
                .replace("{old_key_id}", "placeholder");
            reqwest::Url::parse(&url_clean).map_err(|e| {
                RevvaultError::Other(anyhow::anyhow!(
                    "provider '{}': invalid revoke_url '{}': {e}",
                    self.name,
                    url_template
                ))
            })?;
        }

        Ok(())
    }

    async fn dry_run(&self) -> Result<String> {
        let body = self.create_body.replace("{current_key}", "[current_key]");
        let mut steps = vec![
            format!("1. Read current key from vault (already loaded)"),
            format!(
                "2. {} {} with body: {}",
                self.create_method, self.create_url, body
            ),
            format!(
                "3. Extract new key from response field '{}'",
                self.response_field
            ),
        ];

        if let Some(ref f) = self.id_field {
            steps.push(format!("   Extract new key ID from field '{f}'"));
        }

        steps.push("4. Overwrite vault secret with new key".into());

        if let Some(ref url) = self.revoke_url {
            let old_id_status = match &self.old_key_id {
                Some(id) => format!("(old_key_id = {id})"),
                None => "(no old_key_id stored — first rotation, may not revoke)".into(),
            };
            steps.push(format!(
                "5. {} {} to revoke old key {old_id_status}",
                self.revoke_method, url
            ));
        } else {
            steps.push(
                "5. No revoke_url configured — old key will NOT be revoked automatically".into(),
            );
        }

        steps.push("6. Write entry to rotation-log.jsonl".into());

        Ok(steps.join("\n"))
    }

    async fn rotate(&self) -> Result<RotationOutcome> {
        let client = Client::new();

        // --- Step 1: Create new key ---
        let body = self
            .create_body
            .replace("{current_key}", self.current_key.expose_secret());

        let create_req = match self.create_method.to_uppercase().as_str() {
            "POST" => client.post(&self.create_url),
            "PUT" => client.put(&self.create_url),
            m => {
                return Err(self.rotation_failed(format!("unsupported create_method: {m}")));
            }
        };

        let response = self
            .apply_auth(create_req)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| self.rotation_failed(format!("create request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(self.rotation_failed(format!("create returned {status}: {text}")));
        }

        let json: Value = response
            .json()
            .await
            .map_err(|e| self.rotation_failed(format!("create response is not JSON: {e}")))?;

        let new_value = SecretString::from(
            Self::extract_field(&json, &self.response_field)
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    self.rotation_failed(format!(
                        "field '{}' not found or not a string in create response",
                        self.response_field
                    ))
                })?
                .to_string(),
        );

        let new_key_id = self.id_field.as_deref().and_then(|path| {
            Self::extract_field(&json, path).and_then(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| v.as_u64().map(|n| n.to_string()))
                    .or_else(|| v.as_i64().map(|n| n.to_string()))
            })
        });

        Ok(RotationOutcome::single(new_value, new_key_id))
    }

    async fn revoke_old(&self) -> Result<()> {
        let client = reqwest::Client::new();
        // --- Step 2: Revoke old key ---
        if let Some(ref url_template) = self.revoke_url {
            // Substitute {old_key} with the key value, {old_key_id} with the stored ID.
            let url = url_template
                .replace("{old_key}", self.current_key.expose_secret())
                .replace("{old_key_id}", self.old_key_id.as_deref().unwrap_or(""));

            let revoke_req = match self.revoke_method.to_uppercase().as_str() {
                "DELETE" => client.delete(&url),
                "POST" => client.post(&url),
                "PUT" => client.put(&url),
                m => {
                    return Err(self.rotation_failed(format!("unsupported revoke_method: {m}")));
                }
            };

            let resp = self
                .apply_auth(revoke_req)
                .send()
                .await
                .map_err(|e| self.rotation_failed(format!("revoke request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(self.rotation_failed(format!("revoke returned {status}: {text}")));
            }
        }

        Ok(())
    }
}
