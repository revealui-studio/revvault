//! Fly.io secrets sync client.
//!
//! Consumed by `revvault sync fly` (cli/src/commands/sync.rs) to push vault
//! secrets onto a Fly app. Mirrors [`super::vercel::VercelClient`] (transport +
//! 429 retry + DTOs); manifest deserialization stays in the cli crate.
//!
//! # Why this differs from the Vercel client
//!
//! Fly's API is **write-only for secret values**. The `app.secrets` query
//! returns only secret *names* + an opaque `digest` — never the value. So
//! unlike the Vercel flow, the sync diff cannot do value-equality MATCH
//! detection; it can only tell Add (name absent) from Set (name present).
//! [`FlyClient::set_secrets`] batches every managed secret into one
//! `setSecrets` mutation (= one Fly release) and passes `replaceAll: false`
//! so secrets not in the manifest are never deleted.
//!
//! # Transport boundary
//!
//! Reads may retry bounded 429 responses within one fixed whole-operation
//! deadline. Mutations are dispatched once, including on 429 or an uncertain
//! response. Provider bodies and parser/transport errors never cross the error
//! boundary. This generic sync client does not establish service provisioning
//! authority, custody, target acceptance or safe replay.
//!
//! Endpoint injection is retained for synthetic callers via `with_base_url`;
//! the service observation path independently uses its fixed Machines endpoint.

use std::time::Duration;

use anyhow::{bail, Result};
use reqwest::redirect::Policy;
use serde::{
    de::{DeserializeOwned, IgnoredAny},
    Deserialize, Serialize,
};
use zeroize::Zeroizing;

mod service;
pub use service::{FlyServiceTarget, FlyServiceTargetEvidence};

const DEFAULT_BASE_URL: &str = "https://api.fly.io/graphql";
const RETRY_BACKOFFS_MS: [u64; 3] = [100, 500, 2000];
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 1024 * 1024;
const MAX_REQUEST: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FlyTransportError {
    #[error("revvault_fly_request_denied")]
    RequestDenied,
    #[error("revvault_fly_observation_unverified")]
    ObservationUnverified,
    #[error("revvault_fly_mutation_outcome_unknown")]
    MutationOutcomeUnknown,
}

#[derive(Clone, Copy)]
enum Operation {
    Read,
    Mutation,
}

impl Operation {
    fn error(self) -> FlyTransportError {
        match self {
            Self::Read => FlyTransportError::ObservationUnverified,
            Self::Mutation => FlyTransportError::MutationOutcomeUnknown,
        }
    }
}

#[derive(Deserialize)]
struct GraphQlResponse<T> {
    data: Option<T>,
    // Ignore error contents while requiring the GraphQL array/null shape.
    // Deserialization never retains arbitrary error strings or config values.
    errors: Option<Vec<IgnoredAny>>,
}

#[derive(Deserialize)]
struct SecretsData {
    app: Option<SecretsApp>,
}
#[derive(Deserialize)]
struct SecretsApp {
    secrets: Vec<FlySecret>,
}
#[derive(Deserialize)]
struct MutationData {
    #[serde(rename = "setSecrets")]
    set_secrets: MutationPayload,
}
#[derive(Deserialize)]
struct MutationPayload {
    release: MutationRelease,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum MutationRelease {
    Released(Release),
    NoRelease(()),
}
#[derive(Deserialize)]
struct Release {
    id: String,
    version: i64,
}

// ── Fly API types ─────────────────────────────────────────────────────────

/// A secret as reported by Fly's `app.secrets` query — name + opaque digest.
/// Never carries a value (Fly does not expose secret values via the API).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlySecret {
    pub name: String,
    pub digest: Option<String>,
}

/// Outcome of a `setSecrets` mutation — the release it triggered, if any.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSecretsResult {
    pub release_id: Option<String>,
    pub release_version: Option<i64>,
}

// ── Client ────────────────────────────────────────────────────────────────

/// Thin async client over Fly's GraphQL secrets API.
///
/// Constructed via [`FlyClient::new`] for production use; tests use
/// [`FlyClient::with_base_url`] to point requests at a mock server.
pub struct FlyClient {
    token: Zeroizing<String>,
    base: String,
}

impl FlyClient {
    /// Construct a client with the production Fly GraphQL endpoint. `token` is
    /// a Fly API token (org token or app deploy token) — passed as a bearer.
    pub fn new(token: String) -> Self {
        Self {
            token: Zeroizing::new(token),
            base: DEFAULT_BASE_URL.to_string(),
        }
    }

    /// Override the GraphQL endpoint — used by tests to point the client at a
    /// mockito server.
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    async fn graphql<T: DeserializeOwned>(
        &self,
        query: &str,
        variables: serde_json::Value,
        operation: Operation,
    ) -> Result<T> {
        self.graphql_with_timeout(query, variables, operation, TIMEOUT)
            .await
    }

    // Only tests select a short deadline. No environment or runtime knob can
    // remove the production whole-operation bound, including retry/backoff.
    async fn graphql_with_timeout<T: DeserializeOwned>(
        &self,
        query: &str,
        variables: serde_json::Value,
        operation: Operation,
        timeout: Duration,
    ) -> Result<T> {
        if self.token.trim().is_empty() {
            bail!(FlyTransportError::RequestDenied);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|_| FlyTransportError::RequestDenied)?;
        let body = serde_json::json!({ "query": query, "variables": variables });
        // Serialize into a fixed buffer before dispatch; rejected requests do
        // not acquire an uncertain provider outcome. The HTTP-owned request
        // body remains subject to the transport library's normal lifetime.
        let mut serialized = Zeroizing::new(vec![0_u8; MAX_REQUEST]);
        let size = {
            let mut writer = std::io::Cursor::new(serialized.as_mut_slice());
            serde_json::to_writer(&mut writer, &body)
                .map_err(|_| FlyTransportError::RequestDenied)?;
            writer.position() as usize
        };
        let request = client
            .post(&self.base)
            .bearer_auth(self.token.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serialized[..size].to_vec())
            .build()
            .map_err(|_| FlyTransportError::RequestDenied)?;
        let work = async {
            let mut attempt = 0;
            let mut response = loop {
                let attempt_request = request.try_clone().ok_or_else(|| operation.error())?;
                let response = client.execute(attempt_request).await?;
                if matches!(operation, Operation::Read)
                    && response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                    && attempt < RETRY_BACKOFFS_MS.len()
                {
                    drop(response);
                    tokio::time::sleep(Duration::from_millis(RETRY_BACKOFFS_MS[attempt])).await;
                    attempt += 1;
                    continue;
                }
                break response;
            };
            if !response.status().is_success()
                || response
                    .content_length()
                    .is_some_and(|length| length > MAX_RESPONSE as u64)
            {
                bail!(operation.error());
            }
            // Fixed allocation, bounded chunks, erased raw body on every exit.
            let mut bytes = Zeroizing::new(vec![0_u8; MAX_RESPONSE]);
            let mut size = 0;
            while let Some(chunk) = response.chunk().await? {
                if chunk.len() > MAX_RESPONSE - size {
                    bail!(operation.error());
                }
                bytes[size..size + chunk.len()].copy_from_slice(&chunk);
                size += chunk.len();
            }
            let response: GraphQlResponse<T> = serde_json::from_slice(&bytes[..size])?;
            if response.errors.is_some_and(|errors| !errors.is_empty()) {
                bail!(operation.error());
            }
            let data = response.data.ok_or_else(|| operation.error())?;
            Ok::<T, anyhow::Error>(data)
        };
        tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| operation.error())?
            .map_err(|_| operation.error().into())
    }

    /// List the NAMES (+ opaque digests) of secrets set on a Fly app. Returns
    /// an empty vec when the app has no secrets; errors when the app is not
    /// found (wrong name or insufficient token scope).
    pub async fn list_secret_names(&self, app_name: &str) -> anyhow::Result<Vec<FlySecret>> {
        if app_name.len() > MAX_REQUEST {
            bail!(FlyTransportError::RequestDenied);
        }
        let query = r#"query($name: String!) { app(name: $name) { secrets { name digest } } }"#;
        let data: SecretsData = self
            .graphql(
                query,
                serde_json::json!({ "name": app_name }),
                Operation::Read,
            )
            .await?;
        Ok(data
            .app
            .ok_or(FlyTransportError::ObservationUnverified)?
            .secrets)
    }

    /// Set (create or update) secrets on a Fly app in one batched mutation,
    /// which triggers a single release. `replace_all = false` leaves secrets
    /// not in the batch untouched (no deletion) — orphan cleanup is never
    /// automatic, mirroring the Vercel client's no-delete policy.
    pub async fn set_secrets(
        &self,
        app_name: &str,
        secrets: &[(String, String)],
        replace_all: bool,
    ) -> anyhow::Result<SetSecretsResult> {
        let mut input_size = app_name.len();
        for (key, value) in secrets {
            input_size = input_size
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .and_then(|size| size.checked_add(64))
                .ok_or(FlyTransportError::RequestDenied)?;
            if input_size > MAX_REQUEST {
                bail!(FlyTransportError::RequestDenied);
            }
        }
        if input_size > MAX_REQUEST {
            bail!(FlyTransportError::RequestDenied);
        }
        let mutation = r#"mutation($input: SetSecretsInput!) { setSecrets(input: $input) { release { id version } } }"#;
        let secret_inputs: Vec<serde_json::Value> = secrets
            .iter()
            .map(|(k, v)| serde_json::json!({ "key": k, "value": v }))
            .collect();
        let variables = serde_json::json!({
            "input": {
                "appId": app_name,
                "secrets": secret_inputs,
                "replaceAll": replace_all,
            }
        });
        let data: MutationData = self
            .graphql(mutation, variables, Operation::Mutation)
            .await?;
        match data.set_secrets.release {
            MutationRelease::Released(release)
                if !release.id.is_empty()
                    && release.id.len() <= 256
                    && !release.id.chars().any(char::is_control)
                    && release.version >= 0 =>
            {
                Ok(SetSecretsResult {
                    release_id: Some(release.id),
                    release_version: Some(release.version),
                })
            }
            MutationRelease::NoRelease(()) => Ok(SetSecretsResult {
                release_id: None,
                release_version: None,
            }),
            _ => Err(FlyTransportError::MutationOutcomeUnknown.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn list_secret_names_parses_names_and_digests() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header("authorization", "Bearer tok")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"data":{"app":{"secrets":[{"name":"POSTGRES_URL","digest":"abc"},{"name":"REVEALUI_SECRET","digest":null}]}}}"#,
            )
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let secrets = client.list_secret_names("revealui-worker").await.unwrap();

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0].name, "POSTGRES_URL");
        assert_eq!(secrets[0].digest.as_deref(), Some("abc"));
        assert_eq!(secrets[1].name, "REVEALUI_SECRET");
        assert_eq!(secrets[1].digest, None);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_secret_names_empty_when_no_secrets() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"data":{"app":{"secrets":[]}}}"#)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let secrets = client.list_secret_names("revealui-worker").await.unwrap();
        assert!(secrets.is_empty());
    }

    #[tokio::test]
    async fn list_secret_names_errors_when_app_missing() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"data":{"app":null}}"#)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let err = client.list_secret_names("nope").await.unwrap_err();
        assert_eq!(err.to_string(), "revvault_fly_observation_unverified");
    }

    #[tokio::test]
    async fn set_secrets_sends_batched_input_and_parses_release() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header("authorization", "Bearer tok")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "variables": {
                    "input": {
                        "appId": "revealui-worker",
                        "replaceAll": false,
                        "secrets": [ { "key": "POSTGRES_URL", "value": "postgres://x" } ],
                    }
                }
            })))
            .with_status(200)
            .with_body(r#"{"data":{"setSecrets":{"release":{"id":"rel_1","version":7}}}}"#)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let res = client
            .set_secrets(
                "revealui-worker",
                &[("POSTGRES_URL".to_string(), "postgres://x".to_string())],
                false,
            )
            .await
            .unwrap();

        assert_eq!(res.release_id.as_deref(), Some("rel_1"));
        assert_eq!(res.release_version, Some(7));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn graphql_errors_surface_as_err() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"errors":[{"message":"Unauthorized"}]}"#)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let err = client.list_secret_names("x").await.unwrap_err();
        assert_eq!(err.to_string(), "revvault_fly_observation_unverified");
    }

    #[tokio::test]
    async fn retries_on_429_then_succeeds() {
        let mut server = mockito::Server::new_async().await;
        let m429 = server
            .mock("POST", "/")
            .with_status(429)
            .with_body("{}")
            .expect(2)
            .create_async()
            .await;
        let m200 = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"data":{"app":{"secrets":[]}}}"#)
            .expect(1)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        client.list_secret_names("p").await.unwrap();

        m429.assert_async().await;
        m200.assert_async().await;
    }

    #[tokio::test]
    async fn non_429_error_surfaces_without_retry() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("boom")
            .expect(1)
            .create_async()
            .await;

        let client = FlyClient::new("tok".into()).with_base_url(server.url());
        let err = client.list_secret_names("p").await.unwrap_err();
        assert_eq!(err.to_string(), "revvault_fly_observation_unverified");
        m.assert_async().await;
    }
    async fn mutate(client: &FlyClient) -> Result<SetSecretsResult> {
        client
            .set_secrets(
                "revealfleet-transport-fixture",
                &[("KEY".into(), "synthetic-private-value".into())],
                false,
            )
            .await
    }

    fn assert_closed(error: anyhow::Error, expected: &str) {
        assert_eq!(error.to_string(), expected);
        assert_eq!(format!("{error:#}"), expected);
        assert!(!format!("{error:?}").contains("synthetic-private"));
        assert!(error.downcast_ref::<FlyTransportError>().is_some());
    }

    #[tokio::test]
    async fn mutation_errors_never_retry_or_relay_provider_bodies() {
        for status in [401, 403, 429, 500, 503] {
            let mut server = mockito::Server::new_async().await;
            let request = server
                .mock("POST", "/")
                .with_status(status)
                .with_body("synthetic-private-provider-error")
                .expect(1)
                .create_async()
                .await;
            assert_closed(
                mutate(&FlyClient::new("synthetic-token".into()).with_base_url(server.url()))
                    .await
                    .unwrap_err(),
                "revvault_fly_mutation_outcome_unknown",
            );
            request.assert_async().await;
        }
    }

    #[tokio::test]
    async fn malformed_or_missing_mutation_acknowledgements_remain_unknown() {
        for body in [
            r#"{"errors":[{"message":"synthetic-private-value"}],"data":{"setSecrets":{"release":null}}}"#,
            r#"{"errors":"synthetic-private-errors","data":{"setSecrets":{"release":null}}}"#,
            r#"{"data":null}"#,
            r#"{"data":{}}"#,
            r#"{"data":{"setSecrets":null}}"#,
            r#"{"data":{"setSecrets":{}}}"#,
            r#"{"data":{"setSecrets":{"release":{}}}}"#,
            r#"{"data":{"setSecrets":{"release":{"id":"synthetic-private-id","version":"synthetic-private-version"}}}}"#,
            r#"{"data":{"setSecrets":{"release":{"id":"","version":7}}}}"#,
            r#"{"data":{"setSecrets":{"release":{"id":"rel_1","version":-1}}}}"#,
            "synthetic-private-invalid-json",
        ] {
            let mut server = mockito::Server::new_async().await;
            let request = server
                .mock("POST", "/")
                .with_status(200)
                .with_body(body)
                .expect(1)
                .create_async()
                .await;
            assert_closed(
                mutate(&FlyClient::new("synthetic-token".into()).with_base_url(server.url()))
                    .await
                    .unwrap_err(),
                "revvault_fly_mutation_outcome_unknown",
            );
            request.assert_async().await;
        }
    }

    #[tokio::test]
    async fn explicit_null_release_is_an_acknowledgement_without_release_provenance() {
        let mut server = mockito::Server::new_async().await;
        let request = server.mock("POST", "/").with_status(200)
            .with_body(r#"{"data":{"setSecrets":{"release":null}},"errors":[],"extensions":{"ignored":"synthetic-private-extension"}}"#)
            .expect(1).create_async().await;
        let result = mutate(&FlyClient::new("synthetic-token".into()).with_base_url(server.url()))
            .await
            .unwrap();
        assert!(result.release_id.is_none() && result.release_version.is_none());
        request.assert_async().await;
    }

    #[tokio::test]
    async fn missing_or_malformed_credentials_are_denied_before_dispatch() {
        let mut server = mockito::Server::new_async().await;
        let no_request = server.mock("POST", "/").expect(0).create_async().await;
        for token in ["", " ", "synthetic-private-token\ninvalid"] {
            let client = FlyClient::new(token.into()).with_base_url(server.url());
            assert_closed(
                mutate(&client).await.unwrap_err(),
                "revvault_fly_request_denied",
            );
            assert_closed(
                client.list_secret_names("fixture").await.unwrap_err(),
                "revvault_fly_request_denied",
            );
        }
        assert_closed(
            mutate(&FlyClient::new("synthetic-token".into()).with_base_url("not a URL"))
                .await
                .unwrap_err(),
            "revvault_fly_request_denied",
        );
        no_request.assert_async().await;
    }

    #[tokio::test]
    async fn raw_and_escaped_request_overflow_are_denied_before_dispatch() {
        let mut server = mockito::Server::new_async().await;
        let no_request = server.mock("POST", "/").expect(0).create_async().await;
        let client = FlyClient::new("synthetic-token".into()).with_base_url(server.url());
        for value in [
            "x".repeat(MAX_REQUEST + 1),
            "\u{0001}".repeat(MAX_REQUEST / 3),
        ] {
            assert_closed(
                client
                    .set_secrets("fixture", &[("KEY".into(), value)], false)
                    .await
                    .unwrap_err(),
                "revvault_fly_request_denied",
            );
        }
        no_request.assert_async().await;
    }

    #[tokio::test]
    async fn redirects_cannot_forward_a_read_or_mutation() {
        let mut server = mockito::Server::new_async().await;
        let request = server
            .mock("POST", "/")
            .with_status(307)
            .with_header("location", "/must-not-follow")
            .expect(2)
            .create_async()
            .await;
        let no_redirect = server
            .mock("POST", "/must-not-follow")
            .expect(0)
            .create_async()
            .await;
        let client = FlyClient::new("synthetic-token".into()).with_base_url(server.url());
        assert_closed(
            mutate(&client).await.unwrap_err(),
            "revvault_fly_mutation_outcome_unknown",
        );
        assert_closed(
            client.list_secret_names("fixture").await.unwrap_err(),
            "revvault_fly_observation_unverified",
        );
        request.assert_async().await;
        no_redirect.assert_async().await;
    }

    #[tokio::test]
    async fn declared_and_streamed_response_overflow_remain_closed() {
        for chunked in [false, true] {
            let mut server = mockito::Server::new_async().await;
            let mock = server.mock("POST", "/").with_status(200).expect(2);
            let mock = if chunked {
                mock.with_chunked_body(|writer| {
                    let body = serde_json::json!({"data":{"setSecrets":{"release":null},"app":{"secrets":[]}},"ignored":"x".repeat(MAX_RESPONSE)}).to_string();
                    let _ = writer.write_all(body.as_bytes());
                    Ok(())
                })
            } else {
                mock.with_body(serde_json::json!({"data":{"setSecrets":{"release":null},"app":{"secrets":[]}},"ignored":"x".repeat(MAX_RESPONSE)}).to_string())
            };
            let request = mock.create_async().await;
            let client = FlyClient::new("synthetic-token".into()).with_base_url(server.url());
            assert_closed(
                mutate(&client).await.unwrap_err(),
                "revvault_fly_mutation_outcome_unknown",
            );
            assert_closed(
                client.list_secret_names("fixture").await.unwrap_err(),
                "revvault_fly_observation_unverified",
            );
            request.assert_async().await;
        }
    }

    #[tokio::test]
    async fn streaming_deadline_does_not_authorize_mutation_replay() {
        for operation in [Operation::Read, Operation::Mutation] {
            use std::io::{Read, Write};
            use std::sync::mpsc;
            // An owned server avoids pooled mock servers whose previous
            // blocking body callbacks can postpone accepting this request.
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let (observed_tx, observed_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let server = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(3);
                let (mut socket, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline);
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("synthetic listener failed: {error}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut headers = Vec::new();
                let mut byte = [0];
                while !headers.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                    assert!(headers.len() < 8192);
                }
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{",
                    )
                    .unwrap();
                socket.flush().unwrap();
                observed_tx.send(()).unwrap();
                let _ = release_rx.recv_timeout(Duration::from_secs(3));
            });
            let client = FlyClient::new("synthetic-token".into()).with_base_url(url);
            let started = std::time::Instant::now();
            let error = client
                .graphql_with_timeout::<SecretsData>(
                    "synthetic-query",
                    serde_json::json!({}),
                    operation,
                    Duration::from_millis(500),
                )
                .await
                .err()
                .unwrap();
            assert_closed(error, &operation.error().to_string());
            assert!(started.elapsed() < Duration::from_millis(1500));
            let observed = observed_rx.recv_timeout(Duration::from_secs(1));
            let _ = release_tx.send(());
            server.join().unwrap();
            observed.expect("timeout must follow an observed dispatched request");
        }
    }

    #[tokio::test]
    async fn read_retry_backoff_has_one_operation_deadline() {
        let mut server = mockito::Server::new_async().await;
        let request = server
            .mock("POST", "/")
            .with_status(429)
            .expect(2)
            .create_async()
            .await;
        let client = FlyClient::new("synthetic-token".into()).with_base_url(server.url());
        let started = std::time::Instant::now();
        let error = client
            .graphql_with_timeout::<SecretsData>(
                "synthetic-query",
                serde_json::json!({}),
                Operation::Read,
                Duration::from_millis(400),
            )
            .await
            .err()
            .unwrap();
        assert_closed(error, "revvault_fly_observation_unverified");
        assert!(started.elapsed() < Duration::from_millis(1500));
        request.assert_async().await;
    }
}
