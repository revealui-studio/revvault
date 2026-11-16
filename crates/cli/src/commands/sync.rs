use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Context};
use chrono::Utc;
use clap::Args;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use revvault_core::sync::fly::FlyClient;
use revvault_core::sync::shape::{self, Shape};
use revvault_core::sync::vercel::{
    ensure_key_snapshot, select_env_var, EnvVarType, VercelClient, VercelEnvVar,
};
use revvault_core::{Config, PassageStore};

// ── CLI args ────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct SyncArgs {
    /// Target to sync with: "vercel" or "fly"
    pub target: String,

    /// Path to the sync manifest (default: revvault-vercel.toml)
    #[arg(long, default_value = "revvault-vercel.toml")]
    pub manifest: PathBuf,

    /// Apply changes (default is dry-run)
    #[arg(long)]
    pub apply: bool,

    /// API token for the target (or set VERCEL_TOKEN / FLY_API_TOKEN env var)
    #[arg(long)]
    pub token: Option<String>,

    /// Only sync these manifest project slugs (Vercel) or fly-app names (Fly).
    /// Repeatable. GAP-339: reduces unscoped whole-manifest blast radius.
    #[arg(long = "project", value_name = "SLUG")]
    pub projects: Vec<String>,

    /// Only sync these env var / secret names (UPPER_SNAKE). Repeatable.
    /// GAP-339: per-key apply so license private key is never bulk-rewritten
    /// by accident alongside an unrelated rotation.
    #[arg(long = "key", value_name = "ENV_VAR")]
    pub keys: Vec<String>,
}

// ── TOML manifest schema ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SyncManifest {
    /// Vercel team ID or slug (optional for personal accounts)
    team_id: Option<String>,
    /// Map of project slug → project sync config
    #[serde(default)]
    projects: HashMap<String, ProjectSync>,
}

#[derive(Debug, Deserialize)]
struct ProjectSync {
    /// Vercel project ID
    project_id: String,
    /// Vault path prefix for this project's secrets (e.g., "revealui/vercel/admin")
    vault_prefix: String,
    /// Environment targets: production, preview, development
    #[serde(default = "default_targets")]
    targets: Vec<String>,
    /// Scope every var CREATED under this project to a single preview git
    /// branch (e.g. `"staging"`), so it is only exposed to that branch's
    /// preview deployments rather than every branch's previews. Requires
    /// `targets` to include `"preview"`; `create_env_var` enforces that and
    /// fails loudly otherwise. Updates select this exact branch scope and
    /// preserve the existing row's branch and classification.
    #[serde(default)]
    git_branch: Option<String>,
    /// Skip these env var names (integration-managed, etc.)
    #[serde(default)]
    skip: Vec<String>,
    /// Per-var path + optional shape / sensitivity overrides.
    ///
    /// Supports two TOML forms for backwards compatibility:
    ///
    /// Bare string (path only; shape defaults to `any`, sensitive to `false`):
    /// ```toml
    /// [projects.api.vars]
    /// POSTGRES_URL = "revealui/prod/db/postgres-url"
    /// ```
    ///
    /// Inline table (path + optional `shape` + optional `sensitive`):
    /// ```toml
    /// [projects.api.vars]
    /// POSTGRES_URL      = { path = "revealui/prod/db/postgres-url", shape = "postgres-url" }
    /// STRIPE_SECRET_KEY = { path = "revealui/prod/stripe/secret-key", shape = "stripe-key-live-only", sensitive = true }
    /// ```
    ///
    /// `sensitive = true` requests Vercel type `sensitive` when this var is
    /// CREATED: requests Secret protection. Production/Preview values are
    /// unavailable to pulls; Development Secret values may be returned by the
    /// API. Use it for credentials (Stripe keys, webhook secrets,
    /// signing/JWT secrets). Updates preserve an
    /// existing row's type, so flipping an existing `encrypted` row still
    /// requires a separately reviewed type-transition lifecycle (the diff flags
    /// that drift). Independent
    /// of the marker, a create also requests `sensitive` whenever any
    /// existing remote row with the same key is sensitive or carries legacy
    /// `secret` intent. Legacy intent alone does not verify current protection.
    #[serde(default)]
    vars: HashMap<String, VarEntry>,
}

/// A per-var entry in `[projects.<slug>.vars]`.
///
/// `#[serde(untagged)]` makes TOML bare strings parse as `Path(String)`
/// while inline tables parse as `VarObject`. Existing manifests that use
/// bare strings keep working unchanged.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VarEntry {
    /// Bare string — path only; shape defaults to `Shape::Any`, sensitive
    /// to `false`.
    Path(String),
    /// Inline table — path + optional shape + optional sensitive marker.
    Object(VarObject),
}

/// Inline-table form of a var entry: `{ path = "...", shape = "...",
/// sensitive = true }`. `shape` defaults to `any`; `sensitive` defaults to
/// `false`.
///
/// Unknown keys are rejected so a typo'd `sensitive` marker fails the
/// parse loudly instead of silently leaving a credential downgradable.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VarObject {
    path: String,
    #[serde(default = "default_shape")]
    shape: Shape,
    #[serde(default)]
    sensitive: bool,
    /// Explicit ownership of this key's project-row target set. Defaults to
    /// value-only updates; branch and custom scopes are never rewritten.
    #[serde(default)]
    manage_targets: bool,
}

fn default_shape() -> Shape {
    Shape::Any
}

impl VarEntry {
    fn path(&self) -> &str {
        match self {
            Self::Path(p) => p,
            Self::Object(o) => &o.path,
        }
    }

    fn shape(&self) -> Shape {
        match self {
            Self::Path(_) => Shape::Any,
            Self::Object(o) => o.shape,
        }
    }

    /// True when the inline table sets `sensitive = true`.
    fn sensitive(&self) -> bool {
        match self {
            Self::Path(_) => false,
            Self::Object(o) => o.sensitive,
        }
    }
}

impl ProjectSync {
    fn manages_targets(&self, key: &str) -> bool {
        matches!(self.vars.get(key), Some(VarEntry::Object(o)) if o.manage_targets)
    }

    /// Resolve the vault path + declared shape for a given Vercel var name.
    /// Returns the override if one is set in `vars`, otherwise the
    /// prefix-derived default with `Shape::Any`.
    fn vault_path_for(&self, var_name: &str) -> (String, Shape) {
        match self.vars.get(var_name) {
            Some(entry) => (entry.path().to_string(), entry.shape()),
            None => (format!("{}/{}", self.vault_prefix, var_name), Shape::Any),
        }
    }

    /// True when the manifest marks this var `sensitive = true`.
    fn sensitive_for(&self, var_name: &str) -> bool {
        self.vars.get(var_name).is_some_and(|e| e.sensitive())
    }
}

fn default_targets() -> Vec<String> {
    vec![
        "production".to_string(),
        "preview".to_string(),
        "development".to_string(),
    ]
}

// ── Fly manifest schema ───────────────────────────────────────────────────────
//
// Fly secrets are app-scoped (no per-environment "targets") and the API never
// returns secret *values* — only names + an opaque digest. So the Fly manifest
// is app-centric and lists an explicit curated set of secrets (no prefix-scan:
// we never want to push every secret under a prefix onto a worker app).

#[derive(Debug, Deserialize)]
struct FlyManifest {
    /// Map of logical name → Fly app sync config (TOML `[fly-apps.<name>]`).
    #[serde(default, rename = "fly-apps")]
    fly_apps: HashMap<String, FlyAppSync>,
}

#[derive(Debug, Deserialize)]
struct FlyAppSync {
    /// Fly app name (used as the GraphQL `appId`).
    app: String,
    /// Secret names this sync intentionally never touches.
    #[serde(default)]
    skip: Vec<String>,
    /// Secret name → vault path (+ optional shape), reusing [`VarEntry`].
    /// Every managed secret must be listed — there is no prefix fallback.
    #[serde(default)]
    vars: HashMap<String, VarEntry>,
}

impl FlyAppSync {
    /// Resolve the vault path + declared shape for a Fly secret name, or
    /// `None` when the name is not declared in `vars`.
    fn vault_path_for(&self, var_name: &str) -> Option<(String, Shape)> {
        self.vars
            .get(var_name)
            .map(|entry| (entry.path().to_string(), entry.shape()))
    }
}

// ── Diff engine ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
enum DiffAction {
    Add,
    Update,
    Match,
    Orphan,
    Skip,
    DropShape,
}

#[derive(Debug, Serialize)]
struct DiffEntry {
    key: String,
    action: DiffAction,
    reason: Option<String>,
}

// ── Audit log ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AuditEntry {
    timestamp: String,
    /// One of: "create", "update", "match", "drop-shape", "skip"
    action: String,
    project: String,
    key: String,
    /// Shape category of the vault value (e.g. "postgres-url", "stripe-key",
    /// "vercel-envelope", "empty"). Never the value itself.
    value_shape: String,
    /// "ok" | "failed"
    result: String,
    /// Vercel env-var type requested on create (`encrypted` | `sensitive`).
    /// `None` for non-create actions.
    #[serde(skip_serializing_if = "Option::is_none")]
    var_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_scope: Option<ScopeReceipt>,
}

#[derive(Serialize)]
struct ScopeReceipt {
    row_id: String,
    targets_before: Vec<String>,
    targets_after: Vec<String>,
    git_branch: Option<String>,
    var_type: Option<String>,
    visibility: Option<String>,
}

impl ScopeReceipt {
    fn updated(row: &VercelEnvVar, targets: &[String]) -> Self {
        Self {
            row_id: row.id.clone().expect("selector validates IDs"),
            targets_before: row.target.clone(),
            targets_after: targets.to_vec(),
            git_branch: row.git_branch.clone(),
            var_type: row.var_type.clone(),
            visibility: row.visibility.clone(),
        }
    }
}

/// Append one JSONL row to the audit log inside the synced store's
/// `.revvault/` directory.
fn append_audit_log(store: &PassageStore, entry: &AuditEntry) -> anyhow::Result<()> {
    let log_path = store.store_dir().join(".revvault/rotation-log.jsonl");
    revvault_core::service::assert_personal_path(&log_path)?;
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    writeln!(file, "{}", serde_json::to_string(entry)?)?;
    Ok(())
}

// ── Main runner ─────────────────────────────────────────────────────────────

pub async fn run(args: SyncArgs, json_output: bool) -> anyhow::Result<()> {
    match args.target.as_str() {
        "vercel" => run_vercel(args, json_output).await,
        "fly" => run_fly(args, json_output).await,
        other => bail!("Unknown sync target '{}'. Supported: vercel, fly", other),
    }
}

async fn run_vercel(args: SyncArgs, json_output: bool) -> anyhow::Result<()> {
    let token = args
        .token
        .or_else(|| std::env::var("VERCEL_TOKEN").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("VERCEL_TOKEN not set. Pass --token or set VERCEL_TOKEN env var")
        })?;

    let manifest_content = fs::read_to_string(&args.manifest)
        .with_context(|| format!("Cannot read manifest: {}", args.manifest.display()))?;
    let manifest: SyncManifest =
        toml::from_str(&manifest_content).context("Invalid manifest TOML")?;

    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    let client = VercelClient::new(token, manifest.team_id.clone());

    push_mode(
        &store,
        &client,
        &manifest,
        args.apply,
        json_output,
        &args.projects,
        &args.keys,
    )
    .await
}

async fn run_fly(args: SyncArgs, json_output: bool) -> anyhow::Result<()> {
    let token = args
        .token
        .or_else(|| std::env::var("FLY_API_TOKEN").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("FLY_API_TOKEN not set. Pass --token or set FLY_API_TOKEN env var")
        })?;

    let manifest_content = fs::read_to_string(&args.manifest)
        .with_context(|| format!("Cannot read manifest: {}", args.manifest.display()))?;
    let manifest: FlyManifest =
        toml::from_str(&manifest_content).context("Invalid Fly manifest TOML")?;
    validate_fly_manifest(&manifest, &args.manifest)?;

    let config = Config::resolve()?;
    let store = PassageStore::open(config)?;
    let client = FlyClient::new(token);

    push_mode_fly(
        &store,
        &client,
        &manifest,
        args.apply,
        json_output,
        &args.projects,
        &args.keys,
    )
    .await
}

/// Reject a Fly manifest that declares no `[fly-apps.<name>]` entries.
///
/// `FlyManifest` ignores unknown fields and `fly_apps` defaults to empty, so
/// pointing `sync fly` at a non-Fly manifest — e.g. the default Vercel manifest
/// (`revvault-vercel.toml`) — would otherwise deserialize cleanly and sync
/// nothing, silently skipping expected rotation under `--apply`. Surface that
/// mis-targeting as a loud error instead.
fn validate_fly_manifest(manifest: &FlyManifest, path: &std::path::Path) -> anyhow::Result<()> {
    if manifest.fly_apps.is_empty() {
        anyhow::bail!(
            "No [fly-apps.<name>] entries found in {}. `sync fly` requires a Fly manifest; the default manifest is the Vercel manifest (revvault-vercel.toml). Pass --manifest <fly-manifest> or add a [fly-apps.<name>] section.",
            path.display()
        );
    }
    Ok(())
}

// ── Push mode: sync vault to Vercel ─────────────────────────────────────────

/// Vercel type for a CREATE. `sensitive` is one-way: requested by the
/// manifest marker or preserved from any existing remote row of the same
/// key (a credential that is `sensitive` anywhere must never be re-created
/// as a revealable type). There is no downgrade path.
fn create_type_for(manifest_sensitive: bool, remote_sensitive: bool) -> EnvVarType {
    if manifest_sensitive || remote_sensitive {
        EnvVarType::Sensitive
    } else {
        EnvVarType::Encrypted
    }
}

/// Diff annotation when the manifest wants `sensitive` but the remote row
/// has some other type. Updates PATCH value-only — the type is preserved,
/// never changed, so this drift needs the separately tracked type-transition
/// lifecycle to resolve. `None` when there is no drift.
fn type_drift_reason(manifest_sensitive: bool, remote_type: Option<&str>) -> Option<String> {
    if !manifest_sensitive || remote_type == Some("sensitive") {
        return None;
    }
    Some(format!(
        "type drift: manifest wants sensitive, remote is {} — updates preserve type; supported type transition remains tracked debt",
        remote_type.unwrap_or("unknown")
    ))
}

struct VercelProjectPlan<'a> {
    project_name: &'a String,
    project_cfg: &'a ProjectSync,
    remote_vars: Vec<VercelEnvVar>,
    managed_keys: Vec<&'a str>,
    planned_rows: HashMap<String, VercelEnvVar>,
    planned_values: HashMap<String, SecretString>,
    unchanged_values: std::collections::HashSet<String>,
    remote_sensitive: std::collections::HashSet<String>,
    diff: Vec<DiffEntry>,
}

async fn push_mode(
    store: &PassageStore,
    client: &VercelClient,
    manifest: &SyncManifest,
    apply: bool,
    json_output: bool,
    project_filter: &[String],
    key_filter: &[String],
) -> anyhow::Result<()> {
    let project_filter_set: std::collections::HashSet<&str> =
        project_filter.iter().map(|s| s.as_str()).collect();
    let key_filter_set: std::collections::HashSet<&str> =
        key_filter.iter().map(|s| s.as_str()).collect();

    let mut plans = Vec::new();
    let mut projects: Vec<_> = manifest.projects.iter().collect();
    projects.sort_by_key(|(name, _)| *name);
    for (project_name, project_cfg) in projects {
        if !project_filter_set.is_empty() && !project_filter_set.contains(project_name.as_str()) {
            if !json_output {
                eprintln!("skip project {} (--project filter)", project_name);
            }
            continue;
        }
        let remote_vars = client.list_env_vars(&project_cfg.project_id).await?;

        let decrypted = client
            .list_env_vars_with_values(&project_cfg.project_id)
            .await?;
        let managed_keys: Vec<&str> = project_cfg
            .vars
            .keys()
            .filter(|key| {
                project_cfg.manages_targets(key)
                    && !project_cfg.skip.contains(key)
                    && (key_filter_set.is_empty() || key_filter_set.contains(key.as_str()))
            })
            .map(String::as_str)
            .collect();
        client
            .ensure_no_shared_keys(&project_cfg.project_id, &managed_keys)
            .await?;
        let mut planned_rows: HashMap<String, VercelEnvVar> = HashMap::new();
        let mut planned_values = HashMap::new();
        let mut unchanged_values = std::collections::HashSet::new();

        // Remote rows of ANY target that are Vercel type `sensitive`, by
        // key. Deliberately NOT filtered by the synced targets: when the
        // only surviving rows for a credential sit on other targets, a
        // create on the synced target must still come back `sensitive`.
        let remote_sensitive: std::collections::HashSet<String> = remote_vars
            .iter()
            .filter(|v| v.requires_sensitive_create())
            .map(|v| v.key.clone())
            .collect();

        // Build the union of vars to sync: explicit overrides + everything
        // under the project's vault_prefix.
        let mut vault_var_names: Vec<String> = Vec::new();
        for var_name in project_cfg.vars.keys() {
            vault_var_names.push(var_name.clone());
        }
        let prefix_secrets = store.list(Some(&project_cfg.vault_prefix))?;
        for entry in &prefix_secrets {
            let var_name = entry
                .path
                .strip_prefix(&format!("{}/", project_cfg.vault_prefix))
                .unwrap_or(&entry.path)
                .to_string();
            if !project_cfg.vars.contains_key(&var_name) {
                vault_var_names.push(var_name);
            }
        }

        vault_var_names.sort();
        vault_var_names.dedup();
        let mut diff: Vec<DiffEntry> = Vec::new();

        // Compare vault → remote
        for var_name in &vault_var_names {
            if project_cfg.skip.contains(var_name) {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::Skip,
                    reason: Some("in skip list".to_string()),
                });
                continue;
            }

            // GAP-339: optional per-key filter (reduces --apply blast radius)
            if !key_filter_set.is_empty() && !key_filter_set.contains(var_name.as_str()) {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::Skip,
                    reason: Some("outside --key filter".to_string()),
                });
                continue;
            }

            let (vault_path, declared_shape) = project_cfg.vault_path_for(var_name);

            // Read and validate the vault value before deciding the diff action.
            let vault_value = store.get(&vault_path).map_err(|_| anyhow::anyhow!(
                "Cannot read vault source for selected key '{var_name}' in project '{project_name}'; no selected plan can apply"
            ))?;

            let raw_value = vault_value.expose_secret();
            let violation = shape::check(raw_value, declared_shape).err();

            if let Some(ref v) = violation {
                if project_cfg.manages_targets(var_name) {
                    bail!("Invalid vault source for managed key '{var_name}' in project '{project_name}': {v}; no selected plan can apply");
                }
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::DropShape,
                    reason: Some(format!("shape violation: {v}")),
                });
                continue;
            }

            if let Some(remote) = select_env_var(
                &remote_vars,
                var_name,
                &project_cfg.targets,
                project_cfg.git_branch.as_deref(),
                project_cfg.manages_targets(var_name),
            )? {
                planned_rows.insert(var_name.clone(), remote.clone());
                // Surface (but never auto-fix) manifest-vs-remote type drift.
                let drift = if remote.is_sensitive() {
                    None
                } else {
                    type_drift_reason(
                        project_cfg.sensitive_for(var_name),
                        remote.var_type.as_deref(),
                    )
                };

                let decrypted_row = decrypted
                    .as_ref()
                    .map(|rows| {
                        ensure_key_snapshot(&remote_vars, rows, var_name)?;
                        let matches: Vec<_> = rows.iter().filter(|r| r.id == remote.id).collect();
                        if matches.len() > 1 {
                            bail!("Duplicate decrypted row ID for '{var_name}'");
                        }
                        if let Some(row) = matches.first() {
                            if !remote.same_scope(row) {
                                bail!("Decrypted metadata changed for '{var_name}'");
                            }
                        }
                        Ok(matches.first().copied())
                    })
                    .transpose()?
                    .flatten();
                let targets_changed = project_cfg.manages_targets(var_name)
                    && !remote.has_targets(&project_cfg.targets);
                let value_matches = decrypted_row
                    // This row came from the explicit decrypt=true request and
                    // passed the ID/scope join above. The response flag is optional;
                    // an explicit denial or malformed flag defeats equality proof.
                    .filter(|row| {
                        matches!(
                            row.metadata.get("decrypted"),
                            None | Some(serde_json::Value::Bool(true))
                        )
                    })
                    .and_then(|r| r.value.as_deref())
                    .is_some_and(|value| value == raw_value);
                if value_matches {
                    unchanged_values.insert(var_name.clone());
                }
                let is_match = !targets_changed && value_matches;
                let drift = if targets_changed {
                    Some(format!(
                        "row {} targets {:?} -> {:?}{}",
                        remote.id.as_deref().unwrap_or_default(),
                        remote.target,
                        project_cfg.targets,
                        drift.map(|d| format!("; {d}")).unwrap_or_default()
                    ))
                } else {
                    drift
                };

                if is_match {
                    diff.push(DiffEntry {
                        key: var_name.clone(),
                        action: DiffAction::Match,
                        reason: drift,
                    });
                } else {
                    diff.push(DiffEntry {
                        key: var_name.clone(),
                        action: DiffAction::Update,
                        reason: drift,
                    });
                }
            } else {
                let reason = match create_type_for(
                    project_cfg.sensitive_for(var_name),
                    remote_sensitive.contains(var_name),
                ) {
                    EnvVarType::Sensitive => Some("create as type=sensitive".to_string()),
                    EnvVarType::Encrypted => None,
                };
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::Add,
                    reason,
                });
            }
            planned_values.insert(var_name.clone(), vault_value);
        }

        // Detect orphans (in Vercel but not in vault).
        let mut seen_orphans: std::collections::HashSet<String> = std::collections::HashSet::new();
        for remote_var in remote_vars.iter().filter(|r| {
            r.git_branch == project_cfg.git_branch
                && r.custom_environment_ids.is_empty()
                && r.target.iter().any(|t| project_cfg.targets.contains(t))
        }) {
            if project_cfg.skip.contains(&remote_var.key) {
                continue;
            }
            if remote_var.configuration_id.is_some() {
                continue;
            }
            if !vault_var_names.contains(&remote_var.key) && !seen_orphans.contains(&remote_var.key)
            {
                // Scoped --key mode: only report the keys the operator asked about.
                if !key_filter_set.is_empty() && !key_filter_set.contains(remote_var.key.as_str()) {
                    continue;
                }
                seen_orphans.insert(remote_var.key.clone());
                diff.push(DiffEntry {
                    key: remote_var.key.clone(),
                    action: DiffAction::Orphan,
                    reason: Some("in Vercel but not in vault".to_string()),
                });
            }
        }

        // Output diff
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "project": project_name,
                    "mode": "push",
                    "dry_run": !apply,
                    "diff": diff,
                    "rows": planned_rows.iter().map(|(key, row)| serde_json::json!({
                        "key": key, "id": row.id, "targets_before": row.target,
                        "targets_after": if project_cfg.manages_targets(key) { &project_cfg.targets } else { &row.target },
                        "git_branch": row.git_branch,
                    })).collect::<Vec<_>>(),
                })
            );
        } else {
            println!(
                "\n\x1b[1m{}\x1b[0m (push{})",
                project_name,
                if apply { "" } else { " — dry-run" }
            );
            for entry in &diff {
                let (symbol, color) = match entry.action {
                    DiffAction::Add => ("+", "\x1b[32m"),
                    DiffAction::Update => ("~", "\x1b[33m"),
                    DiffAction::Match => ("=", "\x1b[90m"),
                    DiffAction::Orphan => ("!", "\x1b[31m"),
                    DiffAction::Skip => ("-", "\x1b[90m"),
                    DiffAction::DropShape => ("✗", "\x1b[31m"),
                };
                let reason = entry
                    .reason
                    .as_deref()
                    .map(|r| format!(" ({})", r))
                    .unwrap_or_default();
                println!("  {}{}\x1b[0m {}{}", color, symbol, entry.key, reason);
            }
        }

        plans.push(VercelProjectPlan {
            project_name,
            project_cfg,
            remote_vars,
            managed_keys,
            planned_rows,
            planned_values,
            unchanged_values,
            remote_sensitive,
            diff,
        });
    }

    // Multiple manifest entries may describe disjoint branches or targets,
    // but no immutable row or overlapping ownership may have two intents.
    let mut owned_ids = std::collections::HashSet::new();
    let mut ownership: Vec<(&ProjectSync, &str)> = Vec::new();
    for plan in &plans {
        for entry in &plan.diff {
            if !matches!(
                entry.action,
                DiffAction::Add | DiffAction::Update | DiffAction::Match
            ) {
                continue;
            }
            if let Some(id) = plan
                .planned_rows
                .get(&entry.key)
                .and_then(|r| r.id.as_deref())
            {
                if !owned_ids.insert(id) {
                    bail!("Multiple selected plans target remote row '{id}'");
                }
            }
            for (other, key) in &ownership {
                if other.project_id == plan.project_cfg.project_id
                    && *key == entry.key
                    && other.git_branch == plan.project_cfg.git_branch
                    && (other.manages_targets(key)
                        || plan.project_cfg.manages_targets(&entry.key)
                        || other
                            .targets
                            .iter()
                            .any(|t| plan.project_cfg.targets.contains(t)))
                {
                    bail!("Conflicting selected ownership for '{}'", entry.key);
                }
            }
            ownership.push((plan.project_cfg, &entry.key));
        }
    }

    // No project mutates until every selected project has a valid saved plan
    // and all selected scopes have passed a fresh metadata preflight.
    if apply {
        for plan in &plans {
            let fresh = client.list_env_vars(&plan.project_cfg.project_id).await?;
            client
                .ensure_no_shared_keys(&plan.project_cfg.project_id, &plan.managed_keys)
                .await?;
            for entry in &plan.diff {
                if matches!(
                    entry.action,
                    DiffAction::Add | DiffAction::Update | DiffAction::Match
                ) {
                    ensure_key_snapshot(&plan.remote_vars, &fresh, &entry.key)?;
                }
            }
        }
        let applied = async {
        // Only verified same-key receipts advance the saved expected metadata.
        // Unrelated keys from post-write reads never enter this baseline.
        let mut verified_rows: HashMap<(String, String), Vec<VercelEnvVar>> = HashMap::new();
        for plan in plans {
            let VercelProjectPlan {
                project_name,
                project_cfg,
                mut remote_vars,
                managed_keys: _,
                planned_rows,
                planned_values,
                unchanged_values,
                remote_sensitive,
                diff,
            } = plan;
            for ((project_id, key), rows) in &verified_rows {
                if project_id == &project_cfg.project_id {
                    remote_vars.retain(|row| &row.key != key);
                    remote_vars.extend(rows.iter().cloned());
                }
            }
            for entry in &diff {
                if matches!(entry.action, DiffAction::Add | DiffAction::Update) {
                    let fresh = client.list_env_vars(&project_cfg.project_id).await?;
                    ensure_key_snapshot(&remote_vars, &fresh, &entry.key)?;
                    if project_cfg.manages_targets(&entry.key) {
                        client
                            .ensure_no_shared_keys(&project_cfg.project_id, &[&entry.key])
                            .await?;
                    }
                }
                let (vault_path, declared_shape) = project_cfg.vault_path_for(&entry.key);
                match entry.action {
                    DiffAction::Add => {
                        let secret = planned_values
                            .get(&entry.key)
                            .context("Validated plan value missing")?;
                        let raw = secret.expose_secret();

                        // Shape guard (should already be DROP'd in diff, but be defensive)
                        if let Err(v) = shape::check(raw, declared_shape) {
                            let _ = append_audit_log(
                                store,
                                &AuditEntry {
                                    verified_scope: None,
                                    timestamp: Utc::now().to_rfc3339(),
                                    action: "drop-shape".to_string(),
                                    project: project_name.clone(),
                                    key: entry.key.clone(),
                                    value_shape: shape::classify(raw),
                                    result: "failed".to_string(),
                                    var_type: None,
                                    error: Some(v.to_string()),
                                },
                            );
                            continue;
                        }

                        let var_type = create_type_for(
                            project_cfg.sensitive_for(&entry.key),
                            remote_sensitive.contains(&entry.key),
                        );
                        client
                            .create_env_var(
                                &project_cfg.project_id,
                                &entry.key,
                                raw,
                                &project_cfg.targets,
                                var_type,
                                project_cfg.git_branch.as_deref(),
                            )
                            .await?;
                        let created = client.verify_create(&project_cfg.project_id, &remote_vars,
                            &entry.key, &project_cfg.targets, project_cfg.git_branch.as_deref(),
                            var_type).await?;
                        if project_cfg.manages_targets(&entry.key) {
                            client.ensure_no_shared_keys(&project_cfg.project_id, &[&entry.key]).await?;
                        }
                        let mut rows: Vec<_> = remote_vars.iter().filter(|row| row.key == entry.key).cloned().collect();
                        rows.push(created.clone());
                        verified_rows.insert((project_cfg.project_id.clone(), entry.key.clone()), rows);
                        let mut receipt = ScopeReceipt::updated(&created, &project_cfg.targets);
                        receipt.targets_before.clear();
                        let verified_scope = Some(receipt);
                        append_audit_log(
                            store,
                            &AuditEntry {
                                verified_scope,
                                timestamp: Utc::now().to_rfc3339(),
                                action: "create".to_string(),
                                project: project_name.clone(),
                                key: entry.key.clone(),
                                value_shape: shape::classify(raw),
                                result: "ok".to_string(),
                                var_type: Some(var_type.as_str().to_string()),
                                error: None,
                            },
                        ).context("Remote create completed but audit persistence failed; review a fresh sync plan")?;
                    }
                    DiffAction::Update => {
                        let secret = planned_values
                            .get(&entry.key)
                            .context("Validated plan value missing")?;
                        let raw = secret.expose_secret();

                        if let Err(v) = shape::check(raw, declared_shape) {
                            let _ = append_audit_log(
                                store,
                                &AuditEntry {
                                    verified_scope: None,
                                    timestamp: Utc::now().to_rfc3339(),
                                    action: "drop-shape".to_string(),
                                    project: project_name.clone(),
                                    key: entry.key.clone(),
                                    value_shape: shape::classify(raw),
                                    result: "failed".to_string(),
                                    var_type: None,
                                    error: Some(v.to_string()),
                                },
                            );
                            continue;
                        }

                        let remote = planned_rows.get(&entry.key).context("Planned update row missing")?;
                        let id = remote.id.as_deref().context("Planned update ID missing")?;
                        let changed_targets = (project_cfg.manages_targets(&entry.key)
                            && !remote.has_targets(&project_cfg.targets))
                            .then_some(project_cfg.targets.as_slice());
                                client
                                    .update_env_var(
                                        &project_cfg.project_id,
                                        id,
                                        (!unchanged_values.contains(&entry.key)).then_some(raw),
                                        changed_targets,
                                    )
                                    .await?;
                                let rows = client
                                    .verify_update(
                                        &project_cfg.project_id,
                                        &remote_vars,
                                        remote,
                                        changed_targets,
                                    )
                                    .await?;
                                if project_cfg.manages_targets(&entry.key) {
                                    client
                                        .ensure_no_shared_keys(
                                            &project_cfg.project_id,
                                            &[&entry.key],
                                        )
                                        .await?;
                                }
                                verified_rows.insert((project_cfg.project_id.clone(), entry.key.clone()), rows);
                                append_audit_log(
                                    store,
                                    &AuditEntry {
                                    verified_scope: Some(ScopeReceipt::updated(remote,
                                            if project_cfg.manages_targets(&entry.key) { &project_cfg.targets } else { &remote.target })),
                                        timestamp: Utc::now().to_rfc3339(),
                                        action: "update".to_string(),
                                        project: project_name.clone(),
                                        key: entry.key.clone(),
                                        value_shape: shape::classify(raw),
                                        result: "ok".to_string(),
                                        var_type: None,
                                        error: None,
                                    },
                                ).context("Remote update verified but audit persistence failed; review a fresh sync plan")?;
                    }
                    DiffAction::Match => {
                        let secret = planned_values
                            .get(&entry.key)
                            .context("Validated plan value missing")?;
                        let raw = secret.expose_secret();
                        let _ = append_audit_log(
                            store,
                            &AuditEntry {
                                verified_scope: None,
                                timestamp: Utc::now().to_rfc3339(),
                                action: "match".to_string(),
                                project: project_name.clone(),
                                key: entry.key.clone(),
                                value_shape: shape::classify(raw),
                                result: "ok".to_string(),
                                var_type: None,
                                error: None,
                            },
                        );
                    }
                    DiffAction::DropShape => {
                        if !json_output {
                            eprintln!(
                                "  \x1b[31m✗\x1b[0m DROP {}: {}",
                                entry.key,
                                entry.reason.as_deref().unwrap_or("")
                            );
                        }
                        if let Ok(secret) = store.get(&vault_path) {
                            let raw = secret.expose_secret();
                            let _ = append_audit_log(
                                store,
                                &AuditEntry {
                                    verified_scope: None,
                                    timestamp: Utc::now().to_rfc3339(),
                                    action: "drop-shape".to_string(),
                                    project: project_name.clone(),
                                    key: entry.key.clone(),
                                    value_shape: shape::classify(raw),
                                    result: "failed".to_string(),
                                    var_type: None,
                                    error: entry.reason.clone(),
                                },
                            );
                        }
                    }
                    DiffAction::Orphan => {
                        if !json_output {
                            println!(
                                "  \x1b[31m⚠\x1b[0m  Orphan: {} (retained; supported removal lifecycle remains tracked debt)",
                                entry.key
                            );
                        }
                    }
                    DiffAction::Skip => {}
                }
            }

            let applied = diff
                .iter()
                .filter(|e| matches!(e.action, DiffAction::Add | DiffAction::Update))
                .count();
            if !json_output {
                println!("  {} changes applied", applied);
            }
        }
        anyhow::Ok(())
        }.await;
        applied.context("Sync apply halted; previous verified writes may already have completed. Review the existing success audit receipts and rerun the normal planner for a fresh plan before applying again")?;
    }

    Ok(())
}

// ── Push mode (Fly): batch vault → Fly setSecrets ────────────────────────────
//
// Fly hides secret values, so there is no value-equality MATCH: a present name
// is an Update (re-set), an absent one an Add. All shape-valid secrets are
// batched into ONE `setSecrets` call (= one Fly release). `replace_all=false`
// means secrets not in the manifest are never deleted — orphans are surfaced
// only, mirroring the Vercel client's no-delete policy.

async fn push_mode_fly(
    store: &PassageStore,
    client: &FlyClient,
    manifest: &FlyManifest,
    apply: bool,
    json_output: bool,
    project_filter: &[String],
    key_filter: &[String],
) -> anyhow::Result<()> {
    let project_filter_set: std::collections::HashSet<&str> =
        project_filter.iter().map(|s| s.as_str()).collect();
    let key_filter_set: std::collections::HashSet<&str> =
        key_filter.iter().map(|s| s.as_str()).collect();

    if manifest
        .fly_apps
        .values()
        .flat_map(|app| app.vars.values())
        .any(|entry| matches!(entry, VarEntry::Object(o) if o.manage_targets))
    {
        bail!("manage_targets is supported only for Vercel project variables");
    }

    for (logical_name, app_cfg) in &manifest.fly_apps {
        if !project_filter_set.is_empty() && !project_filter_set.contains(logical_name.as_str()) {
            if !json_output {
                eprintln!("skip fly-app {} (--project filter)", logical_name);
            }
            continue;
        }
        let remote = client.list_secret_names(&app_cfg.app).await?;
        let remote_names: std::collections::HashSet<String> =
            remote.into_iter().map(|s| s.name).collect();

        let mut diff: Vec<DiffEntry> = Vec::new();
        // (key, raw_value) pairs to push in one batched setSecrets on --apply.
        let mut batch: Vec<(String, String)> = Vec::new();

        for var_name in app_cfg.vars.keys() {
            if app_cfg.skip.contains(var_name) {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::Skip,
                    reason: Some("in skip list".to_string()),
                });
                continue;
            }

            if !key_filter_set.is_empty() && !key_filter_set.contains(var_name.as_str()) {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::Skip,
                    reason: Some("outside --key filter".to_string()),
                });
                continue;
            }

            let (vault_path, declared_shape) = match app_cfg.vault_path_for(var_name) {
                Some(v) => v,
                None => continue, // unreachable: var_name came from vars.keys()
            };

            let vault_value = match store.get(&vault_path) {
                Ok(s) => s,
                Err(e) => {
                    if !json_output {
                        eprintln!(
                            "  \x1b[31m✗\x1b[0m {} — cannot read vault path {}: {}",
                            var_name, vault_path, e
                        );
                    }
                    continue;
                }
            };
            let raw_value = vault_value.expose_secret();

            if let Some(v) = shape::check(raw_value, declared_shape).err() {
                diff.push(DiffEntry {
                    key: var_name.clone(),
                    action: DiffAction::DropShape,
                    reason: Some(format!("shape violation: {v}")),
                });
                continue;
            }

            diff.push(DiffEntry {
                key: var_name.clone(),
                action: if remote_names.contains(var_name) {
                    DiffAction::Update
                } else {
                    DiffAction::Add
                },
                reason: None,
            });
            batch.push((var_name.clone(), raw_value.to_string()));
        }

        // Orphans: set on Fly but not in the manifest (never auto-deleted).
        for name in &remote_names {
            if app_cfg.skip.contains(name) || app_cfg.vars.contains_key(name) {
                continue;
            }
            diff.push(DiffEntry {
                key: name.clone(),
                action: DiffAction::Orphan,
                reason: Some("set on Fly but not in manifest".to_string()),
            });
        }

        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "app": app_cfg.app,
                    "logical": logical_name,
                    "mode": "push-fly",
                    "dry_run": !apply,
                    "diff": diff,
                })
            );
        } else {
            println!(
                "\n\x1b[1m{}\x1b[0m → Fly app \x1b[1m{}\x1b[0m (push{})",
                logical_name,
                app_cfg.app,
                if apply { "" } else { " — dry-run" }
            );
            for entry in &diff {
                let (symbol, color) = match entry.action {
                    DiffAction::Add => ("+", "\x1b[32m"),
                    DiffAction::Update => ("~", "\x1b[33m"),
                    DiffAction::Match => ("=", "\x1b[90m"),
                    DiffAction::Orphan => ("!", "\x1b[31m"),
                    DiffAction::Skip => ("-", "\x1b[90m"),
                    DiffAction::DropShape => ("✗", "\x1b[31m"),
                };
                let reason = entry
                    .reason
                    .as_deref()
                    .map(|r| format!(" ({})", r))
                    .unwrap_or_default();
                println!("  {}{}\x1b[0m {}{}", color, symbol, entry.key, reason);
            }
        }

        // Apply: one batched setSecrets call = one Fly release.
        if apply {
            if batch.is_empty() {
                if !json_output {
                    println!("  no secrets to set");
                }
            } else {
                let result = client
                    .set_secrets(&app_cfg.app, &batch, false)
                    .await
                    .with_context(|| format!("setSecrets failed for Fly app '{}'", app_cfg.app))?;
                for (key, raw) in &batch {
                    let _ = append_audit_log(
                        store,
                        &AuditEntry {
                            verified_scope: None,
                            timestamp: Utc::now().to_rfc3339(),
                            action: "set-fly".to_string(),
                            project: app_cfg.app.clone(),
                            key: key.clone(),
                            value_shape: shape::classify(raw),
                            result: "ok".to_string(),
                            var_type: None,
                            error: None,
                        },
                    );
                }
                if !json_output {
                    match result.release_version {
                        Some(v) => println!("  {} secrets set — Fly release v{}", batch.len(), v),
                        None => println!("  {} secrets set", batch.len()),
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed_project(keys: &[&str], manage: bool) -> ProjectSync {
        ProjectSync {
            project_id: "p".into(),
            vault_prefix: "test/discovery-empty".into(),
            targets: vec!["production".into()],
            git_branch: None,
            skip: vec![],
            vars: keys
                .iter()
                .map(|key| {
                    (
                        key.to_string(),
                        VarEntry::Object(VarObject {
                            path: format!("test/managed/{key}"),
                            shape: Shape::Any,
                            sensitive: false,
                            manage_targets: manage,
                        }),
                    )
                })
                .collect(),
        }
    }

    async fn mock_inventory(
        server: &mut mockito::ServerGuard,
        state: &std::sync::Arc<std::sync::Mutex<serde_json::Value>>,
    ) -> Vec<mockito::Mock> {
        let plain = state.clone();
        let decrypted = state.clone();
        vec![
            server
                .mock("GET", "/v10/projects/p/env")
                .with_status(200)
                .with_body_from_request(move |_| {
                    serde_json::json!({"envs": *plain.lock().unwrap()})
                        .to_string()
                        .into_bytes()
                })
                .expect_at_least(1)
                .create_async()
                .await,
            server
                .mock("GET", "/v10/projects/p/env?decrypt=true")
                .with_status(200)
                .with_body_from_request(move |_| {
                    serde_json::json!({"envs": *decrypted.lock().unwrap()})
                        .to_string()
                        .into_bytes()
                })
                .expect_at_least(1)
                .create_async()
                .await,
            server
                .mock("GET", "/v1/env?projectId=p")
                .with_status(200)
                .with_body(r#"{"data":[],"pagination":{"next":null}}"#)
                .expect_at_least(0)
                .create_async()
                .await,
        ]
    }

    fn remote_row(key: &str, id: &str, targets: &[&str]) -> serde_json::Value {
        serde_json::json!({"id":id, "key":key, "target":targets,
            "type":"encrypted", "value":"same", "comment":"preserve"})
    }

    #[test]
    fn managed_targets_is_explicit_and_rejects_typos() {
        let manifest: SyncManifest = toml::from_str(
            r#"
            [projects.api]
            project_id = "p"
            vault_prefix = "test"
            [projects.api.vars]
            A = "test/a"
            B = { path = "test/b" }
            C = { path = "test/c", manage_targets = true }
        "#,
        )
        .unwrap();
        let project = &manifest.projects["api"];
        assert!(!project.manages_targets("A"));
        assert!(!project.manages_targets("B"));
        assert!(project.manages_targets("C"));
        assert!(toml::from_str::<VarEntry>(
            r#"path = "test/c"
            manage_target = true"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn managed_target_drift_applies_with_unchanged_value_including_preview_only() {
        for targets in [vec!["production", "preview"], vec!["preview"]] {
            let (_dir, store) = setup_temp_store();
            store.upsert("test/managed/KEY", b"same").unwrap();
            let mut server = mockito::Server::new_async().await;
            let mut branch = remote_row("KEY", "branch", &["preview"]);
            branch["gitBranch"] = "staging".into();
            let mut custom = remote_row("KEY", "custom", &[]);
            custom["customEnvironmentIds"] = serde_json::json!(["env_custom"]);
            let state = std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!([
                remote_row("KEY", "e1", &targets),
                branch,
                custom,
                remote_row("UNMANAGED", "other", &["preview"])
            ])));
            let preserved = state.lock().unwrap().as_array().unwrap()[1..].to_vec();
            let mocks = mock_inventory(&mut server, &state).await;
            let changed = state.clone();
            let patch = server
                .mock("PATCH", "/v9/projects/p/env/e1")
                .match_body(mockito::Matcher::Json(
                    serde_json::json!({"target":["production"]}),
                ))
                .with_status(200)
                .with_body_from_request(move |_| {
                    changed.lock().unwrap()[0]["target"] = serde_json::json!(["production"]);
                    b"{}".to_vec()
                })
                .expect(1)
                .create_async()
                .await;
            let manifest = single_project_manifest(managed_project(&["KEY"], true));
            let client = VercelClient::new("t".into(), None).with_base_url(server.url());
            // Dry-run displays drift but neither changes metadata nor sends PATCH.
            push_mode(&store, &client, &manifest, false, true, &[], &[])
                .await
                .unwrap();
            assert_eq!(
                state.lock().unwrap()[0]["target"],
                serde_json::json!(targets)
            );
            assert!(!patch.matched_async().await);
            push_mode(&store, &client, &manifest, true, true, &[], &[])
                .await
                .unwrap();
            assert_eq!(
                state.lock().unwrap()[0]["target"],
                serde_json::json!(["production"])
            );
            assert_eq!(state.lock().unwrap().as_array().unwrap()[1..], preserved);
            // Same value and targets are now a match; normal rerun is idempotent.
            push_mode(&store, &client, &manifest, true, true, &[], &[])
                .await
                .unwrap();
            patch.assert_async().await;
            for mock in mocks {
                mock.assert_async().await;
            }
        }
    }

    #[tokio::test]
    async fn decryption_proof_controls_exact_patch_fields() {
        for proof in [
            None,
            Some(serde_json::json!(true)),
            Some(serde_json::json!(false)),
            Some(serde_json::Value::Null),
            Some(serde_json::json!("true")),
            Some(serde_json::json!(1)),
        ] {
            for targets_changed in [false, true] {
                let (_dir, store) = setup_temp_store();
                store.upsert("test/managed/KEY", b"same").unwrap();
                let mut server = mockito::Server::new_async().await;
                let targets = if targets_changed {
                    vec!["production", "preview"]
                } else {
                    vec!["production"]
                };
                let state =
                    std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!([remote_row(
                        "KEY", "e1", &targets
                    )])));
                let mocks = mock_inventory(&mut server, &state).await;
                mocks[1].remove_async().await;
                let mut decrypted = state.lock().unwrap()[0].clone();
                if let Some(flag) = &proof {
                    decrypted["decrypted"] = flag.clone();
                }
                let decrypt = server
                    .mock("GET", "/v10/projects/p/env?decrypt=true")
                    .with_status(200)
                    .with_body(serde_json::json!({"envs":[decrypted]}).to_string())
                    .expect(1)
                    .create_async()
                    .await;
                let value_proven = matches!(proof, None | Some(serde_json::Value::Bool(true)));
                let mut expected = serde_json::json!({});
                if !value_proven {
                    expected["value"] = "same".into();
                }
                if targets_changed {
                    expected["target"] = serde_json::json!(["production"]);
                }
                let changed = state.clone();
                let patch = server
                    .mock("PATCH", "/v9/projects/p/env/e1")
                    .match_body(mockito::Matcher::Json(expected))
                    .with_status(200)
                    .with_body_from_request(move |_| {
                        changed.lock().unwrap()[0]["target"] = serde_json::json!(["production"]);
                        b"{}".to_vec()
                    })
                    .expect(usize::from(targets_changed || !value_proven))
                    .create_async()
                    .await;
                let manifest = single_project_manifest(managed_project(&["KEY"], true));
                let client = VercelClient::new("t".into(), None).with_base_url(server.url());
                push_mode(&store, &client, &manifest, true, true, &[], &[])
                    .await
                    .unwrap();
                decrypt.assert_async().await;
                patch.assert_async().await;
            }
        }
    }

    #[tokio::test]
    async fn unmanaged_targets_and_filters_never_shrink_remote_scope() {
        let (_dir, store) = setup_temp_store();
        store.upsert("test/managed/KEY", b"new").unwrap();
        let mut server = mockito::Server::new_async().await;
        let state = std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!([remote_row(
            "KEY",
            "e1",
            &["preview", "production"]
        )])));
        let _mocks = mock_inventory(&mut server, &state).await;
        let patch = server
            .mock("PATCH", "/v9/projects/p/env/e1")
            .match_body(mockito::Matcher::Json(serde_json::json!({"value":"new"})))
            .with_status(200)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;
        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        let manifest = single_project_manifest(managed_project(&["KEY"], false));
        push_mode(
            &store,
            &client,
            &manifest,
            true,
            true,
            &["different".into()],
            &[],
        )
        .await
        .unwrap();
        push_mode(
            &store,
            &client,
            &manifest,
            true,
            true,
            &[],
            &["different".into()],
        )
        .await
        .unwrap();
        assert!(!patch.matched_async().await);
        push_mode(&store, &client, &manifest, true, true, &[], &[])
            .await
            .unwrap();
        patch.assert_async().await;
        assert_eq!(
            state.lock().unwrap()[0]["target"],
            serde_json::json!(["preview", "production"])
        );
    }

    #[tokio::test]
    async fn partial_apply_recovers_through_normal_planner_without_rewriting_completed_key() {
        let (_dir, store) = setup_temp_store();
        for key in ["A", "B"] {
            store
                .upsert(&format!("test/managed/{key}"), b"same")
                .unwrap();
        }
        let mut server = mockito::Server::new_async().await;
        let state = std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!([
            remote_row("A", "a", &["production", "preview"]),
            remote_row("B", "b", &["preview"])
        ])));
        let _mocks = mock_inventory(&mut server, &state).await;
        let changed = state.clone();
        let first = server
            .mock("PATCH", "/v9/projects/p/env/a")
            .with_status(200)
            .with_body_from_request(move |_| {
                changed.lock().unwrap()[0]["target"] = serde_json::json!(["production"]);
                b"{}".to_vec()
            })
            .expect(1)
            .create_async()
            .await;
        let failed = server
            .mock("PATCH", "/v9/projects/p/env/b")
            .with_status(500)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;
        let manifest = single_project_manifest(managed_project(&["A", "B"], true));
        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        let error = push_mode(&store, &client, &manifest, true, true, &[], &[])
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("previous verified writes may already have completed"));
        assert!(error.to_string().contains("rerun the normal planner"));
        assert!(format!("{error:#}").contains("500"));
        let audit = std::fs::read_to_string(store.store_dir().join(".revvault/rotation-log.jsonl"))
            .unwrap();
        let receipt: serde_json::Value =
            serde_json::from_str(audit.lines().last().unwrap()).unwrap();
        assert_eq!(receipt["key"], "A");
        assert_eq!(receipt["verified_scope"]["row_id"], "a");
        first.assert_async().await;
        failed.assert_async().await;
        failed.remove_async().await;
        let changed = state.clone();
        let retry = server
            .mock("PATCH", "/v9/projects/p/env/b")
            .with_status(200)
            .with_body_from_request(move |_| {
                changed.lock().unwrap()[1]["target"] = serde_json::json!(["production"]);
                b"{}".to_vec()
            })
            .expect(1)
            .create_async()
            .await;
        push_mode(&store, &client, &manifest, true, true, &[], &[])
            .await
            .unwrap();
        first.assert_async().await;
        retry.assert_async().await;
    }

    #[tokio::test]
    async fn duplicate_scope_and_preflight_race_fail_before_any_write() {
        for race in [false, true] {
            let (_dir, store) = setup_temp_store();
            store.upsert("test/managed/KEY", b"same").unwrap();
            let mut server = mockito::Server::new_async().await;
            let original = remote_row("KEY", "e1", &["production", "preview"]);
            let mut rows = vec![original.clone()];
            if !race {
                rows.push(remote_row("KEY", "e2", &["preview"]));
            }
            let state = std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!(rows)));
            let mocks = mock_inventory(&mut server, &state).await;
            if race {
                mocks[1].remove_async().await;
                // The decryption fetch observes the planned row, then an external
                // writer moves its branch before the preflight metadata read.
                let changed = state.clone();
                server
                    .mock("GET", "/v10/projects/p/env?decrypt=true")
                    .with_status(200)
                    .with_body_from_request(move |_| {
                        changed.lock().unwrap()[0]["gitBranch"] = "other".into();
                        serde_json::json!({"envs":[original.clone()]})
                            .to_string()
                            .into_bytes()
                    })
                    .create_async()
                    .await;
            }
            let patch = server
                .mock("PATCH", "/v9/projects/p/env/e1")
                .expect(0)
                .create_async()
                .await;
            let create = server
                .mock("POST", "/v10/projects/p/env")
                .expect(0)
                .create_async()
                .await;
            let manifest = single_project_manifest(managed_project(&["KEY"], true));
            let client = VercelClient::new("t".into(), None).with_base_url(server.url());
            assert!(push_mode(&store, &client, &manifest, true, true, &[], &[])
                .await
                .is_err());
            patch.assert_async().await;
            create.assert_async().await;
        }
    }

    #[tokio::test]
    async fn decrypted_value_is_joined_by_row_id_and_read_failures_surface() {
        for decrypt_failure in [false, true] {
            let (_dir, store) = setup_temp_store();
            store.upsert("test/managed/KEY", b"same").unwrap();
            let mut server = mockito::Server::new_async().await;
            let mut ordinary = remote_row("KEY", "e1", &["production"]);
            ordinary["value"] = "old".into();
            let mut custom = remote_row("KEY", "custom", &["production"]);
            custom["customEnvironmentIds"] = serde_json::json!(["custom"]);
            let state =
                std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!([ordinary, custom])));
            let mocks = mock_inventory(&mut server, &state).await;
            if decrypt_failure {
                mocks[1].remove_async().await;
                server
                    .mock("GET", "/v10/projects/p/env?decrypt=true")
                    .with_status(500)
                    .with_body("{}")
                    .expect(1)
                    .create_async()
                    .await;
            }
            let patch = server
                .mock("PATCH", "/v9/projects/p/env/e1")
                .match_body(mockito::Matcher::Json(serde_json::json!({"value":"same"})))
                .with_status(200)
                .with_body("{}")
                .expect(if decrypt_failure { 0 } else { 1 })
                .create_async()
                .await;
            let wrong = server
                .mock("PATCH", "/v9/projects/p/env/custom")
                .expect(0)
                .create_async()
                .await;
            let client = VercelClient::new("t".into(), None).with_base_url(server.url());
            let manifest = single_project_manifest(managed_project(&["KEY"], false));
            let result = push_mode(&store, &client, &manifest, true, true, &[], &[]).await;
            assert_eq!(result.is_err(), decrypt_failure);
            patch.assert_async().await;
            wrong.assert_async().await;
        }
    }

    #[tokio::test]
    async fn later_project_ambiguity_prevents_earlier_project_write() {
        let (_dir, store) = setup_temp_store();
        for key in ["A", "B"] {
            store
                .upsert(&format!("test/managed/{key}"), b"same")
                .unwrap();
        }
        let mut server = mockito::Server::new_async().await;
        let state = std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!([remote_row(
            "A",
            "a",
            &["production", "preview"]
        )])));
        let _mocks = mock_inventory(&mut server, &state).await;
        let duplicate = serde_json::json!({"envs":[remote_row("B", "b1", &["preview"]), remote_row("B", "b2", &["production"])]}).to_string();
        for path in ["/v10/projects/q/env", "/v10/projects/q/env?decrypt=true"] {
            server
                .mock("GET", path)
                .with_status(200)
                .with_body(&duplicate)
                .create_async()
                .await;
        }
        server
            .mock("GET", "/v1/env?projectId=q")
            .with_status(200)
            .with_body(r#"{"data":[],"pagination":{"next":null}}"#)
            .create_async()
            .await;
        let first = managed_project(&["A"], true);
        let mut second = managed_project(&["B"], true);
        second.project_id = "q".into();
        let manifest = SyncManifest {
            team_id: None,
            projects: HashMap::from([("a".into(), first), ("b".into(), second)]),
        };
        let patch = server
            .mock("PATCH", "/v9/projects/p/env/a")
            .expect(0)
            .create_async()
            .await;
        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        assert!(push_mode(&store, &client, &manifest, true, true, &[], &[])
            .await
            .is_err());
        patch.assert_async().await;
    }

    #[tokio::test]
    async fn managed_create_verifies_new_id_and_writes_metadata_receipt() {
        let (_dir, store) = setup_temp_store();
        store.upsert("test/managed/KEY", b"same").unwrap();
        let mut server = mockito::Server::new_async().await;
        let state = std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!([])));
        let _mocks = mock_inventory(&mut server, &state).await;
        let changed = state.clone();
        let create = server
            .mock("POST", "/v10/projects/p/env")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "key":"KEY", "value":"same", "target":["production"], "type":"sensitive"
            })))
            .with_status(201)
            .with_body_from_request(move |_| {
                let mut row = remote_row("KEY", "created", &["production"]);
                row["type"] = "sensitive".into();
                *changed.lock().unwrap() = serde_json::json!([row]);
                b"{}".to_vec()
            })
            .expect(1)
            .create_async()
            .await;
        let mut project = managed_project(&["KEY"], true);
        if let Some(VarEntry::Object(entry)) = project.vars.get_mut("KEY") {
            entry.sensitive = true;
        }
        let manifest = single_project_manifest(project);
        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        push_mode(&store, &client, &manifest, true, true, &[], &[])
            .await
            .unwrap();
        create.assert_async().await;
        let audit = std::fs::read_to_string(store.store_dir().join(".revvault/rotation-log.jsonl"))
            .unwrap();
        let receipt: serde_json::Value =
            serde_json::from_str(audit.lines().last().unwrap()).unwrap();
        assert_eq!(receipt["verified_scope"]["row_id"], "created");
        assert_eq!(
            receipt["verified_scope"]["targets_after"],
            serde_json::json!(["production"])
        );
        assert_eq!(receipt["verified_scope"]["var_type"], "sensitive");
        assert!(!audit.contains("same"));
    }

    #[tokio::test]
    async fn invalid_selected_sources_prevent_all_writes_and_exclusions_remain_explicit() {
        // Missing/corrupt/invalid managed source, missing ordinary source,
        // then project/key/skip exclusions and the ordinary shape-drop policy.
        for scenario in 0..8 {
            let (_dir, store) = setup_temp_store();
            store.upsert("test/managed/GOOD", b"same").unwrap();
            if scenario == 1 {
                store.upsert("test/managed/BAD", b"same").unwrap();
                std::fs::write(
                    store.store_dir().join("test/managed/BAD.age"),
                    b"not-age-secret",
                )
                .unwrap();
            } else if scenario == 2 || scenario == 7 {
                store.upsert("test/managed/BAD", b"").unwrap();
            }
            let mut server = mockito::Server::new_async().await;
            let state =
                std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!([remote_row(
                    "GOOD",
                    "good",
                    &["production", "preview"]
                )])));
            let _mocks = mock_inventory(&mut server, &state).await;
            let succeeds = scenario >= 4;
            let changed = state.clone();
            let patch = server
                .mock("PATCH", "/v9/projects/p/env/good")
                .match_body(mockito::Matcher::Json(
                    serde_json::json!({"target":["production"]}),
                ))
                .with_status(200)
                .with_body_from_request(move |_| {
                    changed.lock().unwrap()[0]["target"] = serde_json::json!(["production"]);
                    b"{}".to_vec()
                })
                .expect(usize::from(succeeds))
                .create_async()
                .await;
            let create = server
                .mock("POST", "/v10/projects/p/env")
                .expect(0)
                .create_async()
                .await;
            let mut bad = managed_project(&["BAD"], scenario != 3 && scenario != 7);
            if scenario == 6 {
                bad.skip.push("BAD".into());
            }
            let manifest = SyncManifest {
                team_id: None,
                projects: HashMap::from([
                    ("a".into(), managed_project(&["GOOD"], true)),
                    ("b".into(), bad),
                ]),
            };
            let project_filter = if scenario == 4 {
                vec!["a".into()]
            } else {
                vec![]
            };
            let key_filter = if scenario == 5 {
                vec!["GOOD".into()]
            } else {
                vec![]
            };
            let client = VercelClient::new("t".into(), None).with_base_url(server.url());
            let result = push_mode(
                &store,
                &client,
                &manifest,
                true,
                true,
                &project_filter,
                &key_filter,
            )
            .await;
            assert_eq!(result.is_ok(), succeeds, "scenario {scenario}: {result:?}");
            if let Err(error) = result {
                let error = format!("{error:#}");
                assert!(error.contains("BAD"));
                assert!(error.contains("no selected plan can apply"));
                assert!(!error.contains("not-age-secret"));
                assert!(!store
                    .store_dir()
                    .join(".revvault/rotation-log.jsonl")
                    .exists());
            } else if scenario == 7 {
                let audit =
                    std::fs::read_to_string(store.store_dir().join(".revvault/rotation-log.jsonl"))
                        .unwrap();
                let entries: Vec<serde_json::Value> = audit
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert!(entries
                    .iter()
                    .any(|entry| entry["key"] == "GOOD" && entry["result"] == "ok"));
                assert!(entries
                    .iter()
                    .any(|entry| entry["key"] == "BAD" && entry["action"] == "drop-shape"));
            }
            patch.assert_async().await;
            create.assert_async().await;
        }
    }

    #[tokio::test]
    async fn branch_plans_advance_only_verified_same_key_metadata() {
        // 0: our two branch writes succeed; 1: external same-key revision;
        // 2: failed first verification; 3: unrelated changed key must not be adopted.
        for scenario in 0..4 {
            let (_dir, store) = setup_temp_store();
            for key in ["KEY", "OTHER"] {
                store
                    .upsert(&format!("test/managed/{key}"), b"same")
                    .unwrap();
            }
            let mut server = mockito::Server::new_async().await;
            let mut rows = Vec::new();
            for branch in ["a", "b"] {
                let mut row = remote_row("KEY", branch, &["preview"]);
                row["gitBranch"] = branch.into();
                row["type"] = "sensitive".into();
                row["value"] = serde_json::Value::Null;
                row["updatedAt"] = 0.into();
                rows.push(row);
            }
            let mut other = remote_row("OTHER", "other", &["production"]);
            other["updatedAt"] = 0.into();
            rows.push(other);
            let state = std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!(rows)));
            let phase = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let read_state = state.clone();
            let read_phase = phase.clone();
            server
                .mock("GET", "/v10/projects/p/env")
                .with_status(200)
                .with_body_from_request(move |_| {
                    let mut state = read_state.lock().unwrap();
                    let body = serde_json::json!({"envs":*state}).to_string().into_bytes();
                    if scenario == 1 && read_phase.load(std::sync::atomic::Ordering::SeqCst) == 1 {
                        // Change after the first verified response was captured.
                        state[1]["updatedAt"] = 9.into();
                        state[1]["value"] = "external".into();
                        read_phase.store(2, std::sync::atomic::Ordering::SeqCst);
                    }
                    body
                })
                .expect_at_least(1)
                .create_async()
                .await;
            server
                .mock("GET", "/v10/projects/p/env?decrypt=true")
                .with_status(403)
                .expect_at_least(2)
                .create_async()
                .await;
            let changed = state.clone();
            let first_phase = phase.clone();
            let first = server
                .mock("PATCH", "/v9/projects/p/env/a")
                .match_body(mockito::Matcher::Json(serde_json::json!({"value":"same"})))
                .with_status(200)
                .with_body_from_request(move |_| {
                    let mut state = changed.lock().unwrap();
                    state[0]["updatedAt"] = 1.into();
                    if scenario == 2 {
                        state[0]["gitBranch"] = "unexpected".into();
                    }
                    if scenario == 3 {
                        state[2]["updatedAt"] = 9.into();
                        state[2]["value"] = "external".into();
                    }
                    first_phase.store(1, std::sync::atomic::Ordering::SeqCst);
                    b"{}".to_vec()
                })
                .expect(1)
                .create_async()
                .await;
            let changed = state.clone();
            let second = server
                .mock("PATCH", "/v9/projects/p/env/b")
                .match_body(mockito::Matcher::Json(serde_json::json!({"value":"same"})))
                .with_status(200)
                .with_body_from_request(move |_| {
                    changed.lock().unwrap()[1]["updatedAt"] = 1.into();
                    b"{}".to_vec()
                })
                .expect(if scenario == 0 || scenario == 3 { 1 } else { 0 })
                .create_async()
                .await;
            let unrelated = server
                .mock("PATCH", "/v9/projects/p/env/other")
                .expect(0)
                .create_async()
                .await;
            let mut projects = HashMap::new();
            for branch in ["a", "b"] {
                let mut project = managed_project(&["KEY"], false);
                project.git_branch = Some(branch.into());
                project.targets = vec!["preview".into()];
                projects.insert(branch.into(), project);
            }
            if scenario == 3 {
                projects.insert("c".into(), managed_project(&["OTHER"], false));
            }
            let manifest = SyncManifest {
                team_id: None,
                projects,
            };
            let client = VercelClient::new("t".into(), None).with_base_url(server.url());
            let result = push_mode(&store, &client, &manifest, true, true, &[], &[]).await;
            assert_eq!(
                result.is_ok(),
                scenario == 0,
                "scenario {scenario}: {result:?}"
            );
            first.assert_async().await;
            second.assert_async().await;
            unrelated.assert_async().await;
        }
    }

    #[tokio::test]
    async fn aliasing_project_entries_cannot_write_one_immutable_row_twice() {
        let (_dir, store) = setup_temp_store();
        store.upsert("test/managed/KEY", b"new").unwrap();
        let mut server = mockito::Server::new_async().await;
        let state = std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!([remote_row(
            "KEY",
            "same-id",
            &["production"]
        )])));
        let _mocks = mock_inventory(&mut server, &state).await;
        for path in [
            "/v10/projects/alias/env",
            "/v10/projects/alias/env?decrypt=true",
        ] {
            server
                .mock("GET", path)
                .with_status(200)
                .with_body(serde_json::json!({"envs":*state.lock().unwrap()}).to_string())
                .create_async()
                .await;
        }
        let first = managed_project(&["KEY"], false);
        let mut second = managed_project(&["KEY"], false);
        second.project_id = "alias".into();
        let manifest = SyncManifest {
            team_id: None,
            projects: HashMap::from([("a".into(), first), ("b".into(), second)]),
        };
        let patch = server
            .mock("PATCH", "/v9/projects/p/env/same-id")
            .expect(0)
            .create_async()
            .await;
        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        let error = push_mode(&store, &client, &manifest, true, true, &[], &[])
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("Multiple selected plans target remote row"));
        patch.assert_async().await;
    }

    #[tokio::test]
    async fn unreadable_sensitive_values_update_without_redundant_target_fields() {
        for target_drift in [false, true] {
            let (_dir, store) = setup_temp_store();
            store.upsert("test/managed/KEY", b"same").unwrap();
            let mut server = mockito::Server::new_async().await;
            let targets = if target_drift {
                vec!["production", "preview"]
            } else {
                vec!["production"]
            };
            let mut row = remote_row("KEY", "sensitive", &targets);
            row["type"] = "sensitive".into();
            row["value"] = serde_json::Value::Null;
            let state = std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!([row])));
            let mocks = mock_inventory(&mut server, &state).await;
            mocks[1].remove_async().await;
            server
                .mock("GET", "/v10/projects/p/env?decrypt=true")
                .with_status(403)
                .create_async()
                .await;
            let mut body = serde_json::json!({"value":"same"});
            if target_drift {
                body["target"] = serde_json::json!(["production"]);
            }
            let changed = state.clone();
            let patch = server
                .mock("PATCH", "/v9/projects/p/env/sensitive")
                .match_body(mockito::Matcher::Json(body))
                .with_status(200)
                .with_body_from_request(move |_| {
                    let mut state = changed.lock().unwrap();
                    state[0]["target"] = serde_json::json!(["production"]);
                    state[0]["updatedAt"] = 1.into();
                    b"{}".to_vec()
                })
                .expect(1)
                .create_async()
                .await;
            let client = VercelClient::new("t".into(), None).with_base_url(server.url());
            let manifest = single_project_manifest(managed_project(&["KEY"], true));
            push_mode(&store, &client, &manifest, true, true, &[], &[])
                .await
                .unwrap();
            patch.assert_async().await;
            assert_eq!(state.lock().unwrap()[0]["type"], "sensitive");
        }
    }

    fn project_with_vars(vars: HashMap<String, VarEntry>) -> ProjectSync {
        ProjectSync {
            project_id: "prj_test".to_string(),
            vault_prefix: "revealui/vercel/api".to_string(),
            targets: default_targets(),
            git_branch: None,
            skip: vec![],
            vars,
        }
    }

    fn project_with_string_vars(vars: HashMap<String, String>) -> ProjectSync {
        let entries = vars
            .into_iter()
            .map(|(k, v)| (k, VarEntry::Path(v)))
            .collect();
        project_with_vars(entries)
    }

    #[test]
    fn vault_path_for_returns_prefix_default_when_no_override() {
        let cfg = project_with_vars(HashMap::new());
        let (path, shape) = cfg.vault_path_for("STRIPE_SECRET_KEY");
        assert_eq!(path, "revealui/vercel/api/STRIPE_SECRET_KEY");
        assert_eq!(shape, Shape::Any);
    }

    #[test]
    fn vault_path_for_returns_override_when_set() {
        let mut vars = HashMap::new();
        vars.insert(
            "POSTGRES_URL".to_string(),
            VarEntry::Path("revealui/prod/db/postgres-url".to_string()),
        );
        let cfg = project_with_vars(vars);
        let (path, shape) = cfg.vault_path_for("POSTGRES_URL");
        assert_eq!(path, "revealui/prod/db/postgres-url");
        assert_eq!(shape, Shape::Any);
        let (path2, _) = cfg.vault_path_for("STRIPE_SECRET_KEY");
        assert_eq!(path2, "revealui/vercel/api/STRIPE_SECRET_KEY");
    }

    #[test]
    fn vault_path_for_object_entry_returns_declared_shape() {
        let mut vars = HashMap::new();
        vars.insert(
            "POSTGRES_URL".to_string(),
            VarEntry::Object(VarObject {
                path: "revealui/prod/db/postgres-url".to_string(),
                shape: Shape::PostgresUrl,
                sensitive: false,
                manage_targets: false,
            }),
        );
        let cfg = project_with_vars(vars);
        let (path, shape) = cfg.vault_path_for("POSTGRES_URL");
        assert_eq!(path, "revealui/prod/db/postgres-url");
        assert_eq!(shape, Shape::PostgresUrl);
    }

    #[test]
    fn vault_path_for_supports_two_vars_pointing_at_same_path() {
        let mut vars = HashMap::new();
        vars.insert(
            "POSTGRES_URL".to_string(),
            VarEntry::Path("revealui/prod/db/postgres-url".to_string()),
        );
        vars.insert(
            "DATABASE_URL".to_string(),
            VarEntry::Path("revealui/prod/db/postgres-url".to_string()),
        );
        let cfg = project_with_vars(vars);
        let (path1, _) = cfg.vault_path_for("POSTGRES_URL");
        let (path2, _) = cfg.vault_path_for("DATABASE_URL");
        assert_eq!(path1, path2);
    }

    #[test]
    fn manifest_parses_without_vars_field_for_backwards_compat() {
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"
        "#;
        let manifest: SyncManifest = toml::from_str(toml_src).unwrap();
        let api = manifest.projects.get("api").unwrap();
        assert!(api.vars.is_empty());
        let (path, shape) = api.vault_path_for("FOO");
        assert_eq!(path, "revealui/vercel/api/FOO");
        assert_eq!(shape, Shape::Any);
    }

    #[test]
    fn manifest_parses_with_string_vars_table() {
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"

            [projects.api.vars]
            POSTGRES_URL = "revealui/prod/db/postgres-url"
            DATABASE_URL = "revealui/prod/db/postgres-url"
        "#;
        let manifest: SyncManifest = toml::from_str(toml_src).unwrap();
        let api = manifest.projects.get("api").unwrap();
        assert_eq!(api.vars.len(), 2);
        let (path, shape) = api.vault_path_for("POSTGRES_URL");
        assert_eq!(path, "revealui/prod/db/postgres-url");
        assert_eq!(shape, Shape::Any);
        let (foo_path, _) = api.vault_path_for("FOO");
        assert_eq!(foo_path, "revealui/vercel/api/FOO");
    }

    #[test]
    fn manifest_parses_with_object_vars_table() {
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"

            [projects.api.vars]
            POSTGRES_URL = { path = "revealui/prod/db/postgres-url", shape = "postgres-url" }
            STRIPE_SECRET_KEY = { path = "revealui/prod/stripe/secret-key", shape = "stripe-key-live-only" }
        "#;
        let manifest: SyncManifest = toml::from_str(toml_src).unwrap();
        let api = manifest.projects.get("api").unwrap();
        let (path, shape) = api.vault_path_for("POSTGRES_URL");
        assert_eq!(path, "revealui/prod/db/postgres-url");
        assert_eq!(shape, Shape::PostgresUrl);
        let (_, stripe_shape) = api.vault_path_for("STRIPE_SECRET_KEY");
        assert_eq!(stripe_shape, Shape::StripeKeyLiveOnly);
    }

    #[test]
    fn manifest_parses_mixed_string_and_object_vars() {
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"

            [projects.api.vars]
            POSTGRES_URL = "revealui/prod/db/postgres-url"
            STRIPE_KEY = { path = "revealui/prod/stripe/key", shape = "stripe-key-live-only" }
        "#;
        let manifest: SyncManifest = toml::from_str(toml_src).unwrap();
        let api = manifest.projects.get("api").unwrap();
        let (_, pg_shape) = api.vault_path_for("POSTGRES_URL");
        assert_eq!(pg_shape, Shape::Any);
        let (_, stripe_shape) = api.vault_path_for("STRIPE_KEY");
        assert_eq!(stripe_shape, Shape::StripeKeyLiveOnly);
    }

    /// Helper: build a ProjectSync with old-style string vars for tests that
    /// predate D6 (vault_path_for now returns (path, shape) — these tests
    /// only care about the path half).
    #[allow(dead_code)]
    fn project_string_only(vars: HashMap<String, String>) -> ProjectSync {
        project_with_string_vars(vars)
    }

    // ── Sensitive marker (manifest parse + type decision) ────────────────────

    #[test]
    fn manifest_parses_sensitive_marker() {
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"

            [projects.api.vars]
            STRIPE_SECRET_KEY = { path = "revealui/prod/stripe/secret-key", shape = "stripe-key-live-only", sensitive = true }
            POSTGRES_URL = "revealui/prod/db/postgres-url"
        "#;
        let manifest: SyncManifest = toml::from_str(toml_src).unwrap();
        let api = manifest.projects.get("api").unwrap();
        assert!(api.sensitive_for("STRIPE_SECRET_KEY"));
        assert!(!api.sensitive_for("POSTGRES_URL"));
        // prefix-derived vars carry no marker
        assert!(!api.sensitive_for("NOT_DECLARED"));
    }

    #[test]
    fn manifest_object_entry_shape_is_optional() {
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"

            [projects.api.vars]
            REVEALUI_SECRET = { path = "revealui/prod/secret", sensitive = true }
        "#;
        let manifest: SyncManifest = toml::from_str(toml_src).unwrap();
        let api = manifest.projects.get("api").unwrap();
        let (path, shape) = api.vault_path_for("REVEALUI_SECRET");
        assert_eq!(path, "revealui/prod/secret");
        assert_eq!(shape, Shape::Any);
        assert!(api.sensitive_for("REVEALUI_SECRET"));
    }

    #[test]
    fn manifest_rejects_unknown_var_entry_key() {
        // A typo'd marker must fail the parse loudly — silently ignoring
        // `sensitve = true` would leave a credential downgradable.
        let toml_src = r#"
            [projects.api]
            project_id = "prj_test"
            vault_prefix = "revealui/vercel/api"

            [projects.api.vars]
            STRIPE_SECRET_KEY = { path = "revealui/prod/stripe/secret-key", sensitve = true }
        "#;
        assert!(toml::from_str::<SyncManifest>(toml_src).is_err());
    }

    #[test]
    fn create_type_for_never_downgrades() {
        assert_eq!(create_type_for(false, false), EnvVarType::Encrypted);
        assert_eq!(create_type_for(true, false), EnvVarType::Sensitive);
        assert_eq!(create_type_for(false, true), EnvVarType::Sensitive);
        assert_eq!(create_type_for(true, true), EnvVarType::Sensitive);
    }

    #[test]
    fn type_drift_reason_only_fires_on_unmet_sensitive_intent() {
        assert!(type_drift_reason(false, Some("encrypted")).is_none());
        assert!(type_drift_reason(true, Some("sensitive")).is_none());
        let drift = type_drift_reason(true, Some("encrypted")).expect("drift");
        assert!(drift.contains("type drift"), "got: {drift}");
        assert!(drift.contains("encrypted"), "got: {drift}");
        let unknown = type_drift_reason(true, None).expect("drift");
        assert!(unknown.contains("unknown"), "got: {unknown}");
    }

    // ── push_mode integration (temp store + mock Vercel API) ────────────────

    /// Temp store with a generated age identity — mirrors the pattern from
    /// core's `rotation::sync_hook` test module.
    fn setup_temp_store() -> (tempfile::TempDir, PassageStore) {
        let dir = tempfile::tempdir().unwrap();
        let store_dir = dir.path().join("store");
        std::fs::create_dir_all(&store_dir).unwrap();

        let id = age::x25519::Identity::generate();
        let recipient = id.to_public();

        let id_file = dir.path().join("keys.txt");
        std::fs::write(
            &id_file,
            format!(
                "# test key\n{}\n",
                secrecy::ExposeSecret::expose_secret(&id.to_string())
            ),
        )
        .unwrap();

        let recip_file = store_dir.join(".age-recipients");
        std::fs::write(&recip_file, format!("{}\n", recipient)).unwrap();

        let config = Config {
            store_dir,
            identity_file: id_file,
            recipients_file: recip_file,
            editor: None,
            tmpdir: None,
        };
        let store = PassageStore::open(config).unwrap();
        (dir, store)
    }

    fn single_project_manifest(project: ProjectSync) -> SyncManifest {
        SyncManifest {
            team_id: None,
            projects: HashMap::from([("api".to_string(), project)]),
        }
    }

    #[tokio::test]
    async fn push_mode_recreate_preserves_remote_sensitive_type() {
        // The 2026-06-10 regression class: the synced target has no row
        // (deleted / rebuilt), but the key still exists as `sensitive` on
        // another target. The re-create must come back `sensitive` — not
        // silently downgrade to `encrypted`.
        let (_dir, store) = setup_temp_store();
        store
            .upsert("revealui/prod/stripe/secret-key", b"sk_live_x")
            .unwrap();

        let mut server = mockito::Server::new_async().await;
        let m_list = server
            .mock("GET", "/v10/projects/prj_p/env")
            .with_status(200)
            .with_body(
                r#"{"envs":[{"id":"e1","key":"STRIPE_SECRET_KEY","target":["preview"],"type":"sensitive"}]}"#,
            )
            .expect(3)
            .create_async()
            .await;
        let m_decrypt = server
            .mock("GET", "/v10/projects/prj_p/env?decrypt=true")
            .with_status(403)
            .with_body("{}")
            .create_async()
            .await;
        let verified = server.mock("GET", "/v10/projects/prj_p/env").with_status(200)
            .with_body(r#"{"envs":[{"id":"e1","key":"STRIPE_SECRET_KEY","target":["preview"],"type":"sensitive"},{"id":"new","key":"STRIPE_SECRET_KEY","target":["production"],"type":"sensitive"}]}"#).expect(1).create_async().await;
        let m_create = server
            .mock("POST", "/v10/projects/prj_p/env")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "key": "STRIPE_SECRET_KEY",
                "target": ["production"],
                "type": "sensitive",
            })))
            .with_status(201)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let mut vars = HashMap::new();
        vars.insert(
            "STRIPE_SECRET_KEY".to_string(),
            VarEntry::Path("revealui/prod/stripe/secret-key".to_string()),
        );
        let manifest = single_project_manifest(ProjectSync {
            project_id: "prj_p".to_string(),
            vault_prefix: "revealui/vercel/api".to_string(),
            targets: vec!["production".to_string()],
            git_branch: None,
            skip: vec![],
            vars,
        });

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        push_mode(&store, &client, &manifest, true, true, &[], &[])
            .await
            .unwrap();

        m_list.assert_async().await;
        m_decrypt.assert_async().await;
        m_create.assert_async().await;
        verified.assert_async().await;
    }

    #[tokio::test]
    async fn push_mode_creates_sensitive_when_manifest_marks_it() {
        let (_dir, store) = setup_temp_store();
        store
            .upsert("revealui/prod/secret", b"super-secret-value")
            .unwrap();

        let mut server = mockito::Server::new_async().await;
        let m_list = server
            .mock("GET", "/v10/projects/prj_p/env")
            .with_status(200)
            .with_body(r#"{"envs":[]}"#)
            .expect(3)
            .create_async()
            .await;
        let m_decrypt = server
            .mock("GET", "/v10/projects/prj_p/env?decrypt=true")
            .with_status(403)
            .with_body("{}")
            .create_async()
            .await;
        let verified = server.mock("GET", "/v10/projects/prj_p/env").with_status(200)
            .with_body(r#"{"envs":[{"id":"new","key":"REVEALUI_SECRET","target":["production"],"type":"sensitive"}]}"#).expect(1).create_async().await;
        let m_create = server
            .mock("POST", "/v10/projects/prj_p/env")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "key": "REVEALUI_SECRET",
                "type": "sensitive",
            })))
            .with_status(201)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let mut vars = HashMap::new();
        vars.insert(
            "REVEALUI_SECRET".to_string(),
            VarEntry::Object(VarObject {
                path: "revealui/prod/secret".to_string(),
                shape: Shape::Any,
                sensitive: true,
                manage_targets: false,
            }),
        );
        let manifest = single_project_manifest(ProjectSync {
            project_id: "prj_p".to_string(),
            vault_prefix: "revealui/vercel/api".to_string(),
            targets: vec!["production".to_string()],
            git_branch: None,
            skip: vec![],
            vars,
        });

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        push_mode(&store, &client, &manifest, true, true, &[], &[])
            .await
            .unwrap();

        m_list.assert_async().await;
        m_decrypt.assert_async().await;
        m_create.assert_async().await;
        verified.assert_async().await;
    }

    #[tokio::test]
    async fn push_mode_creates_encrypted_by_default() {
        // No marker + no remote history → the default stays `encrypted`.
        let (_dir, store) = setup_temp_store();
        store
            .upsert("revealui/prod/public/api-url", b"https://api.example.com")
            .unwrap();

        let mut server = mockito::Server::new_async().await;
        let m_list = server
            .mock("GET", "/v10/projects/prj_p/env")
            .with_status(200)
            .with_body(r#"{"envs":[]}"#)
            .expect(3)
            .create_async()
            .await;
        let m_decrypt = server
            .mock("GET", "/v10/projects/prj_p/env?decrypt=true")
            .with_status(403)
            .with_body("{}")
            .create_async()
            .await;
        let verified = server.mock("GET", "/v10/projects/prj_p/env").with_status(200)
            .with_body(r#"{"envs":[{"id":"new","key":"NEXT_PUBLIC_API_URL","target":["production"],"type":"encrypted"}]}"#).expect(1).create_async().await;
        let m_create = server
            .mock("POST", "/v10/projects/prj_p/env")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "key": "NEXT_PUBLIC_API_URL",
                "type": "encrypted",
            })))
            .with_status(201)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let mut vars = HashMap::new();
        vars.insert(
            "NEXT_PUBLIC_API_URL".to_string(),
            VarEntry::Path("revealui/prod/public/api-url".to_string()),
        );
        let manifest = single_project_manifest(ProjectSync {
            project_id: "prj_p".to_string(),
            vault_prefix: "revealui/vercel/api".to_string(),
            targets: vec!["production".to_string()],
            git_branch: None,
            skip: vec![],
            vars,
        });

        let client = VercelClient::new("t".into(), None).with_base_url(server.url());
        push_mode(&store, &client, &manifest, true, true, &[], &[])
            .await
            .unwrap();

        m_list.assert_async().await;
        m_decrypt.assert_async().await;
        m_create.assert_async().await;
        verified.assert_async().await;
    }

    // ── Fly manifest ─────────────────────────────────────────────────────────

    #[test]
    fn fly_manifest_parses_apps_and_vars() {
        let toml_src = r#"
            [fly-apps.revealui-worker]
            app = "revealui-worker"

            [fly-apps.revealui-worker.vars]
            POSTGRES_URL = "revealui/prod/db/postgres-url"
            ELECTRIC_SECRET = "revealui/prod/electric/secret"
        "#;
        let manifest: FlyManifest = toml::from_str(toml_src).unwrap();
        let app = manifest.fly_apps.get("revealui-worker").unwrap();
        assert_eq!(app.app, "revealui-worker");
        assert_eq!(app.vars.len(), 2);
        let (path, shape) = app.vault_path_for("POSTGRES_URL").unwrap();
        assert_eq!(path, "revealui/prod/db/postgres-url");
        assert_eq!(shape, Shape::Any);
        assert!(app.vault_path_for("NOT_DECLARED").is_none());
    }

    #[test]
    fn fly_manifest_supports_object_var_with_shape() {
        let toml_src = r#"
            [fly-apps.worker]
            app = "revealui-worker"

            [fly-apps.worker.vars]
            POSTGRES_URL = { path = "revealui/prod/db/postgres-url", shape = "postgres-url" }
        "#;
        let manifest: FlyManifest = toml::from_str(toml_src).unwrap();
        let app = manifest.fly_apps.get("worker").unwrap();
        let (_, shape) = app.vault_path_for("POSTGRES_URL").unwrap();
        assert_eq!(shape, Shape::PostgresUrl);
    }

    #[test]
    fn fly_manifest_skip_list_parses() {
        let toml_src = r#"
            [fly-apps.worker]
            app = "revealui-worker"
            skip = ["NODE_ENV"]

            [fly-apps.worker.vars]
            FOO = "revealui/prod/foo"
        "#;
        let manifest: FlyManifest = toml::from_str(toml_src).unwrap();
        let app = manifest.fly_apps.get("worker").unwrap();
        assert!(app.skip.contains(&"NODE_ENV".to_string()));
    }

    #[test]
    fn empty_fly_manifest_is_rejected() {
        // A Vercel-style manifest has no [fly-apps]; unknown fields are ignored,
        // so it deserializes into an empty FlyManifest. The guard must reject it
        // rather than let `sync fly` silently no-op.
        let vercel_like = r#"
            [projects.revealui-api]
            project_id = "prj_x"
            vault_prefix = "revealui/prod"
        "#;
        let manifest: FlyManifest = toml::from_str(vercel_like).unwrap();
        assert!(manifest.fly_apps.is_empty());
        let err = validate_fly_manifest(&manifest, std::path::Path::new("revvault-vercel.toml"))
            .unwrap_err();
        assert!(err.to_string().contains("No [fly-apps"));
    }

    #[test]
    fn populated_fly_manifest_passes_validation() {
        let toml_src = r#"
            [fly-apps.worker]
            app = "revealui-worker"

            [fly-apps.worker.vars]
            FOO = "revealui/prod/foo"
        "#;
        let manifest: FlyManifest = toml::from_str(toml_src).unwrap();
        validate_fly_manifest(&manifest, std::path::Path::new("fly.toml")).unwrap();
    }
}
