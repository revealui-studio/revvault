//! Rotation executor — vault I/O + provider dispatch + log writing.
//!
//! The executor is the glue between the vault and rotation providers.
//! It reads the current key from the vault, builds the provider, runs
//! the rotation, writes the new key back, runs the sync hook, the
//! `post_rotate` user hooks, the `verify` gate, and finally appends a
//! log entry.
//!
//! # Failure semantics
//!
//! - The `apply_sync_after_rotation` step is infallible at the function
//!   level — sync target failures land as log rows + stderr warnings.
//! - Failed sync prevents in-place revocation. Failed `post_rotate` hooks
//!   prevent revocation when an HTTP revoke URL is configured. Otherwise
//!   user hooks retain their historical warn-on-failure behavior.
//! - The `verify` step is **strict** — a failing verify writes a log
//!   entry with `verified: false` and then the executor returns Err so
//!   the cli exits non-zero. The replacement may already be persisted,
//!   but the old HTTP credential remains usable. Promotion reruns its gates.

use std::io::Write as _;

use chrono::Utc;
use secrecy::{ExposeSecret as _, SecretString};

use crate::rotation::config::ProviderConfig;
use crate::rotation::provider::RotationLogEntry;
use crate::rotation::providers::build_provider;
use crate::rotation::providers::keypair::compute_key_id;
use crate::rotation::slots;
use crate::rotation::sync_hook::{self, SyncLogEntry};
use crate::store::PassageStore;
use crate::sync::shape::{self, Shape};

/// Vault path where a provider's key ID is stored between rotations.
/// e.g. `credentials/vercel/token` → `credentials/vercel/token-id`
fn key_id_path(secret_path: &str) -> String {
    format!("{secret_path}-id")
}

/// Run a full rotation for one provider.
///
/// Steps:
/// 1. Read current key from vault
/// 2. Read previous key ID from vault (if stored)
/// 3. Build and preflight the provider (factory in `providers::build_provider`)
/// 4. Execute rotation (create new key only — no revoke yet)
/// 5. Write new key to vault
/// 6. Write new key ID to vault (if provider returned one)
/// 7. Apply post-rotation sync hook (if `[sync.*]` configured)
/// 8. Run `post_rotate` user hooks (strict when revocation is configured)
/// 9. Run `verify` gate (strict — Err on failure)
/// 10. Revoke the previous key after all gates (skipped for dual-slot)
/// 11. Append log entry
pub async fn execute(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> anyhow::Result<()> {
    let id_path = key_id_path(&provider_config.secret_path);
    let provider_type = provider_config.settings.get("type").map(String::as_str);
    // Generators that do not depend on prior vault state (first rotation
    // must succeed when the leaf is empty).
    let skips_current_key = matches!(provider_type, Some("local") | Some("ed25519-keypair"));

    // 1-2. Read current key + previous key ID (skipped for generators above).
    let (current_key_for_provider, old_key_id) = if skips_current_key {
        (SecretString::from(String::new()), None)
    } else {
        let current = store
            .get(&provider_config.secret_path)
            .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", provider_config.secret_path))?;
        let id = store
            .get(&id_path)
            .ok()
            .map(|s| s.expose_secret().to_string());
        (SecretString::from(current.expose_secret().to_string()), id)
    };

    // Preserve the old credential and ID for recovery if a later sync or verify fails.
    if !skips_current_key && !provider_config.dual_slot {
        let previous = slots::previous_path(&provider_config.secret_path);
        store.upsert(
            &previous,
            current_key_for_provider.expose_secret().as_bytes(),
        )?;
        if let Some(id) = &old_key_id {
            store.upsert(&key_id_path(&previous), id.as_bytes())?;
        }
    }

    // 3. Build provider via factory dispatch on settings["type"].
    let provider = build_provider(
        store,
        provider_name.to_string(),
        current_key_for_provider,
        old_key_id,
        &provider_config.settings,
    )?;

    provider.preflight().await?;

    // 4. Rotate
    let outcome = provider.rotate().await?;

    // 5. Validate output shape before writing to vault.
    //    Universal structural checks (empty / null / envelope) always run.
    //    Per-shape check runs when `output_shape` is declared.
    //    On mismatch the rotation ABORTS — old key remains in vault.
    {
        let declared = provider_config.output_shape.unwrap_or(Shape::Any);
        let raw = outcome.new_value.expose_secret();
        if let Err(violation) = shape::check(raw, declared) {
            return Err(anyhow::anyhow!(
                "rotation provider '{}' returned a value that failed shape validation \
                 ({}); rotation aborted — old key is unchanged. \
                 Shape category: {}",
                provider_name,
                violation,
                shape::classify(raw),
            ));
        }
    }

    // 5b/5c. Write new key (+ companions). Dual-slot: next/previous only; live untouched.
    let write_path = if provider_config.dual_slot {
        let next = slots::write_dual_slot_primary(
            store,
            &provider_config.secret_path,
            &outcome.new_value,
        )?;
        for (path, value) in &outcome.companion_writes {
            slots::write_dual_slot_companion(store, path, value)?;
        }
        eprintln!(
            "  dual_slot: wrote next at '{next}' (live '{}' unchanged — promote to flip)",
            provider_config.secret_path
        );
        next
    } else {
        store
            .upsert(
                &provider_config.secret_path,
                outcome.new_value.expose_secret().as_bytes(),
            )
            .map_err(|e| anyhow::anyhow!("cannot write new key to vault: {e}"))?;
        for (path, value) in &outcome.companion_writes {
            store
                .upsert(path, value.expose_secret().as_bytes())
                .map_err(|e| anyhow::anyhow!("cannot write companion path '{path}': {e}"))?;
        }
        provider_config.secret_path.clone()
    };

    // 6. Write new key ID (enables revocation in the next rotation).
    // Dual-slot: `{secret_path}-next-id` so promote can flip it with the leaf.
    if let Some(ref id) = outcome.new_key_id {
        let kid_write = if provider_config.dual_slot {
            key_id_path(&slots::next_path(&provider_config.secret_path))
        } else {
            id_path.clone()
        };
        store
            .upsert(&kid_write, id.as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot write key ID to vault: {e}"))?;
    }

    // 8. Post-rotation sync hook. The vault is already on the
    // new value at this point (live or dual-slot next); sync is best-effort
    // by default and infallible at the function level (failures land as log
    // entries). When `sync_must_succeed` is set (crown jewels, GAP-261), any
    // non-success row aborts the rotation with Err so operators never
    // silently run with vault/remote drift.
    let sync_log: Option<Vec<SyncLogEntry>> = if let Some(sync_cfg) = &provider_config.sync {
        let entries =
            sync_hook::apply_sync_after_rotation(store, sync_cfg, &outcome.new_value).await;
        for row in &entries {
            if row.status != "success" {
                eprintln!(
                    "  ⚠ Sync to {} failed for {}/{}: {}",
                    row.target,
                    row.env_var,
                    row.vercel_target,
                    row.error.as_deref().unwrap_or("(no error message)"),
                );
            }
        }
        let any_failed = entries.iter().any(|r| r.status != "success");
        if any_failed {
            eprintln!("  Vault is correct but at least one sync target lagged. Retry with:");
            eprintln!("    revvault sync vercel --apply --manifest <path>");
            if provider_config.sync_must_succeed {
                // Still record the partial sync in the log before failing.
                append_log(
                    store,
                    provider_name,
                    &provider_config.secret_path,
                    &outcome.new_key_id,
                    Some(entries.clone()),
                    None,
                )?;
                return Err(anyhow::anyhow!(
                    "provider '{provider_name}': sync_must_succeed=true and at least one \
                     sync target failed — rotation aborted after vault write (retry sync, \
                     then re-run verify)"
                ));
            }
        }
        Some(entries)
    } else {
        None
    };

    // 8. Distribution hook failures must never be followed by revocation.
    let mut hook_failed = false;
    for cmd in &provider_config.post_rotate {
        eprintln!("  Running post_rotate: {cmd}");
        match tokio::process::Command::new("sh")
            .args(["-c", cmd])
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                eprintln!("  ✓ post_rotate succeeded: {cmd}");
            }
            Ok(output) => {
                hook_failed = true;
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!(
                    "  ⚠ post_rotate command failed (exit {}): {cmd}\n    {}",
                    output.status.code().unwrap_or(-1),
                    stderr.trim()
                );
            }
            Err(e) => {
                hook_failed = true;
                eprintln!("  ⚠ post_rotate command could not be executed: {cmd}\n    {e}");
            }
        }
    }

    anyhow::ensure!(
        !hook_failed || !provider_config.settings.contains_key("revoke_url"),
        "post_rotate failed; old credential retained; repair distribution before revoking it"
    );

    // 9. verify gate (STRICT — Err on failure)
    let verified: Option<bool> = match &provider_config.verify {
        None => None,
        Some(verify_cmd) => {
            eprintln!("  Running verify: {verify_cmd}");
            match tokio::process::Command::new("sh")
                .args(["-c", verify_cmd])
                .output()
                .await
            {
                Ok(output) if output.status.success() => {
                    eprintln!("  ✓ Verification passed for '{provider_name}'");
                    Some(true)
                }
                Ok(output) => {
                    let exit_code = output.status.code().unwrap_or(-1);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stderr_trim = stderr.trim();

                    // Write log entry with verified=Some(false) BEFORE returning Err
                    // so the audit trail records the failed verification.
                    append_log(
                        store,
                        provider_name,
                        &provider_config.secret_path,
                        &outcome.new_key_id,
                        sync_log,
                        Some(false),
                    )?;

                    eprintln!(
                        "  ✗ Verification FAILED for '{provider_name}' (exit {exit_code}): {stderr_trim}"
                    );
                    return Err(anyhow::anyhow!(
                        "verify command exited non-zero (code {exit_code}): {verify_cmd}"
                    ));
                }
                Err(e) => {
                    // Spawn / I/O failure — also strict.
                    append_log(
                        store,
                        provider_name,
                        &provider_config.secret_path,
                        &outcome.new_key_id,
                        sync_log,
                        Some(false),
                    )?;

                    eprintln!(
                        "  ✗ Verify command could not be executed for '{provider_name}': {e}"
                    );
                    return Err(anyhow::anyhow!(
                        "verify command could not be executed: {verify_cmd}: {e}"
                    ));
                }
            }
        }
    };

    // Keep the old credential usable if a consumer failed to receive its replacement.
    if !provider_config.dual_slot {
        if sync_log
            .as_ref()
            .is_some_and(|rows| rows.iter().any(|row| row.status != "success"))
        {
            return Err(anyhow::anyhow!(
                "sync failed; old credential retained; repair sync before revoking it"
            ));
        }
        provider.revoke_previous().await?;
    }

    // 10. Append log entry (success path)
    append_log(
        store,
        provider_name,
        &provider_config.secret_path,
        &outcome.new_key_id,
        sync_log,
        verified,
    )?;

    if provider_config.dual_slot {
        eprintln!(
            "✓ Dual-slot rotated provider '{provider_name}' → next at '{write_path}' \
             (live '{}' still current until `revvault rotation promote`)",
            provider_config.secret_path
        );
    } else {
        eprintln!(
            "✓ Rotated '{}' for provider '{}'",
            provider_config.secret_path, provider_name
        );
    }
    if outcome.new_key_id.is_some() {
        let kid_at = if provider_config.dual_slot {
            key_id_path(&slots::next_path(&provider_config.secret_path))
        } else {
            id_path.clone()
        };
        eprintln!("  Key ID stored at '{kid_at}' for next rotation");
    }

    Ok(())
}

/// Promote dual-slot next → live for one provider (GAP-261 residual).
///
/// Requires a prior dual-slot `rotate` that left `{secret_path}-next`.
/// Optionally mirrors the promoted private/public values onto legacy vault
/// paths from settings:
/// - `legacy_private_paths` — comma-separated (e.g. `revdev/license-signing-key`)
/// - `legacy_public_paths` — comma-separated (e.g. `revdev/license-public-key`)
///
/// Customer re-mint (`forge/customers/*/license-key`) stays a `post_rotate`
/// hook (or the existing revforge script) until a later promote subsume PR.
pub async fn promote(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> anyhow::Result<()> {
    if !provider_config.dual_slot {
        return Err(anyhow::anyhow!(
            "provider '{provider_name}': promote requires dual_slot=true in rotation.toml"
        ));
    }

    // Capture old authentication and ID before replacing the live leaves.
    let provider_type = provider_config.settings.get("type").map(String::as_str);
    let current_key = if matches!(provider_type, Some("local") | Some("ed25519-keypair")) {
        SecretString::from(String::new())
    } else {
        store.get(&provider_config.secret_path)?
    };
    let old_id = store
        .get(&key_id_path(&provider_config.secret_path))
        .ok()
        .map(|value| value.expose_secret().to_string());
    let provider = build_provider(
        store,
        provider_name.to_string(),
        current_key,
        old_id.clone(),
        &provider_config.settings,
    )?;
    provider.preflight().await?;

    // Recheck consumers immediately before promotion. A staged rotation may
    // have had a best-effort sync failure or verification may have changed.
    let staged = store.get(&slots::next_path(&provider_config.secret_path))?;
    let sync_log = if let Some(sync_cfg) = &provider_config.sync {
        let rows = sync_hook::apply_sync_after_rotation(store, sync_cfg, &staged).await;
        anyhow::ensure!(
            rows.iter().all(|row| row.status == "success"),
            "promotion sync failed; live credential retained"
        );
        Some(rows)
    } else {
        None
    };
    anyhow::ensure!(
        !provider_config.require_verify || provider_config.verify.is_some(),
        "promotion requires a verify command"
    );
    // HTTP distribution hooks may have failed during staging. Retry them before
    // the verify gate and before any old credential can be revoked.
    if provider_config.settings.contains_key("revoke_url") {
        for command in &provider_config.post_rotate {
            let status = tokio::process::Command::new("sh")
                .args(["-c", command])
                .status()
                .await?;
            anyhow::ensure!(
                status.success(),
                "promotion post_rotate failed; live credential retained"
            );
        }
    }
    let verified = if let Some(command) = &provider_config.verify {
        let status = tokio::process::Command::new("sh")
            .args(["-c", command])
            .status()
            .await?;
        anyhow::ensure!(
            status.success(),
            "promotion verification failed; live credential retained"
        );
        Some(true)
    } else {
        None
    };

    if let Some(id) = &old_id {
        store.upsert(
            &key_id_path(&slots::previous_path(&provider_config.secret_path)),
            id.as_bytes(),
        )?;
    }
    let promoted = slots::promote_leaf(store, &provider_config.secret_path)?;
    eprintln!("  promoted '{}' ← next", provider_config.secret_path);

    // Promote companion public path if configured.
    if let Some(pub_path) = provider_config.settings.get("public_key_path") {
        let pub_promoted = slots::promote_leaf(store, pub_path)?;
        eprintln!("  promoted '{pub_path}' ← next");
        let legacy_pub =
            slots::parse_path_list(provider_config.settings.get("legacy_public_paths"));
        slots::mirror_live_to_paths(store, &pub_promoted, &legacy_pub)?;
    }

    let legacy_priv = slots::parse_path_list(provider_config.settings.get("legacy_private_paths"));
    slots::mirror_live_to_paths(store, &promoted, &legacy_priv)?;

    // Promote next-id leaf (`{secret}-next-id`) → live-id (`{secret}-id`).
    let id_path = key_id_path(&provider_config.secret_path);
    let next_id = key_id_path(&slots::next_path(&provider_config.secret_path));
    if let Ok(kid) = store.get(&next_id) {
        store
            .upsert(&id_path, kid.expose_secret().as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot promote key id to '{id_path}': {e}"))?;
        let _ = store.delete(&next_id);
    }

    // Promotion is the point at which staged credentials become live. A failed
    // promotion never revokes the credential still used by existing consumers.
    provider.revoke_previous().await?;

    append_log(
        store,
        provider_name,
        &provider_config.secret_path,
        &None,
        sync_log,
        verified,
    )?;

    eprintln!("✓ Promoted dual-slot provider '{provider_name}' to live paths");
    Ok(())
}

/// Read-only dual-slot next-leaf checks for crown-jewel keypair providers (GAP-261).
///
/// Does **not** rotate, promote, or mutate the vault. Never prints PEM or private
/// material — only path presence and key ids (kids).
///
/// Checks (fail closed, non-zero via `Err`):
/// 1. `dual_slot = true`
/// 2. `{secret_path}-next-id` present and non-empty
/// 3. `public_key_path` configured and `{public_key_path}-next` present
/// 4. `computeKeyId(next public PEM)` equals the stored next-id kid
///
/// On success, prints a soak/promote checklist for the operator. Promote still
/// requires a separate owner `revvault rotation-promote` invocation.
pub fn verify_dual_slot(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> anyhow::Result<()> {
    if !provider_config.dual_slot {
        return Err(anyhow::anyhow!(
            "provider '{provider_name}': rotation-verify requires dual_slot=true in rotation.toml"
        ));
    }

    let next_id_path = key_id_path(&slots::next_path(&provider_config.secret_path));
    let next_id_raw = store.get(&next_id_path).map_err(|e| {
        anyhow::anyhow!("missing next-id leaf '{next_id_path}' (run dual-slot rotate first): {e}")
    })?;
    let stored_kid = next_id_raw.expose_secret().trim().to_string();
    if stored_kid.is_empty() {
        return Err(anyhow::anyhow!(
            "next-id leaf '{next_id_path}' is present but empty"
        ));
    }
    eprintln!("  ✓ next-id present at '{next_id_path}' kid={stored_kid}");

    let public_base = provider_config
        .settings
        .get("public_key_path")
        .map(String::as_str)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider '{provider_name}': rotation-verify needs settings.public_key_path \
                 to computeKeyId the next public PEM"
            )
        })?;
    let next_public_path = slots::next_path(public_base);
    let next_public = store.get(&next_public_path).map_err(|e| {
        anyhow::anyhow!(
            "missing next public leaf '{next_public_path}' (run dual-slot rotate first): {e}"
        )
    })?;
    // Presence only in the log line — PEM stays in process memory.
    eprintln!("  ✓ next public present at '{next_public_path}'");

    let computed = compute_key_id(next_public.expose_secret());
    if computed != stored_kid {
        return Err(anyhow::anyhow!(
            "kid mismatch: computeKeyId(next public)={computed} != stored next-id={stored_kid} \
             (paths: public='{next_public_path}', id='{next_id_path}')"
        ));
    }
    eprintln!("  ✓ computeKeyId(next public) matches next-id kid={stored_kid}");

    eprintln!();
    eprintln!("✓ Dual-slot next leaves consistent for provider '{provider_name}'");
    eprintln!();
    eprintln!("Operator checklist (this command never promotes or rotates):");
    eprintln!("  [ ] Soak NEXT kid ({stored_kid}) on hosted multi-key verify (GAP-259)");
    eprintln!("  [ ] Confirm remote readback if any sync targets applied");
    eprintln!("  [ ] Owner runs: revvault rotation-promote {provider_name}");
    eprintln!("      (overwrites the live signing key — not automatic)");
    eprintln!();
    eprintln!(
        "Note: copying docs/examples/rotation-license-signing.toml into \
         <store>/.revvault/rotation.toml is an owner store edit; this tool \
         does not mutate rotation.toml."
    );

    Ok(())
}

/// Print a dry-run plan without touching the vault or any API.
pub async fn dry_run(
    store: &PassageStore,
    provider_name: &str,
    provider_config: &ProviderConfig,
) -> anyhow::Result<()> {
    let id_path = key_id_path(&provider_config.secret_path);
    let is_local = provider_config.settings.get("type").map(String::as_str) == Some("local");

    let (current_key_for_provider, old_key_id) = if is_local {
        (SecretString::from(String::new()), None)
    } else {
        let current = store
            .get(&provider_config.secret_path)
            .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", provider_config.secret_path))?;
        let id = store
            .get(&id_path)
            .ok()
            .map(|s| s.expose_secret().to_string());
        (SecretString::from(current.expose_secret().to_string()), id)
    };

    let provider = build_provider(
        store,
        provider_name.to_string(),
        current_key_for_provider,
        old_key_id,
        &provider_config.settings,
    )?;

    provider.preflight().await?;

    let plan = provider.dry_run().await?;
    eprintln!("[dry run] Rotation plan for provider '{provider_name}':\n{plan}");

    if !provider_config.post_rotate.is_empty() {
        eprintln!(
            "[dry run] post_rotate hooks ({} command{}):",
            provider_config.post_rotate.len(),
            if provider_config.post_rotate.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for cmd in &provider_config.post_rotate {
            eprintln!("  - {cmd}");
        }
    }

    if let Some(ref verify_cmd) = provider_config.verify {
        eprintln!("[dry run] verify (strict): {verify_cmd}");
    }

    Ok(())
}

fn append_log(
    store: &PassageStore,
    provider: &str,
    secret_path: &str,
    new_key_id: &Option<String>,
    sync: Option<Vec<SyncLogEntry>>,
    verified: Option<bool>,
) -> anyhow::Result<()> {
    let log_dir = store.store_dir().join(".revvault");
    crate::service::assert_personal_path(&log_dir)?;
    let log_path = log_dir.join("rotation-log.jsonl");
    crate::service::assert_personal_path(&log_path)?;
    std::fs::create_dir_all(&log_dir)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let entry = RotationLogEntry {
        timestamp: Utc::now().to_rfc3339(),
        provider: provider.to_string(),
        secret_path: secret_path.to_string(),
        new_key_id: new_key_id.clone(),
        status: "success".into(),
        sync,
        verified,
    };

    let line = serde_json::to_string(&entry)?;
    writeln!(file, "{line}")?;

    Ok(())
}
