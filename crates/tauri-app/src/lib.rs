mod clipboard_expiry;
mod state;

use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use arboard::Clipboard;
use revvault_core::init::{init_vault, InitOptions};
use revvault_core::rotation::{executor, RotationConfig};
use secrecy::ExposeSecret;
use tauri::{State, WebviewWindow};
use zeroize::Zeroizing;

use state::AppState;

static CLIPBOARD_GENERATION: Mutex<u64> = Mutex::new(0);

#[tauri::command]
fn init_store(state: State<AppState>) -> Result<(), String> {
    state.init()
}

#[tauri::command]
fn list_secrets(state: State<AppState>, prefix: Option<String>) -> Result<Vec<SecretInfo>, String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;
    let entries = store.list(prefix.as_deref()).map_err(|e| e.to_string())?;

    Ok(entries
        .into_iter()
        .map(|e| SecretInfo {
            path: e.path,
            namespace: e.namespace.to_string(),
        })
        .collect())
}

/// Fail closed before decrypting when a native dialog cannot be presented.
fn ensure_native_dialog_available() -> Result<(), String> {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return Err("native dialog unavailable (no DISPLAY or WAYLAND_DISPLAY)".into());
        }
    }
    Ok(())
}

/// Show a vault secret in a native OS dialog owned by Rust.
///
/// The plaintext never crosses Tauri IPC. A compromised webview therefore
/// cannot read the value from the command return. Prefer [`copy_secret`]
/// when the operator only needs the clipboard.
///
/// The OS dialog text is visible to the seated operator and to anything that
/// can capture that window. Availability is checked before decrypt.
#[tauri::command]
fn reveal_secret(
    window: WebviewWindow,
    state: State<AppState>,
    path: String,
) -> Result<(), String> {
    ensure_native_dialog_available()?;
    let value = read_secret(&state, &path)?;
    let title = format!("Secret: {path}");
    let parent = window.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    window
        .run_on_main_thread(move || {
            let result = rfd::MessageDialog::new()
                .set_title(&title)
                .set_description(value.as_str())
                .set_buttons(rfd::MessageButtons::Ok)
                .set_parent(&parent)
                .show();
            let _ = tx.send(result);
        })
        .map_err(|e| e.to_string())?;
    match rx.recv().map_err(|e| e.to_string())? {
        rfd::MessageDialogResult::Ok => Ok(()),
        other => Err(format!("native dialog did not complete: {other}")),
    }
}

#[tauri::command]
fn set_secret(
    state: State<AppState>,
    path: String,
    value: String,
    force: bool,
) -> Result<(), String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;

    if force {
        store
            .upsert(&path, value.as_bytes())
            .map_err(|e| e.to_string())
    } else {
        store
            .set(&path, value.as_bytes())
            .map_err(|e| e.to_string())
    }
}

#[tauri::command]
fn delete_secret(state: State<AppState>, path: String) -> Result<(), String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;
    store.delete(&path).map_err(|e| e.to_string())
}

#[tauri::command]
fn search_secrets(state: State<AppState>, query: String) -> Result<Vec<SecretInfo>, String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;
    let entries = store.search(&query).map_err(|e| e.to_string())?;

    Ok(entries
        .into_iter()
        .map(|e| SecretInfo {
            path: e.path,
            namespace: e.namespace.to_string(),
        })
        .collect())
}

#[tauri::command]
fn init_vault_cmd() -> Result<InitSummary, String> {
    let summary = init_vault(InitOptions::default()).map_err(|e| e.to_string())?;
    Ok(InitSummary {
        store_dir: summary.store_dir.to_string_lossy().into_owned(),
        identity_file: summary.identity_file.to_string_lossy().into_owned(),
        public_key: summary.public_key,
        store_existed: summary.store_existed,
        identity_existed: summary.identity_existed,
    })
}

fn read_secret(state: &AppState, path: &str) -> Result<Zeroizing<String>, String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;
    let secret = store.get(path).map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(secret.expose_secret().to_string()))
}

/// Copy a vault secret to the clipboard without sending the value to JS.
///
/// Auto-clears after 45 seconds if the clipboard still holds this value.
#[tauri::command]
fn copy_secret(state: State<AppState>, path: String) -> Result<(), String> {
    let value = read_secret(&state, &path)?;
    let mut generation = CLIPBOARD_GENERATION.lock().map_err(|e| e.to_string())?;

    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    clipboard
        .set_text(value.as_str())
        .map_err(|e| e.to_string())?;
    *generation = generation.wrapping_add(1);
    let ticket = *generation;
    drop(generation);

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(45));
        if let Ok(generation) = CLIPBOARD_GENERATION.lock() {
            if let Ok(mut cb) = Clipboard::new() {
                if let Ok(current) = cb.get_text() {
                    if clipboard_expiry::should_clear(ticket, *generation, &value, &current) {
                        let _ = cb.set_text("");
                    }
                }
            }
        }
    });

    Ok(())
}

#[tauri::command]
fn list_rotation_providers(state: State<AppState>) -> Result<Vec<ProviderInfo>, String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;
    let store_dir = store.store_dir().to_path_buf();
    drop(guard);

    let config = RotationConfig::load(&store_dir).map_err(|e| e.to_string())?;
    let mut providers: Vec<ProviderInfo> = config
        .providers
        .into_iter()
        .map(|(name, p)| ProviderInfo {
            name,
            secret_path: p.secret_path,
        })
        .collect();
    providers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(providers)
}

#[tauri::command]
async fn rotate_secret(state: State<'_, AppState>, provider_name: String) -> Result<(), String> {
    // Briefly lock to get store_dir — released before any await
    let store_dir = {
        let guard = state.store.lock().map_err(|e| e.to_string())?;
        let store = guard.as_ref().ok_or("Store not initialized")?;
        store.store_dir().to_path_buf()
    };

    let rotation_config = RotationConfig::load(&store_dir).map_err(|e| e.to_string())?;
    let provider_config = rotation_config
        .providers
        .get(&provider_name)
        .ok_or_else(|| format!("Provider '{provider_name}' not found in rotation.toml"))?
        .clone();

    // Open a fresh store so no lock is held across the async HTTP calls
    let config = revvault_core::Config::resolve().map_err(|e| e.to_string())?;
    let store = revvault_core::PassageStore::open(config).map_err(|e| e.to_string())?;

    executor::execute(&store, &provider_name, &provider_config)
        .await
        .map_err(|e| e.to_string())
}

#[derive(serde::Serialize)]
struct ProviderInfo {
    name: String,
    secret_path: String,
}

#[derive(serde::Serialize)]
struct SecretInfo {
    path: String,
    namespace: String,
}

#[derive(serde::Serialize)]
struct InitSummary {
    store_dir: String,
    identity_file: String,
    public_key: String,
    store_existed: bool,
    identity_existed: bool,
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            init_store,
            init_vault_cmd,
            list_secrets,
            reveal_secret,
            set_secret,
            delete_secret,
            search_secrets,
            copy_secret,
            list_rotation_providers,
            rotate_secret,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_secret_errors_when_store_uninitialized() {
        let state = AppState::new();
        let err = read_secret(&state, "misc/token").unwrap_err();
        assert_eq!(err, "Store not initialized");
    }

    #[test]
    fn native_dialog_fails_closed_without_display_on_linux() {
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            if std::env::var_os("DISPLAY").is_none()
                && std::env::var_os("WAYLAND_DISPLAY").is_none()
            {
                let err = ensure_native_dialog_available().unwrap_err();
                assert!(err.contains("native dialog unavailable"));
            }
        }
    }
}
