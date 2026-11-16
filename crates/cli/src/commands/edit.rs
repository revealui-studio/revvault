use std::path::PathBuf;
use std::process::Command;

use clap::Args;
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use revvault_core::Config;
use revvault_core::PassageStore;

use crate::tui_editor;

// Cross-platform handle for the optional memfd-backed temp storage.
//
// On Linux, `secure_tmp` may return a real `memfd::Memfd` (Strategy 2
// below) for in-RAM storage that bypasses the filesystem entirely. The
// kernel reclaims the memory when this handle is dropped.
//
// On macOS and Windows, that code path is gated out (`#[cfg(target_os =
// "linux")]`), so the handle slot must exist in the type signature but
// can never be populated. `std::convert::Infallible` is the empty enum,
// so `Option<Infallible>` is a type that can only ever be `None` —
// exactly the contract we want, with zero runtime cost.
#[cfg(target_os = "linux")]
type MemfdHandle = memfd::Memfd;
#[cfg(not(target_os = "linux"))]
type MemfdHandle = std::convert::Infallible;

#[derive(Args)]
pub struct EditArgs {
    /// Secret path to edit
    pub path: String,
}

/// Minimal struct carrying only what `secure_tmp` needs, so we do not have to
/// clone the full `Config` (which is consumed by `PassageStore::open`).
struct TmpConfig {
    tmpdir: Option<PathBuf>,
}

pub fn run(args: EditArgs) -> anyhow::Result<()> {
    let config = Config::resolve()?;

    // Extract fields we need before config is consumed by PassageStore::open.
    let editor_field = config.editor.clone();
    let tmp_config = TmpConfig {
        tmpdir: config.tmpdir.clone(),
    };

    let store = PassageStore::open(config)?;
    let secret = store.get(&args.path)?;
    let current = Zeroizing::new(secret.expose_secret().to_string());

    // Determine which editor to use.
    let editor_cmd = editor_field
        .or_else(|| std::env::var("EDITOR").ok())
        .unwrap_or_else(|| "builtin".into());

    if editor_cmd == "builtin" {
        // Built-in TUI editor — no temp file needed.
        match tui_editor::edit(&args.path, &current)? {
            None => {
                eprintln!("No changes made.");
            }
            Some(new_content) => {
                let new_content = Zeroizing::new(new_content);
                let trimmed = Zeroizing::new(new_content.trim().to_string());
                if *trimmed == current.trim() {
                    eprintln!("No changes made.");
                } else {
                    store.upsert(&args.path, trimmed.as_bytes())?;
                    eprintln!("{}", super::set::stored_confirmation(&args.path, &trimmed));
                }
            }
        }
        return Ok(());
    }

    // External editor path: write decrypted content to a secure temp file.
    let temporary = secure_tmp(&tmp_config, &current)?;
    let tmp_path = &temporary.path;

    let parts: Vec<&str> = editor_cmd.split_whitespace().collect();
    let (bin, extra_args) = parts
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("EDITOR is empty"))?;

    let bin_path = which::which(bin)
        .map(|p| p.into_os_string())
        .unwrap_or_else(|_| std::ffi::OsString::from(*bin));

    let status = Command::new(&bin_path)
        .args(extra_args)
        .arg(tmp_path)
        .status()?;

    if !status.success() {
        anyhow::bail!("editor exited with non-zero status");
    }

    // Read back and re-encrypt
    let new_value = Zeroizing::new(std::fs::read_to_string(tmp_path)?);
    let trimmed = Zeroizing::new(new_value.trim().to_string());

    // Zero out the temp file contents on disk before removal
    drop(temporary);

    if *trimmed == current.trim() {
        eprintln!("No changes made.");
        return Ok(());
    }

    store.upsert(&args.path, trimmed.as_bytes())?;
    eprintln!("{}", super::set::stored_confirmation(&args.path, &trimmed));

    Ok(())
}

/// Returns an owner that cleans plaintext on every normal return path.
///
/// Priority:
///   1. Linux/WSL2: `/dev/shm` if it is a tmpfs mount
///   2. Linux: `memfd_create` — anonymous in-memory storage
///   3. macOS: `NamedTempFile` with `F_NOCACHE`
///   4. `config.tmpdir` / `TMPDIR` / OS default tempdir
#[allow(unused_variables)]
fn secure_tmp(config: &TmpConfig, content: &str) -> anyhow::Result<SecretTemp> {
    // --- Strategy 1: /dev/shm tmpfs (Linux / WSL2) ---
    // Preferred over memfd because GUI editors (Zed, VS Code) use atomic
    // temp-rename saves that require a real filesystem path.
    #[cfg(target_os = "linux")]
    {
        use nix::sys::statfs::statfs;
        // TMPFS_MAGIC = 0x01021994
        const TMPFS_MAGIC: i64 = 0x0102_1994_u32 as i64;
        if let Ok(st) = statfs("/dev/shm") {
            if st.filesystem_type().0 == TMPFS_MAGIC {
                let shm_tmp = tempfile::NamedTempFile::new_in("/dev/shm")?;
                std::fs::write(shm_tmp.path(), content)?;
                let path = shm_tmp.path().to_path_buf();
                // Retain ownership so error exits also scrub and unlink.
                return Ok(SecretTemp {
                    path,
                    memfd: None,
                    file: Some(shm_tmp),
                });
            }
        }
    }

    // --- Strategy 2: memfd_create (Linux, terminal editors only) ---
    // Only works with editors that do direct write() without temp-rename.
    // Kept as fallback when /dev/shm is unavailable.
    #[cfg(target_os = "linux")]
    {
        use memfd::MemfdOptions;
        use std::io::Write as _;
        if let Ok(mfd) = MemfdOptions::default()
            .allow_sealing(false)
            .close_on_exec(false)
            .create("revvault-edit")
        {
            let mut f = mfd.as_file();
            f.write_all(content.as_bytes())?;
            let fd_num = {
                use std::os::unix::io::AsRawFd;
                mfd.as_raw_fd()
            };
            let proc_path = PathBuf::from(format!("/proc/{}/fd/{fd_num}", std::process::id()));
            return Ok(SecretTemp {
                path: proc_path,
                memfd: Some(mfd),
                file: None,
            });
        }
    }

    // --- Strategy 3: macOS — disable OS caching ---
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let tmp = tempfile::NamedTempFile::new_in(std::env::temp_dir())?;
        // Disable OS-level read/write caching for this fd
        unsafe {
            libc::fcntl(tmp.as_file().as_raw_fd(), libc::F_NOCACHE, 1i32);
        }
        std::fs::write(tmp.path(), content)?;
        let path = tmp.path().to_path_buf();
        return Ok(SecretTemp {
            path,
            memfd: None,
            file: Some(tmp),
        });
    }

    // --- Strategy 4: config.tmpdir / TMPDIR / OS default ---
    #[allow(unreachable_code)]
    {
        let base_dir = config
            .tmpdir
            .clone()
            .or_else(|| std::env::var("TMPDIR").ok().map(PathBuf::from))
            .unwrap_or_else(std::env::temp_dir);
        let tmp = tempfile::NamedTempFile::new_in(&base_dir)?;
        std::fs::write(tmp.path(), content)?;
        let path = tmp.path().to_path_buf();
        Ok(SecretTemp {
            path,
            memfd: None,
            file: Some(tmp),
        })
    }
}

/// Owns plaintext storage through every early return, including editor spawn/read errors.
struct SecretTemp {
    path: PathBuf,
    memfd: Option<MemfdHandle>,
    file: Option<tempfile::NamedTempFile>,
}

impl Drop for SecretTemp {
    fn drop(&mut self) {
        if self.memfd.is_none() {
            if let Ok(meta) = std::fs::metadata(&self.path) {
                let _ = std::fs::write(&self.path, vec![0u8; meta.len() as usize]);
            }
            // Editors may replace the inode during save; remove the path too.
            let _ = std::fs::remove_file(&self.path);
        }
        self.file.take();
        self.memfd.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plaintext_is_removed_after_editor_spawn_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let path = file.path().to_path_buf();
        std::fs::write(&path, "synthetic secret").unwrap();
        let run = || -> std::io::Result<()> {
            let temporary = SecretTemp {
                path: path.clone(),
                memfd: None,
                file: Some(file),
            };
            Command::new(dir.path().join("missing-editor"))
                .arg(&temporary.path)
                .status()?;
            Ok(())
        };
        assert!(run().is_err());
        assert!(!path.exists());
    }
}
