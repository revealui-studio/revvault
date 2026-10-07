# Revvault

Age-encrypted secret vault with CLI and Tauri desktop app.

## Architecture

- `crates/core` — shared library (store, crypto, identity, config, namespaces, import, rotation)
- `crates/cli` — `revvault` CLI binary (clap)
- `crates/tauri-app` — Tauri 2 desktop backend
- `frontend/` — React 19 + TypeScript + Tailwind CSS (Vite)

## Build

Requires Nix with flakes enabled. From WSL:

```bash
cd ~/revealfleet/revvault
direnv allow  # or: nix develop
cargo build --workspace
cargo tauri dev
```

## Store Format

100% passage-compatible. Secrets stored as `.age` files in a directory hierarchy.
Default store: `~/.revealui/passage-store`. Override with `REVVAULT_STORE` env var.

## Conventions

- Rust edition 2021, stable channel
- `thiserror` for library errors, `anyhow` for binary/CLI errors
- `secrecy::SecretString` for decrypted values in memory
- Frontend uses Tailwind v4 (CSS import, no config file)
