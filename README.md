# RevVault

> The canonical secret store for the entire revealfleet. Age-encrypted vault with a CLI, a built-in TUI editor, and a Tauri desktop app. 100% [passage](https://github.com/FiloSottile/passage)-compatible.

Per the fleet-wide [secrets rule](https://github.com/RevealUIStudio/revealui/blob/main/.claude/rules/secrets.md), every secret RevealUI depends on lives here — API keys, database URLs, webhook secrets, JWT/session keys, keypairs, license keys, OAuth client secrets, age identities, SSH keys, anything else. One encryption boundary (the age identity) gates the whole fleet; rotation updates one store and downstream targets (Vercel env vars, Fly app secrets) re-read from the same source.

## Features

- **Encrypted at rest** — `.age` files using x25519 key exchange (the `age` crate, 0.11)
- **CLI.** `init`, `get`, `set`, `generate`, `list`, `search`, `export-env`, `edit`, `delete`, `migrate`, `sync`, `doctor`, `completions`, `rotate`, `rotation-status`. Global `--json` flag for structured output on every command.
- **Editing** — `edit` decrypts to `$EDITOR` (or the editor configured in `config.toml`) and re-encrypts on save. With no editor set it falls back to a built-in ratatui TUI editor. Decrypted plaintext only ever lands in a tmpfs/`memfd`-backed temp path that is zeroized and unlinked on exit.
- **Password generation** — `generate` produces a strong random password (configurable length, optional `--no-symbols` / `--no-ambiguous`), printed, copied to clipboard, or stored under a path.
- **Desktop app** — Tauri 2 backend (`crates/tauri-app`) + React 19 frontend (`frontend/`)
- **Namespaces** — secrets are organized by their first path segment. Built-in namespaces are `revealui/`, `credentials/`, `ssh/`, and `misc/`; any other first segment is treated as a dynamic project namespace (e.g. `revforge/`, `revdev/`).
- **Fuzzy search** — `search` finds secrets by partial path match
- **Migration** — `migrate` imports plaintext secret files from external sources with automatic categorization
- **Rotation.** `revvault rotate <provider>` runs a full rotation against `local`, `http`, `neon`, or `ed25519-keypair` providers (optional `dual_slot` writes `{path}-next` / `-previous`; promote with `revvault rotation-promote`) (auto-selected via `type` in `rotation.toml`): reads the current key, dispatches the provider, validates the returned value's shape, writes the new key back, applies the optional post-rotation sync hook, runs `post_rotate` hooks (warn-on-failure) and an optional strict `verify` gate, then appends a log entry. `--dry-run` previews the plan without touching the vault or any API. `rotation-status` reports the last 10 log entries.
- **Downstream sync** — `sync vercel` and `sync fly` push vault secrets to Vercel env vars / Fly app secrets, driven by a TOML manifest. Dry-run by default (`--apply` to write), with declared-shape validation, orphan detection, a strict no-auto-delete policy, and an append-only audit log.
- **Path validation** — directory traversal and injection attacks blocked
- **Health check** — `doctor` reads every manifest entry and validates value shapes against their declared types

## Quick Start

### Prerequisites

- [Nix](https://nixos.org/download/) with flakes enabled
- An age identity at `~/.config/age/keys.txt` (XDG location, checked first) or the legacy `~/.age-identity/keys.txt`

### Build

```bash
cd ~/revealfleet/revvault
direnv allow  # or: nix develop
cargo build --workspace
```

### CLI Usage

```bash
# Initialize a new vault (creates the store directory and an age identity)
revvault init

# Store a secret
echo "sk_live_abc123" | revvault set revealui/prod/stripe/secret-key

# Retrieve it (TTY print; use vault-private / REVVAULT_ALLOW_PRINT=1 under STREAM_SAFE)
revvault get revealui/prod/stripe/secret-key

# Stream-safe: inject into child env only (paths on argv, never values)
revvault run --env STRIPE_SECRET_KEY=revealui/dev/stripe/secret-key -- pnpm stripe:seed -- --dry-run
revvault run --namespace stripe --namespace neon -- pnpm billing:catalog:sync -- --mode test

# Structured output (use --json in scripts — bare `revvault get` is silent in $(...))
revvault --json get revealui/prod/stripe/secret-key | jq -r .value

# Copy to clipboard instead of printing (not stream-safe; vault-private only)
revvault get revealui/prod/stripe/secret-key --clip

# Generate a strong password and store it (default length 32)
revvault generate revealui/prod/some/api-key
revvault generate --length 48 --no-ambiguous --clip

# List
revvault list
revvault list --tree

# Fuzzy search
revvault search stripe

# Edit in $EDITOR (or the built-in TUI editor when EDITOR is unset)
revvault edit revealui/prod/stripe/secret-key

# Export as KEY=VALUE for shell eval
eval "$(revvault export-env revealui/prod/stripe/secret-key)"

# Rotate a provider's key (dry-run, then apply).
# The provider must match a [providers.<name>] block in .revvault/rotation.toml
revvault rotate vercel --dry-run
revvault rotate vercel

# Show the last 10 rotation log entries
revvault rotation-status

# Push vault secrets to Vercel env vars (dry-run, then apply)
revvault sync vercel --manifest revvault-vercel.toml
revvault sync vercel --manifest revvault-vercel.toml --apply

# Push vault secrets to a Fly app's secrets
revvault sync fly --manifest fly-secrets.toml --apply

# Validate the store (read every entry, check shapes)
revvault doctor

# Migrate plaintext secret files into the vault
revvault migrate --plaintext-dir <source>

# Delete
revvault delete revealui/prod/stripe/secret-key

# Shell completions
revvault completions bash >> ~/.bashrc
```

### Desktop App

```bash
nix develop
cargo tauri dev
```

## Canonical paths

Paths are lower-kebab, grouped by repo or product, then by subsystem:

| Pattern | Example |
|---|---|
| `revealui/dev/<subsystem>/<name>` | `revealui/dev/electric/service-url`, `revealui/dev/admin-session-cookie` |
| `revealui/prod/<subsystem>/<name>` | `revealui/prod/neon/postgres-url`, `revealui/prod/stripe/secret-key`, `revealui/prod/stripe/webhook-secret` |
| `revealui/prod/storage/r2/<name>` | `revealui/prod/storage/r2/access-key-id` |
| `revforge/customers/<slug>/<name>` | `revforge/customers/acme/admin-password` |
| `revdev/<name>` | `revdev/license-signing-private-key` |
| `credentials/<system>/<name>` | `credentials/github/personal-token`, `credentials/anthropic/api-key` |

New paths get a `docs/SECRETS.md` entry in the relevant repo. Mirroring to CI is a publish step, never hand-typed.

## Configuration

Store, identity, editor, and tmpdir resolve in this order — config file wins, then environment, then platform default:

| Setting | Config file (`~/.config/revvault/config.toml`) | Env var | Default |
|---|---|---|---|
| Store directory | `store_path` | `REVVAULT_STORE` (or legacy `PASSAGE_DIR`) | `~/.revealui/passage-store` |
| Identity file | `identity` | `REVVAULT_IDENTITY` | `~/.config/age/keys.txt`, then `~/.age-identity/keys.txt` |
| Editor | `editor` (`"builtin"` forces the TUI editor) | `EDITOR` | built-in TUI editor |
| Temp dir (for edit) | `tmpdir` | `TMPDIR` | `/dev/shm` / `memfd` / OS temp dir |

## Architecture

```
crates/core       — shared library (store, crypto, identity, config, namespaces, import, rotation, sync, init)
crates/cli        — revvault CLI binary (clap)
crates/tauri-app  — Tauri 2 desktop backend
frontend/         — React 19 + TypeScript + Tailwind CSS v4 (Vite)
```

Workspace at version `0.4.0` (pre-1.0 per fleet versioning; see `Cargo.toml` workspace package + `CHANGELOG.md`).

## Store Format

Secrets live in a directory hierarchy as `.age` files:

```
~/.revealui/passage-store/
├── .age-recipients
├── revealui/
│   ├── dev/
│   │   └── electric/service-url.age
│   └── prod/
│       ├── neon/postgres-url.age
│       └── stripe/secret-key.age
├── revforge/
│   └── customers/
│       └── acme/admin-password.age
├── credentials/
│   └── github/personal-token.age
└── ssh/
    └── github.age
```

## Development

```bash
# Enter dev shell
direnv allow  # or: nix develop

# Run all CI checks (fmt, clippy, tests, frontend build)
bash scripts/ci.sh

# Run tests
cargo test --workspace

# Run specific crate tests
cargo test -p revvault-core
cargo test -p revvault-cli
```

Library errors use `thiserror`; binary errors use `anyhow`. Decrypted values are wrapped in `secrecy::SecretString` and never logged. All encryption goes through the `age` crate — no custom crypto.

## License

MIT.
