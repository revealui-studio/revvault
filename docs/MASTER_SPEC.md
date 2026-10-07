---
type: master-spec
repo: revvault
last-updated: 2026-07-23
owner: RevealUI Studio
staleness-status: FRESH
---

# RevVault — Master Spec

**Last Updated:** 2026-07-23  
**Status:** Pre-1.0 — production-grade for studio internal use; workspace **0.4.0**  
**Repo:** [RevealUIStudio/revvault](https://github.com/RevealUIStudio/revvault)

> Surface area, architecture, contracts. Companion to [`MASTER_PLAN.md`](./MASTER_PLAN.md) (status + roadmap).

---

## Mission

Age-encrypted secret vault for revealfleet. Source of truth for every secret per the fleet-wide secrets rule. CLI + Tauri 2 desktop app. 100% [passage](https://github.com/FiloSottile/passage)-compatible.

The trust story compresses to one sentence: *Secrets live in RevVault, encrypted by an age identity that doesn't leave the developer's machine.*

---

## Repository structure

```
revvault/
├── Cargo.toml                # workspace root
├── crates/
│   ├── core/                 # vault primitives — age encryption, path validation, namespace logic
│   ├── cli/                  # binary `revvault` — get/set/list/search/delete/edit/export-env/generate/sync/doctor/rotate
│   └── tauri-app/            # Tauri 2 backend (Rust commands) for the desktop UI
├── frontend/                 # React 19 desktop UI (consumes tauri-app commands)
├── scripts/                  # support scripts (test fixtures, dev helpers)
├── flake.nix                 # Nix dev shell
├── rust-toolchain.toml       # pinned Rust version
└── deny.toml                 # cargo-deny rules
```

### Crate boundaries

| Crate | Responsibility | Dependencies |
|---|---|---|
| `core` | age encryption/decryption, path validation, namespace parsing, vault traversal, manifest parsing | `age`, `serde`, `toml` |
| `cli` | argv parsing, command dispatch, terminal IO (clipboard, prompts), shell-friendly output | `core`, `clap`, `dialoguer` |
| `tauri-app` | Tauri command handlers wrapping `core` for the desktop UI | `core`, `tauri` |

The frontend never touches `core` directly — it goes through `tauri-app` IPC. This boundary keeps secret handling in Rust and out of the JS heap.

---

## CLI surface

| Command | Purpose | Example |
|---|---|---|
| `revvault get <path>` | Decrypt + print one secret to stdout (or clipboard via `--clip`) | `revvault get credentials/stripe/secret-key` |
| `revvault get --json <path>` | JSON output (path + value) — use this in non-TTY contexts; bare `get` returns empty in `$()` | `revvault --json get credentials/stripe/secret-key \| jq -r .value` |
| `revvault set <path>` | Encrypt + store from stdin or interactive prompt | `echo "sk_live_..." \| revvault set credentials/stripe/secret-key` |
| `revvault list [<prefix>]` | List secret paths, optionally namespace-filtered | `revvault list credentials/` |
| `revvault search <query>` | Fuzzy search across paths | `revvault search stripe` |
| `revvault delete <path>` | Remove a secret | `revvault delete credentials/old-key` |
| `revvault edit <path>` | Decrypt → open in `$EDITOR` → re-encrypt on save | `revvault edit credentials/stripe/secret-key` |
| `revvault export-env [<prefix>]` | Materialize `.env`-shaped output for direnv | `revvault export-env revealui/dev/ > .envrc.secret` |
| `revvault generate` | Generate a strong password (CSPRNG) | `revvault generate \| revvault set credentials/new` |
| `revvault sync vercel [--manifest <path>]` | Show diff between vault + Vercel env vars (default = dry-run; manifest defaults to `revvault-vercel.toml`) | `revvault sync vercel --manifest revvault-vercel.toml` |
| `revvault sync vercel --apply [--manifest <path>]` | Push vault values to Vercel; shape-validates each value before the API call | `revvault sync vercel --apply` |
| `revvault sync vercel --project <slug> --key <ENV>` | **Scoped** dry-run/apply (GAP-339). Repeatable flags. Prefer over unscoped `--apply` when rotating one credential. | `revvault sync vercel --project revealui-admin --key REVEALUI_SIGNUP_OPEN` |
| `revvault sync vercel --token <token> ...` | Override Vercel API token (or set `VERCEL_TOKEN` env var) | `revvault sync vercel --apply --token $VERCEL_TOKEN` |
| `revvault doctor [--manifest <path>] [--json]` | **0.2.0+** Vault-only health check — validates every manifest entry against its declared shape; exit 0 = all pass, exit 1 = failures found. Never touches Vercel. | `revvault doctor --manifest revvault-vercel.toml` |
| `revvault rotate <provider> [--dry-run]` | Run a full rotation for a `[providers.<name>]` block in `.revvault/rotation.toml`: dispatches to the `local`/`http`/`neon` provider, shape-validates the returned value, writes it to the vault, runs the sync hook + `post_rotate` hooks + optional strict `verify` gate, appends a log entry. `--dry-run` previews the plan without touching the vault or any API. | `revvault rotate vercel --dry-run` |
| `revvault rotation-status` | Print the last 10 entries from `.revvault/rotation-log.jsonl` | `revvault rotation-status` |

### Path conventions

Paths are lower-kebab, grouped by repo/product, then subsystem:

```
<project>/<subsystem>/<name>
```

Examples:

```
revealui/dev/electric/service-url
revealui/dev/electric/secret
revealui/prod/neon/postgres-url
revealui/prod/stripe/secret-key
revealui/prod/stripe/webhook-secret
revdev/license-signing-private-key
credentials/github/<account>
credentials/anthropic/<account>
ssh/<host>/<key-name>
```

The first path segment is the **namespace**; commands accept namespace prefixes for `list`/`export-env`/`sync`.

---

## Storage layout

```
$HOME/.revealui/passage-store/             # default vault root
├── revealui/
│   ├── dev/
│   │   ├── electric/
│   │   │   ├── service-url.age
│   │   │   └── secret.age
│   │   └── admin-session-cookie.age
│   └── prod/...
├── credentials/
│   └── github/joshua.age
└── ...
```

Each `.age` file is the encrypted secret. Filenames preserve the secret's logical extension (`.json`, `.pem`, etc.) ahead of `.age`.

### Identity

The age identity resolves in order: `identity` in `~/.config/revvault/config.toml`, then the `REVVAULT_IDENTITY` env var, then `~/.config/age/keys.txt` (XDG location, checked first), falling back to the legacy `~/.age-identity/keys.txt`. This file should never leave the developer's machine — that's the encryption boundary.

---

## Tauri desktop UI

Built on Tauri 2 + React 19. Surface mirrors the CLI plus richer browse/search:

| UI surface | Backed by |
|---|---|
| Search bar (fuzzy) | `core::search` via `tauri-app::search_secrets` |
| Tree browser (namespaces) | `core::list` via `tauri-app::list_secrets` |
| Detail pane (reveal/copy/delete/edit) | `core::{get,set,delete}` via tauri commands |
| Add new secret | `core::set` via `tauri-app::create_secret` |
| Import flow | `core::import` (categorizes by path heuristic) |

The desktop app is currently used internally; public release is **Phase 2** in `MASTER_PLAN.md` (notarization + auto-update pipeline pending).

---

## Sync surface

### Vercel sync manifest

Example `revvault-vercel.toml` manifest:

```toml
# revvault-vercel.toml — schema per crates/cli/src/commands/sync.rs ProjectSync
team_id = "team_abc123"  # optional; for personal accounts omit

[projects.revealui-prod]
project_id = "prj_xyz789"          # Vercel project ID (required)
vault_prefix = "revealui/prod/"    # secrets under this prefix sync as-is (required)
targets = ["production"]           # env targets list (default: ["production", "preview", "development"])
skip = ["VERCEL_AUTOMATION_TOKEN"] # var names to skip (integration-managed, etc.)

# per-var overrides — feature shipped via feat/sync-per-var-path-override
# Maps a Vercel var name to an absolute vault path; bypasses <vault_prefix>/<NAME> default
[projects.revealui-prod.vars]
DATABASE_URL = "revealui/prod/neon/postgres-url"
STRIPE_SECRET_KEY = "revealui/prod/stripe/secret-key"

# Inline-table form — optional `shape` constraint + optional `sensitive` marker.
# sensitive = true requests Vercel type `sensitive` on CREATE: the plaintext is
# never revealable in the Vercel UI/API after write. Use for credentials
# (Stripe keys, webhook secrets, signing/JWT secrets). Updates PATCH value-only
# and never change an existing row's type (flip = delete + re-create).
STRIPE_WEBHOOK_SECRET = { path = "revealui/prod/stripe/webhook-secret", shape = "stripe-webhook", sensitive = true }
```

The default behavior maps every `<vault_prefix>/<name>` to env var `NAME` for each target in `targets`. The per-var `[projects.<slug>.vars]` table maps a Vercel var name to a literal vault path, overriding the default prefix-based naming.

### Sync semantics

- `value-only PATCH` to Vercel API to preserve env-var type + target on update (`aa5ebf5`)
- CREATE requests Vercel type `sensitive` when the manifest marks the var `sensitive = true` OR any existing remote row with the same key is `sensitive` (preserve-on-re-create; sensitivity is never silently downgraded — 0.3.0). A rejected type fails the apply loudly naming the requested type; there is no fallback to `encrypted`.
- Type drift (manifest wants `sensitive`, remote row is not) is surfaced as a diff annotation; flipping an existing row requires delete + re-create.
- `remote_map` filtered by `target` to avoid multi-environment ID collision (`b571920`)
- Manifest schema enforced via `serde` deserialization
- Dry-run prints unified diff between vault state and remote state

---

## Rotation surface

`revvault rotate <provider>` is a fully implemented command (`crates/cli/src/commands/rotate.rs`), executed by `crates/core/src/rotation/executor.rs::execute`. It is not a stub: 26 integration tests cover it end to end (`crates/core/tests/rotation_integration.rs`).

Config is a `[providers.<name>]` block per provider in `<store>/.revvault/rotation.toml` (`crates/core/src/rotation/config.rs`). Provider dispatch is by `settings["type"]` (`crates/core/src/rotation/providers/mod.rs::build_provider`):

- `local`: cryptographically random value (`hex32` / `hex64` / `uuid`), no network (`crates/core/src/rotation/providers/local.rs`)
- absent or unrecognized: generic HTTP create + optional revoke pattern, for providers whose auth is the value being rotated, e.g. Stripe/Vercel/GitHub tokens (`crates/core/src/rotation/providers/http.rs`)
- `neon`: Neon Postgres password reset; the auth token is a separate vault secret at `settings["api_key_path"]` (`crates/core/src/rotation/providers/neon.rs`)

Execution steps (`executor.rs::execute`): read the current key and prior key ID from the vault, build and preflight the provider, run the rotation, shape-validate the returned value (abort on mismatch, old key unchanged), write the new key (and key ID) to the vault, apply the optional post-rotation sync hook (best-effort, failures logged), run `post_rotate` shell hooks (warn-on-failure), run an optional `verify` shell command that is strict (a failing verify writes `verified: false` to the log and exits non-zero, though the new key is already in the vault by that point), then append a JSON-line log entry to `.revvault/rotation-log.jsonl`. `revvault rotate <provider> --dry-run` runs preflight and prints the plan without touching the vault or any API (`executor.rs::dry_run`). `revvault rotation-status` prints the last 10 log entries (`crates/cli/src/commands/rotate.rs::status`).

Per-credential-type rotation runbook lives at [`revealui:docs/CREDENTIAL-ROTATION-RUNBOOK`](https://github.com/RevealUIStudio/revealui/blob/main/docs/CREDENTIAL-ROTATION-RUNBOOK).

---

## Security posture

- **Encryption boundary:** the age identity, resolved from `~/.config/age/keys.txt` (XDG, checked first) or the legacy `~/.age-identity/keys.txt`. Never copied to remote, never embedded in CI secrets, never logged.
- **Path validation:** directory traversal (`..`), null bytes, shell metacharacters rejected at the API layer in `core::path::validate`.
- **No plaintext on disk** outside a tmpfs-backed restore directory zeroized on command exit.
- **No logging of values** — debug logs reference paths, never decrypted bodies.
- **CI:** SHA-pinned 37 actions (`60c2912`); Tauri cross-platform build workflow (`9e54c1d`); cargo-deny (`deny.toml`); rust-toolchain pinned (`rust-toolchain.toml`); `gitleaks` scanned.

---

## Versioning

Pre-1.0 per the fleet versioning convention (RevealUI Studio internal). Cargo workspace crates use independent SemVer. Promotion to 1.0.0 gated on real external consumers + stable contract across at least one release cycle.

---

## Compose / coexistence

| Other product | Relationship |
|---|---|
| **RevealUI** | Consumer — every secret in RevealUI's `.env`/CI/runbook lives in RevVault per `secrets.md` rule |
| **RevealCoin** _(cancelled 2026-05-29)_ | Former consumer — its keypair files were destroyed when the product was cancelled; no longer a vault consumer |
| **RevDev** | Consumer — license signing keys |
| **RevForge** | Consumer — per-customer secrets at live path prefix `forge/customers/<slug>/*` (legacy `forge/` prefix in stamped kits) |
| **RevKit** | Sets up the age-identity mount path RevVault expects (`~/.config/age/keys.txt`, falling back to the legacy `~/.age-identity/keys.txt`) |
| **RevCon** | Independent — RevCon manages editor configs, doesn't touch secrets |
| **RevSkills** | Independent |

No reverse dependency: RevVault has no awareness of consumer products. The contract is the encrypted-file-on-disk format + the CLI surface.

---

## See also

- [`docs/MASTER_PLAN.md`](./MASTER_PLAN.md) — current status, phases, owner actions
- [`README.md`](../README.md) — quick start + setup
- Fleet master index (`MASTER_INDEX.md` in the RevealUI Studio internal coordination hub) — fleet-level navigation
- [`revealui:.claude/rules/secrets.md`](https://github.com/RevealUIStudio/revealui/blob/main/.claude/rules/secrets.md) — fleet-wide RevVault-first secrets rule
