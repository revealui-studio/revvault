---
type: master-plan
repo: revvault
last-updated: 2026-07-23
owner: RevealUI Studio
staleness-status: FRESH
---

# RevVault — Master Plan

**Last Updated:** 2026-07-23  
**Status:** Active — production-grade for studio internal use (workspace `0.4.0`); commercial desktop packaging still pre-public-release  
**Owner:** RevealUI Studio  
**Repo:** [RevealUIStudio/revvault](https://github.com/RevealUIStudio/revvault)  
**Fleet master index:** RevealUI Studio internal coordination hub (`MASTER_INDEX.md`, private).

> Fleet-level cross-cutting plans live in the internal coordination hub. This file is RevVault-scoped only.  
> **Code-over-docs:** when this plan and `Cargo.toml` / CLI sources disagree, trust the code.

---

## Headline state

RevVault is the **canonical age-encrypted secret store** for revealfleet. CLI (`revvault`), optional TUI edit path, and Tauri 2 desktop app. Passage-compatible on-disk layout under `~/.revealui/passage-store` (override `REVVAULT_STORE`).

Workspace version: **`0.4.0`** (`Cargo.toml` `[workspace.package]`, `CHANGELOG.md`).

---

## Current reality (2026-07-23)

### What exists

- **Cargo workspace** — `crates/core`, `crates/cli`, `crates/tauri-app` (edition 2021, rust-version 1.88)
- **Frontend** — Tauri 2 + React 19 + Tailwind v4 at `frontend/`
- **Encryption** — age x25519; identity resolution: config → `REVVAULT_IDENTITY` → `~/.config/age/keys.txt` → legacy `~/.age-identity/keys.txt`
- **CLI** — get/set/list/search/delete/edit/export-env/generate/sync/doctor/rotate/rotation-status (see `docs/MASTER_SPEC.md`)
- **Sync** — Vercel push-only (`--pull` removed in 0.2.0); shape validation; `sensitive` create preservation (0.3.0)
- **Rotation** — providers `local` / HTTP / neon; shape gates; rotation log
- **0.4.0** — `get` fails loud on decrypt failure; empty-value warning on stderr

### What works

| Capability | Status | Confidence |
|---|---|---|
| Core get/set/list/delete/search/export-env | Built | High — studio production path |
| `doctor` vault-only shape check | Built | High — 0.2.0+ |
| Vercel sync push + sensitive preserve | Built | High — 0.3.0+ |
| Rotation engine | Built | High — integration-tested |
| Tauri desktop UI | Built | Medium — internal; notarized public release not cut |
| `get` loud decrypt fail | Built | High — 0.4.0 |

### Residuals

| Item | Notes |
|---|---|
| Public desktop release | Notarization + auto-update pipeline still owner-gated |
| Cross-machine vault sync server | Single-machine vault; Vercel is one-way deploy mirror |
| Multi-identity team vault model | Single age identity per operator machine today |
| Audit log for every get/set | Not a first-class product surface yet |

---

## Composition with revealfleet

RevVault is source of truth per fleet `secrets.md`. Consumers (RevealUI, RevDev, RevForge, …) read paths; they do not re-own encryption.

Commercial packaging: Pro-tier desktop + rotation packaging may wrap RevealUI Pro; CLI/core remain MIT.

---

## Roadmap (compressed)

| Phase | Intent | State |
|---|---|---|
| 0–1 | CLI + core vault + passage layout | Done |
| 2 | Desktop packaging (signed/notarized) | Residual / owner-gated |
| 3 | Hardening already shipping (doctor, shapes, sensitive, loud get) | Largely done through 0.4.0 |
| 4 | Multi-machine / multi-identity | Deferred |

---

## Owner action queue

| # | Item | Priority |
|---|---|---|
| 1 | Public Tauri release pipeline (sign + notarize + auto-update) | Medium |
| 2 | Align any consumer docs still saying workspace `0.3.0` | Low (this plan + README fixed 2026-07-23) |

---

## See also

- [`docs/MASTER_SPEC.md`](./MASTER_SPEC.md)  
- [`../README.md`](../README.md)  
- [`../CHANGELOG.md`](../CHANGELOG.md)  
