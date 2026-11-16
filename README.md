# RevVault

> The canonical secret store for the entire RevealFleet. Age-encrypted vault with a CLI, a built-in TUI editor, and a Tauri desktop app. 100% [passage](https://github.com/FiloSottile/passage)-compatible.

Per the fleet-wide [secrets rule](https://github.com/RevealUIStudio/revealui/blob/test/.revealui/content/rules/stream-safe-secrets.md), every secret RevealUI depends on lives here — API keys, database URLs, webhook secrets, JWT/session keys, keypairs, license keys, OAuth client secrets, age identities, SSH keys, anything else. Interactive use resolves the configured age identity and store. Isolated service callers require their own identity, encrypted store and kernel-UID capability; the shared operator identity is not a service credential. Rotation updates the owning store and downstream targets (Vercel env vars, Fly app secrets) re-read from their configured source.

## Features

- **Encrypted at rest** — `.age` files using x25519 key exchange (the `age` crate, 0.11)
- **CLI.** `init`, `get`, `set`, `generate`, `list`, `search`, `export-env`, `edit`, `delete`, `migrate`, `sync`, `doctor`, `completions`, `rotate`, `rotation-verify`, `rotation-promote`, `rotation-status`. Global `--json` flag for structured output on every command.
- **Editing** — `edit` decrypts to `$EDITOR` (or the editor configured in `config.toml`) and re-encrypts on save. With no editor set it falls back to a built-in ratatui TUI editor. Decrypted plaintext only ever lands in a tmpfs/`memfd`-backed temp path that is zeroized and unlinked on exit.
- **Password generation** — `generate` produces a strong random password (configurable length, optional `--no-symbols` / `--no-ambiguous`), printed, copied to clipboard, or stored under a path.
- **Desktop app** — Tauri 2 backend (`crates/tauri-app`) + React 19 frontend (`frontend/`)
- **Namespaces** — secrets are organized by their first path segment. Built-in namespaces are `revealui/`, `credentials/`, `ssh/`, and `misc/`; any other first segment is treated as a dynamic project namespace (e.g. `revforge/`, `revdev/`).
- **Fuzzy search** — `search` finds secrets by partial path match
- **Migration** — `migrate` imports plaintext secret files from external sources with automatic categorization
- **Rotation.** `revvault rotate <provider>` runs a full rotation against `local`, `http`, `neon`, or `ed25519-keypair` providers (optional `dual_slot` writes `{path}-next` / `-previous`; promote with `revvault rotation-promote`) (auto-selected via `type` in `rotation.toml`): reads the current key, dispatches the provider, validates the returned value's shape, writes the new key back, applies the optional post-rotation sync hook, runs `post_rotate` hooks (warn-on-failure) and an optional strict `verify` gate, then appends a log entry. `--dry-run` previews the plan without touching the vault or any API. `rotation-verify` is a read-only dual-slot next-leaf check (presence + `computeKeyId` match; kids/paths only). `rotation-status` reports the last 10 log entries.
- **Downstream sync** — `sync vercel` and `sync fly` push vault secrets to Vercel env vars / Fly app secrets, driven by a TOML manifest. Dry-run by default (`--apply` to write), with declared-shape validation, orphan detection, a strict no-auto-delete policy, and an append-only audit log.
- **Path validation** — directory traversal and injection attacks blocked
- **Health check** — `doctor` reads every manifest entry and validates value shapes against their declared types

## Quick Start

### Isolated service capabilities

The fixed capability, identity, recipients and encrypted leaves now share one
persistent `/var/lib/revvault` namespace. A Machine replacement with the same
accepted image and intact volume can load the existing capability without
initialization, key generation or privileged restore. Preserve root ownership,
private service-group modes and immutable ancestors at the mount boundary.
Legacy split-root `/etc/revvault/services/<uid>.toml` capabilities are rejected,
including when a canonical policy also exists; no alias, fallback, automatic
adoption or rotation is provided. Previously deployed layouts require separately
reviewed migration and native proof. Historical receipts retain their old paths.


On Unix, the kernel UID selects `/var/lib/revvault/services/<uid>/policy.toml`; HOME,
environment variables and personal configuration cannot select another service
principal. The maintained core validates root ownership and immutable ancestors,
matching UID/GID with no foreign supplementary groups, and a private dedicated
store under `/var/lib/revvault/services/<uid>/` (`crates/core/src/service.rs`).
Each service needs its own age identity at `identity.txt`, encrypted leaves under
`store/`, and recipients at `store/.age-recipients`. Do not copy the operator,
controller or reviewer identity into the publisher store. Accepted provisioning
must prove cross-principal ciphertext cannot be decrypted and other principals
cannot read the service identity or store.

The version-1 policy contains `uid`, an exact absolute `command` array,
nonsecret `environment` settings and exact `secrets` environment-name/path
mappings. Unknown fields, traversal, loader-variable injection, mutable paths,
foreign groups and environment/config fallbacks deny access. Service stores
permit only those reads and filtered metadata; all writes are denied in the
shared store primitive (`crates/core/src/store.rs`). Service CLI callers can only
use the maintained `run` delivery path; print/export/mutation/provider commands
are rejected before execution (`crates/cli/src/main.rs`).

`revvault run --service -- <configured command>` requires that capability and
fails before opening a personal vault when it is absent. The exact policy command
receives a cleared environment containing only policy settings and mapped secrets;
caller `--env`, `--namespace` and alternate commands cannot widen it
(`crates/cli/src/commands/run.rs`). Provisioning the fixed policy, separate service
account/store and approved App references remains owner-gated. These source and
synthetic tests do not establish a deployed service boundary. Native Windows
service capabilities remain a separate durable acceptance target. Rotations stay
after implementation and validation.

The existing `init` command supports Linux service provisioning through
`init --service-policy <reviewed-policy> --service-request <request.json>`.
For a nonsecret preview, use `init --service-policy <reviewed-policy> --dry-run --json`
without `--service-request`: it creates no directories or encryption keys and ignores personal vault
environment/configuration. Service mode rejects personal store/identity overrides.
Application requires root, an immutable root-owned input policy, an existing
matching UID/GID account without foreign groups, and immutable command paths.
Initialization creates missing fixed root-owned service namespace ancestors
under `/var/lib/revvault/services`, refusing mutable
or symlink ancestors instead of repairing or adopting them. Initialization
creates a fresh independent identity and private store, with root ownership and
service-group read access; it publishes the immutable policy only after store
construction and directory syncing. Ordinary initialization rejects existing
paths. The maintained `init --service-policy <reviewed-policy> --resume --service-request <request.json>` mode
recovers only a fresh unbound store produced by this initializer: its root-only
pending record binds the canonical policy, immutable command file hashes,
identity and sole-recipient file hashes. Resume verifies exact fresh contents,
root/service-group ownership, protected modes, regular single-link files and
immutable ancestors before publishing the capability, then removes the pending
record. Finalized capabilities, missing provenance, changed policy/code/keys,
extra metadata/ciphertext, symlinks, hard links and unsafe permissions deny
without repair, adoption, key replacement or overwrite. Resume creates no
namespace ancestors and rejects personal overrides and `--dry-run`. A crash after policy publication also keeps runtime admission closed while pending
provenance exists. Exact reviewed resume locks that root-only provenance,
validates the published policy and fresh layout, and finishes without rewriting
policy or keys. Concurrent resumes serialize; finalized repeats deny. Older
unbound stores without provenance remain rejected. This command does not
provision accounts, import App
credentials, grant publication acceptance, or establish native isolation proof.

The explicit `native-service-tests` Cargo feature owns the disposable Linux root
fixture in `crates/core/tests/service_provisioning_native.rs`. It refuses an
operator host and provisions synthetic accounts/data only inside a fresh Docker
container. The fixture exercises positive scoped delivery, operator-store and
foreign-principal read denial, foreign supplementary groups, mutable authority,
inherited GitHub/Git/SSH environment stripping, and refusal to overwrite existing
service identity/policy. Its feature-only fault injector stops the owning
initializer after durable store publication and before capability publication;
native recovery tests verify unchanged identity/recipients and deny modified
provenance, files, authority and contents. The production CLI has no fault
selector. The existing `native-service-custody` CI job owns the digest-pinned
fixture build and isolated Docker CLI runs. It uses separate named volumes for
source custody, encrypted recovery evidence, separate synthetic recovery authority
and fresh restored custody, with no host mounts or runtime network. The restore
run mounts the recovery evidence and separate authority read-only. The authority
holds the synthetic recovery key, independently retained receipt and reviewed
policy; backup storage holds only the encrypted archive.
It verifies retained-volume replacement separately from independent fresh-volume
restore; neither regenerates the original service identity.

Compilation and default suite results do not count as native execution. This
primitive fixture does not establish acceptance of the three coding launchers,
the publisher production image, GitHub permissions, or hosted publication.

The root `Dockerfile` builds the existing CLI with `--locked --release` and two
compiler jobs. Its `runtime` target is an artifact image containing only
`/usr/local/bin/revvault`; it contains no operating system, policy, identity or
ciphertext. Consumers supply a compatible glibc runtime, fixed service account
and reviewed custody. The source-only Dockerfile context excludes operator
configuration and vault data. Publishing or consuming an artifact requires its
own source review; a successful local build grants no runtime acceptance.

The existing `set` command supports create-only scoped import with
`set --service-uid <uid> <approved-secret-path> --service-request <request.json>`. It requires root and loads the
same fixed immutable service policy/store; personal environment/configuration is
not consulted. Input is accepted only after authority/path preflight, through
noninteractive stdin with a 64 KiB limit; terminal input, empty/invalid UTF-8 and
NUL-containing values are denied. The input buffer is erased on success and on
partial-read/error exits, and input errors expose only a fixed denial code.
Secrets never travel through a value argument. Ciphertext
and new parent directories remain root-owned, with service-group read access and
no group/world write access. Other bindings, overwrite/rotation flags, visible
multiline input, mutation by the runtime, and personal-store fallback are denied.
Existing secret replacement remains with the separately reviewed rotation engine.
This import command requires an already provisioned service vault; it does not
create a policy, select a personal store, or grant activation acceptance.

The existing service preview also supports `--source-check`, together with
`--service-policy` and `--dry-run`. This root-only image-review interface verifies
immutable source paths and returns a versioned digest of the canonical policy,
declared service UID, running RevVault executable, and every absolute command
input. It creates no identity, store or capability. Source fingerprints are
review evidence, not provider or custody admission; the result explicitly keeps
`provider_admission` held. The normal unprivileged preview remains available.

The shared Fly GraphQL sync transport uses explicit caller-supplied credentials,
disables proxies, redirects and implicit HTTP retries, and bounds each network
exchange, including read retries, to five seconds. Request and response bodies
are each limited to 1 MiB. Bounded 429 retries are
available only for secret-name observations, within that same deadline. Secret
mutations are sent once. After dispatch, any HTTP, transport, timeout, malformed
or unacknowledged response returns `revvault_fly_mutation_outcome_unknown` with no
provider body or parser error chain. Request construction failures are separately
`revvault_fly_request_denied`. Unknown mutation outcomes require independent
reconciliation; they never authorize replay. A local HTTP deadline or cancellation
does not prove remote execution stopped. Only a typed `data.setSecrets`
acknowledgement with an explicit release object or null can report success.
The client erases its owned token and raw serialization/response buffers on drop;
this is not a claim to erase every HTTP-library or caller-owned copy.

This transport repair does not admit service provisioning: ordinary sync retains
its existing caller credential resolution, and the controller's older
`provision-shadow.ts#importSecrets` Fly CLI route still needs replacement through
the maintained service admission/transport boundary. Neither path may substitute
for accepted isolated provider authority, source/target binding or durable
operation/reconciliation evidence. The generic client has no durable ledger and
cannot stop a separate caller from invoking it again. The existing controller
signer path also imports remotely before publishing its local public-key file;
that sequence needs vault custody and durable interruption/reconciliation evidence
before rotation can be accepted. These remain tracked under INIT-003 stage 2
and [automation commissioning #3087](https://github.com/RevealUIStudio/revealui/issues/3087).

`FlyClient::verify_service_target` extends the existing Fly transport with a
read-only Machines observation. Its reviewed target pins an app, Machine and
instance, digest-only image, single custody volume at `/var/lib/revvault`, expected
UID/source-contract digest, and short expiry. The explicit read credential has
no operator-login, environment or personal-store fallback. The fixed Machines
endpoint disables proxies, redirects and retries, bounds response bytes and the
whole operation, and never returns provider bodies or arbitrary configuration.
Matching configuration produces at most 30 seconds of public evidence with
receiver identity, receiver sources and execution fencing still unverified and
provisioning held. It does not establish an atomic execution fence or authorize
any subsequent mutation.

On Linux, the generic personal configuration, store constructor, initializer and
write paths reject the reserved `/var/lib/revvault` namespace, including existing
symlink aliases and aliases introduced after opening a personal store. Root
must use the guarded service APIs; environment-selected personal paths cannot
adopt service custody. This protects maintained API use and accidental
configuration, not arbitrary filesystem access by a malicious root process.
Ordinary personal paths and existing personal symlink aliases remain supported;
dangling aliases are denied because their destination cannot be verified.

Every production service initialization, resume, restore and import now requires
an immutable root-owned `--service-request` JSON descriptor. The existing core
receiver owns admission and the mutation; lower write primitives are private.
The descriptor uses version 1, a globally unique 32-character lowercase hex
`request_id`, actual `uid`, `operation` (`initialize`, `resume`, `restore`, or
`import`), nullable `selector` (required only for import), nullable
`archive_sha256` (required only for restore), the exact `source_contract_sha256`,
a 64-character lowercase hex `expected_target_sha256`, and Unix `expires_at`
between 30 and 300 seconds ahead at admission. Extra fields deny. The target
fingerprint is recorded as an expectation only; this receiver cannot independently
attest the provider's app, Machine, instance or volume identity.

The CLI arms a fixed 30-second monotonic SIGKILL timer before service reads and
keeps it alive through output. Core callers must explicitly start and retain a
`ServiceReceiverDeadline`; it kills the whole process and is suitable only for a
dedicated receiver, never a shared server. It bounds this in-process receiver,
which spawns no child commands. It does not prove that pending kernel I/O or
provider execution has stopped. Every mutation requires a writable kernel mount
at exactly `/var/lib/revvault`, stable mount/device identity and immutable source
fingerprints. Admission exclusively creates a root-private, single-use claim in
`/var/lib/revvault/requests`, syncing the file and directory before custody writes.
Expiry, source/mount identity and the claim are rechecked after locks and before
publication. Only successful guarded execution can publish `local_complete`;
completion still records provider admission held. Failed, truncated, abandoned,
uncertain and completed claims all reject reuse; no cleanup or retry deletes them.
Distinct requests still obey existing create-only custody and locking rules.

Read-only reconciliation uses the existing command:
`init --service-policy <original-policy> --service-request <original-request.json> --request-status --json`.
It requires root, the same dedicated-process deadline and exact mount/source/UID
binding. It never reads stdin, creates journal directories, mutates custody,
repairs records or retries a mutation. Queries may inspect an expired original
request; mutation admission keeps its future expiry requirement. The three local
observations are `unobserved`, `held` and `local_completion_observed`. A completion
observation requires the exact original canonical claim and completion receipt;
visible bytes cannot prove the original writer's fsync returned. Durability,
process termination, execution fencing and rollback protection stay unverified;
provider admission stays held and `retry_authorized` is always false. Missing
records never prove absence of an in-flight or remote effect. Malformed, partial,
orphaned, linked, unsafe or mismatched records deny with a fixed code and remain
untouched. Source upgrades or a missing/changed mount can deny historical queries;
such a denial never becomes an unobserved or retry-authorizing result. Accepted
provider reconciliation requires independent execution/fencing evidence.

Remote dispatch remains blocked pending independently accepted root execution,
provider volume binding, execution fencing and uncertain-outcome reconciliation.
This volume-local ledger does not prevent storage rollback or cross-volume replay
and is deliberately absent from portable custody checkpoints. A restored volume
requires a separately reviewed dispatch authority; restoring is never a replay
grant. HTTP cancellation does not prove remote termination, and a Machine lease
protects configuration updates without establishing those guarantees. Uncertain
dispatch must remain held without replay or premature lease release. Complete
native and provider validation in the owning primitives before first App import;
generic Fly environment sync is not a replacement. Fleet INIT-003 stage 2 and
[automation issue #3087](https://github.com/RevealUIStudio/revealui/issues/3087)
track hosted commissioning; the canonical private App inventory owns accepted
identities and scoped credential references. None are inferred from source tests.

The maintained Linux service `backup` command accepts only a fixed service UID,
dedicated public age recovery recipient and create-only encrypted output path in
an immutable root-private directory. It snapshots only the active canonical
policy, original service identity, sole recipient and every approved ciphertext
selector. Incomplete stores cannot produce an admissible checkpoint. Root imports
and backups serialize on the same fixed directory lock.
Unknown metadata/selectors, pending initialization, symlinks, hardlinks, unsafe
ownership/modes, oversized inputs and reuse of the service recipient deny. The
checkpoint is independently age-encrypted before disk output; private material
never appears in its nonsecret receipt. Retain and independently accept that
receipt: age recipient encryption does not authenticate the checkpoint producer.

The existing service `init` command also supports `--restore-archive` together
with `--expected-sha256` from an independently accepted receipt. It requires the
reviewed service policy and reads the dedicated recovery identity only through
stdin. Restoration verifies the encrypted archive digest, age integrity, exact
canonical policy, fixed UID, immutable absolute command hashes, original
identity/recipient pairing and scoped ciphertext decryptability before creating
the destination. It stages in a root-private sibling directory, fsyncs files and
directories, and atomically publishes the complete store/capability without
replacement. Existing empty, pending or populated destinations deny; restore
cannot resume, override personal paths, adopt a store or rekey. Feature-only
native interruption before publication leaves no active capability. Abrupt
process death can leave inactive private staging; it never authorizes adoption.

These commands implement local custody checkpoints and restoration, not provider
upload, scheduling, retention monitoring, recovery-key provisioning or hosted
acceptance. Full accepted image/source provenance and separately trusted
transport remain required. No personal-store provider sync or manual copy recipe
is a substitute. Actual keys, provider credentials, activation and rotations
remain subject to their independent owner gates.

Service stores require exactly one encryption identity and its matching sole
recipient. The shared identity/recipient loaders reject malformed non-comment
lines instead of silently dropping them, including in personal vaults. Blank
lines, comments and supported valid key lines remain accepted; personal vaults
still support explicit valid multi-recipient sharing. Correct malformed key
metadata through its owning configuration before accepting this source change.

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

Personal initialization publishes identity and recipient files atomically without
replacing existing files. Concurrent initializers recover the actual winning
private identity. Public-key comments alone are insufficient: an existing
recipient list must contain a recipient derived from a real identity key.
Matching personal multi-recipient files remain unchanged; inconsistent or
comment-only identity files fail without replacing existing bytes.

On Linux, initialization walks directory components without following symlinks
and holds store, metadata and identity-parent descriptors through reads,
publication and directory syncing. Relative paths use one working-directory
anchor. Directory links and final file bindings are checked before success;
observed replacement or a changed working directory fails. Ancestor symlinks,
including symlinked store or identity parents, and `..` components are now
rejected. Ordinary absolute, relative and dot paths remain supported. Existing
directory modes are preserved; newly created directories and key files begin
private. Atomic no-replace rename support is required; no link/unlink publication
fallback is used. Retry syncs the held ancestor chain after interrupted creation
or acknowledgement and preserves an already-published key.

These checks observe bindings during initialization; returned paths do not carry
descriptor custody into later store operations. Same-UID mutation remains outside
the boundary, and stat-then-rename/unlink checks require a parent that excludes
untrusted writers. This is not a fixed per-admission ownership or permissions
policy. Personal configuration and PassageStore identity, recipient and ciphertext
operations still reopen paths. Surrounding root-service staging, directory
publication and later validation also retain path-based operations, with their
existing receiver gates intact. Non-Linux implementations retain their previous
behavior and are not covered by the Linux custody tests. Scoped execution proofs,
credential delivery and complete store/service custody remain outstanding; this
repair grants no automation or service capability.

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

# Export a scalar secret under its path's final component (SECRET_KEY)
eval "$(revvault export-env revealui/prod/stripe/secret-key --format scalar)"
# Auto cannot distinguish every scalar from assignments (for example EMPTY=).
# Use an explicit format for predictable scripts.
# Export a stored KEY=VALUE bundle (including empty values)
eval "$(revvault export-env revealui/env/license --format env)"

# Rotate a provider's key (dry-run, then apply).
# The provider must match a [providers.<name>] block in .revvault/rotation.toml
revvault rotate vercel --dry-run
revvault rotate vercel

# Dual-slot: verify next leaves (no promote; kids only)
revvault rotation-verify license-signing

# HTTP rotations revoke the old key only after persistence, sync, and verification.
# Dual-slot HTTP rotations keep it valid until `rotation promote`.
# A failed sync/verify retains the old remote key; reconcile consumers before
# manually revoking it. The old value/ID are preserved at <path>-previous[-id].

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

For a retryable single-secret conditional write, pipe the desired UTF-8 bytes to
`revvault set <path> --operation-id <UUID> --expected-current-sha256 <SHA256>`.
Use `--expected-absent` instead of a hash for creation. The hash describes the
exact decrypted current bytes; conditional stdin preserves whitespace. Reuse
an operation UUID only for the identical path, expected value and desired bytes.
The command prints a secret-free JSON receipt. A committed retry reports
`current_matches: false` if a later write replaced that operation's value; it
never restores the older value.

Conditional writes require Unix directory syncing. Interrupted prepared writes
fence ordinary reads and writes until the identical operation retries; the
journal and durable receipt are age-encrypted under the store's recipients.
Completed receipts are retained indefinitely; there is no automatic cleanup,
because removing a receipt would discard its operation's retry guarantee.
Writers require writable coordination metadata under `.revvault`. On Unix,
readers open an existing permanent lock read-only; historical read-only stores
without coordination metadata fail closed until supported writable bootstrap.
All maintained writers use the same OS lock, released automatically on process
exit. External Passage writers do not participate in this protocol. This
contract covers one leaf, not atomic promotion of several secrets.


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
| `revforge/customers/<slug>/<name>` | Operator/private RevForge tenant path (no public RevForge repo), e.g. `revforge/customers/acme/admin-password` |
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
├── revforge/                 # operator/private project namespace (RevForge is not a public repo)
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

[MIT](LICENSE).
