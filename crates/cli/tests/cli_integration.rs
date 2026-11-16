use assert_cmd::Command;
use predicates::prelude::*;
use secrecy::ExposeSecret;
use std::path::Path;
use tempfile::TempDir;

/// Set up a temporary store with generated age identity and recipients.
/// Returns (temp_dir, store_path, identity_path) — keep temp_dir alive for the test.
fn setup_temp_store() -> (TempDir, String, String) {
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
            ExposeSecret::expose_secret(&id.to_string())
        ),
    )
    .unwrap();

    let recip_file = store_dir.join(".age-recipients");
    std::fs::write(&recip_file, format!("{recipient}\n")).unwrap();

    let store_path = store_dir.to_string_lossy().to_string();
    let id_path = id_file.to_string_lossy().to_string();

    (dir, store_path, id_path)
}

fn revvault_cmd(store: &str, identity: &str) -> Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("revvault");
    cmd.env("REVVAULT_STORE", store);
    cmd.env("REVVAULT_IDENTITY", identity);
    cmd
}

#[test]
fn bare_invocation_shows_full_help_with_examples() {
    assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Examples:").and(predicate::str::contains("revvault init")),
        );
}

#[test]
fn service_resume_requires_service_policy_and_rejects_personal_overrides() {
    let (_dir, store, identity) = setup_temp_store();
    for args in [
        vec!["init", "--resume"],
        vec![
            "init",
            "--resume",
            "--service-policy",
            "/synthetic/policy",
            "--dry-run",
        ],
        vec![
            "init",
            "--resume",
            "--service-policy",
            "/synthetic/policy",
            "--store-dir",
            &store,
        ],
        vec![
            "init",
            "--resume",
            "--service-policy",
            "/synthetic/policy",
            "--identity-file",
            &identity,
        ],
    ] {
        revvault_cmd(&store, &identity)
            .args(args)
            .assert()
            .failure();
    }
    assert_eq!(std::fs::read_dir(&store).unwrap().count(), 1);
}

#[test]
fn source_check_requires_explicit_service_preview_and_closes_denial_errors() {
    let (_dir, store, identity) = setup_temp_store();
    for args in [
        vec!["init", "--source-check"],
        vec!["init", "--service-policy", "/missing", "--source-check"],
    ] {
        revvault_cmd(&store, &identity)
            .args(args)
            .assert()
            .failure();
    }
    revvault_cmd(&store, &identity)
        .args([
            "--json",
            "init",
            "--service-policy",
            "/nonexistent/synthetic-private-policy",
            "--dry-run",
            "--source-check",
        ])
        .assert()
        .failure()
        .stdout(
            predicate::str::contains("revvault_service_capability_denied")
                .and(predicate::str::contains("synthetic-private-policy").not()),
        );
}

#[test]
fn service_import_denial_never_falls_back_to_operator_store() {
    let (dir, store, identity) = setup_temp_store();
    let before = std::fs::read_dir(&store).unwrap().count();
    revvault_cmd(&store, &identity)
        .args([
            "set",
            "--service-uid",
            "0",
            "revealfleet/publisher/synthetic-key",
        ])
        .write_stdin("synthetic-secret-must-not-reach-operator-store")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "revvault_service_capability_denied",
        ));
    assert_eq!(std::fs::read_dir(&store).unwrap().count(), before);
    assert!(!dir.path().join("store/revealfleet").exists());
}

#[test]
fn service_init_preview_ignores_operator_environment_and_creates_no_keys() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("policy.toml");
    std::fs::write(
        &source,
        r#"
version = 1
uid = 1001
command = ["/usr/local/bin/node", "/app/dist/publisher-run.js"]
[environment]
HOME = "/var/lib/revealfleet/publisher"
[secrets]
REVEALFLEET_PUBLISHER_DATABASE_URL = "revealfleet/publisher/database-url"
"#,
    )
    .unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .env("HOME", dir.path())
        .env("REVVAULT_STORE", dir.path().join("operator-store"))
        .env("REVVAULT_IDENTITY", dir.path().join("operator-identity"))
        .args(["--json", "init", "--service-policy"])
        .arg(&source)
        .arg("--dry-run")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["status"], "service_preview");
    assert_eq!(
        value["plan"]["store_dir"],
        "/var/lib/revvault/services/1001/store"
    );
    assert_eq!(
        value["plan"]["policy_file"],
        "/var/lib/revvault/services/1001/policy.toml"
    );
    assert_eq!(
        value["plan"]["identity_file"],
        "/var/lib/revvault/services/1001/identity.txt"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    assert!(!String::from_utf8(output)
        .unwrap()
        .contains("AGE-SECRET-KEY-"));
}

#[test]
fn set_empty_stdin_fails() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/empty")
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no input provided on stdin"));
}

#[test]
fn uninitialized_vault_points_to_init() {
    // Point both the explicit store override and the home-derived default at
    // paths that do not exist, so store resolution fails as on a fresh machine.
    let dir = tempfile::tempdir().unwrap();
    assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .env("REVVAULT_STORE", dir.path().join("missing-store"))
        .env("HOME", dir.path())
        .env_remove("WINDOWS_USERNAME")
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("revvault init"));
}

#[test]
fn list_empty_store() {
    let (_dir, store, identity) = setup_temp_store();
    revvault_cmd(&store, &identity)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().or(predicate::str::contains("")));
}

#[test]
fn set_and_get_roundtrip() {
    let (_dir, store, identity) = setup_temp_store();

    // Set a secret via stdin
    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/test-key")
        .write_stdin("super-secret-value")
        .assert()
        .success();

    // Get it back
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("credentials/test-key")
        .assert()
        .success()
        .stdout(predicate::str::contains("super-secret-value"));
}

#[test]
fn list_shows_stored_secrets() {
    let (_dir, store, identity) = setup_temp_store();

    // Add some secrets
    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/stripe/sk")
        .write_stdin("sk_live_123")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("ssh/github")
        .write_stdin("ssh-key-data")
        .assert()
        .success();

    // List should show both
    revvault_cmd(&store, &identity)
        .arg("list")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("credentials/stripe/sk")
                .and(predicate::str::contains("ssh/github")),
        );
}

#[test]
fn search_returns_matches() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/stripe/secret-key")
        .write_stdin("sk_live_123")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/unrelated")
        .write_stdin("value")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("search")
        .arg("stripe")
        .assert()
        .success()
        .stdout(predicate::str::contains("stripe"));
}

#[test]
fn delete_removes_secret() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/temp")
        .write_stdin("temporary")
        .assert()
        .success();

    // Verify it exists
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("misc/temp")
        .assert()
        .success();

    // Delete it (--force skips confirmation prompt)
    revvault_cmd(&store, &identity)
        .arg("delete")
        .arg("--force")
        .arg("misc/temp")
        .assert()
        .success();

    // Should be gone
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("misc/temp")
        .assert()
        .failure();
}

#[test]
fn get_nonexistent_fails() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("no/such/secret")
        .assert()
        .failure();
}

// ---------------------------------------------------------------------------
// get exit semantics: decrypt failures, empty values, missing paths
// ---------------------------------------------------------------------------

/// Write an age-encrypted `.age` file directly into the store, bypassing the
/// `set` command (which rejects empty input), so tests can pin behavior for
/// content that `set` itself can never produce: a genuinely empty secret.
fn write_encrypted_file(
    store: &str,
    path: &str,
    plaintext: &[u8],
    recipient: &age::x25519::Recipient,
) {
    let ciphertext =
        revvault_core::crypto::encrypt(plaintext, std::slice::from_ref(recipient)).unwrap();
    let file_path = Path::new(store).join(format!("{path}.age"));
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(file_path, ciphertext).unwrap();
}

/// Parse the age identity out of the `keys.txt` written by `setup_temp_store`.
fn read_identity(identity_path: &str) -> age::x25519::Identity {
    let contents = std::fs::read_to_string(identity_path).unwrap();
    let key_line = contents
        .lines()
        .find(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
        .expect("identity file must contain a key line");
    key_line.trim().parse().unwrap()
}

#[test]
fn get_empty_value_exits_zero_with_warning_on_stderr() {
    let (_dir, store, identity) = setup_temp_store();
    let recipient = read_identity(&identity).to_public();

    write_encrypted_file(&store, "misc/empty", b"", &recipient);

    // --full prints the raw value with no added newline, so a truly empty
    // stored value produces truly empty stdout (default mode still emits a
    // trailing newline from `println!`, which is unrelated to this behavior).
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("--full")
        .arg("misc/empty")
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "warning: stored value is empty (path: misc/empty)",
        ));
}

#[test]
fn get_undecryptable_value_fails_with_path_and_reason() {
    let (_dir, store, identity) = setup_temp_store();

    // Encrypt to a different, unrelated identity so the store's own identity
    // cannot decrypt it (simulates a wrong-identity / key-rotation blob).
    let other_recipient = age::x25519::Identity::generate().to_public();
    write_encrypted_file(
        &store,
        "misc/undecryptable",
        b"orphaned-secret",
        &other_recipient,
    );

    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("misc/undecryptable")
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("misc/undecryptable")
                .and(predicate::str::contains("No matching keys found")),
        );
}

#[test]
fn get_missing_path_stderr_names_path() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("no/such/secret")
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("no/such/secret"));
}

#[test]
fn set_rejects_path_traversal() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("../../etc/passwd")
        .write_stdin("hacked")
        .assert()
        .failure();
}

#[test]
fn set_rejects_absolute_path() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("/etc/passwd")
        .write_stdin("hacked")
        .assert()
        .failure();
}

#[test]
fn get_full_flag_shows_multiline() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/multiline")
        .write_stdin("line1\nline2\nline3")
        .assert()
        .success();

    // Without --full, only first line
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("misc/multiline")
        .assert()
        .success()
        .stdout(predicate::str::contains("line1").and(predicate::str::contains("line2").not()));

    // With --full, all lines
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("--full")
        .arg("misc/multiline")
        .assert()
        .success()
        .stdout(predicate::str::contains("line1").and(predicate::str::contains("line3")));
}

#[test]
fn stream_safe_blocks_tty_get_without_allow_print() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/secret")
        .write_stdin("super-secret-value")
        .assert()
        .success();

    // assert_cmd does not allocate a TTY, so STREAM_SAFE alone still allows
    // get (piped/script path). Force the human-disclosure path via clip.
    revvault_cmd(&store, &identity)
        .env("STREAM_SAFE", "1")
        .env_remove("REVVAULT_ALLOW_PRINT")
        .arg("get")
        .arg("--clip")
        .arg("misc/secret")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("stream-safe")
                .and(predicate::str::contains("REVVAULT_ALLOW_PRINT")),
        );
}

#[test]
fn stream_safe_allows_get_with_allow_print() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/secret")
        .write_stdin("visible-when-allowed")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .env("STREAM_SAFE", "1")
        .env("REVVAULT_ALLOW_PRINT", "1")
        .arg("get")
        .arg("--full")
        .arg("misc/secret")
        .assert()
        .success()
        .stdout(predicate::str::contains("visible-when-allowed"));
}

#[test]
fn run_injects_env_without_printing_value() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/token")
        .write_stdin("tok_from_vault")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("run")
        .arg("--env")
        .arg("MY_TOKEN=misc/token")
        .arg("--")
        .arg("printenv")
        .arg("MY_TOKEN")
        .assert()
        .success()
        .stdout(predicate::str::contains("tok_from_vault"))
        .stderr(predicate::str::contains("tok_from_vault").not());
}

// ---------------------------------------------------------------------------
// init command
// ---------------------------------------------------------------------------

#[test]
fn init_creates_store_and_identity() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let id_file = dir.path().join("keys.txt");

    assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .arg("init")
        .arg("--store-dir")
        .arg(&store_dir)
        .arg("--identity-file")
        .arg(&id_file)
        .assert()
        .success();

    assert!(store_dir.is_dir(), "store directory should be created");
    assert!(id_file.is_file(), "identity file should be created");
    assert!(
        store_dir.join(".age-recipients").is_file(),
        ".age-recipients should be written"
    );
}

#[test]
fn init_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let id_file = dir.path().join("keys.txt");

    // First init
    assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .arg("init")
        .arg("--store-dir")
        .arg(&store_dir)
        .arg("--identity-file")
        .arg(&id_file)
        .assert()
        .success();

    // Second init — must not fail or overwrite identity
    let before = std::fs::read_to_string(&id_file).unwrap();
    assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .arg("init")
        .arg("--store-dir")
        .arg(&store_dir)
        .arg("--identity-file")
        .arg(&id_file)
        .assert()
        .success();
    let after = std::fs::read_to_string(&id_file).unwrap();

    assert_eq!(before, after, "identity file must not be overwritten");
}

// ---------------------------------------------------------------------------
// export-env command
// ---------------------------------------------------------------------------

#[test]
fn export_env_single_value() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/stripe/secret-key")
        .write_stdin("sk_live_abc123")
        .assert()
        .success();

    // Var name derived from last path segment: secret-key → SECRET_KEY
    revvault_cmd(&store, &identity)
        .arg("export-env")
        .arg("credentials/stripe/secret-key")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export SECRET_KEY=")
                .and(predicate::str::contains("sk_live_abc123")),
        );
}

#[test]
fn export_env_kv_lines() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/env/prod")
        .write_stdin("API_KEY=abc123\nDB_URL=postgres://localhost/db")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("export-env")
        .arg("credentials/env/prod")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export API_KEY=")
                .and(predicate::str::contains("abc123"))
                .and(predicate::str::contains("export DB_URL="))
                .and(predicate::str::contains("postgres://localhost/db")),
        );
}

#[test]
fn export_env_single_quote_escaping() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("misc/password")
        .write_stdin("it's a secret")
        .assert()
        .success();

    // Shell quoting: single quotes in value must be escaped as '\''
    revvault_cmd(&store, &identity)
        .arg("export-env")
        .arg("misc/password")
        .assert()
        .success()
        .stdout(predicate::str::contains("export PASSWORD=").and(predicate::str::contains("it")));
}

#[test]
fn export_env_nonexistent_fails() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("export-env")
        .arg("credentials/missing/key")
        .assert()
        .failure();
}

#[test]
fn export_env_public_only_allows_public_key() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("revealui/env/license")
        .write_stdin("REVEALUI_LICENSE_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAtest\n-----END PUBLIC KEY-----")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("export-env")
        .arg("--public-only")
        .arg("revealui/env/license")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "export REVEALUI_LICENSE_PUBLIC_KEY=",
        ));
}

#[test]
fn export_env_public_only_refuses_private_key() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("revealui/env/license")
        .write_stdin(
            "REVEALUI_LICENSE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA\n-----END PRIVATE KEY-----\nREVEALUI_LICENSE_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\nMCow\n-----END PUBLIC KEY-----",
        )
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("export-env")
        .arg("--public-only")
        .arg("revealui/env/license")
        .assert()
        .failure()
        .stderr(predicate::str::contains("public-only refused private-key"));
}

// ---------------------------------------------------------------------------
// list with flags
// ---------------------------------------------------------------------------

#[test]
fn list_with_prefix_filter() {
    let (_dir, store, identity) = setup_temp_store();

    for (path, val) in &[
        ("credentials/stripe/sk", "sk"),
        ("credentials/github/token", "gh"),
        ("ssh/server", "key"),
    ] {
        revvault_cmd(&store, &identity)
            .arg("set")
            .arg(path)
            .write_stdin(*val)
            .assert()
            .success();
    }

    revvault_cmd(&store, &identity)
        .arg("list")
        .arg("credentials")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("credentials/stripe/sk")
                .and(predicate::str::contains("credentials/github/token"))
                .and(predicate::str::contains("ssh/server").not()),
        );
}

#[test]
fn list_tree_format() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/stripe/sk")
        .write_stdin("sk")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("ssh/github")
        .write_stdin("key")
        .assert()
        .success();

    revvault_cmd(&store, &identity)
        .arg("list")
        .arg("--tree")
        .assert()
        .success()
        .stdout(predicate::str::contains("credentials/").and(predicate::str::contains("ssh/")));
}

// ---------------------------------------------------------------------------
// migrate command
// ---------------------------------------------------------------------------

#[test]
fn migrate_dry_run_shows_plan() {
    let (_dir, store, identity) = setup_temp_store();
    let plaintext_dir = tempfile::tempdir().unwrap();

    std::fs::write(plaintext_dir.path().join("stripe_api_key"), "sk_live_123").unwrap();
    std::fs::write(plaintext_dir.path().join("github_token"), "ghp_abc123").unwrap();

    revvault_cmd(&store, &identity)
        .arg("migrate")
        .arg("--plaintext-dir")
        .arg(plaintext_dir.path())
        .arg("--dry-run")
        .assert()
        .success()
        .stderr(predicate::str::contains("dry run"));
}

#[test]
fn migrate_force_imports_files() {
    let (_dir, store, identity) = setup_temp_store();
    let plaintext_dir = tempfile::tempdir().unwrap();

    std::fs::write(plaintext_dir.path().join("stripe_api_key"), "sk_live_123").unwrap();

    revvault_cmd(&store, &identity)
        .arg("migrate")
        .arg("--plaintext-dir")
        .arg(plaintext_dir.path())
        .arg("--force")
        .assert()
        .success()
        .stderr(predicate::str::contains("Migrated"));

    // Verify the imported secret is in the store
    revvault_cmd(&store, &identity)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("stripe"));
}

#[test]
fn migrate_empty_directory() {
    let (_dir, store, identity) = setup_temp_store();
    let plaintext_dir = tempfile::tempdir().unwrap();

    revvault_cmd(&store, &identity)
        .arg("migrate")
        .arg("--plaintext-dir")
        .arg(plaintext_dir.path())
        .arg("--dry-run")
        .assert()
        .success()
        .stderr(predicate::str::contains("No files found"));
}

// ---------------------------------------------------------------------------
// rotate command
// ---------------------------------------------------------------------------

#[test]
fn rotate_no_rotation_config_unknown_provider() {
    let (_dir, store, identity) = setup_temp_store();

    // No rotation.toml in store — asking for any provider should fail
    revvault_cmd(&store, &identity)
        .arg("rotate")
        .arg("nonexistent-provider")
        .assert()
        .failure();
}

#[test]
fn rotate_unknown_provider_with_config() {
    let (_dir, store, identity) = setup_temp_store();

    // Write a rotation.toml with a different provider name
    let revvault_dir = Path::new(&store).join(".revvault");
    std::fs::create_dir_all(&revvault_dir).unwrap();
    std::fs::write(
        revvault_dir.join("rotation.toml"),
        "[providers.other]\nsecret_path = \"misc/key\"\n",
    )
    .unwrap();

    revvault_cmd(&store, &identity)
        .arg("rotate")
        .arg("nonexistent")
        .assert()
        .failure()
        .stderr(predicate::str::contains("nonexistent"));
}

#[test]
fn rotate_dry_run_shows_plan() {
    let (_dir, store, identity) = setup_temp_store();

    // Seed the secret the provider will read
    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/svc/api-key")
        .write_stdin("current-key")
        .assert()
        .success();

    // Write rotation.toml pointing at a syntactically valid (but unreachable) URL
    let revvault_dir = Path::new(&store).join(".revvault");
    std::fs::create_dir_all(&revvault_dir).unwrap();
    std::fs::write(
        revvault_dir.join("rotation.toml"),
        "[providers.svc]\nsecret_path = \"credentials/svc/api-key\"\n\
        [providers.svc.settings]\ncreate_url = \"https://api.example.com/keys\"\n\
        response_field = \"key\"\n",
    )
    .unwrap();

    revvault_cmd(&store, &identity)
        .arg("rotate")
        .arg("--dry-run")
        .arg("svc")
        .assert()
        .success()
        .stderr(predicate::str::contains("dry run"));
}

#[tokio::test]
async fn rotate_executes_via_cli() {
    let mut server = mockito::Server::new_async().await;

    let _mock = server
        .mock("POST", "/keys")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"key":"rotated-value"}"#)
        .create_async()
        .await;

    let (_dir, store, identity) = setup_temp_store();

    // Seed the current secret
    revvault_cmd(&store, &identity)
        .arg("set")
        .arg("credentials/svc/api-key")
        .write_stdin("old-key")
        .assert()
        .success();

    // Write rotation.toml pointing at the mock server
    let revvault_dir = Path::new(&store).join(".revvault");
    std::fs::create_dir_all(&revvault_dir).unwrap();
    std::fs::write(
        revvault_dir.join("rotation.toml"),
        format!(
            "[providers.svc]\nsecret_path = \"credentials/svc/api-key\"\n\
            [providers.svc.settings]\ncreate_url = \"{}/keys\"\nresponse_field = \"key\"\n",
            server.url()
        ),
    )
    .unwrap();

    revvault_cmd(&store, &identity)
        .arg("rotate")
        .arg("svc")
        .assert()
        .success();

    // New key should be in the vault
    revvault_cmd(&store, &identity)
        .arg("get")
        .arg("credentials/svc/api-key")
        .assert()
        .success()
        .stdout(predicate::str::contains("rotated-value"));
}

// ---------------------------------------------------------------------------
// rotation-status command
// ---------------------------------------------------------------------------

#[test]
fn rotation_status_no_history() {
    let (_dir, store, identity) = setup_temp_store();

    revvault_cmd(&store, &identity)
        .arg("rotation-status")
        .assert()
        .success()
        .stderr(predicate::str::contains("No rotation history"));
}

#[test]
fn rotation_status_shows_recent_entries() {
    let (_dir, store, identity) = setup_temp_store();

    // Manually write a log entry
    let revvault_dir = Path::new(&store).join(".revvault");
    std::fs::create_dir_all(&revvault_dir).unwrap();
    let log_entry = r#"{"timestamp":"2026-01-01T00:00:00Z","provider":"svc","secret_path":"credentials/svc/key","new_key_id":null,"status":"success"}"#;
    std::fs::write(
        revvault_dir.join("rotation-log.jsonl"),
        format!("{log_entry}\n"),
    )
    .unwrap();

    revvault_cmd(&store, &identity)
        .arg("rotation-status")
        .assert()
        .success()
        .stdout(predicate::str::contains("svc"));
}

// ---------------------------------------------------------------------------
// completions command
// ---------------------------------------------------------------------------

#[test]
fn completions_generates_bash_output() {
    assert_cmd::cargo::cargo_bin_cmd!("revvault")
        .arg("completions")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn service_request_requires_service_mode_and_rejects_preview() {
    for args in [
        vec!["init", "--service-request", "/missing"],
        vec![
            "init",
            "--service-policy",
            "/missing",
            "--service-request",
            "/missing",
            "--dry-run",
        ],
        vec![
            "set",
            "--service-request",
            "/missing",
            "revealfleet/publisher/key",
        ],
    ] {
        Command::cargo_bin("revvault")
            .unwrap()
            .args(args)
            .assert()
            .failure()
            .code(2);
    }
}

#[test]
fn request_status_requires_service_inputs_and_excludes_mutation_modes() {
    for args in [
        vec!["init", "--request-status"],
        vec!["init", "--service-policy", "/missing", "--request-status"],
        vec![
            "init",
            "--service-policy",
            "/missing",
            "--service-request",
            "/missing",
            "--request-status",
            "--dry-run",
        ],
        vec![
            "init",
            "--service-policy",
            "/missing",
            "--service-request",
            "/missing",
            "--request-status",
            "--resume",
        ],
        vec![
            "init",
            "--service-policy",
            "/missing",
            "--service-request",
            "/missing",
            "--request-status",
            "--restore-archive",
            "/missing",
            "--expected-sha256",
            "invalid",
        ],
    ] {
        Command::cargo_bin("revvault")
            .unwrap()
            .args(args)
            .assert()
            .failure()
            .code(2);
    }
}
