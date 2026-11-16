//! Explicit native primitive proof in a disposable root container. This is not
//! acceptance of the coding launchers, publisher image or hosted GitHub policy.
use revvault_core::{
    init::{
        interrupt_service_vault_after_capability, interrupt_service_vault_after_store,
        native_init_service_vault as init_service_vault,
        native_resume_service_vault as resume_service_vault, service_init_plan,
    },
    service::ServicePolicy,
    Config, PassageStore,
};
use std::os::unix::process::CommandExt;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

const UID: u32 = 19001;
const COMMAND: &str = "/usr/local/bin/revealfleet-native-env";

fn request_file(
    policy: &Path,
    operation: &str,
    selector: Option<&str>,
    archive: Option<&str>,
) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let output = Command::new("/usr/local/bin/revvault")
        .args([
            "--json",
            "init",
            "--service-policy",
            policy.to_str().unwrap(),
            "--dry-run",
            "--source-check",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "synthetic source check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let source: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let path = format!("/root/revealfleet-request-{sequence}.json");
    let request = serde_json::json!({ "version":1, "request_id": format!("{sequence:032x}"), "uid": source["source_contract"]["uid"], "operation":operation,
        "selector":selector, "archive_sha256":archive, "source_contract_sha256":source["source_contract_sha256"],
        "expected_target_sha256":"d".repeat(64), "expires_at":chrono::Utc::now().timestamp()+120 });
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(&serde_json::to_vec(&request).unwrap())
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn status_command(policy: &Path, request: &str) -> std::process::Output {
    Command::new("/usr/local/bin/revvault")
        .args([
            "--json",
            "init",
            "--service-policy",
            policy.to_str().unwrap(),
            "--service-request",
            request,
            "--request-status",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn assert_request_status(policy: &Path, request: &str, expected: &str) {
    let descriptor: serde_json::Value =
        serde_json::from_slice(&fs::read(request).unwrap()).unwrap();
    let id = descriptor["request_id"].as_str().unwrap();
    let records = [
        format!("/var/lib/revvault/requests/{id}.held.json"),
        format!("/var/lib/revvault/requests/{id}.complete.json"),
    ];
    let contents = || {
        records
            .iter()
            .map(|path| match fs::read(path) {
                Ok(bytes) => Some(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => panic!("synthetic record read failed: {e}"),
            })
            .collect::<Vec<_>>()
    };
    let before = contents();
    let output = status_command(policy, request);
    assert!(
        output.status.success(),
        "synthetic status query failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["state"], expected);
    assert_eq!(report["request_id"], descriptor["request_id"]);
    assert_eq!(report["provider_admission"], "held");
    assert_eq!(report["retry_authorized"], false);
    for field in [
        "record_durability",
        "process_termination",
        "execution_fencing",
        "rollback_protection",
    ] {
        assert_eq!(report[field], "unverified");
    }
    assert_eq!(contents(), before, "status query must preserve nonce bytes");
}

fn command_success(program: &str, args: &[&str]) {
    assert!(Command::new(program).args(args).status().unwrap().success());
}

fn as_user(command: &mut Command, uid: u32) {
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(1, &uid) != 0 || libc::setgid(uid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[test]
fn native_service_provisioning_and_kernel_denial() {
    if std::env::var("REVEALFLEET_NATIVE_SERVICE_CHILD").as_deref() == Ok("1") {
        assert_eq!(unsafe { libc::geteuid() }, UID);
        let policy = ServicePolicy::current().unwrap().unwrap();
        let config = Config::resolve().unwrap();
        policy.assert_configuration(&config).unwrap();
        let store = PassageStore::open(config).unwrap();
        use secrecy::ExposeSecret;
        assert_eq!(
            store
                .get("revealfleet/publisher/synthetic-key")
                .unwrap()
                .expose_secret(),
            "synthetic-service-secret"
        );
        assert!(store.get("revealfleet/owner/synthetic-key").is_err());
        assert!(store
            .set("revealfleet/publisher/synthetic-key", b"denied")
            .is_err());
        for path in [
            "/root/operator/gh/token",
            "/root/operator/ssh/key",
            "/root/operator/revvault/identity",
        ] {
            assert!(fs::read(path).is_err());
        }
        return;
    }
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "native fixture requires root inside its disposable container"
    );
    assert!(
        Path::new("/.dockerenv").is_file(),
        "refuse provisioning fixtures on an operator host"
    );
    let restoring = std::env::var("REVEALFLEET_NATIVE_SERVICE_RESTORE").as_deref() == Ok("1");
    if restoring || std::env::var("REVEALFLEET_NATIVE_SERVICE_REPLACEMENT").as_deref() == Ok("1") {
        command_success(
            "/usr/sbin/groupadd",
            &["--gid", "19001", "revealfleet-service-fixture"],
        );
        command_success(
            "/usr/sbin/useradd",
            &[
                "--uid",
                "19001",
                "--gid",
                "19001",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "revealfleet-service-fixture",
            ],
        );
        fs::copy("/usr/bin/env", COMMAND).unwrap();
        fs::set_permissions(COMMAND, fs::Permissions::from_mode(0o755)).unwrap();
        if restoring {
            independent_restore();
            return;
        }
        let root = Path::new("/var/lib/revvault/services/19001");
        let recorded: BTreeMap<String, String> =
            serde_json::from_slice(&fs::read("/var/lib/revvault/replacement-proof.json").unwrap())
                .unwrap();
        for (name, expected) in recorded {
            use sha2::{Digest, Sha256};
            assert_eq!(
                hex::encode(Sha256::digest(fs::read(root.join(name)).unwrap())),
                expected
            );
        }
        assert!(!Path::new("/etc/revvault/services").exists());
        let mut delivery = Command::new("/usr/local/bin/revvault");
        delivery
            .args(["run", "--service", "--", COMMAND])
            .env("GH_TOKEN", "synthetic-owner-token")
            .env("REVVAULT_STORE", "/root/operator");
        as_user(&mut delivery, UID);
        let result = delivery.output().unwrap();
        assert!(result.status.success());
        let environment = String::from_utf8(result.stdout).unwrap();
        assert!(environment.contains("REVEALFLEET_SYNTHETIC_KEY=synthetic-service-secret"));
        assert!(!environment.contains("synthetic-owner"));
        let mut foreign = Command::new("/usr/bin/cat");
        foreign.arg(root.join("identity.txt"));
        as_user(&mut foreign, 65534);
        assert!(!foreign.output().unwrap().status.success());
        println!("native persistent custody replacement PASS; identity/recipient/policy/ciphertext unchanged, no initialization");
        return;
    }
    assert!(!Path::new("/var/lib/revvault/services").exists());
    command_success(
        "/usr/sbin/groupadd",
        &["--gid", "19001", "revealfleet-service-fixture"],
    );
    command_success(
        "/usr/sbin/useradd",
        &[
            "--uid",
            "19001",
            "--gid",
            "19001",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "revealfleet-service-fixture",
        ],
    );
    // A legacy policy never becomes an alias or permits personal fallback.
    fs::create_dir_all("/etc/revvault/services").unwrap();
    fs::write("/etc/revvault/services/19001.toml", "legacy").unwrap();
    let mut legacy_runtime = Command::new("/usr/local/bin/revvault");
    legacy_runtime.args(["run", "--service", "--", COMMAND]);
    as_user(&mut legacy_runtime, UID);
    let result = legacy_runtime.output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("revvault_service_capability_denied"));
    fs::remove_file("/etc/revvault/services/19001.toml").unwrap();
    fs::copy("/usr/bin/env", COMMAND).unwrap();
    fs::set_permissions(COMMAND, fs::Permissions::from_mode(0o755)).unwrap();
    let policy = ServicePolicy {
        version: 1,
        uid: UID,
        command: vec![COMMAND.into()],
        environment: BTreeMap::from([("HOME".into(), "/var/lib/revealfleet/publisher".into())]),
        secrets: BTreeMap::from([(
            "REVEALFLEET_SYNTHETIC_KEY".into(),
            "revealfleet/publisher/synthetic-key".into(),
        )]),
    };
    let input = Path::new("/root/revealfleet-service-fixture.toml");
    fs::write(input, toml::to_string(&policy).unwrap()).unwrap();
    // Source evidence uses the existing preview command. It must not initialize
    // custody, and an altered/writable command must change the evidence or deny.
    let preview = || {
        Command::new("/usr/local/bin/revvault")
            .args(["--json", "init", "--service-policy"])
            .arg(input)
            .args(["--dry-run", "--source-check"])
            .output()
            .unwrap()
    };
    let output = preview();
    assert!(output.status.success());
    let evidence: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(evidence["provider_admission"], "held");
    let contract: revvault_core::service::ServiceSourceContract =
        serde_json::from_value(evidence["source_contract"].clone()).unwrap();
    assert_eq!(contract.uid, UID);
    assert_eq!(contract.command_sha256.len(), 1);
    assert_eq!(
        evidence["source_contract_sha256"],
        contract.sha256().unwrap()
    );
    assert!(!Path::new("/var/lib/revvault/services").exists());
    let unobserved_request = request_file(input, "initialize", None, None);
    assert_request_status(input, &unobserved_request, "unobserved");
    assert!(!Path::new("/var/lib/revvault/requests").exists());
    let command_bytes = fs::read(COMMAND).unwrap();
    let mut changed_command = command_bytes.clone();
    changed_command.extend_from_slice(b"synthetic-changed-command");
    fs::write(COMMAND, changed_command).unwrap();
    assert!(!status_command(input, &unobserved_request).status.success());
    assert!(!Path::new("/var/lib/revvault/requests").exists());
    let changed = preview();
    assert!(changed.status.success());
    let changed: serde_json::Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_ne!(
        evidence["source_contract_sha256"],
        changed["source_contract_sha256"]
    );
    fs::write(COMMAND, command_bytes).unwrap();
    fs::set_permissions(COMMAND, fs::Permissions::from_mode(0o777)).unwrap();
    let writable = preview();
    assert!(!writable.status.success());
    assert!(
        String::from_utf8_lossy(&writable.stdout).contains("revvault_service_capability_denied")
    );
    fs::set_permissions(COMMAND, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!Path::new("/var/lib/revvault/services").exists());
    // Fault occurs in the owning initializer after durable store publication,
    // before capability publication; the production CLI has no fault selector.
    assert!(interrupt_service_vault_after_store(input).is_err());
    let plan = service_init_plan(&policy).unwrap();
    assert!(!plan.policy_file.exists());
    let original_identity = fs::read(&plan.identity_file).unwrap();
    let root = plan.store_dir.parent().unwrap();
    let marker = root.join(".provisioning.toml");
    let original_marker = fs::read(&marker).unwrap();
    let original_recipients = fs::read(&plan.recipients_file).unwrap();
    // Fault artifacts must remain on the custody filesystem for atomic moves/links.
    fs::create_dir("/var/lib/revvault/.native-evidence").unwrap();
    fs::set_permissions(
        "/var/lib/revvault/.native-evidence",
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let recovery_denied = || {
        assert!(resume_service_vault(input).is_err());
        assert!(!plan.policy_file.exists());
        assert_eq!(fs::read(&plan.identity_file).unwrap(), original_identity);
    };
    assert!(init_service_vault(input).is_err());
    let mut unprivileged = Command::new("/usr/local/bin/revvault");
    unprivileged.args([
        "init",
        "--service-policy",
        input.to_str().unwrap(),
        "--resume",
    ]);
    as_user(&mut unprivileged, UID);
    assert!(!unprivileged.output().unwrap().status.success());
    assert_eq!(fs::read(&marker).unwrap(), original_marker);
    let mut private_intent = Command::new("/usr/bin/cat");
    private_intent.arg(&marker);
    as_user(&mut private_intent, UID);
    assert!(!private_intent.output().unwrap().status.success());
    let mut changed = policy.clone();
    changed.environment.insert("PORT".into(), "9999".into());
    fs::write(input, toml::to_string(&changed).unwrap()).unwrap();
    recovery_denied();
    fs::write(input, toml::to_string(&policy).unwrap()).unwrap();
    let command_before = fs::read(COMMAND).unwrap();
    fs::write(COMMAND, b"synthetic-modified-command").unwrap();
    recovery_denied();
    fs::write(COMMAND, &command_before).unwrap();
    fs::rename(
        &marker,
        "/var/lib/revvault/.native-evidence/withheld-intent",
    )
    .unwrap();
    recovery_denied();
    fs::rename(
        "/var/lib/revvault/.native-evidence/withheld-intent",
        &marker,
    )
    .unwrap();
    fs::write(&marker, "malformed intent").unwrap();
    recovery_denied();
    fs::write(&marker, &original_marker).unwrap();
    let foreign_key = age::x25519::Identity::generate().to_public();
    fs::write(&plan.recipients_file, format!("{foreign_key}\n")).unwrap();
    recovery_denied();
    fs::write(&plan.recipients_file, &original_recipients).unwrap();
    fs::write(&plan.identity_file, b"synthetic-modified-identity").unwrap();
    assert!(resume_service_vault(input).is_err());
    assert!(!plan.policy_file.exists());
    assert_eq!(
        fs::read(&plan.identity_file).unwrap(),
        b"synthetic-modified-identity"
    );
    fs::write(&plan.identity_file, &original_identity).unwrap();
    command_success(
        "/usr/bin/chown",
        &["0:65534", plan.identity_file.to_str().unwrap()],
    );
    recovery_denied();
    command_success(
        "/usr/bin/chown",
        &["0:19001", plan.identity_file.to_str().unwrap()],
    );
    fs::hard_link(
        &plan.recipients_file,
        "/var/lib/revvault/.native-evidence/linked-recipients",
    )
    .unwrap();
    recovery_denied();
    fs::remove_file("/var/lib/revvault/.native-evidence/linked-recipients").unwrap();
    fs::set_permissions(root, fs::Permissions::from_mode(0o770)).unwrap();
    recovery_denied();
    fs::set_permissions(root, fs::Permissions::from_mode(0o750)).unwrap();
    for path in [&plan.identity_file, &marker] {
        let before = fs::metadata(path).unwrap().permissions();
        fs::set_permissions(path, fs::Permissions::from_mode(0o660)).unwrap();
        recovery_denied();
        fs::set_permissions(path, before).unwrap();
    }
    let unexpected = plan.store_dir.join("synthetic-existing-secret.age");
    fs::write(&unexpected, b"synthetic-existing-ciphertext").unwrap();
    recovery_denied();
    assert_eq!(
        fs::read(&unexpected).unwrap(),
        b"synthetic-existing-ciphertext"
    );
    fs::remove_file(unexpected).unwrap();
    let extra_metadata = plan.store_dir.join(".revvault/unexpected");
    fs::write(&extra_metadata, "synthetic metadata").unwrap();
    recovery_denied();
    fs::remove_file(extra_metadata).unwrap();
    fs::rename(
        &plan.recipients_file,
        "/var/lib/revvault/.native-evidence/withheld-recipients",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "/var/lib/revvault/.native-evidence/withheld-recipients",
        &plan.recipients_file,
    )
    .unwrap();
    recovery_denied();
    fs::remove_file(&plan.recipients_file).unwrap();
    fs::rename(
        "/var/lib/revvault/.native-evidence/withheld-recipients",
        &plan.recipients_file,
    )
    .unwrap();
    let mut contenders = Vec::new();
    for _ in 0..2 {
        contenders.push(
            Command::new("/usr/local/bin/revvault")
                .args([
                    "--json",
                    "init",
                    "--service-policy",
                    input.to_str().unwrap(),
                    "--resume",
                    "--service-request",
                    &request_file(input, "resume", None, None),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let outcomes: Vec<_> = contenders
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| result.status.success())
            .count(),
        1
    );
    let resumed = outcomes
        .iter()
        .find(|result| result.status.success())
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&resumed.stdout).unwrap()["status"],
        "service_resumed"
    );
    assert_eq!(fs::read(&plan.identity_file).unwrap(), original_identity);
    assert_eq!(
        fs::read(&plan.recipients_file).unwrap(),
        original_recipients
    );
    assert!(!marker.exists());
    assert!(resume_service_vault(input).is_err());
    assert_eq!(plan.policy_file, root.join("policy.toml"));
    // Policy, identity and ciphertext share the only persistent service namespace.
    // Finalized replacement needs no reinitializer and never generates another identity.
    let original_policy = fs::read(&plan.policy_file).unwrap();
    // A finalized store has no pending provenance, even if its capability is
    // later removed by root. Recovery cannot re-adopt that completed store.
    fs::remove_file(&plan.policy_file).unwrap();
    assert!(resume_service_vault(input).is_err());
    assert!(!plan.policy_file.exists());
    assert_eq!(fs::read(&plan.identity_file).unwrap(), original_identity);
    fs::write(&plan.policy_file, &original_policy).unwrap();
    assert!(init_service_vault(input).is_err());
    assert_eq!(fs::read(&plan.identity_file).unwrap(), original_identity);
    assert_eq!(fs::read(&plan.policy_file).unwrap(), original_policy);
    // A policy published before a crash cannot admit a runtime until exact finalization.
    command_success(
        "/usr/sbin/groupadd",
        &["--gid", "19002", "revealfleet-recovery-fixture"],
    );
    command_success(
        "/usr/sbin/useradd",
        &[
            "--uid",
            "19002",
            "--gid",
            "19002",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "revealfleet-recovery-fixture",
        ],
    );
    let mut after_policy = policy.clone();
    after_policy.uid = 19002;
    let after_input = Path::new("/root/revealfleet-after-policy.toml");
    fs::write(after_input, toml::to_string(&after_policy).unwrap()).unwrap();
    assert!(interrupt_service_vault_after_capability(after_input).is_err());
    let after_plan = service_init_plan(&after_policy).unwrap();
    let after_identity = fs::read(&after_plan.identity_file).unwrap();
    assert!(after_plan.policy_file.exists());
    let after_capability = fs::read(&after_plan.policy_file).unwrap();
    assert!(
        PassageStore::open_service_import(19002, "revealfleet/publisher/synthetic-key").is_err()
    );
    let mut pending_runtime = Command::new("/usr/local/bin/revvault");
    pending_runtime.args(["run", "--service", "--", COMMAND]);
    as_user(&mut pending_runtime, 19002);
    let denied_runtime = pending_runtime.output().unwrap();
    assert!(!denied_runtime.status.success());
    assert!(String::from_utf8_lossy(&denied_runtime.stderr)
        .contains("revvault_service_capability_denied"));
    let mut wrong = after_policy.clone();
    wrong.environment.insert("PORT".into(), "9999".into());
    fs::write(after_input, toml::to_string(&wrong).unwrap()).unwrap();
    assert!(resume_service_vault(after_input).is_err());
    assert_eq!(fs::read(&after_plan.identity_file).unwrap(), after_identity);
    fs::write(after_input, toml::to_string(&after_policy).unwrap()).unwrap();
    let contenders: Vec<_> = (0..2)
        .map(|_| {
            Command::new("/usr/local/bin/revvault")
                .args([
                    "--json",
                    "init",
                    "--service-policy",
                    after_input.to_str().unwrap(),
                    "--resume",
                    "--service-request",
                    &request_file(after_input, "resume", None, None),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let outcomes: Vec<_> = contenders
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.status.success())
            .count(),
        1
    );
    assert_eq!(fs::read(&after_plan.policy_file).unwrap(), after_capability);
    assert_eq!(fs::read(&after_plan.identity_file).unwrap(), after_identity);
    assert!(!after_plan
        .store_dir
        .parent()
        .unwrap()
        .join(".provisioning.toml")
        .exists());
    assert!(resume_service_vault(after_input).is_err());

    // Invalid ingress must leave the approved selector absent so a later valid
    // create-only import remains possible. Never exercise this on host custody.
    let ciphertext = plan
        .store_dir
        .join("revealfleet/publisher/synthetic-key.age");
    for input in [vec![], vec![0xff], vec![b'x'; 64 * 1024 + 1]] {
        let mut rejected = Command::new("/usr/local/bin/revvault")
            .args([
                "set",
                "--service-request",
                &request_file(
                    &ServicePolicy::fixed_policy_path(19001),
                    "import",
                    Some("revealfleet/publisher/synthetic-key"),
                    None,
                ),
                "--service-uid",
                "19001",
                "revealfleet/publisher/synthetic-key",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        rejected.stdin.take().unwrap().write_all(&input).unwrap();
        let output = rejected.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("revvault_service_import_input_denied"));
        assert!(!ciphertext.exists());
    }

    // Real receiver deadline: keep stdin open without delivering a value. Only
    // this disposable child may be killed; the consumed nonce must remain held.
    let stalled_request = request_file(
        &ServicePolicy::fixed_policy_path(19001),
        "import",
        Some("revealfleet/publisher/synthetic-key"),
        None,
    );
    let descriptor: serde_json::Value =
        serde_json::from_slice(&fs::read(&stalled_request).unwrap()).unwrap();
    let id = descriptor["request_id"].as_str().unwrap();
    let held = format!("/var/lib/revvault/requests/{id}.held.json");
    let completed = format!("/var/lib/revvault/requests/{id}.complete.json");
    let mut stalled = Command::new("/usr/local/bin/revvault")
        .args([
            "set",
            "--service-request",
            &stalled_request,
            "--service-uid",
            "19001",
            "revealfleet/publisher/synthetic-key",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pending_input = stalled.stdin.take().unwrap();
    let limit = std::time::Instant::now() + std::time::Duration::from_secs(35);
    let status = loop {
        if let Some(status) = stalled.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= limit {
            stalled.kill().unwrap();
            stalled.wait().unwrap();
            panic!("receiver exceeded hard deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    drop(pending_input);
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(Path::new(&held).is_file());
    assert_request_status(
        &ServicePolicy::fixed_policy_path(19001),
        &stalled_request,
        "held",
    );
    assert!(!Path::new(&completed).exists());
    assert!(!ciphertext.exists());
    let replay = Command::new("/usr/local/bin/revvault")
        .args([
            "set",
            "--service-request",
            &stalled_request,
            "--service-uid",
            "19001",
            "revealfleet/publisher/synthetic-key",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("revvault_service_request_denied"));
    assert!(!ciphertext.exists());

    // Exercise maintained scoped import, not a duplicated setup/chmod recipe.
    let import_request = request_file(
        &ServicePolicy::fixed_policy_path(19001),
        "import",
        Some("revealfleet/publisher/synthetic-key"),
        None,
    );
    let mut import = Command::new("/usr/local/bin/revvault")
        .args([
            "set",
            "--service-request",
            &import_request,
            "--service-uid",
            "19001",
            "revealfleet/publisher/synthetic-key",
        ])
        .env("REVVAULT_STORE", "/root/operator/revvault")
        .env("REVVAULT_IDENTITY", "/root/operator/revvault/identity")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    import
        .stdin
        .take()
        .unwrap()
        .write_all(b"synthetic-service-secret")
        .unwrap();
    assert!(import.wait_with_output().unwrap().status.success());
    let selected = "revealfleet/publisher/synthetic-key";
    let scoped = PassageStore::open_service_import(UID, selected).unwrap();
    let original_ciphertext = fs::read(&ciphertext).unwrap();
    assert_request_status(
        &ServicePolicy::fixed_policy_path(19001),
        &import_request,
        "local_completion_observed",
    );
    // Replayed completion is denied before stdin and leaves custody unchanged.
    let replay = Command::new("/usr/local/bin/revvault")
        .args([
            "set",
            "--service-request",
            &import_request,
            "--service-uid",
            "19001",
            selected,
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("revvault_service_request_denied"));
    assert_eq!(fs::read(&ciphertext).unwrap(), original_ciphertext);

    // Root's generic CLI and constructor cannot adopt service custody via
    // ordinary personal configuration, even when the target already exists.
    assert!(PassageStore::open(policy.config()).is_err());
    for command in [vec!["set", "--force", selected], vec!["delete", selected]] {
        let output = Command::new("/usr/local/bin/revvault")
            .args(command)
            .env("REVVAULT_STORE", policy.config().store_dir)
            .env("REVVAULT_IDENTITY", policy.config().identity_file)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("revvault_service_capability_denied")
        );
        assert_eq!(fs::read(&ciphertext).unwrap(), original_ciphertext);
    }

    assert!(scoped.set(selected, b"replacement-denied").is_err());
    assert!(scoped
        .set("revealfleet/owner/synthetic-key", b"foreign-denied")
        .is_err());
    assert!(scoped.upsert(selected, b"overwrite-denied").is_err());
    assert!(scoped.delete(selected).is_err());
    assert_eq!(fs::read(&ciphertext).unwrap(), original_ciphertext);
    assert!(PassageStore::open_service_import(UID, "revealfleet/owner/synthetic-key").is_err());
    fs::create_dir_all("/root/operator/gh").unwrap();
    fs::create_dir_all("/root/operator/ssh").unwrap();
    fs::create_dir_all("/root/operator/revvault").unwrap();
    fs::set_permissions("/root/operator", fs::Permissions::from_mode(0o700)).unwrap();
    for path in [
        "/root/operator/gh/token",
        "/root/operator/ssh/key",
        "/root/operator/revvault/identity",
    ] {
        fs::write(path, "synthetic-owner-secret").unwrap();
    }
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "native_service_provisioning_and_kernel_denial",
            "--nocapture",
        ])
        .env("REVEALFLEET_NATIVE_SERVICE_CHILD", "1")
        .env("HOME", "/root/operator")
        .env("REVVAULT_STORE", "/root/operator/revvault")
        .env("REVVAULT_IDENTITY", "/root/operator/revvault/identity");
    as_user(&mut child, UID);
    assert!(child.status().unwrap().success());
    let mut delivery = Command::new("/usr/local/bin/revvault");
    delivery
        .args(["run", "--service", "--", COMMAND])
        .env("HOME", "/root/operator")
        .env("GH_TOKEN", "synthetic-owner-token")
        .env("GITHUB_TOKEN", "synthetic-owner-token")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "credential.helper")
        .env("GIT_CONFIG_VALUE_0", "synthetic-owner-helper")
        .env("SSH_AUTH_SOCK", "/root/operator/ssh/socket");
    as_user(&mut delivery, UID);
    let result = delivery.output().unwrap();
    assert!(result.status.success(), "scoped native delivery denied");
    let environment = String::from_utf8(result.stdout).unwrap();
    assert!(environment.contains("REVEALFLEET_SYNTHETIC_KEY=synthetic-service-secret"));
    assert!(environment.contains("HOME=/var/lib/revealfleet/publisher"));
    assert!(!environment.contains("synthetic-owner"));
    for forbidden in [
        "GH_TOKEN=",
        "GITHUB_TOKEN=",
        "GIT_CONFIG_",
        "SSH_AUTH_SOCK=",
    ] {
        assert!(!environment.contains(forbidden));
    }
    let recipients_before = fs::read(&plan.recipients_file).unwrap();
    let foreign_recipient = age::x25519::Identity::generate().to_public();
    let with_foreign = format!(
        "{}{}\n",
        String::from_utf8(recipients_before.clone()).unwrap(),
        foreign_recipient
    );
    fs::write(&plan.recipients_file, with_foreign).unwrap();
    assert!(PassageStore::open_service_import(UID, selected).is_err());
    assert!(!delivery.output().unwrap().status.success());
    fs::write(&plan.recipients_file, &recipients_before).unwrap();
    assert_eq!(fs::read(&ciphertext).unwrap(), original_ciphertext);
    // An unrelated kernel principal cannot opt into this service by selecting
    // its store through environment or invoking the same scoped command.
    let mut foreign = Command::new("/usr/local/bin/revvault");
    foreign
        .args(["run", "--service", "--", COMMAND])
        .env("REVVAULT_STORE", &plan.store_dir)
        .env("REVVAULT_IDENTITY", &plan.identity_file);
    as_user(&mut foreign, 65534);
    assert!(!foreign.output().unwrap().status.success());
    let mut foreign_read = Command::new("/usr/bin/cat");
    foreign_read.arg(&plan.identity_file);
    as_user(&mut foreign_read, 65534);
    assert!(!foreign_read.output().unwrap().status.success());
    let mut mixed_groups = Command::new("/usr/local/bin/revvault");
    mixed_groups.args(["run", "--service", "--", COMMAND]);
    unsafe {
        mixed_groups.pre_exec(|| {
            let groups = [UID, 65534];
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                || libc::setgid(UID) != 0
                || libc::setuid(UID) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    assert!(!mixed_groups.output().unwrap().status.success());
    // Mutable policy/identity deny the native capability, rather than falling
    // back to an operator vault.
    fs::set_permissions(&plan.identity_file, fs::Permissions::from_mode(0o660)).unwrap();
    let result = delivery.output().unwrap();
    assert!(!result.status.success());
    fs::set_permissions(&plan.identity_file, fs::Permissions::from_mode(0o640)).unwrap();
    fs::set_permissions(&plan.policy_file, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(!delivery.output().unwrap().status.success());
    fs::set_permissions(&plan.policy_file, fs::Permissions::from_mode(0o644)).unwrap();
    independent_backup(&policy);
    let mut recorded = BTreeMap::new();
    for name in [
        "identity.txt",
        "policy.toml",
        "store/.age-recipients",
        "store/revealfleet/publisher/synthetic-key.age",
    ] {
        use sha2::{Digest, Sha256};
        recorded.insert(
            name.to_string(),
            hex::encode(Sha256::digest(fs::read(root.join(name)).unwrap())),
        );
    }
    fs::write(
        "/var/lib/revvault/replacement-proof.json",
        serde_json::to_vec(&recorded).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        "/var/lib/revvault/replacement-proof.json",
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    println!("native persistent custody prepare PASS; independent identity and scoped ciphertext retained");
}

const RECOVERY: &str = "/root/revealfleet-backup-proof";
const RECOVERY_AUTHORITY: &str = "/root/revealfleet-recovery-authority";

fn independent_backup(policy: &ServicePolicy) {
    use revvault_core::service::backup::backup_service_vault;
    use secrecy::ExposeSecret;
    let destination = Path::new(RECOVERY);
    assert!(
        destination.is_dir(),
        "fixture needs an independent named recovery volume"
    );
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    let authority = Path::new(RECOVERY_AUTHORITY);
    assert!(
        authority.is_dir(),
        "fixture needs a separately mounted synthetic recovery authority"
    );
    fs::set_permissions(authority, fs::Permissions::from_mode(0o700)).unwrap();
    let recovery = age::x25519::Identity::generate();
    let recipient = recovery.to_public().to_string();
    let output = destination.join("checkpoint.age");
    let config = policy.config();
    let original = fs::read(&config.identity_file).unwrap();
    let original_recipients = fs::read(&config.recipients_file).unwrap();
    let service_recipient = revvault_core::Identity::from_file(&config.identity_file)
        .unwrap()
        .default_recipient()
        .to_string();
    assert!(backup_service_vault(UID, &service_recipient, &output).is_err());
    assert!(!output.exists());
    let root = config.store_dir.parent().unwrap();
    let extra = root.join(".provisioning.toml");
    fs::write(&extra, "synthetic pending").unwrap();
    assert!(backup_service_vault(UID, &recipient, &output).is_err());
    fs::remove_file(&extra).unwrap();
    let foreign = config.store_dir.join("foreign.age");
    fs::write(&foreign, "synthetic foreign").unwrap();
    assert!(backup_service_vault(UID, &recipient, &output).is_err());
    fs::remove_file(&foreign).unwrap();
    // Hard links must be on the custody filesystem; the archive is deliberately
    // on a different volume. Keep the extra link outside the scoped namespace.
    let link = Path::new("/var/lib/revvault/.native-evidence/backup-linked-identity");
    fs::hard_link(&config.identity_file, link).unwrap();
    assert!(backup_service_vault(UID, &recipient, &output).is_err());
    fs::remove_file(link).unwrap();
    let held_identity = Path::new("/var/lib/revvault/.native-evidence/backup-identity");
    fs::rename(&config.identity_file, held_identity).unwrap();
    std::os::unix::fs::symlink(held_identity, &config.identity_file).unwrap();
    assert!(backup_service_vault(UID, &recipient, &output).is_err());
    fs::remove_file(&config.identity_file).unwrap();
    fs::rename(held_identity, &config.identity_file).unwrap();
    fs::set_permissions(&config.identity_file, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(backup_service_vault(UID, &recipient, &output).is_err());
    fs::set_permissions(&config.identity_file, fs::Permissions::from_mode(0o640)).unwrap();
    let mut denied = Command::new("/usr/local/bin/revvault");
    denied.args([
        "backup",
        "--service-uid",
        "19001",
        "--recipient",
        &recipient,
        "--output",
        output.to_str().unwrap(),
    ]);
    as_user(&mut denied, UID);
    assert!(!denied.output().unwrap().status.success());
    assert!(!output.exists());
    use std::os::fd::AsRawFd;
    let lock = fs::File::open(root).unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let mut contenders: Vec<_> = (0..2)
        .map(|_| {
            Command::new("/usr/local/bin/revvault")
                .args([
                    "--json",
                    "backup",
                    "--service-uid",
                    "19001",
                    "--recipient",
                    &recipient,
                    "--output",
                    output.to_str().unwrap(),
                ])
                .env("REVVAULT_STORE", "/root/operator/revvault")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let mut import = Command::new("/usr/local/bin/revvault")
        .args([
            "set",
            "--service-request",
            &request_file(
                &ServicePolicy::fixed_policy_path(19001),
                "import",
                Some("revealfleet/publisher/synthetic-key"),
                None,
            ),
            "--service-uid",
            "19001",
            "revealfleet/publisher/synthetic-key",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    import
        .stdin
        .take()
        .unwrap()
        .write_all(b"synthetic replacement denied")
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(250));
    for child in &mut contenders {
        assert!(child.try_wait().unwrap().is_none());
    }
    assert!(import.try_wait().unwrap().is_none());
    assert!(!output.exists());
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
    drop(lock);
    let outcomes = contenders
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| result.status.success())
            .count(),
        1
    );
    assert!(!import.wait_with_output().unwrap().status.success());
    let cli = outcomes
        .iter()
        .find(|result| result.status.success())
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&cli.stdout).unwrap();
    let receipt: revvault_core::service::backup::BackupReceipt =
        serde_json::from_value(response["receipt"].clone()).unwrap();
    assert_eq!(response["status"], "service_backed_up");
    let encrypted = fs::read(&output).unwrap();
    assert!(!encrypted
        .windows(original.len())
        .any(|part| part == original));
    assert!(!String::from_utf8_lossy(&cli.stdout).contains("AGE-SECRET-KEY"));
    assert!(backup_service_vault(UID, &recipient, &output).is_err());
    assert_eq!(fs::read(&output).unwrap(), encrypted);
    assert_eq!(fs::read(&config.identity_file).unwrap(), original);
    assert_eq!(
        fs::read(&config.recipients_file).unwrap(),
        original_recipients
    );
    // This key is generated solely inside a disposable fixture and never emitted.
    fs::write(
        authority.join("synthetic-recovery-identity"),
        recovery.to_string().expose_secret(),
    )
    .unwrap();
    fs::write(
        authority.join("receipt.json"),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
    fs::write(
        authority.join("policy.toml"),
        toml::to_string(policy).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        authority.join("synthetic-recovery-identity"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    for name in ["receipt.json", "policy.toml"] {
        fs::set_permissions(authority.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(!destination.join("synthetic-recovery-identity").exists());
    assert!(!destination.join("receipt.json").exists());
    assert!(!destination.join("policy.toml").exists());
    for path in [
        authority.join("synthetic-recovery-identity"),
        destination.join("checkpoint.age"),
    ] {
        let mut reader = Command::new("/usr/bin/cat");
        reader.arg(path);
        as_user(&mut reader, UID);
        assert!(!reader.output().unwrap().status.success());
    }
    println!("native independent encrypted checkpoint PASS; separate recipient, no plaintext archive, root-only CLI and unsafe/incomplete/foreign/overwrite denials");
}

fn independent_restore() {
    use revvault_core::service::backup::{
        native_restore_service_vault as restore_service_vault, BackupReceipt,
    };
    use secrecy::ExposeSecret;
    use sha2::{Digest, Sha256};
    let source_volume = Path::new(RECOVERY);
    let scratch = tempfile::Builder::new()
        .prefix("revealfleet-restore-fixture-")
        .tempdir_in("/root")
        .unwrap();
    let destination = scratch.path();
    let source_authority = Path::new(RECOVERY_AUTHORITY);
    for name in ["checkpoint.age", "policy.toml", "receipt.json"] {
        let source = if name == "checkpoint.age" {
            source_volume
        } else {
            source_authority
        };
        fs::copy(source.join(name), destination.join(name)).unwrap();
        fs::set_permissions(destination.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let archive = destination.join("checkpoint.age");
    let policy_file = destination.join("policy.toml");
    let receipt: BackupReceipt =
        serde_json::from_slice(&fs::read(destination.join("receipt.json")).unwrap()).unwrap();
    let key = zeroize::Zeroizing::new(
        fs::read_to_string(Path::new(RECOVERY_AUTHORITY).join("synthetic-recovery-identity"))
            .unwrap(),
    );
    let root = Path::new("/var/lib/revvault/services/19001");
    assert!(
        !root.exists(),
        "must restore onto a fresh independent custody volume"
    );
    let denied = |policy: &Path, expected: &str, identity: &str| {
        assert!(restore_service_vault(policy, &archive, expected, identity).is_err());
        assert!(
            !root.exists(),
            "negative restore created an active namespace"
        );
    };
    denied(&policy_file, &"0".repeat(64), &key);
    denied(
        &policy_file,
        &receipt.archive_sha256,
        age::x25519::Identity::generate()
            .to_string()
            .expose_secret(),
    );
    let original_policy = fs::read(&policy_file).unwrap();
    let mut changed: ServicePolicy =
        toml::from_str(std::str::from_utf8(&original_policy).unwrap()).unwrap();
    changed.environment.insert("PORT".into(), "9999".into());
    fs::write(&policy_file, toml::to_string(&changed).unwrap()).unwrap();
    denied(&policy_file, &receipt.archive_sha256, &key);
    fs::write(&policy_file, &original_policy).unwrap();
    let source = fs::read(COMMAND).unwrap();
    fs::write(COMMAND, "synthetic changed command").unwrap();
    denied(&policy_file, &receipt.archive_sha256, &key);
    fs::write(COMMAND, source).unwrap();
    let encrypted = fs::read(&archive).unwrap();
    fs::write(&archive, &encrypted[..encrypted.len() / 2]).unwrap();
    denied(&policy_file, &receipt.archive_sha256, &key);
    // Even a matching digest cannot make malformed/truncated age input valid.
    denied(
        &policy_file,
        &hex::encode(Sha256::digest(&encrypted[..encrypted.len() / 2])),
        &key,
    );
    fs::write(&archive, &encrypted).unwrap();
    let linked = destination.join("linked-archive");
    fs::hard_link(&archive, &linked).unwrap();
    denied(&policy_file, &receipt.archive_sha256, &key);
    fs::remove_file(linked).unwrap();
    let held_archive = destination.join("held-archive.age");
    fs::rename(&archive, &held_archive).unwrap();
    std::os::unix::fs::symlink(&held_archive, &archive).unwrap();
    denied(&policy_file, &receipt.archive_sha256, &key);
    fs::remove_file(&archive).unwrap();
    fs::rename(held_archive, &archive).unwrap();
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o644)).unwrap();
    denied(&policy_file, &receipt.archive_sha256, &key);
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        revvault_core::service::backup::interrupt_restore_before_publication(
            &policy_file,
            &archive,
            &receipt.archive_sha256,
            &key
        )
        .is_err()
    );
    assert!(!root.exists());
    assert!(fs::read_dir("/var/lib/revvault/services")
        .unwrap()
        .next()
        .is_none());
    // An empty or pending target is not an absent target and cannot be adopted.
    fs::create_dir(root).unwrap();
    assert!(restore_service_vault(&policy_file, &archive, &receipt.archive_sha256, &key).is_err());
    fs::write(root.join(".provisioning.toml"), "synthetic pending").unwrap();
    assert!(restore_service_vault(&policy_file, &archive, &receipt.archive_sha256, &key).is_err());
    fs::remove_file(root.join(".provisioning.toml")).unwrap();
    fs::remove_dir(root).unwrap();
    let mut child = Command::new("/usr/local/bin/revvault")
        .args([
            "--json",
            "init",
            "--service-policy",
            policy_file.to_str().unwrap(),
            "--service-request",
            &request_file(&policy_file, "restore", None, Some(&receipt.archive_sha256)),
            "--restore-archive",
            archive.to_str().unwrap(),
            "--expected-sha256",
            &receipt.archive_sha256,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(key.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "restore CLI failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()["status"],
        "service_restored"
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("AGE-SECRET-KEY"));
    for (name, expected) in &receipt.files {
        assert_eq!(
            hex::encode(Sha256::digest(fs::read(root.join(name)).unwrap())),
            *expected
        );
    }
    // Replay/populated target cannot replace an already restored capability.
    assert!(restore_service_vault(&policy_file, &archive, &receipt.archive_sha256, &key).is_err());
    let mut delivery = Command::new("/usr/local/bin/revvault");
    delivery
        .args(["run", "--service", "--", COMMAND])
        .env("GH_TOKEN", "synthetic-owner-token");
    as_user(&mut delivery, UID);
    let result = delivery.output().unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout)
        .contains("REVEALFLEET_SYNTHETIC_KEY=synthetic-service-secret"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("synthetic-owner-token"));
    let mut foreign = Command::new("/usr/bin/cat");
    foreign.arg(root.join("identity.txt"));
    as_user(&mut foreign, 65534);
    assert!(!foreign.output().unwrap().status.success());
    println!("native independent fresh-volume restore PASS; exact original identity/recipient/policy/ciphertext, source and digest pinning, scoped delivery and replay denial");
}
