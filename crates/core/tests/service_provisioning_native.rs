//! Explicit native primitive proof in a disposable root container. This is not
//! acceptance of the coding launchers, publisher image or hosted GitHub policy.
use revvault_core::{
    init::{
        init_service_vault, interrupt_service_vault_after_capability,
        interrupt_service_vault_after_store, resume_service_vault, service_init_plan,
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
        assert!(store
            .upsert("revealfleet/publisher/synthetic-key", b"denied")
            .is_err());
        assert!(store.delete("revealfleet/publisher/synthetic-key").is_err());
        assert!(store
            .compare_and_upsert(
                "revealfleet/publisher/synthetic-key",
                revvault_core::store::ExpectedCurrent::Absent,
                b"denied",
                "35b4a913-3d30-4a23-9ac1-072a55dde99e",
            )
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
    if std::env::var("REVEALFLEET_NATIVE_SERVICE_REPLACEMENT").as_deref() == Ok("1") {
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

    // Exercise maintained scoped import, not a duplicated setup/chmod recipe.
    let mut import = Command::new("/usr/local/bin/revvault")
        .args([
            "set",
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
    let ciphertext = plan
        .store_dir
        .join("revealfleet/publisher/synthetic-key.age");
    let original_ciphertext = fs::read(&ciphertext).unwrap();
    assert!(scoped.set(selected, b"replacement-denied").is_err());
    assert!(scoped
        .set("revealfleet/owner/synthetic-key", b"foreign-denied")
        .is_err());
    assert!(scoped.upsert(selected, b"overwrite-denied").is_err());
    assert!(scoped.delete(selected).is_err());
    assert!(scoped
        .compare_and_upsert(
            selected,
            revvault_core::store::ExpectedCurrent::Absent,
            b"conditional-overwrite-denied",
            "35b4a913-3d30-4a23-9ac1-072a55dde99e",
        )
        .is_err());
    assert!(!plan.store_dir.join(".revvault/pending.age").exists());
    assert!(!plan.store_dir.join(".revvault/operations").exists());

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
    // Runtime must never recreate missing coordination metadata.
    let lock_path = plan.store_dir.join(".revvault/store.lock");
    let withheld_lock = Path::new("/var/lib/revvault/.native-evidence/withheld-lock");
    fs::rename(&lock_path, withheld_lock).unwrap();
    let missing_lock = delivery.output().unwrap();
    assert!(!missing_lock.status.success());
    assert!(!lock_path.exists());
    fs::rename(withheld_lock, &lock_path).unwrap();
    assert!(delivery.output().unwrap().status.success());

    // The existing pending-operation fence remains authoritative for services.
    let pending = plan.store_dir.join(".revvault/pending.age");
    fs::write(&pending, b"synthetic pending-operation fence").unwrap();
    assert!(!delivery.output().unwrap().status.success());
    assert!(pending.exists());
    fs::remove_file(&pending).unwrap();
    assert!(delivery.output().unwrap().status.success());
    assert_eq!(fs::read(&ciphertext).unwrap(), original_ciphertext);

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
    let mut recorded = BTreeMap::new();
    for name in [
        "identity.txt",
        "store/.revvault/store.lock",
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
