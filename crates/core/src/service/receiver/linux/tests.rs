use super::*;
use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};

fn request() -> ServiceMutationRequest {
    ServiceMutationRequest {
        version: 1,
        request_id: "a".repeat(32),
        uid: 19001,
        operation: ServiceOperation::Import,
        selector: Some("revealfleet/publisher/key".into()),
        source_contract_sha256: "b".repeat(64),
        expected_target_sha256: "c".repeat(64),
        expires_at: 1060,
        archive_sha256: None,
    }
}

#[test]
fn request_binds_actual_operation_uid_selector_archive_and_bounded_expiry() {
    let r = request();
    assert!(r
        .validate(
            19001,
            ServiceOperation::Import,
            r.selector.as_deref(),
            None,
            1000
        )
        .is_ok());
    for now in [759, 1031, 1060, i64::MIN, i64::MAX] {
        assert!(r
            .validate(
                19001,
                ServiceOperation::Import,
                r.selector.as_deref(),
                None,
                now
            )
            .is_err());
    }
    assert!(r
        .validate(
            19002,
            ServiceOperation::Import,
            r.selector.as_deref(),
            None,
            1000
        )
        .is_err());
    assert!(r
        .validate(
            19001,
            ServiceOperation::Resume,
            r.selector.as_deref(),
            None,
            1000
        )
        .is_err());
    assert!(r
        .validate(
            19001,
            ServiceOperation::Import,
            Some("revealfleet/owner/key"),
            None,
            1000
        )
        .is_err());
    assert!(r
        .validate(
            19001,
            ServiceOperation::Import,
            r.selector.as_deref(),
            Some(&"d".repeat(64)),
            1000
        )
        .is_err());
    for field in [
        "request_id",
        "source_contract_sha256",
        "expected_target_sha256",
    ] {
        let mut value = serde_json::to_value(&r).unwrap();
        value[field] = serde_json::json!("../unsafe");
        let invalid: ServiceMutationRequest = serde_json::from_value(value).unwrap();
        assert!(invalid
            .validate(
                19001,
                ServiceOperation::Import,
                r.selector.as_deref(),
                None,
                1000
            )
            .is_err());
    }
    let mut value = serde_json::to_value(&r).unwrap();
    value["unexpected_authority"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ServiceMutationRequest>(value).is_err());
}

#[test]
fn mount_evidence_requires_exact_unique_writable_custody_mount() {
    let valid = "42 1 8:1 / /var/lib/revvault rw,relatime - ext4 /dev/test rw";
    assert!(mount_identity(valid).is_ok());
    for invalid in [
        valid.replace(" rw,", " ro,"),
        valid.replace("/var/lib/revvault ", "/var/lib/revvault-copy "),
        format!("{valid}\n{valid}"),
        "42 1 8:1 / /var/lib/revvault rw".into(),
    ] {
        assert!(mount_identity(&invalid).is_err());
    }
}

fn journal(directory: &Path) -> Journal {
    Journal {
        directory: directory.into(),
        owner: unsafe { libc::geteuid() },
        request_id: "a".repeat(32),
        claim: b"synthetic nonsecret claim".to_vec(),
    }
}

#[test]
fn durable_claim_survives_drop_and_rejects_reuse_after_completion() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let j = journal(dir.path());
    j.claim().unwrap();
    j.verify().unwrap();
    drop(j);
    let j = journal(dir.path());
    assert!(j.claim().is_err());
    j.complete().unwrap();
    assert!(j.verify().is_err());
    assert!(j.complete().is_err());
    assert!(j.claim().is_err());
    assert!(fs::read_to_string(j.complete_path())
        .unwrap()
        .contains("local_complete"));
}

#[test]
fn incomplete_truncated_symlink_and_orphaned_records_remain_held() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let j = journal(dir.path());
    fs::write(j.complete_path(), b"").unwrap();
    assert!(j.claim().is_err());
    fs::remove_file(j.complete_path()).unwrap();
    fs::write(j.claim_path(), b"").unwrap();
    assert!(j.claim().is_err());
    assert!(j.verify().is_err());
    fs::remove_file(j.claim_path()).unwrap();
    std::os::unix::fs::symlink("/absent", j.claim_path()).unwrap();
    assert!(j.claim().is_err());
    assert!(j.verify().is_err());
    fs::remove_file(j.claim_path()).unwrap();
    j.claim().unwrap();
    fs::set_permissions(j.claim_path(), fs::Permissions::from_mode(0o640)).unwrap();
    assert!(j.verify().is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert!(j.check_directory().is_err());
}

#[test]
fn concurrent_claims_have_exactly_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let winners = std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| journal(dir.path()).claim().is_ok()))
            .collect();
        jobs.into_iter()
            .map(|job| usize::from(job.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(winners, 1);
}

#[test]
fn deadline_kills_only_dedicated_child_and_drop_cancels_its_timer() {
    const CHILD: &str = "REVEALFLEET_SYNTHETIC_TIMER_TEST";
    if let Ok(mode) = std::env::var(CHILD) {
        let timer = ServiceReceiverDeadline::arm(Duration::from_millis(100)).unwrap();
        if mode == "cancel" {
            drop(timer);
        }
        std::thread::sleep(Duration::from_millis(350));
        return;
    }
    let executable = std::env::current_exe().unwrap();
    for mode in ["kill", "cancel"] {
        let output = std::process::Command::new(&executable)
            .args(["--exact", "service::receiver::linux::tests::deadline_kills_only_dedicated_child_and_drop_cancels_its_timer", "--test-threads=1"])
            .env(CHILD, mode).output().unwrap();
        if mode == "kill" {
            assert_eq!(output.status.signal(), Some(libc::SIGKILL));
        } else {
            assert!(output.status.success());
        }
    }
}

#[test]
fn unprivileged_receiver_denies_before_reading_request_or_policy() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    assert!(ServiceReceiverDeadline::start().is_err());
    let timer = ServiceReceiverDeadline::arm(Duration::from_secs(5)).unwrap();
    let denied = ServiceMutationGuard::begin(
        &timer,
        Path::new("/absent/request"),
        ServiceInvocation::Initialize {
            policy: "/absent/policy".into(),
        },
    )
    .err()
    .unwrap();
    assert_eq!(denied.to_string(), "revvault_service_request_denied");
}

#[test]
fn status_observes_without_creating_or_changing_nonce_records() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("absent-journal");
    let j = journal(&missing);
    assert_eq!(j.status().unwrap(), ServiceRequestState::Unobserved);
    assert!(!missing.exists());
    let j = journal(root.path());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(j.status().unwrap(), ServiceRequestState::Unobserved);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    j.claim().unwrap();
    let before = fs::read(j.claim_path()).unwrap();
    assert_eq!(j.status().unwrap(), ServiceRequestState::Held);
    j.complete().unwrap();
    let receipt = fs::read(j.complete_path()).unwrap();
    for _ in 0..2 {
        assert_eq!(
            j.status().unwrap(),
            ServiceRequestState::LocalCompletionObserved
        );
        assert_eq!(fs::read(j.claim_path()).unwrap(), before);
        assert_eq!(fs::read(j.complete_path()).unwrap(), receipt);
    }
    assert!(j.claim().is_err());
}

#[test]
fn status_denies_orphan_partial_foreign_and_unsafe_completion_records() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let j = journal(dir.path());
    j.write_new(&j.complete_path(), &j.completion_bytes().unwrap())
        .unwrap();
    assert!(j.status().is_err()); // completion without durable claim
    fs::remove_file(j.complete_path()).unwrap();
    j.claim().unwrap();
    let valid: serde_json::Value = serde_json::from_slice(&j.completion_bytes().unwrap()).unwrap();
    let mut cases = vec![Vec::new(), b"{truncated".to_vec()];
    for (key, value) in [
        ("version", serde_json::json!(2)),
        ("request_sha256", serde_json::json!("d".repeat(64))),
        ("status", serde_json::json!("accepted")),
        ("provider_admission", serde_json::json!("accepted")),
        ("extra", serde_json::json!(true)),
    ] {
        let mut invalid = valid.clone();
        invalid[key] = value;
        cases.push(serde_json::to_vec(&invalid).unwrap());
    }
    for bytes in cases {
        j.write_new(&j.complete_path(), &bytes).unwrap();
        assert!(j.status().is_err());
        assert_eq!(fs::read(j.complete_path()).unwrap(), bytes);
        fs::remove_file(j.complete_path()).unwrap();
    }
    j.complete().unwrap();
    fs::set_permissions(j.complete_path(), fs::Permissions::from_mode(0o640)).unwrap();
    assert!(j.status().is_err());
    fs::remove_file(j.complete_path()).unwrap();
    std::os::unix::fs::symlink("/absent", j.complete_path()).unwrap();
    assert!(j.status().is_err());
    fs::remove_file(j.complete_path()).unwrap();
    fs::hard_link(j.claim_path(), j.complete_path()).unwrap();
    assert!(j.status().is_err());
}

#[test]
fn status_denies_changed_claim_and_blocking_special_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let j = journal(dir.path());
    j.claim().unwrap();
    fs::write(j.claim_path(), vec![b'x'; j.claim.len()]).unwrap();
    assert!(j.status().is_err());
    fs::remove_file(j.claim_path()).unwrap();
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(j.claim_path().as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(j.status().is_err()); // O_NONBLOCK + descriptor type check
}

#[test]
fn status_keeps_expired_original_binding_separate_from_mutation_admission() {
    let mut r = request();
    r.expires_at = 1;
    assert!(r
        .validate_binding(19001, ServiceOperation::Import, r.selector.as_deref(), None)
        .is_ok());
    assert!(r
        .validate(
            19001,
            ServiceOperation::Import,
            r.selector.as_deref(),
            None,
            1000
        )
        .is_err());
    for expiry in [0, -1, i64::MAX] {
        r.expires_at = expiry;
        assert!(r
            .validate_binding(19001, ServiceOperation::Import, r.selector.as_deref(), None)
            .is_err());
    }
}

#[test]
fn status_denies_unprivileged_callers_without_path_access() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let timer = ServiceReceiverDeadline::arm(Duration::from_secs(5)).unwrap();
    let error = ServiceMutationGuard::status(
        &timer,
        Path::new("/absent/request"),
        Path::new("/absent/policy"),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "revvault_service_request_denied");
}

#[test]
fn every_observation_keeps_retry_and_provider_authority_denied() {
    let r = request();
    let j = Journal::for_request(PathBuf::from("/unused"), &r).unwrap();
    for state in [
        ServiceRequestState::Unobserved,
        ServiceRequestState::Held,
        ServiceRequestState::LocalCompletionObserved,
    ] {
        let report = serde_json::to_value(j.observation(r.clone(), state)).unwrap();
        assert_eq!(report["request_id"], r.request_id);
        assert_eq!(
            report["request_sha256"],
            hex::encode(Sha256::digest(&j.claim))
        );
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
    }
}
