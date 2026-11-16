use super::*;
use serde_json::{json, Value};

fn target() -> FlyServiceTarget {
    FlyServiceTarget {
        version: 1,
        app: "revealfleet-publisher".into(),
        machine_id: "a123456789abcd".into(),
        instance_id: "01HQ73A7BFFDF1B6WMGHFZZ4E7".into(),
        image: format!(
            "registry.fly.io/revealfleet-publisher@sha256:{}",
            "a".repeat(64)
        ),
        volume_id: "vol_abcdefgh1234".into(),
        service_uid: 1001,
        source_contract_sha256: "b".repeat(64),
        expires_at: Utc::now().timestamp() + 300,
    }
}

fn machine(target: &FlyServiceTarget) -> Value {
    json!({
        "id": target.machine_id,
        "instance_id": target.instance_id,
        "state": "started",
        "image_ref": {"digest": format!("sha256:{}", "a".repeat(64))},
        "config": {
            "image": target.image,
            "mounts": [{"volume": target.volume_id, "path": "/var/lib/revvault"}],
            "env": {"synthetic_private_value": "never-include-this-in-evidence"}
        }
    })
}

fn route(target: &FlyServiceTarget) -> String {
    format!("/apps/{}/machines/{}", target.app, target.machine_id)
}

#[test]
fn rejects_malformed_targets_and_binds_every_expected_field() {
    let valid = target();
    let now = Utc::now().timestamp();
    valid.validate(now).unwrap();
    let cases = [
        ("version", json!(2)),
        ("app", json!("../foreign")),
        ("machine_id", json!("../foreign")),
        ("instance_id", json!("../foreign")),
        ("volume_id", json!("vol_../../foreign")),
        (
            "image",
            json!("registry.fly.io/revealfleet-publisher:latest"),
        ),
        (
            "image",
            json!(format!("registry.fly.io/foreign@sha256:{}", "a".repeat(64))),
        ),
        ("service_uid", json!(0)),
        ("source_contract_sha256", json!("b".repeat(63))),
        ("expires_at", json!(now - 1)),
        ("expires_at", json!(now + 601)),
    ];
    for (field, value) in cases {
        let mut json = serde_json::to_value(&valid).unwrap();
        json[field] = value;
        let invalid: FlyServiceTarget = serde_json::from_value(json).unwrap();
        assert_eq!(invalid.validate(now).unwrap_err().to_string(), DENIED);
        assert_ne!(valid.digest().unwrap(), invalid.digest().unwrap());
    }
    let mut unknown = serde_json::to_value(valid).unwrap();
    unknown["arbitrary_command"] = json!("denied");
    assert!(serde_json::from_value::<FlyServiceTarget>(unknown).is_err());
}

#[tokio::test]
async fn matching_provider_configuration_still_holds_provisioning() {
    let mut server = mockito::Server::new_async().await;
    let target = target();
    let request = server
        .mock("GET", route(&target).as_str())
        .match_header("authorization", "Bearer synthetic-read-token")
        .with_body(machine(&target).to_string())
        .expect(1)
        .create_async()
        .await;
    let no_exec = server
        .mock("POST", mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    let evidence = FlyClient::new("synthetic-read-token".into())
        .verify_service_target_at(&target, &server.url(), TIMEOUT)
        .await
        .unwrap();
    let json = serde_json::to_value(evidence).unwrap();
    assert_eq!(json["target_sha256"], target.digest().unwrap());
    assert_eq!(json["provider_configuration_matches"], true);
    assert_eq!(json["expected_service_uid"], 1001);
    for field in ["receiver_identity", "receiver_sources", "execution_fencing"] {
        assert_eq!(json[field], "unverified");
    }
    assert_eq!(json["provisioning"], "held");
    assert!(json["expires_at"].as_i64().unwrap() <= json["observed_at"].as_i64().unwrap() + 30);
    assert!(!json.to_string().contains("never-include-this-in-evidence"));
    assert!(!json.to_string().contains("synthetic-read-token"));
    request.assert_async().await;
    no_exec.assert_async().await;
}

#[tokio::test]
async fn rejects_identity_image_volume_and_state_changes_without_execution() {
    let target = target();
    let original = machine(&target);
    for (pointer, value) in [
        ("/id", json!("a0000000000000")),
        ("/instance_id", json!("01HQ73A7BFFDF1B6WMGHFZZ4E8")),
        ("/state", json!("stopped")),
        (
            "/image_ref/digest",
            json!(format!("sha256:{}", "c".repeat(64))),
        ),
        (
            "/config/image",
            json!("registry.fly.io/revealfleet-publisher:latest"),
        ),
        ("/config/mounts/0/volume", json!("vol_foreign1234")),
        ("/config/mounts/0/path", json!("/tmp")),
        ("/config/mounts", json!([])),
        (
            "/config/mounts",
            json!([
                {"volume": target.volume_id, "path": "/var/lib/revvault"},
                {"volume": "vol_foreign1234", "path": "/foreign"}
            ]),
        ),
    ] {
        let mut server = mockito::Server::new_async().await;
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let request = server
            .mock("GET", route(&target).as_str())
            .with_body(changed.to_string())
            .expect(1)
            .create_async()
            .await;
        let no_exec = server
            .mock("POST", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;
        let error = FlyClient::new("synthetic-read-token".into())
            .verify_service_target_at(&target, &server.url(), TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), DENIED, "{pointer}");
        request.assert_async().await;
        no_exec.assert_async().await;
    }
}

#[tokio::test]
async fn rejects_missing_credentials_and_expired_targets_before_provider_io() {
    let mut server = mockito::Server::new_async().await;
    let request = server
        .mock("GET", mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    let mut target = target();
    assert!(FlyClient::new(String::new())
        .verify_service_target_at(&target, &server.url(), TIMEOUT)
        .await
        .is_err());
    target.expires_at = Utc::now().timestamp() - 1;
    assert!(FlyClient::new("synthetic-read-token".into())
        .verify_service_target_at(&target, &server.url(), TIMEOUT)
        .await
        .is_err());
    request.assert_async().await;
}

#[tokio::test]
async fn bounds_responses_and_never_relays_provider_errors_or_redirects() {
    for (status, body) in [
        (403, "synthetic-private-provider-error".to_string()),
        (429, "synthetic-private-rate-limit".to_string()),
        (500, "synthetic-private-server-error".to_string()),
        (200, "synthetic-private-invalid-json".to_string()),
        (200, "x".repeat(MAX_RESPONSE + 1)),
        (302, String::new()),
    ] {
        let mut server = mockito::Server::new_async().await;
        let target = target();
        let request = server
            .mock("GET", route(&target).as_str())
            .with_status(status)
            .with_header("location", "/should-not-follow")
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let no_redirect = server
            .mock("GET", "/should-not-follow")
            .expect(0)
            .create_async()
            .await;
        let error = FlyClient::new("synthetic-read-token".into())
            .verify_service_target_at(&target, &server.url(), TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), DENIED);
        request.assert_async().await;
        no_redirect.assert_async().await;
    }
}

#[tokio::test]
async fn streaming_provider_response_has_a_whole_operation_deadline() {
    let mut server = mockito::Server::new_async().await;
    let target = target();
    let request = server
        .mock("GET", route(&target).as_str())
        .with_chunked_body(|writer| {
            std::thread::sleep(Duration::from_secs(2));
            let _ = writer.write_all(b"{}");
            Ok(())
        })
        .expect(1)
        .create_async()
        .await;
    let started = std::time::Instant::now();
    let error = FlyClient::new("synthetic-read-token".into())
        .verify_service_target_at(&target, &server.url(), Duration::from_millis(500))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), DENIED);
    assert!(started.elapsed() < Duration::from_millis(1500));
    request.assert_async().await;
}
