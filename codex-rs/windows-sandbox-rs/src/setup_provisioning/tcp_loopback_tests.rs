use super::tests::payload_json;
use super::{Payload, validate_network_mode};
use serde_json::json;

fn loopback_payload(home: &std::path::Path) -> Payload {
    let mut value = payload_json();
    value["codex_home"] = json!(home);
    value["version"] = json!(crate::branding::TCP_LOOPBACK_SETUP_VERSION);
    value["allow_tcp_loopback"] = json!(true);
    value["offline_username"] = json!(crate::branding::TCP_LOOPBACK_OFFLINE_USERNAME);
    value["online_username"] = json!(crate::branding::TCP_LOOPBACK_ONLINE_USERNAME);
    value["allow_local_binding"] = json!(false);
    value["proxy_ports"] = json!([]);
    serde_json::from_value(value).unwrap()
}

#[test]
fn tcp_loopback_requires_version_separate_accounts_and_no_udp_or_proxy_exception() {
    let home = tempfile::tempdir().unwrap();
    let valid = loopback_payload(home.path());
    validate_network_mode(&valid).unwrap();
    for case in 0..6 {
        let mut payload = valid.clone();
        match case {
            0 => payload.version = 5,
            1 => payload.offline_username = crate::branding::OFFLINE_USERNAME.into(),
            2 => payload.online_username = crate::branding::ONLINE_USERNAME.into(),
            3 => payload.allow_local_binding = true,
            4 => payload.proxy_ports = vec![8080],
            _ => payload.allow_tcp_loopback = false,
        }
        assert!(
            validate_network_mode(&payload).is_err(),
            "invalid case {case}"
        );
    }
}

#[test]
fn tcp_loopback_refuses_foreign_home_before_mutating_it() {
    let home = tempfile::tempdir().unwrap();
    let sandbox = home.path().join(".sandbox");
    std::fs::create_dir(&sandbox).unwrap();
    let marker = json!({"version": 5, "offline_username": crate::branding::OFFLINE_USERNAME,
        "online_username": crate::branding::ONLINE_USERNAME});
    let path = sandbox.join("setup_marker.json");
    std::fs::write(&path, marker.to_string()).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(validate_network_mode(&loopback_payload(home.path())).is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn tcp_loopback_names_fit_windows_sam_limit_and_do_not_reuse_strict_accounts() {
    assert!(crate::branding::TCP_LOOPBACK_OFFLINE_USERNAME.len() <= 20);
    assert!(crate::branding::TCP_LOOPBACK_ONLINE_USERNAME.len() <= 20);
    assert_ne!(
        crate::branding::TCP_LOOPBACK_OFFLINE_USERNAME,
        crate::branding::OFFLINE_USERNAME
    );
    assert_ne!(
        crate::branding::TCP_LOOPBACK_ONLINE_USERNAME,
        crate::branding::ONLINE_USERNAME
    );
}

#[test]
fn tcp_loopback_refuses_foreign_credentials_without_marker() {
    let home = tempfile::tempdir().unwrap();
    let secrets = home.path().join(".sandbox-secrets");
    std::fs::create_dir(&secrets).unwrap();
    let users = json!({"version":5,
        "offline":{"username":crate::branding::OFFLINE_USERNAME,"password":"test-only"},
        "online":{"username":crate::branding::ONLINE_USERNAME,"password":"test-only"}});
    let path = secrets.join("sandbox_users.json");
    std::fs::write(&path, users.to_string()).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(validate_network_mode(&loopback_payload(home.path())).is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
}
