//! Version dispatch and approved-read admission gate; pure payload checks only.

use super::Payload;
use super::SetupErrorCode;
use super::validate_authorized_execution;
use super::validate_network_mode;
use super::validate_payload_version;
use crate::extract_setup_failure;
use serde_json::json;
use tempfile::TempDir;

fn payload_with_version(version: u32) -> Payload {
    let mut value = super::tests::payload_json();
    value["version"] = json!(version);
    serde_json::from_value(value).unwrap()
}

fn with_authorized_read_paths(mut payload: Payload) -> Payload {
    payload.authorized_read_paths = vec![r"C:\workspace".into()];
    payload
}

#[test]
fn version_gate_accepts_legacy_and_current_ordinary_payloads() {
    assert!(validate_payload_version(&payload_with_version(
        crate::branding::LEGACY_SETUP_VERSION
    ))
    .is_ok());
    assert!(validate_payload_version(&payload_with_version(super::SETUP_VERSION)).is_ok());
}

#[test]
fn version_gate_accepts_approved_reads_only_at_current_version() {
    let approved = with_authorized_read_paths(payload_with_version(super::SETUP_VERSION));
    assert!(validate_payload_version(&approved).is_ok());

    for version in [crate::branding::LEGACY_SETUP_VERSION, 4, 8] {
        let payload = with_authorized_read_paths(payload_with_version(version));
        assert!(
            validate_payload_version(&payload).is_err(),
            "approved reads at version {version} must be refused"
        );
    }
}

#[test]
fn version_gate_rejects_unknown_versions_for_ordinary_payloads() {
    for version in [4, 6, 8] {
        assert!(
            validate_payload_version(&payload_with_version(version)).is_err(),
            "ordinary payload at version {version} must be refused"
        );
    }
}

#[test]
fn tcp_loopback_gate_keeps_version_and_refuses_approved_reads() {
    let home = TempDir::new().unwrap();
    let mut value = super::tests::payload_json();
    value["codex_home"] = json!(home.path());
    value["version"] = json!(crate::branding::TCP_LOOPBACK_SETUP_VERSION);
    value["allow_tcp_loopback"] = json!(true);
    value["offline_username"] = json!(crate::branding::TCP_LOOPBACK_OFFLINE_USERNAME);
    value["online_username"] = json!(crate::branding::TCP_LOOPBACK_ONLINE_USERNAME);
    value["allow_local_binding"] = json!(false);
    value["proxy_ports"] = json!([]);
    let loopback: Payload = serde_json::from_value(value).unwrap();
    assert!(validate_payload_version(&loopback).is_ok());
    assert!(validate_network_mode(&loopback).is_ok());

    let loopback_approved = with_authorized_read_paths(loopback);
    assert!(validate_payload_version(&loopback_approved).is_err());
    assert!(validate_network_mode(&loopback_approved).is_err());
}

#[test]
fn payload_defaults_authorized_read_paths_to_empty() {
    let payload = payload_with_version(super::SETUP_VERSION);
    assert!(payload.authorized_read_paths.is_empty());
}

#[test]
fn authorized_execution_gate_reports_structured_rejection_for_missing_manifest() {
    let home = TempDir::new().unwrap();
    let mut payload = with_authorized_read_paths(payload_with_version(super::SETUP_VERSION));
    payload.codex_home = home.path().to_path_buf();
    let err = validate_authorized_execution(&payload).expect_err("missing manifest");
    let failure = extract_setup_failure(&err).expect("structured rejection");
    assert_eq!(failure.code, SetupErrorCode::HelperAuthorizedReadRejected);
    assert!(failure.message.contains("protected-path manifest"));
}

#[test]
fn ordinary_execution_gate_passes_without_reading_any_manifest() {
    let home = TempDir::new().unwrap();
    let mut payload = payload_with_version(super::SETUP_VERSION);
    payload.codex_home = home.path().to_path_buf();
    assert!(validate_authorized_execution(&payload).is_ok());
}

#[test]
fn authorized_principal_names_fit_windows_sam_limit_and_stay_distinct() {
    use crate::branding::AUTHORIZED_OFFLINE_USERNAME;
    use crate::branding::AUTHORIZED_ONLINE_USERNAME;
    use crate::branding::AUTHORIZED_USERS_GROUP;
    for name in [
        AUTHORIZED_OFFLINE_USERNAME,
        AUTHORIZED_ONLINE_USERNAME,
        AUTHORIZED_USERS_GROUP,
    ] {
        assert!(name.len() <= 20, "{name} exceeds the 20-character SAM limit");
    }
    for name in [
        AUTHORIZED_OFFLINE_USERNAME,
        AUTHORIZED_ONLINE_USERNAME,
        AUTHORIZED_USERS_GROUP,
    ] {
        assert_ne!(name, crate::branding::OFFLINE_USERNAME);
        assert_ne!(name, crate::branding::ONLINE_USERNAME);
        assert_ne!(name, crate::branding::TCP_LOOPBACK_OFFLINE_USERNAME);
        assert_ne!(name, crate::branding::TCP_LOOPBACK_ONLINE_USERNAME);
        assert_ne!(name, crate::branding::SANDBOX_USERS_GROUP);
    }
}
