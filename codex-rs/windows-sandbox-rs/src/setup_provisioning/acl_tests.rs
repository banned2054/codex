use super::DELETE;
use super::DaclInheritance;
use super::FILE_GENERIC_EXECUTE;
use super::FILE_GENERIC_READ;
use super::FILE_GENERIC_WRITE;
use super::GRANT_ACCESS;
use super::Payload;
use super::SETUP_VERSION;
use super::SetupMode;
use super::SetupRuntime;
use super::WRITE_DAC;
use super::convert_string_sid_to_sid;
use super::lock_sandbox_bin_dir;
use super::lock_sandbox_dir;
use super::resolve_sid;
use super::sid_bytes_to_psid;
use crate::ensure_allow_write_aces;
use crate::extract_setup_failure;
use crate::path_mask_allows;
use crate::read_setup_error_report;
use crate::workspace_write_cap_sid_for_root;
use crate::write_setup_error_report;
use pretty_assertions::assert_eq;
use std::fs;
use windows_sys::Win32::Foundation::ERROR_PATH_NOT_FOUND;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;

#[test]
fn bin_lock_report_retains_native_open_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut payload: Payload =
        serde_json::from_value(super::tests::payload_json()).expect("fixture payload");
    // The no-reparse open cannot create a bin whose parent does not exist.
    // It fails before resolving account SIDs or changing any permissions.
    payload.codex_home = temp.path().join("missing-home");
    payload.mode = SetupMode::ProvisionOnly;
    let bin = super::sandbox_bin_dir(&payload.codex_home);
    let error = lock_sandbox_bin_dir(&payload, &[]).expect_err("missing bin parent");
    let failure = extract_setup_failure(&error).expect("structured lock failure");
    let expected = crate::SetupFailure::new(
        crate::SetupErrorCode::HelperSandboxLockFailed,
        format!(
            "lock sandbox bin dir {0} failed: open directory {0}: NtCreateFile: {1}",
            bin.display(),
            std::io::Error::from_raw_os_error(ERROR_PATH_NOT_FOUND as i32),
        ),
    );
    assert_eq!(failure, &expected);

    write_setup_error_report(
        temp.path(),
        &crate::SetupErrorReport {
            code: failure.code,
            message: failure.message.clone(),
        },
    )
    .expect("write structured failure");
    let report = read_setup_error_report(temp.path())
        .expect("read structured failure")
        .expect("failure report");
    assert_eq!(crate::SetupFailure::from_report(report), expected);
    assert!(!payload.codex_home.exists());
}

#[test]
fn provision_only_locks_plain_directory_via_handle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let sandbox_bin = temp.path().join(".sandbox-bin");
    let real_user = std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string());
    let real_sid = resolve_sid(&real_user).expect("resolve real user SID");

    lock_sandbox_dir(
        &sandbox_bin,
        &real_user,
        &real_sid,
        GRANT_ACCESS,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
        DaclInheritance::Protected,
        SetupMode::ProvisionOnly,
    )
    .expect("lock sandbox bin via no-reparse handle");

    assert!(sandbox_bin.is_dir());
}

#[test]
fn lock_sandbox_dir_blocks_inherited_write_for_runner_files() {
    for setup_mode in [SetupMode::Full, SetupMode::ProvisionOnly] {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let sandbox_bin = workspace.join(".sandbox-bin");
        fs::create_dir(&workspace).expect("create workspace");

        let workspace_sid = workspace_write_cap_sid_for_root(temp.path(), temp.path(), temp.path())
            .expect("workspace SID");
        let workspace_psid =
            unsafe { convert_string_sid_to_sid(&workspace_sid).expect("convert workspace SID") };
        let sandbox_group_sid =
            resolve_sid("Authenticated Users").expect("resolve sandbox group SID");
        let sandbox_group_psid =
            sid_bytes_to_psid(&sandbox_group_sid).expect("convert sandbox group SID");
        unsafe { ensure_allow_write_aces(&workspace, &[workspace_psid]) }
            .expect("grant inherited workspace write access");

        fs::create_dir(&sandbox_bin).expect("create sandbox bin");
        let existing_runner = sandbox_bin.join("existing-runner.exe");
        fs::write(&existing_runner, b"existing").expect("create existing runner");
        assert!(
            path_mask_allows(
                &existing_runner,
                &[workspace_psid],
                FILE_GENERIC_WRITE | DELETE,
                /*require_all_bits*/ true,
            )
            .expect("check inherited runner write and delete access")
        );

        let real_user = std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string());
        let payload = Payload {
            version: SETUP_VERSION,
            offline_username: String::new(),
            online_username: String::new(),
            codex_home: workspace.clone(),
            command_cwd: workspace.clone(),
            read_roots: Vec::new(),
            write_roots: Vec::new(),
            deny_read_paths: Vec::new(),
            deny_write_paths: Vec::new(),
            authorized_read_paths: Vec::new(),
            proxy_ports: Vec::new(),
            allow_local_binding: false,
            allow_tcp_loopback: false,
            otel: None,
            real_user,
            user_profile: None,
            mode: setup_mode,
            runtime: SetupRuntime::Legacy,
            refresh_only: false,
        };
        lock_sandbox_bin_dir(&payload, &sandbox_group_sid).expect("lock sandbox bin");
        let real_sid = resolve_sid(&payload.real_user).expect("resolve real owner SID");
        let real_psid = sid_bytes_to_psid(&real_sid).expect("convert real owner SID");
        assert!(
            path_mask_allows(
                &sandbox_bin,
                &[real_psid],
                WRITE_DAC,
                /*require_all_bits*/ true
            )
            .expect("owner ACE permits refreshing the bin DACL")
        );
        assert!(
            !path_mask_allows(
                &sandbox_bin,
                &[sandbox_group_psid],
                WRITE_DAC,
                /*require_all_bits*/ true,
            )
            .expect("sandbox cannot change the bin DACL")
        );
        let new_runner = sandbox_bin.join("new-runner.exe");
        fs::write(&new_runner, b"new").expect("create new runner");

        for path in [&sandbox_bin, &existing_runner, &new_runner] {
            assert!(
                !path_mask_allows(
                    path,
                    &[workspace_psid],
                    FILE_GENERIC_WRITE | DELETE,
                    /*require_all_bits*/ false,
                )
                .expect("check protected path write and delete access")
            );
            assert!(
                path_mask_allows(
                    path,
                    &[sandbox_group_psid],
                    FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                    /*require_all_bits*/ true,
                )
                .expect("check protected path read and execute access")
            );
        }

        unsafe {
            LocalFree(real_psid as HLOCAL);
            LocalFree(workspace_psid as HLOCAL);
            LocalFree(sandbox_group_psid as HLOCAL);
        }
    }
}

#[test]
fn authorized_read_survives_reapproval_and_restores_deny_each_time() -> anyhow::Result<()> {
    use windows_sys::Win32::Foundation as win;

    use super::reconcile_authorized_read_acls;
    use crate::acl::{dacl_has_read_deny_for_sid, fetch_dacl_handle};
    use crate::token::LocalSid;

    let principal_sid = "S-1-5-21-10-20-30-44";
    let group = LocalSid::from_string(principal_sid)?;
    let group_psid = group.as_ptr();
    let rx_mask = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

    let home = tempfile::tempdir()?;
    fs::create_dir_all(crate::setup::sandbox_dir(home.path()))?;
    let approved = home.path().join("approved");
    let unapproved = home.path().join("unapproved");
    fs::create_dir(&approved)?;
    fs::create_dir(&unapproved)?;
    let approved_file = approved.join("fixture.txt");
    fs::write(&approved_file, b"approved fixture")?;

    let mut value = super::tests::payload_json();
    value["codex_home"] = serde_json::json!(home.path());
    value["deny_read_paths"] = serde_json::json!([approved, unapproved]);
    let mut payload: Payload = serde_json::from_value(value)?;
    let has_deny = |path: &std::path::Path| -> anyhow::Result<bool> {
        unsafe {
            let (dacl, descriptor) = fetch_dacl_handle(path)?;
            let denied = dacl_has_read_deny_for_sid(dacl, group_psid);
            win::LocalFree(descriptor as win::HLOCAL);
            Ok(denied)
        }
    };

    for cycle in 1..=2 {
        payload.authorized_read_paths = vec![approved.clone()];
        reconcile_authorized_read_acls(&payload, principal_sid, group_psid)?;
        for path in [&approved, &approved_file] {
            let allowed = path_mask_allows(path, &[group_psid], rx_mask, true)?;
            let denied = has_deny(path)?;
            assert!(
                allowed && !denied,
                "cycle {cycle}: {} must retain its approved grant (allow={allowed}, deny={denied})",
                path.display()
            );
        }
        assert!(has_deny(&unapproved)?);

        payload.authorized_read_paths.clear();
        reconcile_authorized_read_acls(&payload, principal_sid, group_psid)?;
        for path in [&approved, &approved_file] {
            assert!(has_deny(path)?, "cycle {cycle}: the deny must be restored");
            assert!(
                !path_mask_allows(path, &[group_psid], rx_mask, false)?,
                "cycle {cycle}: the temporary grant must be gone"
            );
        }
    }

    Ok(())
}
