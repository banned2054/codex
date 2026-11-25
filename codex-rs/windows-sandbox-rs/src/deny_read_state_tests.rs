//! Exercises recovery and its file-safety boundaries on real Windows files.

use super::*;
use crate::token::LocalSid;
use pretty_assertions::assert_eq;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::os::windows::ffi::OsStringExt;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn load_propagates_io_errors_and_preserves_missing_file_behavior() -> Result<()> {
    let temp = TempDir::new()?;
    let state_path = temp.path().join(DENY_READ_ACL_STATE_FILE);
    assert!(load_state(&state_path)?.principals.is_empty());

    fs::create_dir(&state_path)?;
    let error = load_state(&state_path).err().expect("read error");
    assert!(error.downcast_ref::<std::io::Error>().is_some());
    Ok(())
}

#[test]
fn load_waits_for_a_legacy_writer_without_recovering_over_it() -> Result<()> {
    let temp = TempDir::new()?;
    let path = temp.path().join(DENY_READ_ACL_STATE_FILE);
    let valid = br#"{"principals":{"legacy":["existing"]}}"#;
    fs::write(&path, valid)?;
    let mut writer = OpenOptions::new().write(true).truncate(true).open(&path)?;
    std::thread::scope(|scope| -> Result<()> {
        let write = scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(75));
            writer.write_all(valid)
        });
        let state = load_state(&path)?;
        write.join().expect("legacy writer")?;
        assert_eq!(state.principals["legacy"], vec![PathBuf::from("existing")]);
        Ok(())
    })?;

    let _writer = OpenOptions::new().write(true).truncate(true).open(&path)?;
    let error = load_state(&path)
        .err()
        .expect("active writer must prevent recovery");
    let error = error
        .downcast_ref::<std::io::Error>()
        .expect("sharing error");
    assert_eq!(
        error.raw_os_error(),
        Some(win::ERROR_SHARING_VIOLATION as i32)
    );
    Ok(())
}

#[test]
fn sync_rebuilds_corrupt_bookkeeping_only_after_successful_apply() -> Result<()> {
    let temp = TempDir::new()?;
    let state_dir = sandbox_dir(temp.path());
    fs::create_dir(&state_dir)?;
    let state_path = state_dir.join(DENY_READ_ACL_STATE_FILE);
    let malformed = b"   ";
    fs::write(&state_path, malformed)?;
    let blocker = temp.path().join("ordinary-file");
    fs::write(&blocker, b"not a directory")?;
    let sid_string = "S-1-5-21-10-20-30-40";
    let sid = LocalSid::from_string(sid_string)?;

    // Creating a child beneath a file fails before any ACL can be changed.
    let error = unsafe {
        sync_persistent_deny_read_acls(
            temp.path(),
            sid_string,
            &[blocker.join("child")],
            sid.as_ptr(),
        )
    }
    .expect_err("apply error must propagate");
    assert!(error.downcast_ref::<std::io::Error>().is_some());
    assert_eq!(fs::read(&state_path)?.as_slice(), malformed);

    let historical = temp.path().join("historical");
    let current = temp.path().join("current");
    fs::create_dir(&historical)?;
    unsafe { crate::acl::add_deny_read_ace(&historical, sid.as_ptr()) }?;
    let applied = unsafe {
        sync_persistent_deny_read_acls(
            temp.path(),
            sid_string,
            std::slice::from_ref(&current),
            sid.as_ptr(),
        )
    }?;
    assert_eq!(applied, vec![current.clone()]);
    let rebuilt: PersistentDenyReadAclState = serde_json::from_slice(&fs::read(&state_path)?)?;
    assert_eq!(
        rebuilt.principals,
        BTreeMap::from([(sid_string.to_owned(), vec![current])])
    );
    unsafe {
        let (dacl, descriptor) = crate::acl::fetch_dacl_handle(&historical)?;
        let preserved = crate::acl::dacl_has_read_deny_for_sid(dacl, sid.as_ptr());
        win::LocalFree(descriptor as win::HLOCAL);
        assert!(preserved, "unknown historical restrictions remain in place");
    }

    let error = unsafe {
        sync_persistent_deny_read_acls(
            &temp.path().join("missing-home"),
            sid_string,
            &[],
            sid.as_ptr(),
        )
    }
    .expect_err("save error must propagate");
    assert!(error.downcast_ref::<std::io::Error>().is_some());
    Ok(())
}

/// Linked bookkeeping, valid or malformed, must preserve its victim and existing denies without adding new ones.
#[test]
fn sync_rejects_linked_state_before_changing_acls() -> Result<()> {
    let temp = TempDir::new()?;
    let state_dir = sandbox_dir(temp.path());
    fs::create_dir(&state_dir)?;
    let path = state_dir.join(DENY_READ_ACL_STATE_FILE);
    let victim = temp.path().join("victim");
    let sid_string = "S-1-5-21-10-20-30-40";
    let sid = LocalSid::from_string(sid_string)?;
    let previous = temp.path().join("previous");
    let desired = temp.path().join("desired");
    fs::create_dir(&previous)?;
    fs::create_dir(&desired)?;
    unsafe { crate::acl::add_deny_read_ace(&previous, sid.as_ptr()) }?;
    let valid = serde_json::to_vec(&PersistentDenyReadAclState {
        principals: BTreeMap::from([(sid_string.to_owned(), vec![previous.clone()])]),
    })?;
    for contents in [b"not json: keep me".as_slice(), valid.as_slice()] {
        fs::write(&victim, contents)?;
        for link_kind in ["hardlink", "symlink"] {
            if link_kind == "hardlink" {
                fs::hard_link(&victim, &path)?;
            } else {
                std::os::windows::fs::symlink_file(&victim, &path)?;
            }
            let error = unsafe {
                sync_persistent_deny_read_acls(
                    temp.path(),
                    sid_string,
                    std::slice::from_ref(&desired),
                    sid.as_ptr(),
                )
            }
            .expect_err("linked state must be rejected");
            assert!(format!("{error:#}").contains(if link_kind == "hardlink" {
                "multiple links"
            } else {
                "reparse point"
            }));
            assert_eq!(fs::read(&victim)?, contents);
            for (target, expected_deny) in [(&previous, true), (&desired, false)] {
                unsafe {
                    let (dacl, descriptor) = crate::acl::fetch_dacl_handle(target)?;
                    let denied = crate::acl::dacl_has_read_deny_for_sid(dacl, sid.as_ptr());
                    win::LocalFree(descriptor as win::HLOCAL);
                    assert_eq!(denied, expected_deny, "rejected state must not change ACLs");
                }
            }
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

#[test]
fn store_keeps_file_identity_permissions_and_legacy_writer_compatibility() -> Result<()> {
    let temp = TempDir::new()?;
    let path = temp.path().join(DENY_READ_ACL_STATE_FILE);
    let state = PersistentDenyReadAclState {
        principals: BTreeMap::from([("kept".to_owned(), vec![PathBuf::from("secret")])]),
    };
    fs::write(
        &path,
        b"malformed longer than the new state                                               ",
    )?;
    let sid = LocalSid::from_string("S-1-5-21-10-20-30-40")?;
    unsafe { crate::acl::add_deny_read_ace(&path, sid.as_ptr()) }?;
    let file = File::open(&path)?;
    let mut before = unsafe { std::mem::zeroed::<winfs::BY_HANDLE_FILE_INFORMATION>() };
    assert_ne!(
        unsafe {
            winfs::GetFileInformationByHandle(file.as_raw_handle() as win::HANDLE, &mut before)
        },
        0
    );
    // A legacy writer can remain open after finishing valid bytes; normal store
    // must not newly fail just because that writer has not closed its handle.
    let _writer = OpenOptions::new().write(true).open(&path)?;
    // A delete-access holder may coexist with readers and legacy writers. Wait
    // for it to close without allowing replacement during validation or writing.
    let holder = OpenOptions::new()
        .access_mode(winfs::DELETE)
        .share_mode(winfs::FILE_SHARE_READ | winfs::FILE_SHARE_WRITE | winfs::FILE_SHARE_DELETE)
        .open(&path)?;
    std::thread::scope(|scope| -> Result<()> {
        let release = scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(75));
            drop(holder);
        });
        store_state(&path, &state)?;
        release.join().expect("delete-access holder");
        Ok(())
    })?;
    let root = path.ancestors().last().expect("drive root");
    let mut volume = [0u16; 50];
    assert_ne!(
        unsafe {
            winfs::GetVolumeNameForVolumeMountPointW(
                crate::winutil::to_wide(root).as_ptr(),
                volume.as_mut_ptr(),
                volume.len() as u32,
            )
        },
        0
    );
    let end = volume
        .iter()
        .position(|unit| *unit == 0)
        .expect("volume name");
    let volume_path =
        PathBuf::from(OsString::from_wide(&volume[..end])).join(path.strip_prefix(root)?);
    store_state(&volume_path, &state)?;

    let alias_dir = TempDir::new()?;
    let junction = alias_dir.path().join("sandbox-junction");
    assert!(
        Command::new("cmd.exe")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(temp.path())
            .output()?
            .status
            .success()
    );
    store_state(&junction.join(DENY_READ_ACL_STATE_FILE), &state)?;
    let reopened = File::open(&path)?;
    let mut after = unsafe { std::mem::zeroed::<winfs::BY_HANDLE_FILE_INFORMATION>() };
    assert_ne!(
        unsafe {
            winfs::GetFileInformationByHandle(reopened.as_raw_handle() as win::HANDLE, &mut after)
        },
        0
    );
    assert_eq!(
        (
            after.dwVolumeSerialNumber,
            after.nFileIndexHigh,
            after.nFileIndexLow
        ),
        (
            before.dwVolumeSerialNumber,
            before.nFileIndexHigh,
            before.nFileIndexLow
        )
    );
    assert_eq!(load_state(&path)?.principals, state.principals);
    unsafe {
        let (dacl, descriptor) = crate::acl::fetch_dacl_handle(&path)?;
        let preserved = crate::acl::dacl_has_read_deny_for_sid(dacl, sid.as_ptr());
        win::LocalFree(descriptor as win::HLOCAL);
        assert!(preserved);
    }
    Ok(())
}

// An unreleased delete-access handle must produce a bounded sharing error,
// leaving the existing bytes intact instead of truncating or replacing them.
#[test]
fn store_times_out_without_modifying_state_held_for_delete() -> Result<()> {
    let temp = TempDir::new()?;
    let path = temp.path().join(DENY_READ_ACL_STATE_FILE);
    let original = br#"{"principals":{"kept":["secret"]}}"#;
    fs::write(&path, original)?;
    let holder = OpenOptions::new()
        .access_mode(winfs::DELETE)
        .share_mode(winfs::FILE_SHARE_READ | winfs::FILE_SHARE_WRITE | winfs::FILE_SHARE_DELETE)
        .open(&path)?;
    let started = Instant::now();
    let error = store_state(&path, &PersistentDenyReadAclState::default())
        .expect_err("delete-access holder must block storage");
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .expect("sharing error")
            .raw_os_error(),
        Some(win::ERROR_SHARING_VIOLATION as i32)
    );
    assert_eq!(fs::read(&path)?, original);
    drop(holder);
    assert_eq!(
        load_state(&path)?.principals["kept"],
        vec![PathBuf::from("secret")]
    );
    Ok(())
}

#[test]
fn recovered_bookkeeping_tracks_repeated_calls_and_a_later_profile_change() -> Result<()> {
    let temp = TempDir::new()?;
    let state_dir = sandbox_dir(temp.path());
    fs::create_dir(&state_dir)?;
    let path = state_dir.join(DENY_READ_ACL_STATE_FILE);
    // Simulate an interrupted in-place save, after an older deny was applied.
    fs::write(&path, br#"{"principals":"#)?;
    let sid_string = "S-1-5-21-10-20-30-40";
    let sid = LocalSid::from_string(sid_string)?;
    let historical = temp.path().join("historical");
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    fs::create_dir(&historical)?;
    unsafe { crate::acl::add_deny_read_ace(&historical, sid.as_ptr()) }?;

    for desired in [&first, &first, &second, &second] {
        let applied = unsafe {
            sync_persistent_deny_read_acls(
                temp.path(),
                sid_string,
                std::slice::from_ref(desired),
                sid.as_ptr(),
            )
        }?;
        assert_eq!(applied, vec![desired.clone()]);
        let state = load_state(&path)?;
        assert_eq!(
            state.principals,
            BTreeMap::from([(sid_string.to_owned(), vec![desired.clone()])])
        );
    }
    // Recovery must preserve both unknown historical denies and the current profile.
    for target in [&historical, &second] {
        unsafe {
            let (dacl, descriptor) = crate::acl::fetch_dacl_handle(target)?;
            let denied = crate::acl::dacl_has_read_deny_for_sid(dacl, sid.as_ptr());
            win::LocalFree(descriptor as win::HLOCAL);
            assert!(denied, "deny must remain at {}", target.display());
        }
    }
    Ok(())
}

/// The restore path: an empty desired grant set revokes every previously
/// granted approved-read RX ACE and clears that principal's bookkeeping.
#[test]
fn authorized_grant_sync_revokes_previous_grants_on_empty_desired_set() -> Result<()> {
    let temp = TempDir::new()?;
    let state_dir = sandbox_dir(temp.path());
    fs::create_dir(&state_dir)?;
    let state_path = state_dir.join(AUTHORIZED_READ_ACL_STATE_FILE);
    let approved = temp.path().join("approved");
    let other = temp.path().join("other-approved");
    fs::create_dir(&approved)?;
    fs::create_dir(&other)?;
    let sid_string = "S-1-5-21-10-20-30-41";
    let sid = LocalSid::from_string(sid_string)?;
    let rx_mask = winfs::FILE_GENERIC_READ | winfs::FILE_GENERIC_EXECUTE;

    let granted = unsafe {
        sync_persistent_authorized_read_grants(
            temp.path(),
            sid_string,
            &[approved.clone(), other.clone()],
            sid.as_ptr(),
        )
    }?;
    assert_eq!(granted, vec![approved.clone(), other.clone()]);
    for target in [&approved, &other] {
        assert!(
            crate::path_mask_allows(target, &[sid.as_ptr()], rx_mask, /*require_all_bits*/ true)?,
            "approved read must be granted at {}",
            target.display()
        );
    }
    let stored: PersistentDenyReadAclState = serde_json::from_slice(&fs::read(&state_path)?)?;
    assert_eq!(
        stored.principals,
        BTreeMap::from([(sid_string.to_owned(), vec![approved.clone(), other.clone()])])
    );

    // Restore: desired set shrinks to only one path; the stale grant must go.
    let granted = unsafe {
        sync_persistent_authorized_read_grants(
            temp.path(),
            sid_string,
            std::slice::from_ref(&approved),
            sid.as_ptr(),
        )
    }?;
    assert_eq!(granted, vec![approved.clone()]);
    assert!(!crate::path_mask_allows(
        &other,
        &[sid.as_ptr()],
        rx_mask,
        /*require_all_bits*/ false
    )?);

    // Full restore: empty desired set revokes the remaining grant.
    let restored = unsafe {
        sync_persistent_authorized_read_grants(temp.path(), sid_string, &[], sid.as_ptr())
    }?;
    assert!(restored.is_empty());
    assert!(!crate::path_mask_allows(
        &approved,
        &[sid.as_ptr()],
        rx_mask,
        /*require_all_bits*/ false
    )?);
    let stored: PersistentDenyReadAclState = serde_json::from_slice(&fs::read(&state_path)?)?;
    assert!(stored.principals.is_empty());
    Ok(())
}

/// Missing approved paths are skipped without materializing directories, and
/// an empty effective grant set removes the bookkeeping entry.
#[test]
fn authorized_grant_sync_skips_missing_paths_without_materializing() -> Result<()> {
    let temp = TempDir::new()?;
    let state_dir = sandbox_dir(temp.path());
    fs::create_dir(&state_dir)?;
    let state_path = state_dir.join(AUTHORIZED_READ_ACL_STATE_FILE);
    let missing = temp.path().join("not-created-yet");
    let sid_string = "S-1-5-21-10-20-30-42";
    let sid = LocalSid::from_string(sid_string)?;

    let granted = unsafe {
        sync_persistent_authorized_read_grants(
            temp.path(),
            sid_string,
            std::slice::from_ref(&missing),
            sid.as_ptr(),
        )
    }?;
    assert!(granted.is_empty());
    assert!(!missing.exists(), "grant sync must not create directories");
    let stored: PersistentDenyReadAclState = serde_json::from_slice(&fs::read(&state_path)?)?;
    assert!(stored.principals.is_empty());
    Ok(())
}

/// A failed revocation must propagate and keep the bookkeeping entry so the next
/// sync retries it; a retry after the blocker clears converges to an empty set.
#[test]
fn revocation_failure_propagates_and_keeps_bookkeeping_for_retry() -> Result<()> {
    let temp = TempDir::new()?;
    let state_dir = sandbox_dir(temp.path());
    fs::create_dir(&state_dir)?;
    let state_path = state_dir.join(AUTHORIZED_READ_ACL_STATE_FILE);
    let approved = temp.path().join("approved");
    fs::create_dir(&approved)?;
    let sid_string = "S-1-5-21-10-20-30-43";
    let sid = LocalSid::from_string(sid_string)?;

    let granted = unsafe {
        sync_persistent_authorized_read_grants(
            temp.path(),
            sid_string,
            std::slice::from_ref(&approved),
            sid.as_ptr(),
        )
    }?;
    assert_eq!(granted, vec![approved.clone()]);

    // Deleting the target makes revoke_ace fail (the security info of a missing path
    // cannot be read), which must surface instead of being reported as success.
    fs::remove_dir(&approved)?;
    let error = unsafe {
        sync_persistent_authorized_read_grants(temp.path(), sid_string, &[], sid.as_ptr())
    }
    .expect_err("revocation failure must propagate");
    assert!(
        format!("{error:#}").contains("revoke stale ACE"),
        "unexpected error: {error:#}"
    );

    // The bookkeeping still records the path so the next sync retries the revocation.
    let stored: PersistentDenyReadAclState = serde_json::from_slice(&fs::read(&state_path)?)?;
    assert_eq!(
        stored.principals[sid_string],
        vec![approved.clone()],
        "bookkeeping must survive a failed revocation"
    );

    // Recreating the path lets the retry converge to the empty desired set.
    fs::create_dir(&approved)?;
    let restored = unsafe {
        sync_persistent_authorized_read_grants(temp.path(), sid_string, &[], sid.as_ptr())
    }?;
    assert!(restored.is_empty());
    let stored: PersistentDenyReadAclState = serde_json::from_slice(&fs::read(&state_path)?)?;
    assert!(stored.principals.is_empty());
    Ok(())
}

fn has_read_deny(path: &Path, psid: *mut c_void) -> Result<bool> {
    unsafe {
        let (dacl, descriptor) = crate::acl::fetch_dacl_handle(path)?;
        let denied = crate::acl::dacl_has_read_deny_for_sid(dacl, psid);
        win::LocalFree(descriptor as win::HLOCAL);
        Ok(denied)
    }
}

/// Marks a file for deletion while keeping its name: it stays on disk with its
/// ACL until the returned handle is dropped, but nothing else can open it.
fn mark_delete_pending(path: &Path) -> Result<File> {
    let handle = OpenOptions::new()
        .access_mode(winfs::DELETE)
        .share_mode(winfs::FILE_SHARE_READ | winfs::FILE_SHARE_WRITE | winfs::FILE_SHARE_DELETE)
        .open(path)?;
    let information = winfs::FILE_DISPOSITION_INFO { DeleteFile: true };
    assert_ne!(
        unsafe {
            winfs::SetFileInformationByHandle(
                handle.as_raw_handle() as win::HANDLE,
                winfs::FileDispositionInfo,
                &information as *const _ as *const c_void,
                std::mem::size_of_val(&information) as u32,
            )
        },
        0,
        "mark {} for deletion: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    Ok(handle)
}

/// Unlike the approved-read grant above, a read deny cannot outlive its target:
/// a stale entry whose target is gone is already clean. The sync succeeds,
/// keeps revoking the entries after it, and forgets the entry.
#[test]
fn stale_deny_for_deleted_target_file_is_dropped_from_bookkeeping() -> Result<()> {
    let temp = TempDir::new()?;
    let state_dir = sandbox_dir(temp.path());
    fs::create_dir(&state_dir)?;
    let path = state_dir.join(DENY_READ_ACL_STATE_FILE);
    let sid_string = "S-1-5-21-10-20-30-44";
    let sid = LocalSid::from_string(sid_string)?;
    let deleted = temp.path().join("deleted");
    let leftover = temp.path().join("leftover");
    let current = temp.path().join("current");
    fs::write(&deleted, b"secret")?;
    fs::create_dir(&leftover)?;
    fs::create_dir(&current)?;
    let previous = [deleted.clone(), leftover.clone(), current.clone()];
    unsafe { sync_persistent_deny_read_acls(temp.path(), sid_string, &previous, sid.as_ptr()) }?;
    assert_eq!(load_state(&path)?.principals[sid_string], previous);

    fs::remove_file(&deleted)?;
    assert_eq!(
        File::open(&deleted)
            .expect_err("target is gone")
            .raw_os_error(),
        Some(win::ERROR_FILE_NOT_FOUND as i32)
    );

    // The missing target ends its own entry; the sync must still reach `leftover`.
    let applied = unsafe {
        sync_persistent_deny_read_acls(
            temp.path(),
            sid_string,
            std::slice::from_ref(&current),
            sid.as_ptr(),
        )
    }?;
    assert_eq!(applied, vec![current.clone()]);
    assert!(!has_read_deny(&leftover, sid.as_ptr())?);
    assert!(has_read_deny(&current, sid.as_ptr())?);
    assert_eq!(
        load_state(&path)?.principals,
        BTreeMap::from([(sid_string.to_owned(), vec![current])])
    );
    Ok(())
}

/// Entries below a parent directory that no longer exists are cleaned the same way.
#[test]
fn stale_deny_for_deleted_parent_directory_is_dropped_from_bookkeeping() -> Result<()> {
    let temp = TempDir::new()?;
    let state_dir = sandbox_dir(temp.path());
    fs::create_dir(&state_dir)?;
    let path = state_dir.join(DENY_READ_ACL_STATE_FILE);
    let sid_string = "S-1-5-21-10-20-30-45";
    let sid = LocalSid::from_string(sid_string)?;
    let parent = temp.path().join("deleted-parent");
    let first = parent.join("first");
    let second = parent.join("second");
    fs::create_dir_all(&first)?;
    fs::create_dir_all(&second)?;
    let previous = [first, second.clone()];
    unsafe { sync_persistent_deny_read_acls(temp.path(), sid_string, &previous, sid.as_ptr()) }?;
    assert_eq!(load_state(&path)?.principals[sid_string], previous);

    fs::remove_dir_all(&parent)?;
    assert_eq!(
        File::open(&second)
            .expect_err("parent is gone")
            .raw_os_error(),
        Some(win::ERROR_PATH_NOT_FOUND as i32)
    );

    assert!(
        unsafe { sync_persistent_deny_read_acls(temp.path(), sid_string, &[], sid.as_ptr()) }?
            .is_empty()
    );
    assert!(load_state(&path)?.principals.is_empty());
    Ok(())
}

/// A target that still exists but cannot be opened may still carry its deny ACE:
/// the sync must fail with the stage and path, keep the entry, and converge once
/// the target is gone.
#[test]
fn stale_deny_for_unopenable_target_fails_and_keeps_bookkeeping() -> Result<()> {
    let temp = TempDir::new()?;
    let state_dir = sandbox_dir(temp.path());
    fs::create_dir(&state_dir)?;
    let path = state_dir.join(DENY_READ_ACL_STATE_FILE);
    let sid_string = "S-1-5-21-10-20-30-46";
    let sid = LocalSid::from_string(sid_string)?;
    let stale = temp.path().join("stale");
    fs::write(&stale, b"secret")?;
    let applied = unsafe {
        sync_persistent_deny_read_acls(
            temp.path(),
            sid_string,
            std::slice::from_ref(&stale),
            sid.as_ptr(),
        )
    }?;
    assert_eq!(applied, vec![stale.clone()]);

    // The file is still on disk with its ACE, but every other open is denied.
    let holder = mark_delete_pending(&stale)?;
    assert_eq!(
        File::open(&stale)
            .expect_err("target cannot be opened")
            .raw_os_error(),
        Some(win::ERROR_ACCESS_DENIED as i32)
    );
    let error =
        unsafe { sync_persistent_deny_read_acls(temp.path(), sid_string, &[], sid.as_ptr()) }
            .expect_err("an unopenable target must not be reported as revoked");
    let error = format!("{error:#}");
    assert!(
        error.contains(&format!(
            "revoke stale ACE for {sid_string} at {}: open stale read-deny ACL target {}: ",
            stale.display(),
            stale.display()
        )),
        "unexpected error: {error}"
    );
    assert!(error.contains("(os error 5)"), "unexpected error: {error}");
    let stored: PersistentDenyReadAclState = serde_json::from_slice(&fs::read(&path)?)?;
    assert_eq!(
        stored.principals[sid_string],
        vec![stale],
        "bookkeeping must survive a failed revocation"
    );

    // Releasing the holder completes the deletion; the retry then converges.
    drop(holder);
    assert!(
        unsafe { sync_persistent_deny_read_acls(temp.path(), sid_string, &[], sid.as_ptr()) }?
            .is_empty()
    );
    let stored: PersistentDenyReadAclState = serde_json::from_slice(&fs::read(&path)?)?;
    assert!(stored.principals.is_empty());
    Ok(())
}
