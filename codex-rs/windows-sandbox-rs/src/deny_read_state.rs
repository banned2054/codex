use crate::acl::revoke_ace;
use crate::deny_read_acl::apply_deny_read_acls;
use crate::deny_read_acl::lexical_path_key;
use crate::setup::sandbox_dir;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::ffi::c_void;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;
use windows_sys::Win32::Foundation as win;
use windows_sys::Win32::Storage::FileSystem as winfs;

const DENY_READ_ACL_STATE_FILE: &str = "deny_read_acl_state.json";
const AUTHORIZED_READ_ACL_STATE_FILE: &str = "authorized_read_acl_state.json";

#[derive(Default, Deserialize, Serialize)]
struct PersistentDenyReadAclState {
    principals: BTreeMap<String, Vec<PathBuf>>,
}

/// Reconciles the persistent deny-read ACEs owned by one sandbox principal.
///
/// Workspace-write and elevated sandbox sessions intentionally leave ACLs in
/// place after a command exits, because descendants may outlive the launcher.
/// That makes the ACL set stateful across runs. Persist the paths applied for
/// each SID, apply the new desired set first, and only then revoke stale paths
/// from the same SID so profile changes do not leave old deny-read ACEs behind.
///
/// Malformed bookkeeping is rebuilt after applying current denies. Unknown
/// historical restrictions cannot safely be revoked and remain in place.
///
/// # Safety
/// Caller must pass a valid SID pointer matching `principal_sid`.
pub unsafe fn sync_persistent_deny_read_acls(
    codex_home: &Path,
    principal_sid: &str,
    desired_paths: &[PathBuf],
    psid: *mut c_void,
) -> Result<Vec<PathBuf>> {
    unsafe {
        sync_persistent_principal_paths(
            codex_home,
            DENY_READ_ACL_STATE_FILE,
            principal_sid,
            desired_paths,
            psid,
            apply_deny_read_acls,
        )
    }
}

/// Reconciles the persistent RX grants owned by the authorized principal.
///
/// Approved-read grants are additive exceptions, so unlike `read_roots` they
/// must be revocable: each call applies the desired grant set first and then
/// revokes every previously granted path that is no longer desired. An empty
/// desired set therefore fully restores the authorized principal while still
/// keeping the deny bookkeeping authoritative. Missing paths are skipped
/// without materializing anything, so the grant set tracks what actually
/// exists on disk.
///
/// # Safety
/// Caller must pass a valid SID pointer matching `principal_sid`.
pub(crate) unsafe fn sync_persistent_authorized_read_grants(
    codex_home: &Path,
    principal_sid: &str,
    desired_paths: &[PathBuf],
    psid: *mut c_void,
) -> Result<Vec<PathBuf>> {
    unsafe {
        sync_persistent_principal_paths(
            codex_home,
            AUTHORIZED_READ_ACL_STATE_FILE,
            principal_sid,
            desired_paths,
            psid,
            apply_authorized_read_grants,
        )
    }
}

/// Shared per-principal reconcile: apply the desired set, revoke stale paths
/// recorded for the same SID in `state_file`, then persist the new bookkeeping.
///
/// # Safety
/// Caller must pass a valid SID pointer matching `principal_sid`; `apply` must
/// be safe to call with the same pointer.
unsafe fn sync_persistent_principal_paths(
    codex_home: &Path,
    state_file: &str,
    principal_sid: &str,
    desired_paths: &[PathBuf],
    psid: *mut c_void,
    apply: unsafe fn(&[PathBuf], *mut c_void) -> Result<Vec<PathBuf>>,
) -> Result<Vec<PathBuf>> {
    let state_path = sandbox_dir(codex_home).join(state_file);
    let mut state = load_state(&state_path)?;
    let previous_paths = state
        .principals
        .get(principal_sid)
        .cloned()
        .unwrap_or_default();

    let applied_paths = unsafe { apply(desired_paths, psid) }?;
    let desired_keys = applied_paths
        .iter()
        .map(|path| lexical_path_key(path))
        .collect::<HashSet<_>>();

    // Revocation failures must never be reported as success: a stale grant (or deny)
    // ACE that survives keeps the principal's effective surface wider than the
    // bookkeeping claims. The bookkeeping is left untouched on failure so the next
    // sync retries the same revocation; revoke_ace is idempotent for ACEs that are
    // already gone, so retrying previously revoked paths is safe.
    for path in previous_paths {
        if !desired_keys.contains(&lexical_path_key(&path)) {
            revoke_ace(&path, psid).with_context(|| {
                format!(
                    "revoke stale ACE for {principal_sid} at {}",
                    path.display()
                )
            })?;
        }
    }

    if applied_paths.is_empty() {
        state.principals.remove(principal_sid);
    } else {
        state
            .principals
            .insert(principal_sid.to_string(), applied_paths.clone());
    }
    store_state(&state_path, &state)?;

    Ok(applied_paths)
}

/// Applies RX grant ACEs for the desired authorized paths without
/// materializing missing ones, mirroring the deny planner's lexical-plus-
/// canonical coverage. On a mid-way failure the grants added by this call are
/// revoked before the error is returned so bookkeeping stays consistent.
///
/// # Safety
/// Caller must pass a valid SID pointer for the authorized principal.
unsafe fn apply_authorized_read_grants(
    paths: &[PathBuf],
    psid: *mut c_void,
) -> Result<Vec<PathBuf>> {
    let planned = crate::deny_read_acl::plan_deny_read_acl_paths(paths)?;
    // Annotation pins the element type before the `revoke_ace` coercion below
    // can lock inference onto the unsized `&Path` target.
    let mut applied: Vec<PathBuf> = Vec::new();
    for path in planned {
        if !path.exists() {
            continue;
        }
        let result = unsafe {
            crate::acl::grant_read_execute_aces(
                &path,
                &[psid],
                windows_sys::Win32::Security::OBJECT_INHERIT_ACE
                    | windows_sys::Win32::Security::CONTAINER_INHERIT_ACE,
            )
        }
        .with_context(|| format!("grant authorized-read ACE to {}", path.display()));
        if let Err(err) = result {
            // Roll back the grants this call added; a rollback failure is folded into
            // the error so an orphaned RX ACE is never hidden behind a bare failure.
            let mut rollback_errors = Vec::new();
            for added_path in &applied {
                if let Err(revoke_err) = revoke_ace(added_path, psid) {
                    rollback_errors.push(format!("{}: {revoke_err:#}", added_path.display()));
                }
            }
            if rollback_errors.is_empty() {
                return Err(err);
            }
            return Err(err.context(format!(
                "revoking partially applied authorized-read grants failed: {}",
                rollback_errors.join("; ")
            )));
        }
        applied.push(path);
    }
    Ok(applied)
}

fn load_state(path: &Path) -> Result<PersistentDenyReadAclState> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let stable = Instant::now() >= deadline;
        let bytes = (|| -> Result<Vec<u8>> {
            // Ordinary reads allow legacy writers; malformed recovery excludes live writers.
            let share_mode = if stable {
                winfs::FILE_SHARE_READ | winfs::FILE_SHARE_DELETE
            } else {
                winfs::FILE_SHARE_READ | winfs::FILE_SHARE_WRITE | winfs::FILE_SHARE_DELETE
            };
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(share_mode)
                .custom_flags(winfs::FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)?;
            // Validate the same leaf before either accepting state or recovering it.
            validate_state_file(&file)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok(bytes)
        })();
        match bytes {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(state) => return Ok(state),
                Err(_) if !stable => std::thread::sleep(Duration::from_millis(25)),
                Err(_) => return Ok(PersistentDenyReadAclState::default()),
            },
            Err(err)
                if err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(PersistentDenyReadAclState::default());
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("read deny-read ACL state {}", path.display()));
            }
        }
    }
}

fn store_state(path: &Path, state: &PersistentDenyReadAclState) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state).context("serialize deny-read ACL state")?;
    (|| -> Result<()> {
        // Recovery makes malformed files writable. Never follow the state leaf
        // or truncate it before checking the actual object. Resolve configured
        // parent paths normally, including junctions and volume GUIDs.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut file = loop {
            let opened = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(winfs::FILE_SHARE_READ | winfs::FILE_SHARE_WRITE)
                .custom_flags(winfs::FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path);
            match opened {
                Ok(file) => break file,
                Err(error)
                    if error.raw_os_error() == Some(win::ERROR_SHARING_VIOLATION as i32)
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.into()),
            }
        };
        validate_state_file(&file)?;
        file.write_all(&bytes)?;
        file.set_len(bytes.len() as u64)?;
        Ok(())
    })()
    .with_context(|| format!("write deny-read ACL state {}", path.display()))
}

fn validate_state_file(file: &File) -> Result<()> {
    let mut info = unsafe { std::mem::zeroed::<winfs::BY_HANDLE_FILE_INFORMATION>() };
    if unsafe { winfs::GetFileInformationByHandle(file.as_raw_handle() as win::HANDLE, &mut info) }
        == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        info.dwFileAttributes & winfs::FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "state file is a reparse point"
    );
    ensure!(info.nNumberOfLinks == 1, "state file has multiple links");
    Ok(())
}

#[cfg(test)]
#[path = "deny_read_state_tests.rs"]
mod tests;
