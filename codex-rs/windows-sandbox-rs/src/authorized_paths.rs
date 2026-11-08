//! Approved-read path set math and the trusted protected-path manifest.
//!
//! The manifest lives in `CODEX_HOME/.sandbox-secrets/protected_paths.json`,
//! a directory the sandbox group is permanently denied from reading, so the
//! payload's approved-read list is checked against a list a sandboxed process
//! cannot tamper with. The helper never trusts `authorized_read_paths` alone:
//! an approved-read request without a parsable manifest is refused before any
//! ACE is applied, and any approved path that overlaps a protected path in
//! either direction is refused as well.

use crate::deny_read_acl::lexical_path_key;
use crate::path_normalization::canonicalize_path;
use crate::setup::sandbox_secrets_dir;
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

const PROTECTED_PATHS_FILE: &str = "protected_paths.json";

fn protected_paths_path(codex_home: &Path) -> PathBuf {
    sandbox_secrets_dir(codex_home).join(PROTECTED_PATHS_FILE)
}

/// Normalizes a path to its final on-disk location (following reparse points
/// when the path exists) as a case-insensitive forward-slash key.
pub(crate) fn normalized_path_key(path: &Path) -> String {
    lexical_path_key(&canonicalize_path(path))
}

/// Returns true when `descendant` equals `ancestor` or lies beneath it, using
/// normalized keys with forward-slash separators and no trailing slash.
fn key_covers(ancestor: &str, descendant: &str) -> bool {
    descendant == ancestor
        || descendant
            .strip_prefix(ancestor)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn keys_overlap(left: &str, right: &str) -> bool {
    key_covers(left, right) || key_covers(right, left)
}

/// Returns the first pair (approved, protected) whose trees overlap in either
/// direction, or None when no approved path touches a protected path.
pub(crate) fn find_protected_overlap(
    authorized: &[PathBuf],
    protected: &[PathBuf],
) -> Option<(PathBuf, PathBuf)> {
    let protected_keys = protected
        .iter()
        .map(|path| (normalized_path_key(path), path))
        .collect::<Vec<_>>();
    for authorized_path in authorized {
        let authorized_key = normalized_path_key(authorized_path);
        if let Some((_, protected_path)) = protected_keys
            .iter()
            .find(|(protected_key, _)| keys_overlap(&authorized_key, protected_key))
        {
            return Some((authorized_path.clone(), (*protected_path).clone()));
        }
    }
    None
}

/// Computes the deny set for the authorized principal: the full deny set minus
/// every path covered by an approved-read path, compared by normalized final
/// location so a deny entered through a reparse-point alias is still removed.
pub(crate) fn authorized_deny_read_paths(
    deny_read_paths: &[PathBuf],
    authorized_read_paths: &[PathBuf],
) -> Vec<PathBuf> {
    let authorized_keys = authorized_read_paths
        .iter()
        .map(|path| normalized_path_key(path))
        .collect::<HashSet<_>>();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for path in deny_read_paths {
        if authorized_keys.contains(&normalized_path_key(path)) {
            continue;
        }
        if seen.insert(lexical_path_key(path)) {
            out.push(path.clone());
        }
    }
    out
}

/// Loads the trusted protected-path manifest.
///
/// Three outcomes are distinct failures: the manifest is missing, it cannot be
/// parsed, or an entry is not an absolute path. The error text always names the
/// manifest path and the concrete reason.
pub(crate) fn load_protected_paths(codex_home: &Path) -> Result<Vec<PathBuf>> {
    let path = protected_paths_path(codex_home);
    let bytes = std::fs::read(&path).map_err(|err| {
        anyhow::Error::new(err).context(format!(
            "approved-read request requires the trusted protected-path manifest {} (missing or unreadable)",
            path.display()
        ))
    })?;
    let raw = serde_json::from_slice::<Vec<String>>(&bytes)
        .with_context(|| format!("parse protected-path manifest {}", path.display()))?;
    let mut paths = Vec::with_capacity(raw.len());
    for entry in raw {
        let entry_path = PathBuf::from(&entry);
        if !entry_path.is_absolute() {
            bail!(
                "protected-path manifest {} contains a non-absolute path {entry:?}",
                path.display()
            );
        }
        paths.push(entry_path);
    }
    Ok(paths)
}

/// Validates an approved-read request against the trusted manifest.
///
/// Approved-read requests must carry a readable, parsable manifest, and no
/// approved path may overlap a protected path in either direction. The helper
/// refuses the whole request before applying any ACE when validation fails.
pub(crate) fn validate_authorized_read_paths(
    codex_home: &Path,
    authorized_read_paths: &[PathBuf],
) -> Result<()> {
    let protected = load_protected_paths(codex_home)?;
    if let Some((authorized, protected)) = find_protected_overlap(authorized_read_paths, &protected)
    {
        bail!(
            "approved-read path {} overlaps protected path {} from the trusted manifest; refusing the request",
            authorized.display(),
            protected.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::authorized_deny_read_paths;
    use super::find_protected_overlap;
    use super::normalized_path_key;
    use super::validate_authorized_read_paths;
    use pretty_assertions::assert_eq;
    use std::path::Path;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn paths<const N: usize>(values: [&str; N]) -> Vec<PathBuf> {
        values.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn normalized_path_key_unifies_case_separators_and_trailing_slash() {
        assert_eq!(
            normalized_path_key(Path::new(r"C:\Data\Secrets\")),
            normalized_path_key(Path::new("c:/data/secrets"))
        );
    }

    #[test]
    fn deny_diff_removes_paths_covered_by_authorized_entries() {
        let deny = paths([r"C:\a\one", r"C:\a\two", r"C:\b\three"]);
        let authorized = paths([r#"c:/A/ONE/"#]);

        assert_eq!(
            authorized_deny_read_paths(&deny, &authorized),
            paths([r"C:\a\two", r"C:\b\three"])
        );
    }

    #[test]
    fn deny_diff_keeps_deny_siblings_of_an_authorized_child() {
        // Exact normalized set difference: a deny on the parent stays in place
        // when only a child is approved; the approved child loses only its own
        // deny entry.
        let deny = paths([r"C:\secret"]);
        let authorized = paths([r"C:\secret\sub"]);

        assert_eq!(authorized_deny_read_paths(&deny, &authorized), deny);
    }

    #[test]
    fn deny_diff_is_empty_when_authorized_covers_everything() {
        let deny = paths([r"C:\a", r"C:\b\c"]);
        assert!(authorized_deny_read_paths(&deny, &[]).len() == 2);
        assert!(authorized_deny_read_paths(&deny, &deny).is_empty());
    }

    #[test]
    fn deny_diff_deduplicates_lexical_duplicates() {
        let deny = paths([r"C:\a", r"c:/a", r"C:\b"]);
        assert_eq!(
            authorized_deny_read_paths(&deny, &[]),
            paths([r"C:\a", r"C:\b"])
        );
    }

    #[test]
    fn overlap_hits_in_both_directions() {
        let authorized = paths([r"C:\workspace\allowed"]);
        let protected = paths([r"C:\workspace\allowed\deep\file.txt"]);
        let hit = find_protected_overlap(&authorized, &protected).expect("child hit");
        assert_eq!(hit, (authorized[0].clone(), protected[0].clone()));

        let protected = paths([r"C:\Workspace"]);
        let hit = find_protected_overlap(&authorized, &protected).expect("ancestor hit");
        assert_eq!(hit, (authorized[0].clone(), protected[0].clone()));

        let protected = paths([r"C:\elsewhere"]);
        assert!(find_protected_overlap(&authorized, &protected).is_none());
    }

    #[test]
    fn sibling_prefix_does_not_count_as_coverage() {
        // C:\workspace2 must not be treated as covered by C:\workspace.
        let authorized = paths([r"C:\workspace2\data"]);
        let protected = paths([r"C:\workspace"]);
        assert!(find_protected_overlap(&authorized, &protected).is_none());
    }

    #[test]
    fn validate_rejects_missing_manifest_without_touching_anything() {
        let home = TempDir::new().expect("tempdir");
        let authorized = paths([r"C:\workspace"]);
        let err = validate_authorized_read_paths(home.path(), &authorized)
            .expect_err("missing manifest must reject");
        let text = format!("{err:#}");
        assert!(text.contains("requires the trusted protected-path manifest"), "{text}");
    }

    #[test]
    fn validate_rejects_unparsable_manifest() {
        let home = TempDir::new().expect("tempdir");
        let secrets = home.path().join(".sandbox-secrets");
        std::fs::create_dir_all(&secrets).expect("secrets dir");
        std::fs::write(secrets.join("protected_paths.json"), b"{not json").expect("write");
        let authorized = paths([r"C:\workspace"]);
        let err = validate_authorized_read_paths(home.path(), &authorized)
            .expect_err("unparsable manifest must reject");
        assert!(format!("{err:#}").contains("parse protected-path manifest"));
    }

    #[test]
    fn validate_rejects_non_absolute_manifest_entries() {
        let home = TempDir::new().expect("tempdir");
        let secrets = home.path().join(".sandbox-secrets");
        std::fs::create_dir_all(&secrets).expect("secrets dir");
        std::fs::write(secrets.join("protected_paths.json"), r#"["relative\\path"]"#)
            .expect("write");
        let err = validate_authorized_read_paths(home.path(), &paths([r"C:\workspace"]))
            .expect_err("non-absolute manifest entry must reject");
        assert!(format!("{err:#}").contains("non-absolute path"));
    }

    #[test]
    fn validate_rejects_overlap_with_manifest_entry_case_insensitively() {
        let home = TempDir::new().expect("tempdir");
        let secrets = home.path().join(".sandbox-secrets");
        std::fs::create_dir_all(&secrets).expect("secrets dir");
        let protected = home.path().join("Protect-ed Data");
        std::fs::create_dir_all(&protected).expect("protected dir");
        let manifest = serde_json::to_vec(&vec![protected.to_string_lossy().to_string()])
            .expect("serialize manifest");
        std::fs::write(secrets.join("protected_paths.json"), manifest).expect("write");
        for authorized in [
            vec![protected.join("config")],
            vec![protected.clone()],
            vec![PathBuf::from(protected.to_string_lossy().to_ascii_lowercase())],
        ] {
            let err = validate_authorized_read_paths(home.path(), &authorized)
                .expect_err("overlap must reject");
            assert!(format!("{err:#}").contains("overlaps protected path"), "{err:#}");
        }
        let sibling = home.path().join("unrelated");
        assert!(validate_authorized_read_paths(home.path(), &[sibling]).is_ok());
    }

    #[test]
    fn validate_rejects_overlap_through_reparse_alias() {
        let home = TempDir::new().expect("tempdir");
        let secrets = home.path().join(".sandbox-secrets");
        std::fs::create_dir_all(&secrets).expect("secrets dir");
        let target = home.path().join("real-protected");
        std::fs::create_dir_all(&target).expect("protected target");
        let junction = home.path().join("alias-junction");
        assert!(
            std::process::Command::new("cmd.exe")
                .args(["/c", "mklink", "/J"])
                .arg(&junction)
                .arg(&target)
                .output()
                .expect("spawn mklink")
                .status
                .success(),
            "junction creation failed"
        );
        // The manifest names the alias; the request names the real location.
        let manifest = serde_json::to_vec(&vec![junction.to_string_lossy().to_string()])
            .expect("serialize manifest");
        std::fs::write(secrets.join("protected_paths.json"), manifest).expect("write");
        let err = validate_authorized_read_paths(home.path(), &[target.clone()])
            .expect_err("reparse-resolved overlap must reject");
        assert!(format!("{err:#}").contains("overlaps protected path"), "{err:#}");
    }

    #[test]
    fn validate_accepts_empty_manifest() {
        let home = TempDir::new().expect("tempdir");
        let secrets = home.path().join(".sandbox-secrets");
        std::fs::create_dir_all(&secrets).expect("secrets dir");
        std::fs::write(secrets.join("protected_paths.json"), "[]").expect("write");
        assert!(
            validate_authorized_read_paths(home.path(), &paths([r"C:\workspace"])).is_ok(),
            "an explicitly empty trusted manifest permits any approved path"
        );
    }
}
