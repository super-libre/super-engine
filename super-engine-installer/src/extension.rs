// SPDX-License-Identifier: GPL-3.0-only
//! A product's GNOME Shell extension: where its releases come from, where it
//! goes, and whether this install takes one.
//!
//! What the COSMIC applet is on COSMIC's panel, a product's extension is in
//! GNOME Shell's top bar. It has releases of its own, in
//! [`GnomeExtension::repo`], each carrying the extension's directory as
//! `<name>-noarch[-beta].tar.gz` with a `SHA256SUMS`, its settings schema
//! already compiled. The installer places it with the other system-wide
//! files, under `<prefix>/share/gnome-shell/extensions/<uuid>`, where GNOME
//! Shell looks for extensions every user may enable, and never installs one
//! older than the one it found.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::errors::InstallError;

/// A product's GNOME Shell extension.
#[derive(Debug, Clone, Copy)]
pub struct GnomeExtension {
    /// Where its releases are published, e.g.
    /// `github.com/super-libre/super-gnome-shell-extension`.
    pub repo: &'static str,
    /// Its UUID, from its `metadata.json`: the name of its directory, and how
    /// GNOME Shell enables it.
    pub uuid: &'static str,
    /// The name its release tarballs start with.
    pub name: &'static str,
}

/// The platform in an extension's tarball name, where a binary's has a
/// target triple: an extension is JavaScript, and runs on any.
pub const PLATFORM: &str = "noarch";

/// The extension's directory under `prefix`.
#[must_use]
pub fn dir(prefix: &Path, extension: &GnomeExtension) -> PathBuf {
    prefix
        .join("share/gnome-shell/extensions")
        .join(extension.uuid)
}

/// The version installed under `prefix`: its `metadata.json`'s
/// `version-name`. `None` when none is installed, or its metadata doesn't
/// say.
#[must_use]
pub fn installed_version(prefix: &Path, extension: &GnomeExtension) -> Option<String> {
    let metadata = std::fs::read_to_string(dir(prefix, extension).join("metadata.json")).ok()?;
    version_name(&metadata)
}

/// `metadata.json`'s `version-name`, when it has one.
fn version_name(metadata: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(metadata).ok()?;
    value.get("version-name")?.as_str().map(str::to_string)
}

/// Whether an extension is installed under `prefix`, to update on an update
/// of the product.
#[must_use]
pub fn is_installed(prefix: &Path, extension: &GnomeExtension) -> bool {
    dir(prefix, extension).join("metadata.json").is_file()
}

/// Every file of the extension extracted to `staged`, relative to it, sorted.
///
/// # Errors
/// [`InstallError::InstallFailed`] when `staged` is no extension, or another
/// one: it must have an `extension.js`, and a `metadata.json` naming
/// `extension`'s UUID.
pub fn release_files(
    staged: &Path,
    extension: &GnomeExtension,
) -> Result<Vec<PathBuf>, InstallError> {
    let metadata = std::fs::read_to_string(staged.join("metadata.json")).map_err(|e| {
        InstallError::InstallFailed(format!("the GNOME Shell extension's metadata.json: {e}"))
    })?;
    let uuid = serde_json::from_str::<serde_json::Value>(&metadata)
        .ok()
        .and_then(|value| value.get("uuid")?.as_str().map(str::to_string));
    if uuid.as_deref() != Some(extension.uuid) {
        return Err(InstallError::InstallFailed(format!(
            "the GNOME Shell extension's metadata.json names {}, not {}",
            uuid.as_deref().unwrap_or("no UUID"),
            extension.uuid
        )));
    }
    if !staged.join("extension.js").is_file() {
        return Err(InstallError::InstallFailed(
            "the GNOME Shell extension has no extension.js".to_string(),
        ));
    }
    let mut files = Vec::new();
    collect_files(staged, Path::new(""), &mut files)
        .map_err(|e| InstallError::InstallFailed(format!("read the GNOME Shell extension: {e}")))?;
    files.sort();
    Ok(files)
}

fn collect_files(root: &Path, rel: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root.join(rel))? {
        let entry = entry?;
        let path = rel.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_files(root, &path, out)?;
        } else if kind.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// The files of the extension installed under `prefix` that its new release
/// in `keep` (relative paths, as [`release_files`] gives them) no longer
/// has: what it would otherwise leave behind.
#[must_use]
pub fn stale_files(prefix: &Path, extension: &GnomeExtension, keep: &[PathBuf]) -> Vec<PathBuf> {
    let installed = dir(prefix, extension);
    let mut found = Vec::new();
    if collect_files(&installed, Path::new(""), &mut found).is_err() {
        return Vec::new();
    }
    let keep: BTreeSet<&PathBuf> = keep.iter().collect();
    let mut stale: Vec<PathBuf> = found
        .into_iter()
        .filter(|rel| !keep.contains(rel))
        .map(|rel| installed.join(rel))
        .collect();
    stale.sort();
    stale
}

/// `org.gnome.shell`'s `enabled-extensions`, as `gsettings get` prints it,
/// with `uuid` added: `None` when it is already there, or the value doesn't
/// read as a list of strings.
#[must_use]
pub fn enabled_with(current: &str, uuid: &str) -> Option<String> {
    let mut uuids = string_list(current)?;
    if uuids.iter().any(|u| u == uuid) {
        return None;
    }
    uuids.push(uuid.to_string());
    Some(format_list(&uuids))
}

/// `org.gnome.shell`'s `disabled-extensions` without `uuid`: `None` when it
/// isn't there, or the value doesn't read as a list of strings.
#[must_use]
pub fn disabled_without(current: &str, uuid: &str) -> Option<String> {
    let uuids = string_list(current)?;
    if !uuids.iter().any(|u| u == uuid) {
        return None;
    }
    let kept: Vec<String> = uuids.into_iter().filter(|u| u != uuid).collect();
    Some(format_list(&kept))
}

/// A `GVariant` string array as `gsettings get` prints it: `['a', 'b']`, or
/// `@as []` when empty. UUIDs hold no quotes or commas, which keeps this
/// simple; anything else doesn't parse.
fn string_list(value: &str) -> Option<Vec<String>> {
    let value = value.trim();
    let value = value.strip_prefix("@as").map_or(value, str::trim_start);
    let inner = value.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    inner
        .split(',')
        .map(|item| {
            let item = item.trim();
            let unquoted = item
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .or_else(|| item.strip_prefix('"').and_then(|s| s.strip_suffix('"')))?;
            (!unquoted.contains(['\'', '"'])).then(|| unquoted.to_string())
        })
        .collect()
}

fn format_list(uuids: &[String]) -> String {
    let quoted: Vec<String> = uuids.iter().map(|u| format!("'{u}'")).collect();
    format!("[{}]", quoted.join(", "))
}

#[cfg(test)]
fn write(dir: &Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// An extension named `uuid` as its release tarball extracts into `dir`.
#[cfg(test)]
pub(crate) fn fake_release(dir: &Path, uuid: &str) {
    write(
        dir,
        "metadata.json",
        &format!(r#"{{"uuid": "{uuid}", "version-name": "0.2.0"}}"#),
    );
    write(dir, "extension.js", "export default class {}");
    write(dir, "core/model.js", "");
    write(dir, "schemas/gschemas.compiled", "");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_dir::TestDir;
    use crate::tests::TEST_EXTENSION as EXTENSION;

    #[test]
    fn it_goes_where_gnome_shell_looks_for_every_users_extensions() {
        assert_eq!(
            dir(Path::new("/usr/local"), &EXTENSION),
            Path::new("/usr/local/share/gnome-shell/extensions/super-test@example.com")
        );
    }

    #[test]
    fn the_installed_version_is_its_version_name() {
        let prefix = TestDir::new("extension-version");
        assert_eq!(installed_version(&prefix, &EXTENSION), None);
        assert!(!is_installed(&prefix, &EXTENSION));
        fake_release(&dir(&prefix, &EXTENSION), EXTENSION.uuid);
        assert_eq!(
            installed_version(&prefix, &EXTENSION).as_deref(),
            Some("0.2.0")
        );
        assert!(is_installed(&prefix, &EXTENSION));
    }

    #[test]
    fn a_release_lists_every_file_it_carries() {
        let staged = TestDir::new("extension-release");
        fake_release(&staged, EXTENSION.uuid);
        let files = release_files(&staged, &EXTENSION).unwrap();
        assert_eq!(
            files,
            [
                "core/model.js",
                "extension.js",
                "metadata.json",
                "schemas/gschemas.compiled"
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn another_extension_is_refused() {
        let staged = TestDir::new("extension-other");
        fake_release(&staged, "someone-else@example.com");
        let err = release_files(&staged, &EXTENSION).unwrap_err();
        assert!(
            err.to_string().contains("someone-else@example.com"),
            "{err}"
        );
    }

    #[test]
    fn a_release_without_its_code_is_refused() {
        let staged = TestDir::new("extension-no-code");
        fake_release(&staged, EXTENSION.uuid);
        std::fs::remove_file(staged.join("extension.js")).unwrap();
        assert!(release_files(&staged, &EXTENSION).is_err());
    }

    #[test]
    fn what_a_new_release_dropped_goes() {
        let prefix = TestDir::new("extension-stale");
        let installed = dir(&prefix, &EXTENSION);
        fake_release(&installed, EXTENSION.uuid);
        write(&installed, "shell/old.js", "");
        let keep = [
            "core/model.js",
            "extension.js",
            "metadata.json",
            "schemas/gschemas.compiled",
        ]
        .map(PathBuf::from);
        assert_eq!(
            stale_files(&prefix, &EXTENSION, &keep),
            [installed.join("shell/old.js")]
        );
    }

    #[test]
    fn nothing_installed_leaves_nothing_stale() {
        let prefix = TestDir::new("extension-none");
        assert_eq!(stale_files(&prefix, &EXTENSION, &[]), Vec::<PathBuf>::new());
    }

    #[test]
    fn enabling_adds_the_uuid_once() {
        assert_eq!(enabled_with("@as []", "a@b").as_deref(), Some("['a@b']"));
        assert_eq!(
            enabled_with("['x@y']", "a@b").as_deref(),
            Some("['x@y', 'a@b']")
        );
        assert_eq!(enabled_with("['x@y', 'a@b']", "a@b"), None);
        assert_eq!(enabled_with("not a list", "a@b"), None);
    }

    #[test]
    fn enabling_takes_the_uuid_off_the_disabled_list() {
        assert_eq!(
            disabled_without("['a@b', 'x@y']", "a@b").as_deref(),
            Some("['x@y']")
        );
        assert_eq!(disabled_without("['a@b']", "a@b").as_deref(), Some("[]"));
        assert_eq!(disabled_without("@as []", "a@b"), None);
    }
}
