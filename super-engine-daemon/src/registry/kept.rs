// SPDX-License-Identifier: GPL-3.0-only
//! Builds an install replaced, kept so that installing one again downloads
//! nothing.
//!
//! A backend has one build installed at a time. Moving a model to a framework
//! the installed build does not run installs that framework's build over it,
//! and moving back used to download the first build all over again. So an
//! install that replaces a build of the same release keeps the build it
//! replaces, at `<backends_dir>/.builds/<install dir name>/<build>/`: a
//! backend directory whose models went to the build that replaced it. An
//! install of a build kept here moves it back into place instead of
//! downloading it.
//!
//! Only builds of the release installed are kept. An install of another
//! release drops the rest ([`prune`]), and so does an uninstall
//! ([`remove_all`]).

use std::path::{Path, PathBuf};

use ring::digest::SHA256;
use super_engine_spec::registry::SelectedAsset;
use super_engine_spec::verify::sha256_matches;
use tokio::fs;

use crate::registry::installed;

/// The root every backend's kept builds sit under, a direct child of the
/// backends directory. Like the staging root it is never a backend's own
/// install directory: a `[backend].id` cannot start with a dot, and
/// discovery only reads a `backend.toml` one level down, where none is.
pub const KEPT_DIR_NAME: &str = ".builds";

/// Where the builds replaced in `backends_dir/dir_name` are kept.
#[must_use]
pub fn dir_for(backends_dir: &Path, dir_name: &str) -> PathBuf {
    backends_dir.join(KEPT_DIR_NAME).join(dir_name)
}

/// The directory name a kept build of `asset` gets, e.g. `cuda-cuda13-sm86`
/// or `vulkan`. Readable for whoever looks on disk; the record inside, not
/// the name, is what [`find`] matches on. Every character outside `[a-z0-9]`
/// becomes `_`, so the name is one safe path component whatever the index
/// put in `accel`.
fn build_name(asset: &SelectedAsset) -> String {
    let mut parts = vec![if asset.accel.is_empty() {
        "build".to_string()
    } else {
        asset.accel.join("+")
    }];
    parts.extend(asset.cuda_major.map(|major| format!("cuda{major}")));
    parts.extend(asset.cuda_sm.map(|sm| format!("sm{sm}")));
    if asset.cudnn {
        parts.push("cudnn".to_string());
    }
    parts
        .join("-")
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Whether the backend directory `dir` holds the build `asset` names, of the
/// release whose manifest hashes to `manifest_sha256`.
///
/// An empty pin never matches: without it two releases cannot be told apart
/// (a custom repository pins nothing), and a download is the safe answer.
async fn holds(dir: &Path, manifest_sha256: &str, asset: &SelectedAsset) -> bool {
    if manifest_sha256.is_empty() {
        return false;
    }
    let Some(record) = installed::read(dir) else {
        return false;
    };
    if record.selected != *asset {
        return false;
    }
    let Ok(manifest) = fs::read(dir.join("backend.toml")).await else {
        return false;
    };
    let actual = hex::encode(ring::digest::digest(&SHA256, &manifest).as_ref());
    sha256_matches(&actual, manifest_sha256)
}

/// The kept build of the backend installed at `backends_dir/dir_name` that
/// `asset` names, of the release whose manifest hashes to `manifest_sha256`.
pub async fn find(
    backends_dir: &Path,
    dir_name: &str,
    manifest_sha256: &str,
    asset: &SelectedAsset,
) -> Option<PathBuf> {
    let mut entries = fs::read_dir(dir_for(backends_dir, dir_name)).await.ok()?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let dir = entry.path();
        if dir.is_dir() && holds(&dir, manifest_sha256, asset).await {
            return Some(dir);
        }
    }
    None
}

/// Whether installing the build `asset` names, of the release whose manifest
/// hashes to `manifest_sha256`, downloads nothing: it is the build installed
/// at `backends_dir/dir_name`, or one kept from an earlier install.
pub async fn on_disk(
    backends_dir: &Path,
    dir_name: &str,
    manifest_sha256: &str,
    asset: &SelectedAsset,
) -> bool {
    holds(&backends_dir.join(dir_name), manifest_sha256, asset).await
        || find(backends_dir, dir_name, manifest_sha256, asset)
            .await
            .is_some()
}

/// Where the build installed at `installed_dir` is kept when an install of
/// the build `incoming` names, with the manifest `incoming_manifest`, replaces
/// it. `None` when it is not worth keeping: another release's build, which
/// [`prune`] would drop anyway, the same build installed again, or a
/// directory with no record of what it is (a local import).
pub async fn keep_destination(
    backends_dir: &Path,
    dir_name: &str,
    installed_dir: &Path,
    incoming_manifest: &[u8],
    incoming: &SelectedAsset,
) -> Option<PathBuf> {
    let record = installed::read(installed_dir)?;
    if record.selected == *incoming {
        return None;
    }
    let manifest = fs::read(installed_dir.join("backend.toml")).await.ok()?;
    if manifest != incoming_manifest {
        return None;
    }
    Some(dir_for(backends_dir, dir_name).join(build_name(&record.selected)))
}

/// Drop every build kept for `backends_dir/dir_name` that is not of the
/// release whose manifest is `manifest`: the release installed now. Best
/// effort; a build left behind costs disk and is dropped by the next install.
pub async fn prune(backends_dir: &Path, dir_name: &str, manifest: &[u8]) {
    let root = dir_for(backends_dir, dir_name);
    let Ok(mut entries) = fs::read_dir(&root).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let dir = entry.path();
        let same_release = fs::read(dir.join("backend.toml"))
            .await
            .is_ok_and(|kept| kept == manifest);
        if same_release {
            continue;
        }
        match fs::remove_dir_all(&dir).await {
            Ok(()) => log::info!("Dropped the kept build {}", dir.display()),
            Err(e) => log::warn!("Could not drop the kept build {}: {e}", dir.display()),
        }
    }
    // Gone once it holds nothing; a failure just means it still does.
    let _ = fs::remove_dir(&root).await;
}

/// Drop every build kept for `backends_dir/dir_name`: the backend was
/// uninstalled, or moved to another directory name.
///
/// # Errors
/// When the kept builds exist and cannot be removed.
pub async fn remove_all(backends_dir: &Path, dir_name: &str) -> std::io::Result<()> {
    match fs::remove_dir_all(dir_for(backends_dir, dir_name)).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &[u8] = b"[backend]\nversion = \"1.0.0\"\n";
    const OTHER_RELEASE: &[u8] = b"[backend]\nversion = \"1.1.0\"\n";

    fn sha(bytes: &[u8]) -> String {
        hex::encode(ring::digest::digest(&SHA256, bytes).as_ref())
    }

    fn asset(accel: &[&str], cuda_major: Option<u32>) -> SelectedAsset {
        SelectedAsset {
            target: "x86_64-unknown-linux-gnu".into(),
            accel: accel.iter().map(|a| (*a).to_string()).collect(),
            cuda_major,
            cuda_sm: None,
            cudnn: false,
        }
    }

    /// A backend directory holding `asset`'s build, of the release `manifest`.
    fn build_dir(dir: &Path, manifest: &[u8], asset: &SelectedAsset) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("backend.toml"), manifest).unwrap();
        installed::write(dir, asset).unwrap();
    }

    #[test]
    fn a_build_name_is_one_safe_path_component() {
        assert_eq!(
            build_name(&asset(&["cuda", "cpu"], Some(13))),
            "cuda_cpu-cuda13"
        );
        assert_eq!(build_name(&asset(&["vulkan"], None)), "vulkan");
        assert_eq!(build_name(&asset(&["../x"], None)), "___x");
        assert_eq!(build_name(&asset(&[], None)), "build");
    }

    #[tokio::test]
    async fn a_kept_build_is_found_by_its_record_and_its_release() {
        let root = tempfile::tempdir().unwrap();
        let cuda = asset(&["cuda"], Some(13));
        build_dir(&dir_for(root.path(), "app.x").join("cuda"), MANIFEST, &cuda);

        assert!(
            find(root.path(), "app.x", &sha(MANIFEST), &cuda)
                .await
                .is_some()
        );
        assert!(
            find(root.path(), "app.x", &sha(OTHER_RELEASE), &cuda)
                .await
                .is_none(),
            "another release's build is not this one"
        );
        assert!(
            find(
                root.path(),
                "app.x",
                &sha(MANIFEST),
                &asset(&["cuda"], Some(12))
            )
            .await
            .is_none(),
            "another CUDA major is another build"
        );
        assert!(
            find(root.path(), "app.x", "", &cuda).await.is_none(),
            "without a pin nothing tells two releases apart"
        );
    }

    #[tokio::test]
    async fn the_installed_build_and_a_kept_one_are_both_on_disk() {
        let root = tempfile::tempdir().unwrap();
        let (cuda, vulkan, cpu) = (
            asset(&["cuda"], Some(13)),
            asset(&["vulkan"], None),
            asset(&["cpu"], None),
        );
        build_dir(&root.path().join("app.x"), MANIFEST, &vulkan);
        build_dir(&dir_for(root.path(), "app.x").join("cuda"), MANIFEST, &cuda);

        let pin = sha(MANIFEST);
        assert!(on_disk(root.path(), "app.x", &pin, &vulkan).await);
        assert!(on_disk(root.path(), "app.x", &pin, &cuda).await);
        assert!(!on_disk(root.path(), "app.x", &pin, &cpu).await);
        assert!(
            !on_disk(root.path(), "app.x", &sha(OTHER_RELEASE), &vulkan).await,
            "an update downloads the new release's build"
        );
    }

    #[tokio::test]
    async fn only_another_build_of_the_same_release_is_kept() {
        let root = tempfile::tempdir().unwrap();
        let installed = root.path().join("app.x");
        let (cuda, vulkan) = (asset(&["cuda"], Some(13)), asset(&["vulkan"], None));
        build_dir(&installed, MANIFEST, &cuda);

        assert_eq!(
            keep_destination(root.path(), "app.x", &installed, MANIFEST, &vulkan).await,
            Some(dir_for(root.path(), "app.x").join("cuda-cuda13"))
        );
        assert_eq!(
            keep_destination(root.path(), "app.x", &installed, OTHER_RELEASE, &vulkan).await,
            None,
            "an update's predecessor is not kept"
        );
        assert_eq!(
            keep_destination(root.path(), "app.x", &installed, MANIFEST, &cuda).await,
            None,
            "the same build installed again replaces itself"
        );
        std::fs::remove_file(installed.join(installed::RECORD_FILE)).unwrap();
        assert_eq!(
            keep_destination(root.path(), "app.x", &installed, MANIFEST, &vulkan).await,
            None,
            "a local import says nothing of what it is"
        );
    }

    #[tokio::test]
    async fn pruning_keeps_only_the_installed_releases_builds() {
        let root = tempfile::tempdir().unwrap();
        let kept = dir_for(root.path(), "app.x");
        build_dir(&kept.join("cuda"), MANIFEST, &asset(&["cuda"], Some(13)));
        build_dir(&kept.join("cpu"), OTHER_RELEASE, &asset(&["cpu"], None));

        prune(root.path(), "app.x", MANIFEST).await;
        assert!(kept.join("cuda").exists());
        assert!(!kept.join("cpu").exists());

        prune(root.path(), "app.x", OTHER_RELEASE).await;
        assert!(!kept.exists(), "an empty kept directory goes too");
    }

    #[tokio::test]
    async fn removing_all_kept_builds_tolerates_there_being_none() {
        let root = tempfile::tempdir().unwrap();
        remove_all(root.path(), "app.x").await.unwrap();
        build_dir(
            &dir_for(root.path(), "app.x").join("cuda"),
            MANIFEST,
            &asset(&["cuda"], Some(13)),
        );
        remove_all(root.path(), "app.x").await.unwrap();
        assert!(!dir_for(root.path(), "app.x").exists());
    }
}
