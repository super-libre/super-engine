// SPDX-License-Identifier: GPL-3.0-only
//! Staging: extract the release tarball, detect which components to
//! install, and build the manifest the root phase later applies verbatim.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use super_engine_protocol::ProductSpec;
use super_engine_spec::verify::{tar_budget_step, tar_entry_unsafe_reason, unpack_cap};

use crate::Installer;
use crate::errors::InstallError;

/// Which of the three installable components are selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Components {
    pub daemon: bool,
    pub app: bool,
    pub applet: bool,
}

impl Components {
    /// The wire strings for the `complete` event's `components` field, in
    /// `["daemon", "app", "applet"]` order (only the selected subset).
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)] // interface fixed by the design doc: `&self`
    pub fn names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if self.daemon {
            names.push("daemon".to_string());
        }
        if self.app {
            names.push("app".to_string());
        }
        if self.applet {
            names.push("applet".to_string());
        }
        names
    }
}

/// An explicit component selection: either the four `--components` CLI
/// values (`all|daemon|app|applet`, see `From<&str>` below), or
/// `AllButApplet` — reachable only from the interactive menu's "All" option
/// when no COSMIC panel is present, never from `--components` (the CLI's
/// `all` keeps meaning literally-all, so the hermetic e2e test stays
/// deterministic regardless of the CI host's COSMIC availability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentSelection {
    All,
    AllButApplet,
    Daemon,
    App,
    Applet,
}

impl From<&str> for ComponentSelection {
    /// Maps the four `--components` values clap's `PossibleValuesParser`
    /// restricts input to; anything else (only reachable if that validation
    /// is ever loosened) defaults to `All`.
    fn from(s: &str) -> Self {
        match s {
            "daemon" => ComponentSelection::Daemon,
            "app" => ComponentSelection::App,
            "applet" => ComponentSelection::Applet,
            _ => ComponentSelection::All,
        }
    }
}

/// Decide which components to install.
///
/// `explicit`, if given, wins outright — no detection runs. Otherwise: if
/// `<prefix>/bin` already has any of `product`'s `<slug>-*` binaries, this is
/// an update —
/// only the components already present are refreshed (the daemon always,
/// since it is the core piece every install has). Otherwise this is a fresh
/// install: daemon and app always, and the applet only when `cosmic_available`
/// (installing a COSMIC applet with no COSMIC panel to host it is useless).
#[must_use]
pub fn plan_components(
    explicit: Option<ComponentSelection>,
    prefix: &Path,
    cosmic_available: bool,
    product: &ProductSpec,
) -> Components {
    if let Some(selection) = explicit {
        return match selection {
            ComponentSelection::All => Components {
                daemon: true,
                app: true,
                applet: true,
            },
            ComponentSelection::AllButApplet => Components {
                daemon: true,
                app: true,
                applet: false,
            },
            ComponentSelection::Daemon => Components {
                daemon: true,
                ..Components::default()
            },
            ComponentSelection::App => Components {
                app: true,
                ..Components::default()
            },
            ComponentSelection::Applet => Components {
                applet: true,
                ..Components::default()
            },
        };
    }

    let installed: Vec<String> = std::fs::read_dir(prefix.join("bin"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    let slug = product.slug;
    let is_update = installed
        .iter()
        .any(|name| name.starts_with(&format!("{slug}-")));

    if is_update {
        Components {
            daemon: true,
            app: installed.iter().any(|name| *name == format!("{slug}-app")),
            applet: installed
                .iter()
                .any(|name| *name == format!("{slug}-cosmic-applet")),
        }
    } else {
        Components {
            daemon: true,
            app: true,
            applet: cosmic_available,
        }
    }
}

/// Unpack the release tarball at `tarball` (gzip'd tar) into `staging`,
/// creating `staging` if needed.
///
/// Two passes, mirroring a daemon's install-time extraction
/// (`super_engine_daemon::registry::install`) and the indexer's publish-time
/// validation (`super_engine_indexer`'s `assets`) so a tarball that passes
/// one passes the other: the first pass rejects any entry
/// [`tar_entry_unsafe_reason`] flags (an absolute path, a `..` component, or a
/// symlink — a symlink entry would otherwise become a root-copied link target
/// once staged), *before* anything is written to disk; the second pass
/// unpacks while enforcing the archive-scaled [`unpack_cap`]/[`tar_budget_step`]
/// decompression-bomb budget.
///
/// # Errors
/// [`InstallError::InstallFailed`] if `tarball` cannot be opened, contains an
/// unsafe entry, exceeds the unpack budget, or cannot be unpacked into
/// `staging`.
pub fn extract_tarball(tarball: &Path, staging: &Path) -> Result<(), InstallError> {
    let fail = |what: &str, e: &dyn std::fmt::Display| {
        InstallError::InstallFailed(format!("{}: {what}: {e}", tarball.display()))
    };
    let total_cap = unpack_cap(
        std::fs::metadata(tarball)
            .map_err(|e| fail("stat", &e))?
            .len(),
    );

    // First pass: validate every entry without unpacking anything.
    {
        let file = std::fs::File::open(tarball).map_err(|e| fail("open", &e))?;
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries().map_err(|e| fail("read", &e))? {
            let entry = entry.map_err(|e| fail("read entry", &e))?;
            let path = entry.path().map_err(|e| fail("read entry path", &e))?;
            let path_str = path.to_string_lossy();
            if let Some(reason) =
                tar_entry_unsafe_reason(&path_str, entry.header().entry_type().is_symlink())
            {
                return Err(InstallError::InstallFailed(format!(
                    "{}: unsafe tar entry: {reason}",
                    tarball.display()
                )));
            }
        }
    }

    // Second pass: unpack, enforcing the per-entry and total-output budgets.
    std::fs::create_dir_all(staging).map_err(|e| fail("create staging dir", &e))?;
    let file = std::fs::File::open(tarball).map_err(|e| fail("open", &e))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut total: u64 = 0;
    for entry in archive.entries().map_err(|e| fail("read", &e))? {
        let mut entry = entry.map_err(|e| fail("read entry", &e))?;
        total = tar_budget_step(entry.size(), total, total_cap).map_err(|reason| {
            InstallError::InstallFailed(format!("{}: {reason}", tarball.display()))
        })?;
        entry.unpack_in(staging).map_err(|e| fail("extract", &e))?;
    }
    Ok(())
}

/// The `<short_name>` convenience wrapper — invokes `<slug>-cli` directly.
/// Its second comment line is [`Installer::wrapper_usage`].
#[must_use]
pub fn wrapper_script(prefix: &Path, installer: &Installer) -> String {
    let product = installer.product;
    format!(
        "#!/bin/bash\n\
         # {display} convenience wrapper — invokes {slug}-cli directly.\n\
         # {usage}\n\
         exec \"{prefix}/bin/{slug}-cli\" \"$@\"\n",
        display = product.display_name,
        slug = product.slug,
        usage = installer.wrapper_usage,
        prefix = prefix.display(),
    )
}

/// One file the root phase copies into place: `source` (inside `staging`, or
/// the running installer's own path for the self-entry) → `dest` (an
/// absolute path under an allowed root), installed with permission `mode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub source: PathBuf,
    pub dest: PathBuf,
    pub mode: u32,
}

/// The full set of files to install, built while still unprivileged so the
/// root phase only ever copies files it's already been told about — it never
/// reads the tarball, the network, or `$HOME`.
///
/// Deliberately carries no `staging_root`/`self_exe` fields: those are the
/// root phase's trust anchors for [`crate::root_phase::apply_manifest`]'s
/// source-containment check, and a value read back out of this same,
/// untrusted JSON would let a crafted manifest defend against itself (e.g.
/// claim its own `staging_root` is `/`). The root phase derives both from
/// argv/the OS instead — see `root_phase::run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub entries: Vec<ManifestEntry>,
}

/// Every `resources/<slug>-cosmic-applet-*.desktop` file in `staging`,
/// sorted for deterministic manifest ordering.
///
/// # Errors
/// [`InstallError::InstallFailed`] when the glob yields zero entries (F5): a
/// missing or renamed `resources/` directory would otherwise silently install
/// the applet binary with no launcher entry at all, since a `for` loop over
/// an empty `Vec` just does nothing — the same "required, not merely
/// best-effort" treatment [`required_entry`] already gives the applet icon.
fn applet_desktop_files(staging: &Path, slug: &str) -> Result<Vec<PathBuf>, InstallError> {
    let resources = staging.join("resources");
    let prefix = format!("{slug}-cosmic-applet-");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&resources)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".desktop"))
        })
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(InstallError::InstallFailed(format!(
            "staging missing any {prefix}*.desktop file under {}",
            resources.display()
        )));
    }
    Ok(files)
}

/// A required source is missing from `staging` — the tarball is malformed or
/// doesn't carry what `components` asked for.
fn required_entry(
    staging: &Path,
    rel: &str,
    dest: PathBuf,
    mode: u32,
) -> Result<ManifestEntry, InstallError> {
    let source = staging.join(rel);
    if !source.exists() {
        return Err(InstallError::InstallFailed(format!(
            "staging missing {rel}"
        )));
    }
    Ok(ManifestEntry { source, dest, mode })
}

/// Build the manifest for `components`, resolving every source against
/// `staging` and every destination against `prefix` (`unit_dir` for the
/// systemd unit). `self_exe` is the running installer's own binary — every
/// install/update re-stages a copy of itself at `<prefix>/bin/<slug>-install`
/// so a later `--root-phase` re-run and in-app updates keep working. The root
/// phase recognizes this entry by comparing its `source` against its own
/// `std::env::current_exe()` at apply time — nothing here needs to (or
/// should) tell it which entry that is.
///
/// # Errors
/// [`InstallError::InstallFailed`] when a required source for a selected
/// component is missing from `staging` — caught here, before escalation, so a
/// broken tarball never prompts for a root password.
#[allow(clippy::trivially_copy_pass_by_ref)] // interface fixed by the design doc: `&Components`
pub fn build_manifest(
    staging: &Path,
    prefix: &Path,
    unit_dir: &Path,
    components: &Components,
    self_exe: &Path,
    installer: &Installer,
) -> Result<Manifest, InstallError> {
    let product = installer.product;
    let slug = product.slug;
    let bin = prefix.join("bin");
    let mut entries = vec![ManifestEntry {
        source: self_exe.to_path_buf(),
        dest: bin.join(product.installer_binary()),
        mode: 0o755,
    }];

    if components.daemon {
        for name in [
            product.daemon_binary(),
            format!("{slug}-cli"),
            product.consent_helper(),
        ] {
            entries.push(required_entry(staging, &name, bin.join(&name), 0o755)?);
        }

        // The wrapper has no source in the tarball — generate it now and
        // stage it as a real file, so the root phase only ever copies files.
        let generated_dir = staging.join("generated");
        std::fs::create_dir_all(&generated_dir).map_err(|e| {
            InstallError::InstallFailed(format!("create {}: {e}", generated_dir.display()))
        })?;
        let wrapper_path = generated_dir.join(product.short_name);
        std::fs::write(&wrapper_path, wrapper_script(prefix, installer)).map_err(|e| {
            InstallError::InstallFailed(format!("write {}: {e}", wrapper_path.display()))
        })?;
        entries.push(ManifestEntry {
            source: wrapper_path,
            dest: bin.join(product.short_name),
            mode: 0o755,
        });

        let unit = format!("{slug}.service");
        entries.push(required_entry(
            staging,
            &format!("systemd/{unit}"),
            unit_dir.join(&unit),
            0o644,
        )?);
    }

    if components.app {
        let app = format!("{slug}-app");
        entries.push(required_entry(staging, &app, bin.join(&app), 0o755)?);
        entries.push(required_entry(
            staging,
            &format!("resources/{app}.desktop"),
            prefix.join(format!("share/applications/{app}.desktop")),
            0o644,
        )?);
        entries.push(required_entry(
            staging,
            &format!("resources/icons/hicolor/scalable/apps/{app}.svg"),
            prefix.join(format!("share/icons/hicolor/scalable/apps/{app}.svg")),
            0o644,
        )?);
        // Metainfo is optional upstream (older tarballs may not carry it):
        // skip the entry rather than fail if it's absent.
        let metainfo = staging.join(format!("resources/{app}.metainfo.xml"));
        if metainfo.exists() {
            entries.push(ManifestEntry {
                source: metainfo,
                dest: prefix.join(format!("share/metainfo/{app}.metainfo.xml")),
                mode: 0o644,
            });
        }
    }

    if components.applet {
        let applet = format!("{slug}-cosmic-applet");
        entries.push(required_entry(staging, &applet, bin.join(&applet), 0o755)?);
        for path in applet_desktop_files(staging, slug)? {
            let name = path
                .file_name()
                .expect("filtered on file_name above")
                .to_owned();
            entries.push(ManifestEntry {
                source: path,
                dest: prefix.join("share/applications").join(name),
                mode: 0o644,
            });
        }
        entries.push(required_entry(
            staging,
            &format!("resources/icons/hicolor/scalable/apps/{applet}.svg"),
            prefix.join(format!("share/icons/hicolor/scalable/apps/{applet}.svg")),
            0o644,
        )?);
    }

    Ok(Manifest { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::INSTALLER;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use super_engine_protocol::test_product::TEST;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A fresh, empty per-test temp directory (per-pid, plus a per-call
    /// counter so parallel tests in this binary never collide).
    fn test_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "super-engine-installer-stage-{}-{n}",
            std::process::id()
        ));
        // F6: clear a pre-existing directory first — the pid+counter name
        // is only unique within one process run, so PID reuse across
        // separate test-binary invocations could otherwise leak files from
        // a previous run into this one.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A temp dir with an (always-created, possibly empty) `bin/` and each of
    /// `paths` touched as an empty file under it (parent dirs created as
    /// needed). Used as a fake `prefix` for detection tests: `mktree(&[])`
    /// exercises `plan_components`'s `Ok(ReadDir)`-but-empty path (a `bin/`
    /// that exists with nothing in it); see
    /// `detection_fresh_install_with_no_bin_directory_at_all` below for the
    /// sibling case where `bin/` doesn't exist at all (the `read_dir` `Err`
    /// path `.into_iter().flatten()` also has to handle).
    fn mktree(paths: &[&str]) -> PathBuf {
        let dir = test_dir();
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        for p in paths {
            let full = dir.join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, b"").unwrap();
        }
        dir
    }

    /// The full tarball layout (binaries at root, `systemd/`, `resources/**`)
    /// in a temp dir, as a fake `staging` tree.
    fn fake_staging() -> PathBuf {
        fake_staging_without(&[])
    }

    /// Like [`fake_staging`], but omits every entry whose basename is in
    /// `missing`.
    fn fake_staging_without(missing: &[&str]) -> PathBuf {
        let dir = test_dir();
        let files = [
            "super-test-daemon",
            "super-test-cli",
            "super-test-consent",
            "super-test-app",
            "super-test-cosmic-applet",
            "systemd/super-test.service",
            "resources/super-test-app.desktop",
            "resources/icons/hicolor/scalable/apps/super-test-app.svg",
            "resources/super-test-app.metainfo.xml",
            "resources/super-test-cosmic-applet-full.desktop",
            "resources/super-test-cosmic-applet-left.desktop",
            "resources/super-test-cosmic-applet-right.desktop",
            "resources/icons/hicolor/scalable/apps/super-test-cosmic-applet.svg",
        ];
        for f in files {
            if missing
                .iter()
                .any(|m| std::path::Path::new(f).file_name().unwrap() == *m)
            {
                continue;
            }
            let full = dir.join(f);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, b"").unwrap();
        }
        dir
    }

    #[test]
    fn detection_update_mode_only_updates_whats_present() {
        let prefix = mktree(&["bin/super-test-daemon", "bin/super-test-app"]); // helper: temp dir + touch files
        let c = plan_components(None, &prefix, true, &TEST);
        assert!(c.daemon && c.app && !c.applet);
    }

    #[test]
    fn detection_fresh_install_takes_all_gated_on_cosmic() {
        let prefix = mktree(&[]); // empty bin/ (F6: `mktree` always creates it)
        let c = plan_components(None, &prefix, false, &TEST);
        assert!(c.daemon && c.app && !c.applet);
        let c = plan_components(None, &prefix, true, &TEST);
        assert!(c.applet);
    }

    #[test]
    fn detection_fresh_install_with_no_bin_directory_at_all() {
        // F6: the sibling of the empty-`bin/`-directory case above — here
        // `bin/` doesn't exist at all, exercising `read_dir`'s `Err` path
        // rather than an empty `Ok(ReadDir)`. `plan_components` must treat
        // both identically: `.into_iter().flatten()` empties out either way,
        // so this is still a fresh install.
        let prefix = test_dir(); // no `bin/` subdirectory created
        assert!(!prefix.join("bin").exists());
        let c = plan_components(None, &prefix, false, &TEST);
        assert!(c.daemon && c.app && !c.applet);
        let c = plan_components(None, &prefix, true, &TEST);
        assert!(c.daemon && c.app && c.applet);
    }

    #[test]
    fn detection_update_mode_only_applet_present() {
        // The daemon is always refreshed on an update (the core piece every
        // install has) even when only the applet binary is present.
        let prefix = mktree(&["bin/super-test-cosmic-applet"]);
        let c = plan_components(None, &prefix, true, &TEST);
        assert!(c.daemon && !c.app && c.applet);
    }

    #[test]
    fn detection_update_mode_all_three_present() {
        let prefix = mktree(&[
            "bin/super-test-daemon",
            "bin/super-test-app",
            "bin/super-test-cosmic-applet",
        ]);
        let c = plan_components(None, &prefix, false, &TEST); // cosmic gone, but applet was already installed
        assert!(c.daemon && c.app && c.applet);
    }

    #[test]
    fn explicit_daemon_selects_only_daemon() {
        let prefix = mktree(&["bin/super-test-app"]);
        let c = plan_components(Some(ComponentSelection::Daemon), &prefix, true, &TEST);
        assert!(c.daemon && !c.app && !c.applet);
    }

    #[test]
    fn explicit_app_selects_only_app() {
        let prefix = mktree(&[]);
        let c = plan_components(Some(ComponentSelection::App), &prefix, true, &TEST);
        assert!(!c.daemon && c.app && !c.applet);
    }

    #[test]
    fn explicit_applet_selects_only_applet() {
        let prefix = mktree(&[]);
        // Explicit `--components=applet` bypasses the `cosmic_available`
        // gate entirely — unlike the interactive menu's option 4, the CLI
        // flag is trusted outright.
        let c = plan_components(Some(ComponentSelection::Applet), &prefix, false, &TEST);
        assert!(!c.daemon && !c.app && c.applet);
    }

    #[test]
    fn explicit_all_selects_everything_regardless_of_existing_state() {
        let prefix = mktree(&["bin/super-test-daemon"]);
        let c = plan_components(Some(ComponentSelection::All), &prefix, true, &TEST);
        assert!(c.daemon && c.app && c.applet);
    }

    #[test]
    fn all_but_applet_always_skips_applet_while_all_stays_all_inclusive() {
        let prefix = mktree(&[]);
        // `AllButApplet` (the interactive menu's "All (skip COSMIC applet)"
        // path) skips the applet even when a COSMIC panel is present.
        let c = plan_components(Some(ComponentSelection::AllButApplet), &prefix, true, &TEST);
        assert!(c.daemon && c.app && !c.applet);
        // Explicit `All` (the `--components=all` CLI path) stays literally
        // all-inclusive regardless of `cosmic_available` — this must never
        // change, since the hermetic e2e test relies on it being
        // deterministic on a CI host with no cosmic-panel.
        let c = plan_components(Some(ComponentSelection::All), &prefix, false, &TEST);
        assert!(c.daemon && c.app && c.applet);
    }

    #[test]
    fn manifest_covers_selected_components_with_modes() {
        let staging = fake_staging(); // helper: full tarball layout in a temp dir
        let m = build_manifest(
            &staging,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &Components {
                daemon: true,
                app: true,
                applet: false,
            },
            std::path::Path::new("/proc/self/exe"),
            &INSTALLER,
        )
        .unwrap();
        let dests: Vec<String> = m
            .entries
            .iter()
            .map(|e| e.dest.display().to_string())
            .collect();
        assert!(dests.contains(&"/usr/local/bin/super-test-daemon".to_string()));
        assert!(dests.contains(&"/usr/local/bin/test".to_string()));
        assert!(dests.contains(&"/usr/lib/systemd/user/super-test.service".to_string()));
        assert!(
            dests.contains(&"/usr/local/share/applications/super-test-app.desktop".to_string())
        );
        assert!(dests.contains(&"/usr/local/bin/super-test-install".to_string()));
        assert!(!dests.iter().any(|d| d.contains("cosmic-applet")));
        let unit = m
            .entries
            .iter()
            .find(|e| e.dest.ends_with("super-test.service"))
            .unwrap();
        assert_eq!(unit.mode, 0o644);
        let wrapper = m
            .entries
            .iter()
            .find(|e| e.dest.ends_with("bin/test"))
            .unwrap();
        assert_eq!(wrapper.mode, 0o755);
        // The generated wrapper's staged content is exactly the known script.
        let content = std::fs::read_to_string(&wrapper.source).unwrap();
        assert!(content.starts_with("#!/bin/bash\n"));
        assert!(content.contains("exec \"/usr/local/bin/super-test-cli\" \"$@\""));
    }

    #[test]
    fn manifest_missing_required_source_errors_before_escalation() {
        let staging = fake_staging_without(&["super-test-app"]);
        let err = build_manifest(
            &staging,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &Components {
                daemon: false,
                app: true,
                applet: false,
            },
            std::path::Path::new("/proc/self/exe"),
            &INSTALLER,
        )
        .unwrap_err();
        assert!(matches!(err, crate::errors::InstallError::InstallFailed(_)));
    }

    #[test]
    fn manifest_errors_when_applet_desktop_glob_is_empty() {
        // F5: if `resources/` is missing or renamed so the
        // `super-test-cosmic-applet-*.desktop` glob yields zero entries, the
        // applet binary would otherwise get installed with no launcher
        // entry at all — silently, since a `for` loop over an empty `Vec`
        // just does nothing. That must be a hard error for a selected
        // applet component, exactly like the sibling `required_entry` icon
        // check just below it.
        let staging = fake_staging_without(&[
            "super-test-cosmic-applet-full.desktop",
            "super-test-cosmic-applet-left.desktop",
            "super-test-cosmic-applet-right.desktop",
        ]);
        let err = build_manifest(
            &staging,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &Components {
                daemon: false,
                app: false,
                applet: true,
            },
            std::path::Path::new("/proc/self/exe"),
            &INSTALLER,
        )
        .unwrap_err();
        assert!(matches!(err, crate::errors::InstallError::InstallFailed(_)));
    }

    #[test]
    fn manifest_skips_optional_metainfo_when_absent() {
        let staging = fake_staging_without(&["super-test-app.metainfo.xml"]);
        let m = build_manifest(
            &staging,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &Components {
                daemon: false,
                app: true,
                applet: false,
            },
            std::path::Path::new("/proc/self/exe"),
            &INSTALLER,
        )
        .unwrap();
        assert!(
            !m.entries
                .iter()
                .any(|e| e.dest.to_string_lossy().contains("metainfo"))
        );
    }

    #[test]
    fn manifest_self_exe_entry_is_present_with_0755() {
        let staging = fake_staging();
        let m = build_manifest(
            &staging,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &Components::default(),
            std::path::Path::new("/some/self/exe"),
            &INSTALLER,
        )
        .unwrap();
        let self_entry = m
            .entries
            .iter()
            .find(|e| e.dest.ends_with("bin/super-test-install"))
            .expect("self-exe entry must always be present, regardless of components selected");
        assert_eq!(self_entry.mode, 0o755);
        assert_eq!(self_entry.source, std::path::Path::new("/some/self/exe"));
    }

    #[test]
    fn tarball_round_trip() {
        let tmp = test_dir();
        let tree = tmp.join("tree");
        std::fs::create_dir_all(tree.join("systemd")).unwrap();
        std::fs::write(tree.join("super-test-daemon"), b"bin").unwrap();
        std::fs::write(tree.join("systemd/super-test.service"), b"[Unit]").unwrap();
        let tgz = tmp.join("t.tar.gz");
        {
            let f = std::fs::File::create(&tgz).unwrap();
            let enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
            let mut tar = tar::Builder::new(enc);
            tar.append_dir_all(".", &tree).unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        let out = tmp.join("out");
        extract_tarball(&tgz, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("super-test-daemon")).unwrap(),
            b"bin"
        );
        assert_eq!(
            std::fs::read(out.join("systemd/super-test.service")).unwrap(),
            b"[Unit]"
        );
    }

    #[test]
    fn extract_tarball_rejects_a_symlink_entry() {
        // A symlink entry in the tarball would otherwise become a
        // root-copied link target once staged and manifest-installed — the
        // same exploit class as a dangling symlink at the install
        // destination, but smuggled in from the archive side.
        let tmp = test_dir();
        let tgz = tmp.join("evil.tar.gz");
        {
            let f = std::fs::File::create(&tgz).unwrap();
            let enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
            let mut tar = tar::Builder::new(enc);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            tar.append_link(&mut header, "evil-link", "/etc/passwd")
                .unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        let out = tmp.join("out");
        assert!(extract_tarball(&tgz, &out).is_err());
        assert!(!out.join("evil-link").exists());
    }

    #[test]
    fn extract_tarball_rejects_an_absolute_path_entry() {
        // `Header::set_path` itself refuses an absolute path unless told
        // otherwise, so this uses `set_path_absolute` — the same escape
        // hatch a maliciously-crafted (not tar-rs-authored) archive can use
        // — to actually get one into the archive and prove
        // `extract_tarball`'s own `tar_entry_unsafe_reason` check (not
        // tar-rs's) is what's rejecting it.
        let tmp = test_dir();
        let tgz = tmp.join("evil-abs.tar.gz");
        {
            let f = std::fs::File::create(&tgz).unwrap();
            let enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
            let mut tar = tar::Builder::new(enc);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(0);
            header.set_path_absolute("/etc/evil-absolute").unwrap();
            header.set_cksum();
            tar.append(&header, std::io::empty()).unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        let out = tmp.join("out");
        let err = extract_tarball(&tgz, &out).unwrap_err();
        assert!(matches!(err, crate::errors::InstallError::InstallFailed(_)));
        assert!(!std::path::Path::new("/etc/evil-absolute").exists());
    }

    #[test]
    fn extract_tarball_rejects_a_parent_dir_entry() {
        // `Header::set_path`/`set_path_absolute` both unconditionally refuse
        // a `..` component (tar-rs's own defense), so a legitimately built
        // archive can never carry one through the high-level API. To prove
        // `extract_tarball`'s *own* `tar_entry_unsafe_reason` check (not
        // tar-rs) is what would catch one, this writes the raw name bytes
        // directly into the header, bypassing `set_path` entirely — modeling
        // a maliciously hand-crafted (not tar-rs-authored) archive.
        let tmp = test_dir();
        let tgz = tmp.join("evil-dotdot.tar.gz");
        {
            let f = std::fs::File::create(&tgz).unwrap();
            let enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
            let mut tar = tar::Builder::new(enc);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(0);
            let name = b"../evil-dotdot";
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            header.set_cksum();
            tar.append(&header, std::io::empty()).unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        let out = tmp.join("out");
        let err = extract_tarball(&tgz, &out).unwrap_err();
        assert!(matches!(err, crate::errors::InstallError::InstallFailed(_)));
        assert!(!tmp.join("evil-dotdot").exists());
    }

    #[test]
    fn extract_tarball_enforces_the_decompression_bomb_cap() {
        // The per-entry cap (`tar_budget_step` against
        // `MAX_TARBALL_ENTRY_BYTES`) is checked against the tar header's
        // DECLARED size before `unpack_in` ever reads/writes a single byte
        // of body — so this proves the cap fires without needing gigabytes
        // of real data on disk: the header lies about its size, and no
        // matching body is ever written.
        let tmp = test_dir();
        let tgz = tmp.join("bomb.tar.gz");
        {
            let f = std::fs::File::create(&tgz).unwrap();
            let enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
            let mut tar = tar::Builder::new(enc);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_path("huge-file").unwrap();
            header.set_size(super_engine_spec::verify::MAX_TARBALL_ENTRY_BYTES + 1);
            header.set_cksum();
            tar.append(&header, std::io::empty()).unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        let out = tmp.join("out");
        let err = extract_tarball(&tgz, &out).unwrap_err();
        assert!(matches!(err, crate::errors::InstallError::InstallFailed(_)));
        assert!(!out.join("huge-file").exists());
    }
}
