// SPDX-License-Identifier: GPL-3.0-only
//! Staging: extract the release tarball, detect which components to
//! install, and build the manifest the root phase later applies verbatim.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use super_engine_spec::verify::{tar_budget_step, tar_entry_unsafe_reason, unpack_cap};

use crate::errors::InstallError;
use crate::{GnomeExtension, Installer, Retired};

/// Which of the installable components are selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)] // one flag per component, as the `complete` event lists them
pub struct Components {
    pub daemon: bool,
    pub app: bool,
    /// The product's COSMIC applet
    /// ([`Installer::cosmic_applet`](crate::Installer::cosmic_applet)).
    pub applet: bool,
    /// The product's GNOME Shell extension
    /// ([`Installer::gnome_extension`](crate::Installer::gnome_extension)).
    pub extension: bool,
}

/// Which desktops are here to host what a product adds to them: COSMIC's
/// panel its applet, GNOME Shell its extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Desktops {
    /// A COSMIC panel is on `$PATH`.
    pub cosmic: bool,
    /// GNOME Shell is on `$PATH`.
    pub gnome: bool,
}

#[cfg(test)]
impl Desktops {
    pub const NONE: Self = Self {
        cosmic: false,
        gnome: false,
    };
    pub const COSMIC: Self = Self {
        cosmic: true,
        gnome: false,
    };
    pub const GNOME: Self = Self {
        cosmic: false,
        gnome: true,
    };
}

impl Components {
    /// The wire strings for the `complete` event's `components` field, in
    /// `["daemon", "app", "applet", "extension"]` order (only the selected
    /// subset).
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
        if self.extension {
            names.push("extension".to_string());
        }
        names
    }
}

/// An explicit component selection: either the `--components` CLI values
/// (`all|daemon|app|applet|extension`, see `From<&str>` below), or
/// `AllDetected` — reachable only from the interactive menu's "All" option,
/// never from `--components`: the daemon and the app, with the applet where a
/// COSMIC panel is and the extension where GNOME Shell is. The CLI's `all`
/// keeps meaning the daemon, the app and the applet whatever the host has,
/// so the hermetic e2e test stays deterministic regardless of the CI host's
/// desktop; the extension is detected, picked from the menu, or asked for by
/// name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentSelection {
    All,
    AllDetected,
    Daemon,
    App,
    Applet,
    Extension,
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
            "extension" => ComponentSelection::Extension,
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
/// install: daemon and app always, the applet only where `desktops` has a
/// COSMIC panel, and the extension only where it has GNOME Shell (installing
/// either with nothing to host it is useless). A product without an applet
/// or an extension never gets one.
#[must_use]
pub fn plan_components(
    explicit: Option<ComponentSelection>,
    prefix: &Path,
    desktops: Desktops,
    installer: &Installer,
) -> Components {
    let product = installer.product;
    let has_applet = installer.cosmic_applet.is_some();
    let has_extension = installer.gnome_extension.is_some();
    if let Some(selection) = explicit {
        return match selection {
            ComponentSelection::All => Components {
                daemon: true,
                app: true,
                applet: has_applet,
                extension: false,
            },
            ComponentSelection::AllDetected => Components {
                daemon: true,
                app: true,
                applet: desktops.cosmic && has_applet,
                extension: desktops.gnome && has_extension,
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
                applet: has_applet,
                ..Components::default()
            },
            ComponentSelection::Extension => Components {
                extension: has_extension,
                ..Components::default()
            },
        };
    }

    let in_bin: Vec<String> = std::fs::read_dir(prefix.join("bin"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    let slug = product.slug;
    let is_update = in_bin
        .iter()
        .any(|name| name.starts_with(&format!("{slug}-")));

    if is_update {
        Components {
            daemon: true,
            app: in_bin
                .iter()
                .any(|name| installer.apps.contains(&name.as_str())),
            applet: installer.cosmic_applet.is_some_and(|applet| {
                in_bin
                    .iter()
                    .any(|name| *name == format!("{slug}-cosmic-applet") || name == applet.name)
            }),
            extension: installer
                .gnome_extension
                .is_some_and(|extension| crate::extension::is_installed(prefix, &extension)),
        }
    } else {
        Components {
            daemon: true,
            app: true,
            applet: desktops.cosmic && has_applet,
            extension: desktops.gnome && has_extension,
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
    /// Files the root phase removes once every entry is in place: what an
    /// entry replaces under another name. Each is an absolute path under an
    /// allowed root, as a `dest` is, and is never a directory.
    #[serde(default)]
    pub removals: Vec<PathBuf>,
}

/// Every `resources/<applet>-*.desktop` file in `staging`, sorted for
/// deterministic manifest ordering.
///
/// # Errors
/// [`InstallError::InstallFailed`] when the glob yields zero entries (F5): a
/// missing or renamed `resources/` directory would otherwise silently install
/// the applet binary with no launcher entry at all, since a `for` loop over
/// an empty `Vec` just does nothing — the same "required, not merely
/// best-effort" treatment [`required_entry`] already gives the applet icon.
fn applet_desktop_files(staging: &Path, applet: &str) -> Result<Vec<PathBuf>, InstallError> {
    let resources = staging.join("resources");
    let prefix = format!("{applet}-");
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

/// What installs of the products in `retired` left under `prefix` and in
/// `unit_dir`, besides their applets (see [`product_applet_files`]).
fn retired_files(prefix: &Path, unit_dir: &Path, retired: &Retired) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = retired
        .binaries
        .iter()
        .map(|binary| prefix.join("bin").join(binary))
        .collect();
    files.extend(retired.units.iter().map(|unit| unit_dir.join(unit)));
    for app in retired.apps {
        files.push(prefix.join(format!("share/applications/{app}.desktop")));
        files.push(prefix.join(format!("share/icons/hicolor/scalable/apps/{app}.svg")));
        files.extend(
            app_icon_paths(app)
                .into_iter()
                .map(|rel| prefix.join("share/icons/hicolor").join(rel)),
        );
        files.push(prefix.join(format!("share/metainfo/{app}.metainfo.xml")));
    }
    files
}

/// The fixed sizes an app's PNG icon may come in beside its scalable SVG:
/// the freedesktop hicolor sizes, up to the 512 px the spec allows.
const APP_ICON_SIZES: &[u32] = &[16, 22, 24, 32, 48, 64, 128, 256, 512];

/// The app's icons other than the scalable SVG, relative to a hicolor theme
/// root: a PNG at each of [`APP_ICON_SIZES`], and the one-colour symbolic
/// icon panels and trays recolour.
fn app_icon_paths(app: &str) -> Vec<String> {
    let mut paths: Vec<String> = APP_ICON_SIZES
        .iter()
        .map(|n| format!("{n}x{n}/apps/{app}.png"))
        .collect();
    paths.push(format!("symbolic/apps/{app}-symbolic.svg"));
    paths
}

/// The entries for those of the app's [`app_icon_paths`] the release in
/// `staging` carries under `resources/icons/hicolor`. None is required: a
/// release from before they shipped still installs, with the SVG alone.
fn optional_app_icons(staging: &Path, prefix: &Path, app: &str) -> Vec<ManifestEntry> {
    let theme = staging.join("resources/icons/hicolor");
    app_icon_paths(app)
        .into_iter()
        .filter_map(|rel| {
            let source = theme.join(&rel);
            source.is_file().then(|| ManifestEntry {
                source,
                dest: prefix.join("share/icons/hicolor").join(&rel),
                mode: 0o644,
            })
        })
        .collect()
}

/// What a product's own COSMIC applet installed under `prefix`: its binary,
/// its three launcher entries and its icon. The applet with releases of its
/// own replaces them.
fn product_applet_files(prefix: &Path, product_applet: &str) -> Vec<PathBuf> {
    let mut files = vec![prefix.join("bin").join(product_applet)];
    for side in ["full", "left", "right"] {
        files.push(prefix.join(format!(
            "share/applications/{product_applet}-{side}.desktop"
        )));
    }
    files.push(prefix.join(format!(
        "share/icons/hicolor/scalable/apps/{product_applet}.svg"
    )));
    files
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

/// The `<short_name>` wrapper's entry. The wrapper has no source in the
/// tarball — generate it now and stage it as a real file, so the root phase
/// only ever copies files.
fn stage_wrapper(
    staging: &Path,
    prefix: &Path,
    installer: &Installer,
) -> Result<ManifestEntry, InstallError> {
    let short_name = installer.product.short_name;
    let generated_dir = staging.join("generated");
    std::fs::create_dir_all(&generated_dir).map_err(|e| {
        InstallError::InstallFailed(format!("create {}: {e}", generated_dir.display()))
    })?;
    let wrapper_path = generated_dir.join(short_name);
    std::fs::write(&wrapper_path, wrapper_script(prefix, installer)).map_err(|e| {
        InstallError::InstallFailed(format!("write {}: {e}", wrapper_path.display()))
    })?;
    Ok(ManifestEntry {
        source: wrapper_path,
        dest: prefix.join("bin").join(short_name),
        mode: 0o755,
    })
}

/// The entries for the [`Installer::extra_binaries`] the release in `staging`
/// carries. None is required: a release from before one shipped does not
/// carry it, and still installs.
fn extra_binary_entries<'a>(
    staging: &'a Path,
    bin: &'a Path,
    installer: &'a Installer,
) -> impl Iterator<Item = ManifestEntry> + 'a {
    installer.extra_binaries.iter().filter_map(move |name| {
        let source = staging.join(name);
        source.exists().then(|| ManifestEntry {
            source,
            dest: bin.join(name),
            mode: 0o755,
        })
    })
}

/// Build the manifest for `components`, resolving every source against
/// `staging` and every destination against `prefix` (`unit_dir` for the
/// systemd unit).
///
/// The applet's sources are in `applet`, the extracted tarball of the
/// applet's own release (see [`crate::applet`]), never in the product's
/// tarball: a product's release may still carry an applet, and it is
/// ignored. With the applet component selected, the `<slug>-cosmic-applet`
/// the product once bundled goes, and `applet` is `None` when the installed
/// applet is already as new as the release, which then stays.
///
/// The extension's sources are in `extension`, the extracted tarball of the
/// product's extension's own release (see [`crate::extension`]). Each of its
/// files goes under `<prefix>/share/gnome-shell/extensions/<uuid>`, and the
/// files of the installed one that the release no longer has go. `extension`
/// is `None` when the installed extension is already as new as the release,
/// which then stays.
///
/// `self_exe` is the running installer's own binary — every
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
#[allow(clippy::too_many_arguments)] // one source per component that has releases of its own
pub fn build_manifest(
    staging: &Path,
    applet: Option<&Path>,
    prefix: &Path,
    unit_dir: &Path,
    components: &Components,
    self_exe: &Path,
    installer: &Installer,
    extension: Option<&Path>,
) -> Result<Manifest, InstallError> {
    let product = installer.product;
    let slug = product.slug;
    let bin = prefix.join("bin");
    let mut removals = Vec::new();
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
        entries.extend(extra_binary_entries(staging, &bin, installer));
        entries.push(stage_wrapper(staging, prefix, installer)?);

        let unit = format!("{slug}.service");
        entries.push(required_entry(
            staging,
            &format!("systemd/{unit}"),
            unit_dir.join(&unit),
            0o644,
        )?);

        removals.extend(retired_files(prefix, unit_dir, &installer.retired));
    }

    let apps: &[&str] = if components.app { installer.apps } else { &[] };
    for app in apps {
        entries.push(required_entry(staging, app, bin.join(app), 0o755)?);
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
        entries.extend(optional_app_icons(staging, prefix, app));
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

    if components.applet
        && let Some(cosmic_applet) = &installer.cosmic_applet
    {
        // The applet replaces the one the product once bundled, and those of
        // the products it replaces, whether this run installs it or finds it
        // already current.
        removals.extend(product_applet_files(
            prefix,
            &format!("{slug}-cosmic-applet"),
        ));
        for applet in installer.retired.applets {
            removals.extend(product_applet_files(prefix, applet));
        }
        if let Some(applet) = applet {
            let name = cosmic_applet.name;
            entries.push(required_entry(applet, name, bin.join(name), 0o755)?);
            for path in applet_desktop_files(applet, name)? {
                let entry = path
                    .file_name()
                    .expect("filtered on file_name above")
                    .to_owned();
                entries.push(ManifestEntry {
                    source: path,
                    dest: prefix.join("share/applications").join(entry),
                    mode: 0o644,
                });
            }
            entries.push(required_entry(
                applet,
                &format!("resources/icons/hicolor/scalable/apps/{name}.svg"),
                prefix.join(format!("share/icons/hicolor/scalable/apps/{name}.svg")),
                0o644,
            )?);
        }
    }

    if components.extension
        && let (Some(staged), Some(gnome_extension)) = (extension, &installer.gnome_extension)
    {
        let (placed, stale) = extension_manifest(staged, prefix, gnome_extension)?;
        entries.extend(placed);
        removals.extend(stale);
    }

    Ok(Manifest { entries, removals })
}

/// The extension's part of the manifest: each file of its release in
/// `staged` placed under its directory, and the files of the one installed
/// that the release no longer has, to remove.
fn extension_manifest(
    staged: &Path,
    prefix: &Path,
    gnome_extension: &GnomeExtension,
) -> Result<(Vec<ManifestEntry>, Vec<PathBuf>), InstallError> {
    let files = crate::extension::release_files(staged, gnome_extension)?;
    let dir = crate::extension::dir(prefix, gnome_extension);
    let stale = crate::extension::stale_files(prefix, gnome_extension, &files);
    let placed = files
        .into_iter()
        .map(|rel| ManifestEntry {
            source: staged.join(&rel),
            dest: dir.join(rel),
            mode: 0o644,
        })
        .collect();
    Ok((placed, stale))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_dir::TestDir;
    use crate::tests::{INSTALLER, TEST_APPLET, TEST_EXTENSION};
    use std::path::PathBuf;
    use super_engine_protocol::test_product::TEST;

    /// A fresh, empty temp directory for one test, removed when it ends.
    fn test_dir() -> TestDir {
        TestDir::new("super-engine-installer-stage-")
    }

    /// A temp dir with an (always-created, possibly empty) `bin/` and each of
    /// `paths` touched as an empty file under it (parent dirs created as
    /// needed). Used as a fake `prefix` for detection tests: `mktree(&[])`
    /// exercises `plan_components`'s `Ok(ReadDir)`-but-empty path (a `bin/`
    /// that exists with nothing in it); see
    /// `detection_fresh_install_with_no_bin_directory_at_all` below for the
    /// sibling case where `bin/` doesn't exist at all (the `read_dir` `Err`
    /// path `.into_iter().flatten()` also has to handle).
    fn mktree(paths: &[&str]) -> TestDir {
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
    fn fake_staging() -> TestDir {
        fake_staging_without(&[])
    }

    /// Like [`fake_staging`], but omits every entry whose basename is in
    /// `missing`.
    fn fake_staging_without(missing: &[&str]) -> TestDir {
        let dir = test_dir();
        let files = [
            "super-test-daemon",
            "super-test-cli",
            "super-test-consent",
            "super-test-mcp",
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

    /// The extracted tarball of an applet release: the binary, its launcher
    /// entries and its icon, less any whose basename is in `missing`.
    fn fake_applet_release_without(missing: &[&str]) -> TestDir {
        let dir = test_dir();
        let name = TEST_APPLET.name;
        for f in [
            name.to_string(),
            format!("resources/{name}-full.desktop"),
            format!("resources/{name}-left.desktop"),
            format!("resources/{name}-right.desktop"),
            format!("resources/icons/hicolor/scalable/apps/{name}.svg"),
        ] {
            if missing
                .iter()
                .any(|m| Path::new(&f).file_name().unwrap() == *m)
            {
                continue;
            }
            let full = dir.join(f);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, b"").unwrap();
        }
        dir
    }

    fn fake_applet_release() -> TestDir {
        fake_applet_release_without(&[])
    }

    fn applet_only_manifest(staging: &Path, applet: Option<&Path>) -> Manifest {
        build_manifest(
            staging,
            applet,
            Path::new("/usr/local"),
            Path::new("/usr/lib/systemd/user"),
            &Components {
                daemon: false,
                app: false,
                applet: true,
                extension: false,
            },
            Path::new("/proc/self/exe"),
            &INSTALLER,
            None,
        )
        .expect("an applet-only manifest")
    }

    const PRODUCT_APPLET_FILES: [&str; 5] = [
        "/usr/local/bin/super-test-cosmic-applet",
        "/usr/local/share/applications/super-test-cosmic-applet-full.desktop",
        "/usr/local/share/applications/super-test-cosmic-applet-left.desktop",
        "/usr/local/share/applications/super-test-cosmic-applet-right.desktop",
        "/usr/local/share/icons/hicolor/scalable/apps/super-test-cosmic-applet.svg",
    ];

    /// The applet's release installs in place of the product's own applet,
    /// which goes once the shared one is in place.
    #[test]
    fn the_applet_release_replaces_the_products_own_applet() {
        let applet = fake_applet_release();
        let m = applet_only_manifest(&fake_staging(), Some(&*applet));

        for expected in [
            "/usr/local/bin/super-test-shared-applet",
            "/usr/local/share/applications/super-test-shared-applet-full.desktop",
            "/usr/local/share/applications/super-test-shared-applet-left.desktop",
            "/usr/local/share/applications/super-test-shared-applet-right.desktop",
            "/usr/local/share/icons/hicolor/scalable/apps/super-test-shared-applet.svg",
        ] {
            let entry = m
                .entries
                .iter()
                .find(|e| e.dest == Path::new(expected))
                .unwrap_or_else(|| panic!("{expected} missing from {:?}", m.entries));
            assert!(
                entry.source.starts_with(&applet),
                "{expected} must come from the applet's release, not {}",
                entry.source.display()
            );
        }
        assert!(
            !m.entries.iter().any(|e| e
                .dest
                .to_string_lossy()
                .contains("super-test-cosmic-applet")),
            "the product's own applet must not be installed beside the shared one: {:?}",
            m.entries
        );
        assert_eq!(m.removals, PRODUCT_APPLET_FILES.map(PathBuf::from));
    }

    /// A product release that bundles an applet, the shared one or its own,
    /// still takes the applet from the applet's release.
    #[test]
    fn an_applet_in_the_products_tarball_is_ignored() {
        let staging = fake_staging();
        let bundled = fake_applet_release();
        for f in ["", "resources"] {
            for entry in std::fs::read_dir(bundled.join(f)).unwrap() {
                let entry = entry.unwrap();
                if entry.path().is_file() {
                    std::fs::copy(entry.path(), staging.join(f).join(entry.file_name())).unwrap();
                }
            }
        }
        let applet = fake_applet_release();
        let m = applet_only_manifest(&staging, Some(&*applet));
        for e in &m.entries {
            if e.dest.to_string_lossy().contains("cosmic-applet") {
                assert!(e.source.starts_with(&applet), "{e:?}");
            }
        }
    }

    /// With the installed applet already as new as the release, nothing of
    /// the applet is copied, and the product's own applet still goes.
    #[test]
    fn an_applet_already_current_stays_and_the_products_own_still_goes() {
        let m = applet_only_manifest(&fake_staging(), None);
        assert!(
            !m.entries
                .iter()
                .any(|e| e.dest.to_string_lossy().contains("cosmic-applet")),
            "{:?}",
            m.entries
        );
        assert_eq!(m.removals, PRODUCT_APPLET_FILES.map(PathBuf::from));
    }

    /// An applet deselected removes nothing: the product's own applet only
    /// goes when the shared one takes its place.
    #[test]
    fn no_applet_component_removes_nothing() {
        let applet = fake_applet_release();
        let m = build_manifest(
            &fake_staging(),
            Some(&*applet),
            Path::new("/usr/local"),
            Path::new("/usr/lib/systemd/user"),
            &Components {
                daemon: true,
                app: true,
                applet: false,
                extension: false,
            },
            Path::new("/proc/self/exe"),
            &INSTALLER,
            None,
        )
        .unwrap();
        assert!(m.removals.is_empty(), "{:?}", m.removals);
        assert!(
            !m.entries
                .iter()
                .any(|e| e.dest.to_string_lossy().contains("cosmic-applet"))
        );
    }

    /// On an update, the product's installed applet keeps the applet component,
    /// just as the product's own applet does.
    #[test]
    fn detection_update_mode_counts_the_products_applet() {
        let prefix = mktree(&["bin/super-test-daemon", "bin/super-test-shared-applet"]);
        let c = plan_components(None, &prefix, Desktops::NONE, &INSTALLER);
        assert!(c.daemon && c.applet);
    }

    #[test]
    fn detection_update_mode_only_updates_whats_present() {
        let prefix = mktree(&["bin/super-test-daemon", "bin/super-test-app"]); // helper: temp dir + touch files
        let c = plan_components(None, &prefix, Desktops::COSMIC, &INSTALLER);
        assert!(c.daemon && c.app && !c.applet);
    }

    #[test]
    fn detection_fresh_install_takes_all_gated_on_cosmic() {
        let prefix = mktree(&[]); // empty bin/ (F6: `mktree` always creates it)
        let c = plan_components(None, &prefix, Desktops::NONE, &INSTALLER);
        assert!(c.daemon && c.app && !c.applet);
        let c = plan_components(None, &prefix, Desktops::COSMIC, &INSTALLER);
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
        let c = plan_components(None, &prefix, Desktops::NONE, &INSTALLER);
        assert!(c.daemon && c.app && !c.applet);
        let c = plan_components(None, &prefix, Desktops::COSMIC, &INSTALLER);
        assert!(c.daemon && c.app && c.applet);
    }

    #[test]
    fn detection_update_mode_only_applet_present() {
        // The daemon is always refreshed on an update (the core piece every
        // install has) even when only the applet binary is present.
        let prefix = mktree(&["bin/super-test-cosmic-applet"]);
        let c = plan_components(None, &prefix, Desktops::COSMIC, &INSTALLER);
        assert!(c.daemon && !c.app && c.applet);
    }

    #[test]
    fn detection_update_mode_all_three_present() {
        let prefix = mktree(&[
            "bin/super-test-daemon",
            "bin/super-test-app",
            "bin/super-test-cosmic-applet",
        ]);
        let c = plan_components(None, &prefix, Desktops::NONE, &INSTALLER); // cosmic gone, but applet was already installed
        assert!(c.daemon && c.app && c.applet);
    }

    #[test]
    fn explicit_daemon_selects_only_daemon() {
        let prefix = mktree(&["bin/super-test-app"]);
        let c = plan_components(
            Some(ComponentSelection::Daemon),
            &prefix,
            Desktops::COSMIC,
            &INSTALLER,
        );
        assert!(c.daemon && !c.app && !c.applet);
    }

    #[test]
    fn explicit_app_selects_only_app() {
        let prefix = mktree(&[]);
        let c = plan_components(
            Some(ComponentSelection::App),
            &prefix,
            Desktops::COSMIC,
            &INSTALLER,
        );
        assert!(!c.daemon && c.app && !c.applet);
    }

    #[test]
    fn explicit_applet_selects_only_applet() {
        let prefix = mktree(&[]);
        // Explicit `--components=applet` bypasses the `cosmic_available`
        // gate entirely — unlike the interactive menu's option 4, the CLI
        // flag is trusted outright.
        let c = plan_components(
            Some(ComponentSelection::Applet),
            &prefix,
            Desktops::NONE,
            &INSTALLER,
        );
        assert!(!c.daemon && !c.app && c.applet);
    }

    #[test]
    fn explicit_all_selects_everything_regardless_of_existing_state() {
        let prefix = mktree(&["bin/super-test-daemon"]);
        let c = plan_components(
            Some(ComponentSelection::All),
            &prefix,
            Desktops::COSMIC,
            &INSTALLER,
        );
        assert!(c.daemon && c.app && c.applet);
    }

    #[test]
    fn all_detected_takes_the_add_ons_whose_desktop_is_here() {
        let prefix = mktree(&[]);
        let all = Some(ComponentSelection::AllDetected);
        let c = plan_components(all, &prefix, Desktops::COSMIC, &INSTALLER);
        assert!(c.daemon && c.app && c.applet && !c.extension);
        let c = plan_components(all, &prefix, Desktops::GNOME, &INSTALLER);
        assert!(c.daemon && c.app && !c.applet && c.extension);
        let c = plan_components(all, &prefix, Desktops::NONE, &INSTALLER);
        assert!(c.daemon && c.app && !c.applet && !c.extension);
    }

    #[test]
    fn all_stays_the_daemon_the_app_and_the_applet_whatever_the_desktop() {
        // Explicit `All` (the `--components=all` CLI path) never depends on
        // the host's desktop — this must never change, since the hermetic
        // e2e test relies on it being deterministic on a CI host with no
        // cosmic-panel or GNOME Shell.
        let prefix = mktree(&[]);
        for desktops in [Desktops::NONE, Desktops::GNOME] {
            let c = plan_components(Some(ComponentSelection::All), &prefix, desktops, &INSTALLER);
            assert!(c.daemon && c.app && c.applet && !c.extension);
        }
    }

    #[test]
    fn a_product_without_add_ons_never_gets_one() {
        let installer = Installer {
            cosmic_applet: None,
            gnome_extension: None,
            ..INSTALLER
        };
        let prefix = mktree(&[]);
        let both = Desktops {
            cosmic: true,
            gnome: true,
        };
        for explicit in [
            None,
            Some(ComponentSelection::All),
            Some(ComponentSelection::AllDetected),
            Some(ComponentSelection::Applet),
            Some(ComponentSelection::Extension),
        ] {
            let c = plan_components(explicit, &prefix, both, &installer);
            assert!(!c.applet && !c.extension, "{explicit:?}");
        }
        // Nor does an update that finds the applet it once bundled.
        let prefix = mktree(&["bin/super-test-daemon", "bin/super-test-cosmic-applet"]);
        assert!(!plan_components(None, &prefix, both, &installer).applet);
    }

    #[test]
    fn a_fresh_install_on_gnome_takes_the_extension() {
        let prefix = mktree(&[]);
        let c = plan_components(None, &prefix, Desktops::GNOME, &INSTALLER);
        assert!(c.daemon && c.app && !c.applet && c.extension);
        let c = plan_components(
            None,
            &prefix,
            Desktops::GNOME,
            &crate::tests::MERGED_INSTALLER,
        );
        assert!(!c.extension);
    }

    #[test]
    fn an_update_keeps_an_installed_extension_whatever_the_desktop() {
        let prefix = mktree(&["bin/super-test-daemon"]);
        assert!(!plan_components(None, &prefix, Desktops::GNOME, &INSTALLER).extension);
        crate::extension::fake_release(
            &crate::extension::dir(&prefix, &TEST_EXTENSION),
            TEST_EXTENSION.uuid,
        );
        assert!(plan_components(None, &prefix, Desktops::NONE, &INSTALLER).extension);
    }

    #[test]
    fn explicit_extension_selects_only_the_extension() {
        let prefix = mktree(&[]);
        let c = plan_components(
            Some(ComponentSelection::Extension),
            &prefix,
            Desktops::NONE,
            &INSTALLER,
        );
        assert_eq!(
            c,
            Components {
                extension: true,
                ..Components::default()
            }
        );
    }

    fn extension_only_manifest(prefix: &Path, staged: &Path) -> Result<Manifest, InstallError> {
        build_manifest(
            &fake_staging(),
            None,
            prefix,
            Path::new("/usr/lib/systemd/user"),
            &Components {
                extension: true,
                ..Components::default()
            },
            Path::new("/proc/self/exe"),
            &INSTALLER,
            Some(staged),
        )
    }

    #[test]
    fn the_extension_goes_where_gnome_shell_looks_and_what_it_dropped_goes() {
        let prefix = test_dir();
        let dir = crate::extension::dir(&prefix, &TEST_EXTENSION);
        crate::extension::fake_release(&dir, TEST_EXTENSION.uuid);
        std::fs::write(dir.join("old.js"), "").unwrap();
        let staged = test_dir();
        crate::extension::fake_release(&staged, TEST_EXTENSION.uuid);

        let m = extension_only_manifest(&prefix, &staged).unwrap();
        let mut placed: Vec<(PathBuf, PathBuf, u32)> = m
            .entries
            .iter()
            .filter(|e| e.dest.starts_with(&dir))
            .map(|e| (e.source.clone(), e.dest.clone(), e.mode))
            .collect();
        placed.sort();
        let expected: Vec<(PathBuf, PathBuf, u32)> = [
            "core/model.js",
            "extension.js",
            "metadata.json",
            "schemas/gschemas.compiled",
        ]
        .iter()
        .map(|rel| (staged.join(rel), dir.join(rel), 0o644))
        .collect();
        assert_eq!(placed, expected);
        // Only the installer itself besides.
        assert_eq!(m.entries.len(), expected.len() + 1);
        assert_eq!(m.removals, [dir.join("old.js")]);
    }

    #[test]
    fn another_extension_never_reaches_the_root_phase() {
        let staged = test_dir();
        crate::extension::fake_release(&staged, "someone-else@example.com");
        assert!(extension_only_manifest(&test_dir(), &staged).is_err());
    }

    #[test]
    fn manifest_covers_selected_components_with_modes() {
        let staging = fake_staging(); // helper: full tarball layout in a temp dir
        let m = build_manifest(
            &staging,
            None,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &Components {
                daemon: true,
                app: true,
                applet: false,
                extension: false,
            },
            std::path::Path::new("/proc/self/exe"),
            &INSTALLER,
            None,
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

    fn daemon_only() -> Components {
        Components {
            daemon: true,
            app: false,
            applet: false,
            extension: false,
        }
    }

    #[test]
    fn an_extra_binary_installs_with_the_daemon() {
        let staging = fake_staging();
        let prefix = std::path::Path::new("/usr/local");
        let units = std::path::Path::new("/usr/lib/systemd/user");
        let me = std::path::Path::new("/proc/self/exe");
        let m = build_manifest(
            &staging,
            None,
            prefix,
            units,
            &daemon_only(),
            me,
            &INSTALLER,
            None,
        )
        .unwrap();
        let mcp = m
            .entries
            .iter()
            .find(|e| e.dest.ends_with("bin/super-test-mcp"))
            .expect("the extra binary is installed");
        assert_eq!(mcp.source, staging.join("super-test-mcp"));
        assert_eq!(mcp.mode, 0o755);

        let app_only = Components {
            daemon: false,
            app: true,
            applet: false,
            extension: false,
        };
        let m = build_manifest(
            &staging, None, prefix, units, &app_only, me, &INSTALLER, None,
        )
        .unwrap();
        assert!(
            !m.entries
                .iter()
                .any(|e| e.dest.ends_with("bin/super-test-mcp"))
        );
    }

    #[test]
    fn a_release_without_an_extra_binary_still_installs() {
        let staging = fake_staging_without(&["super-test-mcp"]);
        let m = build_manifest(
            &staging,
            None,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &daemon_only(),
            std::path::Path::new("/proc/self/exe"),
            &INSTALLER,
            None,
        )
        .unwrap();
        assert!(
            !m.entries
                .iter()
                .any(|e| e.dest.ends_with("bin/super-test-mcp"))
        );
        assert!(
            m.entries
                .iter()
                .any(|e| e.dest.ends_with("bin/super-test-daemon"))
        );
    }

    /// The tarball of a product that replaced two others: its daemon, and an
    /// app of each.
    fn merged_staging() -> TestDir {
        let dir = test_dir();
        for f in [
            "super-test-daemon",
            "super-test-cli",
            "super-test-consent",
            "systemd/super-test.service",
            "super-a-app",
            "super-b-app",
            "resources/super-a-app.desktop",
            "resources/super-b-app.desktop",
            "resources/icons/hicolor/scalable/apps/super-a-app.svg",
            "resources/icons/hicolor/scalable/apps/super-b-app.svg",
        ] {
            let full = dir.join(f);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, b"").unwrap();
        }
        dir
    }

    fn merged_manifest(components: Components) -> Result<Manifest, InstallError> {
        build_manifest(
            &merged_staging(),
            None,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &components,
            std::path::Path::new("/proc/self/exe"),
            &crate::tests::MERGED_INSTALLER,
            None,
        )
    }

    /// Every app the installer names is installed, none of them named after
    /// the slug.
    #[test]
    fn the_app_component_installs_every_named_app() {
        let m = merged_manifest(Components {
            daemon: false,
            app: true,
            applet: false,
            extension: false,
        })
        .unwrap();
        let dests: Vec<String> = m
            .entries
            .iter()
            .map(|e| e.dest.display().to_string())
            .collect();
        for app in ["super-a-app", "super-b-app"] {
            assert!(
                dests.contains(&format!("/usr/local/bin/{app}")),
                "{dests:?}"
            );
            assert!(
                dests.contains(&format!("/usr/local/share/applications/{app}.desktop")),
                "{dests:?}"
            );
            assert!(
                dests.contains(&format!(
                    "/usr/local/share/icons/hicolor/scalable/apps/{app}.svg"
                )),
                "{dests:?}"
            );
        }
        assert!(!dests.iter().any(|d| d.ends_with("super-test-app")));
    }

    /// An install of the daemon takes away what the replaced products
    /// installed: their binaries, their unit and their app's launcher entry.
    #[test]
    fn a_daemon_install_removes_what_the_replaced_products_left() {
        let m = merged_manifest(Components {
            daemon: true,
            app: false,
            applet: false,
            extension: false,
        })
        .unwrap();
        for gone in [
            "/usr/local/bin/super-a-daemon",
            "/usr/local/bin/super-a-cli",
            "/usr/local/bin/a",
            "/usr/lib/systemd/user/super-a.service",
            "/usr/local/share/applications/super-old-app.desktop",
            "/usr/local/share/icons/hicolor/scalable/apps/super-old-app.svg",
            "/usr/local/share/metainfo/super-old-app.metainfo.xml",
        ] {
            assert!(
                m.removals.contains(&PathBuf::from(gone)),
                "{gone} stays: {:?}",
                m.removals
            );
        }
    }

    /// Without the daemon, the replaced products' files stay: an app-only run
    /// does not take the user's daemon away.
    #[test]
    fn an_app_only_install_leaves_the_replaced_products_alone() {
        let m = merged_manifest(Components {
            daemon: false,
            app: true,
            applet: false,
            extension: false,
        })
        .unwrap();
        assert!(m.removals.is_empty(), "{:?}", m.removals);
    }

    /// The product's applet replaces the replaced products' applets too.
    #[test]
    fn the_shared_applet_replaces_the_replaced_products_applets() {
        let m = merged_manifest(Components {
            daemon: false,
            app: false,
            applet: true,
            extension: false,
        })
        .unwrap();
        for gone in [
            "/usr/local/bin/super-a-cosmic-applet",
            "/usr/local/share/applications/super-a-cosmic-applet-full.desktop",
            "/usr/local/share/icons/hicolor/scalable/apps/super-a-cosmic-applet.svg",
        ] {
            assert!(m.removals.contains(&PathBuf::from(gone)), "{gone} stays");
        }
    }

    /// An update finds the app component by any app the installer names.
    #[test]
    fn detection_update_mode_finds_any_named_app() {
        let prefix = mktree(&["bin/super-test-daemon", "bin/super-b-app"]);
        let c = plan_components(
            None,
            &prefix,
            Desktops::NONE,
            &crate::tests::MERGED_INSTALLER,
        );
        assert!(c.daemon && c.app);
        let prefix = mktree(&["bin/super-test-daemon"]);
        let c = plan_components(
            None,
            &prefix,
            Desktops::NONE,
            &crate::tests::MERGED_INSTALLER,
        );
        assert!(!c.app);
    }

    #[test]
    fn manifest_missing_required_source_errors_before_escalation() {
        let staging = fake_staging_without(&["super-test-app"]);
        let err = build_manifest(
            &staging,
            None,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &Components {
                daemon: false,
                app: true,
                applet: false,
                extension: false,
            },
            std::path::Path::new("/proc/self/exe"),
            &INSTALLER,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::errors::InstallError::InstallFailed(_)));
    }

    #[test]
    fn manifest_errors_when_applet_desktop_glob_is_empty() {
        // F5: if the applet release's `resources/` is missing or renamed so
        // the `super-test-shared-applet-*.desktop` glob yields zero entries, the
        // applet binary would otherwise get installed with no launcher
        // entry at all — silently, since a `for` loop over an empty `Vec`
        // just does nothing. That must be a hard error for a selected
        // applet component, exactly like the sibling `required_entry` icon
        // check just below it.
        let applet = fake_applet_release_without(&[
            "super-test-shared-applet-full.desktop",
            "super-test-shared-applet-left.desktop",
            "super-test-shared-applet-right.desktop",
        ]);
        let err = build_manifest(
            &fake_staging(),
            Some(&*applet),
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &Components {
                daemon: false,
                app: false,
                applet: true,
                extension: false,
            },
            std::path::Path::new("/proc/self/exe"),
            &INSTALLER,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::errors::InstallError::InstallFailed(_)));
    }

    /// The app's PNG sizes and symbolic icon install beside its SVG when the
    /// release carries them, into the same hicolor theme, and are skipped
    /// when it does not.
    #[test]
    fn manifest_installs_the_app_icon_sizes_the_release_carries() {
        let components = Components {
            daemon: false,
            app: true,
            applet: false,
            extension: false,
        };
        let build = |staging: &Path| {
            build_manifest(
                staging,
                None,
                std::path::Path::new("/usr/local"),
                std::path::Path::new("/usr/lib/systemd/user"),
                &components,
                std::path::Path::new("/proc/self/exe"),
                &INSTALLER,
                None,
            )
            .unwrap()
        };
        let icons = |m: &Manifest| -> Vec<String> {
            m.entries
                .iter()
                .map(|e| e.dest.to_string_lossy().into_owned())
                .filter(|d| d.contains("/share/icons/hicolor/") && !d.contains("/scalable/"))
                .collect()
        };

        let staging = fake_staging();
        assert!(icons(&build(&staging)).is_empty());

        let theme = staging.join("resources/icons/hicolor");
        for rel in [
            "48x48/apps/super-test-app.png",
            "symbolic/apps/super-test-app-symbolic.svg",
        ] {
            std::fs::create_dir_all(theme.join(rel).parent().unwrap()).unwrap();
            std::fs::write(theme.join(rel), b"").unwrap();
        }
        let mut got = icons(&build(&staging));
        got.sort();
        assert_eq!(
            got,
            [
                "/usr/local/share/icons/hicolor/48x48/apps/super-test-app.png",
                "/usr/local/share/icons/hicolor/symbolic/apps/super-test-app-symbolic.svg",
            ]
        );
    }

    #[test]
    fn manifest_skips_optional_metainfo_when_absent() {
        let staging = fake_staging_without(&["super-test-app.metainfo.xml"]);
        let m = build_manifest(
            &staging,
            None,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &Components {
                daemon: false,
                app: true,
                applet: false,
                extension: false,
            },
            std::path::Path::new("/proc/self/exe"),
            &INSTALLER,
            None,
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
            None,
            std::path::Path::new("/usr/local"),
            std::path::Path::new("/usr/lib/systemd/user"),
            &Components::default(),
            std::path::Path::new("/some/self/exe"),
            &INSTALLER,
            None,
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
