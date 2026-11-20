// SPDX-License-Identifier: GPL-3.0-only
//! Installer and self-updater for a product built on super-engine. One
//! binary serves the curl bootstrap (interactive), the app's in-app update
//! (--non-interactive --json-progress), and the escalated file-placement
//! step (--root-phase).
//!
//! A product's installer is a `main` that hands [`main`] its [`Installer`].
//! Everything it installs is named after the product: `<slug>-daemon`,
//! `<slug>-cli`, `<slug>-consent`, the `<short_name>` wrapper and the
//! `<slug>.service` user unit; `<slug>-app`; and the installer itself as
//! `<slug>-install`. Releases come from the product's `repo`, as
//! `<slug>-<triple>[-beta].tar.gz` with a `SHA256SUMS`.
//!
//! What the product adds to a desktop has releases of its own, which the
//! product names in its [`Installer`]: its COSMIC applet
//! ([`CosmicApplet`]), which replaces the `<slug>-cosmic-applet` a release
//! from before it installs, and its GNOME Shell extension
//! ([`GnomeExtension`]). Nothing here names one.

mod applet;
mod cli;
mod download;
mod errors;
mod escalate;
mod extension;
mod post_install;
mod progress;
mod resolve;
mod root_phase;
mod stage;
#[cfg(test)]
mod test_dir;
mod verify;

use std::io::IsTerminal;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

pub use applet::CosmicApplet;
use errors::InstallError;
pub use extension::GnomeExtension;
use progress::{Event, Phase, Reporter};
pub use stage::Components;
use stage::Desktops;
use super_engine_protocol::ProductSpec;

/// What makes an installer one product's.
#[derive(Debug, Clone, Copy)]
pub struct Installer {
    /// The product: its names, and the repo its releases come from.
    pub product: &'static ProductSpec,
    /// The `User-Agent` of every request, `<slug>/<version>` by convention.
    pub user_agent: &'static str,
    /// What the `<short_name>` wrapper is for, the second comment line of
    /// the script, e.g. `Used by keyboard shortcuts.`
    pub wrapper_usage: &'static str,
    /// The product's own post-install steps, run after the shared ones. They
    /// are best-effort: they log what fails, and the install still succeeds.
    pub after_install: Option<fn(&AfterInstall<'_>)>,
    /// Binaries the `daemon` component installs beside the daemon, the CLI
    /// and the consent helper, by name, e.g. an MCP server. Each is skipped
    /// when the release does not carry it, so a release from before it
    /// shipped still installs.
    pub extra_binaries: &'static [&'static str],
    /// The apps the `app` component installs, by binary name: each with its
    /// `resources/<name>.desktop` and icon, and its metainfo when the release
    /// carries one. A product's apps need not carry its slug.
    pub apps: &'static [&'static str],
    /// The product's COSMIC applet, from its own releases: the `applet`
    /// component, installed where a COSMIC panel is. `None` for a product
    /// without one.
    pub cosmic_applet: Option<CosmicApplet>,
    /// The product's GNOME Shell extension, from its own releases: the
    /// `extension` component, installed where GNOME Shell is. `None` for a
    /// product without one.
    pub gnome_extension: Option<GnomeExtension>,
    /// What installs of the products this one replaces left behind. It goes
    /// with an install of the daemon: their units are stopped first, then
    /// their files removed.
    pub retired: Retired,
}

/// Files and units of products an [`Installer`]'s product replaces, by name.
/// Removing a file that is not there is a no-op, so the lists name everything
/// any of their releases installed.
#[derive(Debug, Clone, Copy)]
pub struct Retired {
    /// Files under `<prefix>/bin`.
    pub binaries: &'static [&'static str],
    /// User units: stopped and disabled, then removed from the unit
    /// directory, so the replaced daemon never runs beside the new one.
    pub units: &'static [&'static str],
    /// Apps whose launcher entry, icon and metainfo go.
    pub apps: &'static [&'static str],
    /// COSMIC applets whose binary, three launcher entries and icon go.
    pub applets: &'static [&'static str],
}

impl Retired {
    /// A product that replaces nothing.
    pub const NONE: Self = Self {
        binaries: &[],
        units: &[],
        apps: &[],
        applets: &[],
    };
}

/// What an [`Installer::after_install`] step knows about the install that
/// just finished.
#[derive(Debug, Clone, Copy)]
pub struct AfterInstall<'a> {
    /// The components this run installed or updated.
    pub components: Components,
    /// Whether a person is at the terminal to answer a prompt: not
    /// `--non-interactive`, and stderr is a terminal.
    pub interactive: bool,
    /// Whether a COSMIC panel is on `$PATH`.
    pub cosmic_available: bool,
    /// Whether GNOME Shell is on `$PATH`.
    pub gnome_available: bool,
    /// Where the files went, e.g. `/usr/local`.
    pub prefix: &'a Path,
}

/// Owns the installer's private staging directory: mode `0700` and an
/// unpredictable name (pid + random suffix) so a local user can neither
/// pre-create it nor race its creation to plant a symlink, closing the
/// user-writable-staging race the root phase (running with no visibility
/// into how staging came to be) can't itself defend against. Canonicalized
/// immediately after creation so the manifest/staged sources are recorded
/// under a real path — the root phase's containment check canonicalizes
/// `staging_root` but compares entry sources to it lexically, so a
/// non-canonical (but equivalent, e.g. via a symlinked temp-dir ancestor)
/// path here would otherwise fail closed for no real reason. Removed on
/// drop so a cancelled/failed run never leaks the extracted, multi-hundred-
/// MB release tree — the same reason the shell installer used a `trap`.
struct StagingGuard {
    path: PathBuf,
}

impl StagingGuard {
    fn new(product: &ProductSpec) -> Result<Self, InstallError> {
        let name = format!(
            "{}-{}-{}",
            product.installer_binary(),
            std::process::id(),
            random_suffix()
        );
        let path = std::env::temp_dir().join(name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| {
                InstallError::InstallFailed(format!("create staging dir {}: {e}", path.display()))
            })?;
        let path = std::fs::canonicalize(&path).map_err(|e| {
            InstallError::InstallFailed(format!("resolve staging dir {}: {e}", path.display()))
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 8 random bytes, hex-encoded — the unpredictable half of the staging
/// directory's name (obligation (b): pid alone is guessable/reused).
/// Delegates to the shared helper so this crate and each product app's
/// self-update download directory draw from the same RNG/encoding.
fn random_suffix() -> String {
    super_engine_spec::verify::random_hex_suffix(8)
}

/// The outcome of mapping one trimmed line of `/dev/tty` input from the
/// interactive menu: either a selection to install, an explicit quit
/// (`q`/`Q`), or a retry with the message to show before looping back to the
/// prompt (an unavailable option picked, or plain garbage input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuChoice {
    Select(stage::ComponentSelection),
    Quit,
    Retry(&'static str),
}

/// One numbered option of the interactive menu.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MenuOption {
    label: String,
    /// What picking it does: a selection, or a retry saying why it can't be
    /// picked here.
    choice: MenuChoice,
}

/// The interactive menu's options, numbered from 1 in this order: all, the
/// daemon, the app, then each of the product's add-ons. "All" installs the
/// add-ons whose desktop is here, and says which it skips, so its label is
/// never a lie. An add-on whose desktop isn't here shows, but can't be
/// picked. An add-on the product doesn't have doesn't show.
fn menu_options(installer: &Installer, desktops: Desktops) -> Vec<MenuOption> {
    let add_ons = [
        (
            installer.cosmic_applet.is_some(),
            desktops.cosmic,
            "COSMIC applet",
            "COSMIC Applet only",
            stage::ComponentSelection::Applet,
            "COSMIC panel not found - applet not available",
        ),
        (
            installer.gnome_extension.is_some(),
            desktops.gnome,
            "GNOME Shell extension",
            "GNOME Shell Extension only",
            stage::ComponentSelection::Extension,
            "GNOME Shell not found - extension not available",
        ),
    ];
    let notes: Vec<String> = add_ons
        .iter()
        .filter(|(offered, ..)| *offered)
        .map(|(_, here, name, ..)| {
            if *here {
                format!("includes {name}")
            } else {
                format!("skips {name}")
            }
        })
        .collect();
    let all = if notes.is_empty() {
        "All".to_string()
    } else {
        format!("All ({})", notes.join(", "))
    };
    let mut options = vec![
        MenuOption {
            label: all,
            choice: MenuChoice::Select(stage::ComponentSelection::AllDetected),
        },
        MenuOption {
            label: "Daemon + CLI only".to_string(),
            choice: MenuChoice::Select(stage::ComponentSelection::Daemon),
        },
        MenuOption {
            label: "Desktop App only".to_string(),
            choice: MenuChoice::Select(stage::ComponentSelection::App),
        },
    ];
    for (offered, here, _, label, selection, missing) in add_ons {
        if !offered {
            continue;
        }
        options.push(if here {
            MenuOption {
                label: label.to_string(),
                choice: MenuChoice::Select(selection),
            }
        } else {
            MenuOption {
                label: format!("{label} (not available)"),
                choice: MenuChoice::Retry(missing),
            }
        });
    }
    options
}

/// Pure mapping from one trimmed line of interactive-menu input to a
/// [`MenuChoice`], extracted out of `run_interactive_menu`'s I/O loop so the
/// whole choice matrix is testable without a `/dev/tty`: an option's number,
/// nothing for the first, or `q`.
#[must_use]
fn menu_choice(input: &str, options: &[MenuOption]) -> MenuChoice {
    let picked = match input {
        "" => options.first(),
        "q" | "Q" => return MenuChoice::Quit,
        _ => input
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| options.get(i)),
    };
    picked.map_or(
        MenuChoice::Retry("Invalid option. Please try again."),
        |option| option.choice,
    )
}

/// The interactive component-selection menu, printed to stderr and read from
/// `/dev/tty` (independent of stdin, which `--json-progress` callers may be
/// piping/redirecting). Returns `None` on `q`/EOF; the caller treats that as
/// a cancelled install and exits 0.
fn run_interactive_menu(
    product: &ProductSpec,
    triple: &str,
    options: &[MenuOption],
) -> Result<Option<stage::ComponentSelection>, InstallError> {
    use std::io::{BufRead, Write};
    let tty = std::fs::File::open("/dev/tty")
        .map_err(|e| InstallError::InstallFailed(format!("open /dev/tty: {e}")))?;
    let mut reader = std::io::BufReader::new(tty);
    loop {
        eprintln!("=============================================");
        eprintln!("      {} Installation Menu", product.display_name);
        eprintln!("=============================================");
        eprintln!();
        eprintln!("Detected system:");
        eprintln!("  Architecture: {triple}");
        eprintln!();
        eprintln!("What would you like to install?");
        eprintln!();
        for (number, option) in options.iter().enumerate() {
            eprintln!("{}. {}", number + 1, option.label);
        }
        eprintln!();
        eprintln!("q. Quit");
        eprintln!();
        eprintln!("=============================================");
        eprint!("Select option [1-{}, q] (default: 1): ", options.len());
        let _ = std::io::stderr().flush();

        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| InstallError::InstallFailed(format!("read /dev/tty: {e}")))?;
        if n == 0 {
            // EOF on /dev/tty — treat like an explicit quit.
            return Ok(None);
        }
        match menu_choice(line.trim(), options) {
            MenuChoice::Select(selection) => return Ok(Some(selection)),
            MenuChoice::Quit => return Ok(None),
            MenuChoice::Retry(message) => eprintln!("{message}"),
        }
    }
}

/// Pick the release to install, and its tarball for `triple`, from the
/// product's repo.
async fn resolve_release(
    installer: &Installer,
    cli: &cli::Cli,
    triple: &str,
) -> Result<resolve::ResolvedTarget, InstallError> {
    let product = installer.product;
    let repo = super_engine_forge::RepoRef::parse(product.repo)
        .map_err(|e| InstallError::InstallFailed(format!("release repo {}: {e}", product.repo)))?;
    let client = super_engine_forge::Github::from_env(installer.user_agent);
    resolve::resolve_target(
        &client,
        &repo,
        product.slug,
        cli.version.as_deref(),
        cli.beta,
        triple,
    )
    .await
}

/// An add-on with releases of its own: what it is called in messages, where
/// its releases are, what its tarballs start with, the platform they name,
/// and the version installed now.
struct AddOn<'a> {
    what: &'a str,
    repo: &'a str,
    name: &'a str,
    platform: &'a str,
    installed: Option<String>,
}

/// Pick the release of `add_on` to install, from its own repo, on the same
/// channel as the product. `None` when the one installed is already as new,
/// or newer: see [`resolve::should_install`].
async fn resolve_add_on(
    installer: &Installer,
    cli: &cli::Cli,
    add_on: AddOn<'_>,
) -> Result<Option<resolve::ResolvedTarget>, InstallError> {
    let AddOn {
        what,
        repo,
        name,
        platform,
        installed,
    } = add_on;
    let repo_ref = super_engine_forge::RepoRef::parse(repo)
        .map_err(|e| InstallError::InstallFailed(format!("the {what}'s repo {repo}: {e}")))?;
    let client = super_engine_forge::Github::from_env(installer.user_agent);
    let target = resolve::resolve_target(&client, &repo_ref, name, None, cli.beta, platform)
        .await
        .map_err(|e| match e {
            InstallError::NoReleaseFound(m) => {
                InstallError::NoReleaseFound(format!("the {what}: {m}"))
            }
            InstallError::DownloadFailed(m) => {
                InstallError::DownloadFailed(format!("the {what}: {m}"))
            }
            other => other,
        })?;
    if resolve::should_install(installed.as_deref(), &target.release.tag) {
        Ok(Some(target))
    } else {
        log::info!(
            "{what} {} is installed, as new as {} or newer; keeping it",
            installed.as_deref().unwrap_or("?"),
            target.release.tag
        );
        Ok(None)
    }
}

/// The release of the product's applet to install, when the `applet`
/// component is selected and the one installed under `prefix` is older.
async fn resolve_applet(
    installer: &Installer,
    cli: &cli::Cli,
    triple: &str,
    prefix: &Path,
) -> Result<Option<resolve::ResolvedTarget>, InstallError> {
    let Some(applet) = &installer.cosmic_applet else {
        return Ok(None);
    };
    let add_on = AddOn {
        what: "COSMIC applet",
        repo: applet.repo,
        name: applet.name,
        platform: triple,
        installed: applet::installed_version(prefix, applet).await,
    };
    resolve_add_on(installer, cli, add_on).await
}

/// The release of the product's extension to install, when the `extension`
/// component is selected and the one installed under `prefix` is older.
async fn resolve_extension(
    installer: &Installer,
    cli: &cli::Cli,
    prefix: &Path,
) -> Result<Option<resolve::ResolvedTarget>, InstallError> {
    let Some(gnome_extension) = &installer.gnome_extension else {
        return Ok(None);
    };
    let add_on = AddOn {
        what: "GNOME Shell extension",
        repo: gnome_extension.repo,
        name: gnome_extension.name,
        platform: extension::PLATFORM,
        installed: extension::installed_version(prefix, gnome_extension),
    };
    resolve_add_on(installer, cli, add_on).await
}

/// Download `target`'s tarball into `staging` and check it against the
/// release's `SHA256SUMS`, returning where it landed.
async fn download_verified(
    installer: &Installer,
    target: &resolve::ResolvedTarget,
    staging: &Path,
    reporter: Reporter,
) -> Result<PathBuf, InstallError> {
    reporter.emit(&Event::Phase {
        phase: Phase::Download,
        message: &format!("downloading {}", target.tarball_name),
    });
    let tarball_path = staging.join(&target.tarball_name);
    download::download_to_file(
        installer.user_agent,
        &target.tarball_url,
        &tarball_path,
        |bytes_done, bytes_total| {
            reporter.emit(&Event::Progress {
                phase: Phase::Download,
                bytes_done,
                bytes_total,
            });
        },
    )
    .await?;
    let sums = download::download_string(
        installer.user_agent,
        &target.sums_url,
        super_engine_spec::verify::MAX_SHA256SUMS_BYTES,
    )
    .await?;

    reporter.emit(&Event::Phase {
        phase: Phase::Verify,
        message: "verifying checksum",
    });
    verify::verify_file(&tarball_path, &target.tarball_name, &sums)?;
    Ok(tarball_path)
}

/// Whether this install replaces or removes an applet binary the panel may be
/// running: the product's applet, when a newer release of it is being
/// installed over it, or the one the product once bundled, or one of the
/// products it replaces.
fn applet_changes(installer: &Installer, prefix: &Path, applet_release: bool) -> bool {
    let bin = prefix.join("bin");
    let product_applet = format!("{}-cosmic-applet", installer.product.slug);
    (applet_release
        && installer
            .cosmic_applet
            .is_some_and(|applet| bin.join(applet.name).exists()))
        || std::iter::once(product_applet.as_str())
            .chain(installer.retired.applets.iter().copied())
            .any(|applet| bin.join(applet).exists())
}

/// One of something for each of the product's add-ons, when it has one.
struct AddOns<T> {
    applet: Option<T>,
    extension: Option<T>,
}

/// The release of each add-on to install: when its component is selected,
/// and the one installed under `prefix` is older.
async fn resolve_add_ons(
    installer: &Installer,
    cli: &cli::Cli,
    triple: &str,
    prefix: &Path,
    components: &Components,
) -> Result<AddOns<resolve::ResolvedTarget>, InstallError> {
    Ok(AddOns {
        applet: if components.applet {
            resolve_applet(installer, cli, triple, prefix).await?
        } else {
            None
        },
        extension: if components.extension {
            resolve_extension(installer, cli, prefix).await?
        } else {
            None
        },
    })
}

/// Download and check each add-on's release in `targets` into `staging`.
async fn download_add_ons(
    installer: &Installer,
    targets: &AddOns<resolve::ResolvedTarget>,
    staging: &Path,
    reporter: Reporter,
) -> Result<AddOns<PathBuf>, InstallError> {
    let mut tarballs = AddOns {
        applet: None,
        extension: None,
    };
    if let Some(target) = &targets.applet {
        tarballs.applet = Some(download_verified(installer, target, staging, reporter).await?);
    }
    if let Some(target) = &targets.extension {
        tarballs.extension = Some(download_verified(installer, target, staging, reporter).await?);
    }
    Ok(tarballs)
}

/// Extract each add-on's release tarball in `tarballs` into a directory of
/// its own under `staging`.
fn extract_add_ons(
    tarballs: &AddOns<PathBuf>,
    staging: &Path,
) -> Result<AddOns<PathBuf>, InstallError> {
    let extract = |tarball: &Option<PathBuf>, dir: &str| -> Result<Option<PathBuf>, InstallError> {
        let Some(tarball) = tarball else {
            return Ok(None);
        };
        let extracted = staging.join(dir);
        stage::extract_tarball(tarball, &extracted)?;
        Ok(Some(extracted))
    };
    Ok(AddOns {
        applet: extract(&tarballs.applet, "applet")?,
        extension: extract(&tarballs.extension, "extension")?,
    })
}

/// What installing an extension release, when `extension_release`, does:
/// put it where there was none, which turns it on, or over an older one.
/// Captured before the root phase runs, like [`applet_changes`].
fn extension_change(
    installer: &Installer,
    prefix: &Path,
    extension_release: bool,
) -> Option<post_install::ExtensionChange> {
    if !extension_release {
        return None;
    }
    let there = installer
        .gnome_extension
        .is_some_and(|extension| extension::is_installed(prefix, &extension));
    Some(if there {
        post_install::ExtensionChange::Updated
    } else {
        post_install::ExtensionChange::Installed
    })
}

async fn run(
    installer: &Installer,
    cli: &cli::Cli,
    reporter: Reporter,
) -> Result<(), InstallError> {
    let product = installer.product;
    reporter.emit(&Event::Phase {
        phase: Phase::Resolve,
        message: "resolving release",
    });
    let triple = resolve::target_triple()?;
    let target = resolve_release(installer, cli, triple).await?;

    let path_env = std::env::var("PATH").unwrap_or_default();
    let desktops = Desktops {
        cosmic: escalate::which("cosmic-panel", &path_env).is_some(),
        gnome: escalate::which("gnome-shell", &path_env).is_some(),
    };
    let prefix = Path::new("/usr/local");
    let unit_dir = Path::new("/usr/lib/systemd/user");

    let mut explicit = cli.components;
    if explicit.is_none() && !cli.non_interactive && std::io::stderr().is_terminal() {
        let options = menu_options(installer, desktops);
        match run_interactive_menu(product, triple, &options)? {
            Some(selection) => explicit = Some(selection),
            None => return Ok(()),
        }
    }

    let components = stage::plan_components(explicit, prefix, desktops, installer);
    let add_on_targets = resolve_add_ons(installer, cli, triple, prefix, &components).await?;

    // Staging dir: 0700, unpredictable name, canonicalized — see
    // `StagingGuard`'s doc comment (obligation (b)). RAII-cleaned on every
    // exit path, including an early `?` return.
    let staging = StagingGuard::new(product)?;
    let tarball_path = download_verified(installer, &target, staging.path(), reporter).await?;
    let add_on_tarballs =
        download_add_ons(installer, &add_on_targets, staging.path(), reporter).await?;

    reporter.emit(&Event::Phase {
        phase: Phase::Stage,
        message: "staging files",
    });
    let extracted = staging.path().join("extracted");
    stage::extract_tarball(&tarball_path, &extracted)?;
    let add_ons = extract_add_ons(&add_on_tarballs, staging.path())?;

    // Captured before the root phase runs: whether a running applet's binary
    // changes under it, which the panel needs restarting to pick up. That is
    // the product's applet replaced by a newer release, or the one the
    // product once bundled removed in its favor. The same goes for the
    // extension: whether it goes where there was none, or over an older one.
    let applet_changes = applet_changes(installer, prefix, add_ons.applet.is_some());
    let extension_change = extension_change(installer, prefix, add_ons.extension.is_some());
    let self_exe = std::env::current_exe()
        .map_err(|e| InstallError::InstallFailed(format!("current_exe: {e}")))?;
    let manifest = stage::build_manifest(
        &extracted,
        add_ons.applet.as_deref(),
        prefix,
        unit_dir,
        &components,
        &self_exe,
        installer,
        add_ons.extension.as_deref(),
    )?;
    let manifest_path = staging.path().join("manifest.json");
    let manifest_json = serde_json::to_string(&manifest)
        .map_err(|e| InstallError::InstallFailed(format!("serialize manifest: {e}")))?;
    std::fs::write(&manifest_path, manifest_json).map_err(|e| {
        InstallError::InstallFailed(format!("write {}: {e}", manifest_path.display()))
    })?;

    if cli.dry_run {
        reporter.emit(&Event::Complete {
            installed_version: &target.release.tag,
            components: &components.names(),
        });
        return Ok(());
    }

    reporter.emit(&Event::Phase {
        phase: Phase::Escalate,
        message: "waiting for authorization",
    });
    let stderr_tty = std::io::stderr().is_terminal();
    let has_sudo = escalate::which("sudo", &path_env).is_some();
    let has_pkexec = escalate::which("pkexec", &path_env).is_some();
    let method = escalate::pick_method(stderr_tty, has_sudo, has_pkexec)?;
    reporter.emit(&Event::Phase {
        phase: Phase::Install,
        message: "installing files",
    });
    // While their unit files are still there to disable: the root phase
    // removes them, and the replaced daemon must not run beside the new one.
    if components.daemon {
        post_install::stop_retired_units(&installer.retired).await;
    }
    escalate::run_root_phase(method, &manifest_path).await?;

    reporter.emit(&Event::Phase {
        phase: Phase::PostInstall,
        message: "finishing installation",
    });
    let interactive = !cli.non_interactive && std::io::stderr().is_terminal();
    post_install::run(
        installer,
        &components,
        applet_changes,
        extension_change,
        interactive,
        prefix,
    )
    .await?;

    reporter.emit(&Event::Complete {
        installed_version: &target.release.tag,
        components: &components.names(),
    });
    Ok(())
}

/// Run the installer: a product's whole `main`.
///
/// # Panics
/// If the tokio runtime cannot be built.
#[must_use = "the installer's binary exits with this code"]
pub fn main(installer: &Installer) -> std::process::ExitCode {
    super_engine_forge::install_crypto_provider();
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    let cli = cli::parse_cli(installer.product);

    // Escalated re-exec: sync, no runtime, no env dependence.
    if let Some(manifest) = cli.root_phase {
        return std::process::ExitCode::from(root_phase::run(&manifest));
    }

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let reporter = if cli.json_progress {
        Reporter::Json
    } else {
        Reporter::Human(installer.product.display_name)
    };
    match runtime.block_on(run(installer, &cli, reporter)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            reporter.emit(&Event::Error {
                code: e.code(),
                message: &e.to_string(),
            });
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super_engine_protocol::test_product::TEST;

    /// The test product's COSMIC applet.
    pub(crate) const TEST_APPLET: CosmicApplet = CosmicApplet {
        repo: "github.com/example/super-test-cosmic-applet",
        name: "super-test-shared-applet",
    };

    /// The test product's GNOME Shell extension.
    pub(crate) const TEST_EXTENSION: GnomeExtension = GnomeExtension {
        repo: "github.com/example/super-test-gnome-shell-extension",
        uuid: "super-test@example.com",
        name: "super-test-gnome-shell-extension",
    };

    /// The installer the unit tests stage for.
    pub(crate) static INSTALLER: Installer = Installer {
        product: &TEST,
        user_agent: "super-engine-installer-tests",
        wrapper_usage: "Used by the tests.",
        after_install: None,
        extra_binaries: &["super-test-mcp"],
        apps: &["super-test-app"],
        cosmic_applet: Some(TEST_APPLET),
        gnome_extension: Some(TEST_EXTENSION),
        retired: Retired::NONE,
    };

    /// A product that replaced two others, each with an app of its own, and
    /// has no GNOME Shell extension.
    pub(crate) static MERGED_INSTALLER: Installer = Installer {
        product: &TEST,
        user_agent: "super-engine-installer-tests",
        wrapper_usage: "Used by the tests.",
        after_install: None,
        extra_binaries: &[],
        apps: &["super-a-app", "super-b-app"],
        cosmic_applet: Some(TEST_APPLET),
        gnome_extension: None,
        retired: Retired {
            binaries: &["super-a-daemon", "super-a-cli", "a"],
            units: &["super-a.service"],
            apps: &["super-old-app"],
            applets: &["super-a-cosmic-applet"],
        },
    };

    /// A product with neither add-on.
    fn plain_installer() -> Installer {
        Installer {
            cosmic_applet: None,
            gnome_extension: None,
            ..INSTALLER
        }
    }

    fn labels(options: &[MenuOption]) -> Vec<&str> {
        options.iter().map(|o| o.label.as_str()).collect()
    }

    #[test]
    fn all_says_which_add_ons_it_includes_and_which_it_skips() {
        assert_eq!(
            labels(&menu_options(&INSTALLER, Desktops::COSMIC)),
            [
                "All (includes COSMIC applet, skips GNOME Shell extension)",
                "Daemon + CLI only",
                "Desktop App only",
                "COSMIC Applet only",
                "GNOME Shell Extension only (not available)",
            ]
        );
        assert_eq!(
            labels(&menu_options(&INSTALLER, Desktops::GNOME))[0],
            "All (skips COSMIC applet, includes GNOME Shell extension)"
        );
        assert_eq!(
            labels(&menu_options(&MERGED_INSTALLER, Desktops::NONE)),
            [
                "All (skips COSMIC applet)",
                "Daemon + CLI only",
                "Desktop App only",
                "COSMIC Applet only (not available)",
            ]
        );
    }

    #[test]
    fn a_product_without_add_ons_offers_none() {
        assert_eq!(
            labels(&menu_options(&plain_installer(), Desktops::COSMIC)),
            ["All", "Daemon + CLI only", "Desktop App only"]
        );
    }

    #[test]
    fn the_default_and_1_pick_all_the_desktop_takes() {
        let options = menu_options(&INSTALLER, Desktops::GNOME);
        for input in ["", "1"] {
            assert_eq!(
                menu_choice(input, &options),
                MenuChoice::Select(stage::ComponentSelection::AllDetected)
            );
        }
    }

    #[test]
    fn menu_choice_2_and_3_pick_daemon_and_app_regardless_of_desktop() {
        for desktops in [Desktops::NONE, Desktops::COSMIC, Desktops::GNOME] {
            let options = menu_options(&INSTALLER, desktops);
            assert_eq!(
                menu_choice("2", &options),
                MenuChoice::Select(stage::ComponentSelection::Daemon)
            );
            assert_eq!(
                menu_choice("3", &options),
                MenuChoice::Select(stage::ComponentSelection::App)
            );
        }
    }

    #[test]
    fn an_add_on_is_picked_only_where_its_desktop_is() {
        let cosmic = menu_options(&INSTALLER, Desktops::COSMIC);
        assert_eq!(
            menu_choice("4", &cosmic),
            MenuChoice::Select(stage::ComponentSelection::Applet)
        );
        assert!(matches!(menu_choice("5", &cosmic), MenuChoice::Retry(_)));
        let gnome = menu_options(&INSTALLER, Desktops::GNOME);
        assert!(matches!(menu_choice("4", &gnome), MenuChoice::Retry(_)));
        assert_eq!(
            menu_choice("5", &gnome),
            MenuChoice::Select(stage::ComponentSelection::Extension)
        );
    }

    #[test]
    fn menu_choice_q_quits_regardless_of_case_or_desktop() {
        for desktops in [Desktops::NONE, Desktops::COSMIC] {
            let options = menu_options(&INSTALLER, desktops);
            assert_eq!(menu_choice("q", &options), MenuChoice::Quit);
            assert_eq!(menu_choice("Q", &options), MenuChoice::Quit);
        }
    }

    #[test]
    fn menu_choice_anything_else_retries() {
        let options = menu_options(&INSTALLER, Desktops::COSMIC);
        for bad in ["0", "6", "abc", "-1", " ", "1 "] {
            assert!(
                matches!(menu_choice(bad, &options), MenuChoice::Retry(_)),
                "{bad:?} should retry"
            );
        }
        // A product without add-ons has no option 4.
        let plain = menu_options(&plain_installer(), Desktops::COSMIC);
        assert!(matches!(menu_choice("4", &plain), MenuChoice::Retry(_)));
    }
}
