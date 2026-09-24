// SPDX-License-Identifier: GPL-3.0-only
//! One `env_logger` initializer for every daemon and client binary.
//!
//! Replaces five near-identical setups (and one that silently defaulted to
//! `error`, plus a CLI with none at all). `RUST_LOG` always wins; otherwise the
//! level falls back to the caller's default. Call this ONCE, as early in `main`
//! as possible — before any config load — so startup diagnostics (e.g. a
//! "config invalid, reset to defaults" warning) aren't emitted before the logger
//! exists and dropped.

#[cfg(target_os = "macos")]
use crate::ProductSpec;

/// Initialize logging with an `Info` default level. `RUST_LOG` still overrides.
pub fn init() {
    init_with(log::LevelFilter::Info);
}

/// Initialize logging with an explicit default level. `RUST_LOG` still
/// overrides (e.g. the daemon passes `Debug` under `--verbose`).
pub fn init_with(default_level: log::LevelFilter) {
    if std::env::var_os("RUST_LOG").is_some() {
        env_logger::init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(default_level)
            .init();
    }
}

/// Send stdout and stderr to the file `<PREFIX>_LOG_FILE` names, relative to
/// `$HOME`, the way launchd's `StandardErrorPath` would. Call it first in
/// `main`, before [`init`], so nothing is written to the old stderr after it.
///
/// The `LaunchAgent`s inside a macOS app bundle cannot say where to log
/// themselves. Their plists ship inside a signed bundle, so they are the same
/// for every user, and launchd expands neither `~` nor `$HOME`, so there is
/// no way for them to name a file in the user's home. They set this variable
/// to a path relative to `$HOME` instead — which launchd does set for a user
/// agent — and the process opens it. Without the variable this does nothing.
///
/// Both descriptors, not a logger target, so a panic lands in the file as well.
/// A failure is reported on the stderr that was about to be replaced, and
/// leaves it in place: a log that goes nowhere beats a process that will not
/// start.
#[cfg(target_os = "macos")]
pub fn redirect_stdio(product: &ProductSpec) {
    use std::os::fd::AsRawFd as _;

    let var = product.env("LOG_FILE");
    let Some(relative) = std::env::var_os(&var) else {
        return;
    };
    let Some(home) = std::env::var_os("HOME") else {
        eprintln!("{var} is set but HOME is not; logging to stderr");
        return;
    };
    let path = std::path::Path::new(&home).join(relative);
    if let Some(dir) = path.parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        eprintln!("cannot create {}: {e}; logging to stderr", dir.display());
        return;
    }
    let file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!("cannot open {}: {e}; logging to stderr", path.display());
            return;
        }
    };
    for fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: both descriptors are open for the duration of the call, and
        // `dup2` replaces `fd` atomically. The file's own descriptor closes
        // when `file` drops; the two duplicates keep the file open.
        if unsafe { libc::dup2(file.as_raw_fd(), fd) } == -1 {
            eprintln!(
                "cannot redirect output to {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
            return;
        }
    }
}
