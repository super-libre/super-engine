// SPDX-License-Identifier: GPL-3.0-only
//! A WASM backend's private `/tmp`.
//!
//! A component is instantiated afresh for every request, so nothing it holds
//! in memory outlives the request. Some state has to: a cloned voice is
//! registered once and then named by every synthesis that uses it. This is
//! where such state lives. It is the WASM counterpart of a subprocess
//! backend's private `/tmp`, and is scratch in the same way:
//!
//! - One directory per loaded component, empty when the component loads,
//!   seen by the component as `/tmp` and by no other backend.
//! - Removed when the component is dropped, which is when its model unloads.
//!   Nothing in it has to survive that, because the daemon hands a loaded
//!   model what it needs again after every load.
//! - Under the runtime directory, which is memory-backed on Linux, so what a
//!   backend keeps there never reaches the disk.
//!
//! A daemon that dies cannot run the removal, so creating one first sweeps
//! away any left by a daemon that is no longer running.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use super_engine_protocol::ProductSpec;

/// The directory, under the product's runtime directory, that holds every
/// component's private `/tmp`.
const PARENT: &str = "wasm-tmp";

/// Tells apart the directories one daemon creates.
static NEXT: AtomicU64 = AtomicU64::new(0);

/// One component's private `/tmp`, removed on drop.
#[derive(Debug)]
pub struct PrivateTmp {
    path: PathBuf,
}

impl PrivateTmp {
    /// Create an empty one under `product`'s runtime directory.
    ///
    /// # Errors
    /// If the directory cannot be created.
    pub fn create(product: &ProductSpec) -> Result<Self> {
        let parent = super_engine_protocol::runtime::secure_runtime_path(product, PARENT);
        Self::create_in(&parent)
    }

    /// Create an empty one under `parent`.
    fn create_in(parent: &Path) -> Result<Self> {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        sweep_orphans(parent);
        loop {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let name = format!(
                "{}-{}-{nanos:08x}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let path = parent.join(name);
            match create_private_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("creating {}", path.display()));
                }
            }
        }
    }

    /// Where it is on the host.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTmp {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            log::warn!("removing {}: {e}", self.path.display());
        }
    }
}

/// Create `path`, readable by its owner alone.
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
}

/// Remove the directories of daemons that are no longer running: each is
/// named for the process that made it.
fn sweep_orphans(parent: &Path) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.split('-').next())
            .and_then(|p| p.parse::<u32>().ok())
        else {
            continue;
        };
        if pid != std::process::id() && !is_running(pid) {
            let path = entry.path();
            if let Err(e) = std::fs::remove_dir_all(&path) {
                log::warn!("removing the orphaned {}: {e}", path.display());
            }
        }
    }
}

/// Whether a process with this id exists. A process belonging to another
/// user exists too, though it cannot be signalled.
#[cfg(unix)]
fn is_running(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks that the process exists and may be
    // signalled; nothing is sent.
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    alive || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Without a way to ask, assume it is: leaving a directory behind is better
/// than removing a live one.
#[cfg(not(unix))]
fn is_running(_pid: u32) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_is_empty_private_and_gone_on_drop() {
        let parent = tempfile::tempdir().unwrap();
        let tmp = PrivateTmp::create_in(parent.path()).unwrap();
        let path = tmp.path().to_path_buf();
        assert!(path.starts_with(parent.path()));
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        std::fs::create_dir(path.join("voices")).unwrap();
        std::fs::write(path.join("voices/a.wav"), b"RIFF").unwrap();
        drop(tmp);
        assert!(!path.exists());
    }

    #[test]
    fn two_are_never_the_same_directory() {
        let parent = tempfile::tempdir().unwrap();
        let a = PrivateTmp::create_in(parent.path()).unwrap();
        let b = PrivateTmp::create_in(parent.path()).unwrap();
        assert_ne!(a.path(), b.path());
    }

    #[test]
    fn a_dead_daemons_directory_is_swept_and_a_live_ones_kept() {
        let parent = tempfile::tempdir().unwrap();
        // No process has id `u32::MAX`; pid_t cannot even hold it.
        let dead = parent.path().join(format!("{}-0-0", u32::MAX));
        std::fs::create_dir(&dead).unwrap();
        std::fs::write(dead.join("clip.wav"), b"RIFF").unwrap();
        let live = parent.path().join(format!("{}-0-0", std::process::id()));
        std::fs::create_dir(&live).unwrap();
        let unrelated = parent.path().join("not-a-pid");
        std::fs::create_dir(&unrelated).unwrap();

        let _tmp = PrivateTmp::create_in(parent.path()).unwrap();
        assert!(!dead.exists(), "the dead daemon's directory is swept");
        assert!(live.exists(), "this daemon's own is kept");
        assert!(unrelated.exists(), "a name that is not ours is left alone");
    }
}
