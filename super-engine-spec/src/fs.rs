// SPDX-License-Identifier: GPL-3.0-only
//! Small filesystem helpers shared by the daemon and the indexer.
//!
//! Unix only. The mode a file is created with is part of what these helpers
//! promise, and a platform without Unix modes could not keep that promise for
//! [`write_atomic_private`], so this does not build there.

use std::ffi::OsString;
use std::fs::{File, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Atomically replace `path` with `contents`. The file gets mode `0o666` minus
/// the umask, usually `0o644`, as [`std::fs::write`] would give it.
///
/// The bytes go to a temp file beside `path`, which is `fsync`ed and then
/// renamed over `path`. The directory is `fsync`ed after that, so the rename
/// survives a power cut. A crash leaves either the old file or the new one,
/// never a truncated mix.
///
/// Every call gets a temp file of its own, so two writers racing on the same
/// `path` each rename a whole file: the last rename wins, and the file is never
/// a mix of the two. Which one lands last is up to the caller to order.
///
/// The temp file lives in the same directory so the rename stays on one
/// filesystem (a rename across filesystems is not atomic). It is named
/// `.<file name>.<random>.tmp`, so plain listings don't show it.
///
/// If `path` is a symlink, the rename replaces the link with a regular file.
///
/// # Errors
/// Returns any I/O error from creating, writing or syncing the temp file, from
/// the rename, or from syncing the directory. On any error before the rename
/// lands, the temp file is removed.
pub fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    write_atomic_with_mode(path, contents, 0o666)
}

/// [`write_atomic`] for a file only its owner may read or write: mode `0o600`.
///
/// The temp file is created with that mode, so the contents are never readable
/// by anyone else, not even for the moment between writing them and a later
/// `chmod`. Use it for secrets, session tokens and recorded voice.
///
/// # Errors
/// As [`write_atomic`].
pub fn write_atomic_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    write_atomic_with_mode(path, contents, 0o600)
}

/// `mode` is the one the temp file is created with, so the umask still removes
/// bits from it, as it would for [`std::fs::write`].
fn write_atomic_with_mode(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} names no file", path.display()),
        )
    })?;
    // `Path::parent` is `Some("")` for a bare file name.
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let mut prefix = OsString::from(".");
    prefix.push(file_name);
    prefix.push(".");

    // Until `persist` succeeds, dropping `tmp` (on any `?` below) removes it.
    let mut tmp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .permissions(Permissions::from_mode(mode))
        .tempfile_in(dir)?;
    tmp.write_all(contents)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::{write_atomic, write_atomic_private};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    /// Names in `dir`, sorted.
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn writes_and_overwrites_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");

        write_atomic(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        // Overwriting replaces the contents and leaves no temp file behind.
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_eq!(entries(dir.path()), ["index.json"]);
    }

    #[test]
    fn a_plain_write_gets_the_mode_std_would_give() {
        let dir = tempfile::tempdir().unwrap();
        // Whatever the umask is, `std::fs::write` applies the same one.
        let reference = dir.path().join("reference");
        std::fs::write(&reference, b"").unwrap();
        let path = dir.path().join("daemon.ron");

        write_atomic(&path, b"()").unwrap();
        assert_eq!(mode(&path), mode(&reference));
    }

    #[test]
    fn a_private_write_is_owner_only_even_over_a_wider_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.ron");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_atomic_private(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(mode(&path), 0o600);
    }

    /// Saves can race: each settings change spawns its own blocking save.
    /// With one shared temp name, two of them wrote into the same file and
    /// renamed a mix of both. Each must land whole.
    #[test]
    fn racing_writers_each_land_a_whole_file() {
        const WRITERS: u8 = 4;
        const ROUNDS: usize = 10;
        const LEN: usize = 64 * 1024;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.ron");
        std::thread::scope(|scope| {
            for writer in 0..WRITERS {
                let path = &path;
                scope.spawn(move || {
                    let contents = vec![b'a' + writer; LEN];
                    for _ in 0..ROUNDS {
                        write_atomic(path, &contents).unwrap();
                    }
                });
            }
        });

        let landed = std::fs::read(&path).unwrap();
        assert_eq!(landed.len(), LEN);
        assert!(
            landed.iter().all(|&b| b == landed[0]),
            "the file mixes two writers"
        );
        assert_eq!(entries(dir.path()), ["daemon.ron"]);
    }

    #[test]
    fn a_failed_rename_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        // A non-empty directory where the file should go: the rename fails.
        let path = dir.path().join("daemon.ron");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("inside"), b"").unwrap();

        assert!(write_atomic(&path, b"()").is_err());
        assert_eq!(entries(dir.path()), ["daemon.ron"]);
    }
}
