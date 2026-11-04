// SPDX-License-Identifier: GPL-3.0-only
//! One daemon per socket.
//!
//! A daemon started while another was serving the same socket used to run its
//! whole startup, loading (and possibly rewriting) the config and sweeping
//! backend units. Then it deleted the live daemon's socket and bound its own.
//! The first daemon kept running, holding its models, unreachable. Its
//! shutdown would later delete the newcomer's socket in turn.
//!
//! [`InstanceLock`] stops a second daemon before it does any of that.

use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The exclusive lock on `<socket>.lock`, held for as long as the daemon runs.
///
/// Taking it is the first thing a daemon does after it starts logging, before
/// it loads its config or touches anything another daemon could be using.
/// [`serve`](crate::http::server::serve) takes it and binds the socket it
/// names. Holding it is what makes removing a leftover socket file there safe:
/// no other daemon can be serving that path.
///
/// It is an `flock` on an open file, so the kernel drops it when the process
/// ends, however it ends: a crash, `SIGKILL` and `process::exit` included. The
/// file itself is never deleted. Deleting it would let a second daemon lock a
/// new file at the same path while the first still held the old one.
#[derive(Debug)]
pub struct InstanceLock {
    socket_path: PathBuf,
    /// Never read: the lock lasts as long as the open file does.
    _file: File,
}

/// Why [`InstanceLock::acquire`] failed.
#[derive(Debug, thiserror::Error)]
pub enum AcquireError {
    /// Another process holds the lock: a daemon is serving this socket.
    #[error("another daemon is already serving {}", .0.display())]
    AlreadyRunning(PathBuf),
    /// The lock file could not be created or locked.
    #[error("could not lock {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl InstanceLock {
    /// Lock `<socket_path>.lock`, creating it (and its directory) if needed.
    ///
    /// Never waits: a lock someone else holds is
    /// [`AlreadyRunning`](AcquireError::AlreadyRunning) at once.
    ///
    /// # Errors
    /// [`AcquireError::AlreadyRunning`] when another daemon holds the lock, and
    /// [`AcquireError::Io`] when the file cannot be created or locked.
    pub fn acquire(socket_path: &Path) -> Result<Self, AcquireError> {
        let mut lock_path = socket_path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        let io = |source| AcquireError::Io {
            path: lock_path.clone(),
            source,
        };

        if let Some(dir) = lock_path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(io)?;
        match file.try_lock() {
            Ok(()) => Ok(Self {
                socket_path: socket_path.to_owned(),
                _file: file,
            }),
            Err(TryLockError::WouldBlock) => {
                Err(AcquireError::AlreadyRunning(socket_path.to_owned()))
            }
            Err(TryLockError::Error(e)) => Err(io(e)),
        }
    }

    /// The socket this lock guards.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

#[cfg(test)]
mod tests {
    use super::{AcquireError, InstanceLock};

    #[test]
    fn a_second_daemon_on_the_same_socket_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("run/stt/super-stt-http.sock");

        let first = InstanceLock::acquire(&socket).unwrap();
        assert_eq!(first.socket_path(), socket);
        // `flock` belongs to the open file, not the process, so a second
        // open in this same process stands in for a second daemon.
        match InstanceLock::acquire(&socket) {
            Err(AcquireError::AlreadyRunning(path)) => assert_eq!(path, socket),
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }
    }

    #[test]
    fn the_lock_is_free_again_once_its_holder_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("super-stt-http.sock");

        drop(InstanceLock::acquire(&socket).unwrap());
        // The lock file is left in place, and taking it again works.
        assert!(dir.path().join("super-stt-http.sock.lock").exists());
        InstanceLock::acquire(&socket).unwrap();
    }

    #[test]
    fn daemons_on_different_sockets_do_not_meet() {
        let dir = tempfile::tempdir().unwrap();
        let _stt = InstanceLock::acquire(&dir.path().join("stt.sock")).unwrap();
        let _tts = InstanceLock::acquire(&dir.path().join("tts.sock")).unwrap();
    }
}
