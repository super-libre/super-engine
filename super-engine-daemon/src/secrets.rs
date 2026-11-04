// SPDX-License-Identifier: GPL-3.0-only
//! The daemon's secrets file: the session tokens it has issued and every
//! backend's API keys, in `<state>/<slug>/secrets.ron` with mode 0600.
//!
//! Only the daemon reads or writes it, through one [`Secrets`] per process.
//! Every change is made to a copy of what is in memory, the whole file is
//! written again with [`write_atomic_private`], and only then does the copy
//! replace what is in memory, all under one lock. So the file is always one
//! whole state, the latest, and at no point can another user read it.
//!
//! It replaces the system keyring. The daemon could only reach that through
//! the secret service: a locked keyring held startup on its unlock prompt, and
//! a headless machine had none at all. Against other users, a file the user
//! owns at 0600 keeps the secrets as the keyring did. Against the user's own
//! processes, neither one does.

use crate::auth::tokens::TokenMeta;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use super_engine_protocol::ProductSpec;
use super_engine_spec::fs::write_atomic_private;

/// The file's name in the product's state directory.
pub const FILE_NAME: &str = "secrets.ron";

/// Why the secrets file could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    /// The file exists and could not be read, or could not be moved aside.
    #[error("could not read {}: {source}", .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The new file could not be written.
    #[error("could not write {}: {source}", .path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The contents could not be encoded.
    #[error("could not encode the secrets file: {0}")]
    Encode(#[from] ron::Error),
    /// The blocking write task panicked or was cancelled.
    #[error("secrets task failed: {0}")]
    Task(String),
}

/// What the file holds.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Contents {
    /// The session tokens the daemon has issued, by token.
    sessions: HashMap<String, TokenMeta>,
    /// Backend API keys: by the backend's source, then by the secret's name.
    backend_secrets: BTreeMap<String, BTreeMap<String, String>>,
}

/// The daemon's secrets, in memory and in the file. Cheap to clone; clones
/// share one copy and one lock.
#[derive(Clone)]
pub struct Secrets {
    inner: Arc<Inner>,
}

struct Inner {
    /// Where the file is, or `None` for [`Secrets::in_memory`], which never
    /// writes one.
    path: Option<PathBuf>,
    contents: Mutex<Contents>,
}

impl Secrets {
    /// Open `product`'s secrets file, in its
    /// [state directory](super_engine_protocol::paths::state_dir).
    ///
    /// # Errors
    /// As [`at`](Self::at).
    pub fn open(product: &ProductSpec) -> Result<Self, SecretsError> {
        Self::at(super_engine_protocol::paths::state_dir(product).join(FILE_NAME))
    }

    /// Open the secrets file at `path`.
    ///
    /// No file yet is an empty one; it is written on the first change. A file
    /// that does not parse is moved aside to `<path>.unreadable-<unix time>`,
    /// so nothing in it is lost, and the daemon starts with no secrets. Its
    /// clients ask for consent again, and the user enters the backends' keys
    /// again.
    ///
    /// # Errors
    /// When the file exists but cannot be read, or cannot be moved aside.
    /// The daemon must not start then: its first write would replace a file it
    /// never read.
    pub fn at(path: PathBuf) -> Result<Self, SecretsError> {
        let contents = match std::fs::read_to_string(&path) {
            Ok(text) => match ron::from_str(&text) {
                Ok(contents) => contents,
                Err(e) => {
                    set_aside(&path, &e)?;
                    Contents::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Contents::default(),
            Err(source) => return Err(SecretsError::Read { path, source }),
        };
        Ok(Self::with(Some(path), contents))
    }

    /// Secrets that live in memory only, for tests. Nothing is ever written.
    #[must_use]
    pub fn in_memory() -> Self {
        Self::with(None, Contents::default())
    }

    fn with(path: Option<PathBuf>, contents: Contents) -> Self {
        Self {
            inner: Arc::new(Inner {
                path,
                contents: Mutex::new(contents),
            }),
        }
    }

    /// The file, or `None` for [`in_memory`](Self::in_memory).
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.inner.path.as_deref()
    }

    /// A backend secret, such as `OPENAI_API_KEY` for one backend `source`.
    ///
    /// # Panics
    /// If a thread panicked while holding the secrets' lock.
    #[must_use]
    pub fn get_backend_secret(&self, source: &str, name: &str) -> Option<String> {
        self.inner
            .contents
            .lock()
            .unwrap()
            .backend_secrets
            .get(source)
            .and_then(|secrets| secrets.get(name))
            .cloned()
    }

    /// Whether a backend secret has a value.
    #[must_use]
    pub fn has_backend_secret(&self, source: &str, name: &str) -> bool {
        self.get_backend_secret(source, name).is_some()
    }

    /// Store or replace a backend secret, and write the file. Blocking (it
    /// `fsync`s); on the async runtime use
    /// [`set_backend_secret_async`](Self::set_backend_secret_async).
    ///
    /// # Errors
    /// When the file cannot be written. Nothing changes then, in memory either.
    pub fn set_backend_secret(
        &self,
        source: &str,
        name: &str,
        value: &str,
    ) -> Result<(), SecretsError> {
        self.update(|contents| {
            contents
                .backend_secrets
                .entry(source.to_string())
                .or_default()
                .insert(name.to_string(), value.to_string());
        })
    }

    /// Delete a backend secret, and write the file. A secret that is not
    /// there is already deleted. Blocking; see
    /// [`delete_backend_secret_async`](Self::delete_backend_secret_async).
    ///
    /// # Errors
    /// When the file cannot be written. Nothing changes then, in memory either.
    pub fn delete_backend_secret(&self, source: &str, name: &str) -> Result<(), SecretsError> {
        self.update(|contents| {
            if let Some(secrets) = contents.backend_secrets.get_mut(source) {
                secrets.remove(name);
                if secrets.is_empty() {
                    contents.backend_secrets.remove(source);
                }
            }
        })
    }

    /// [`set_backend_secret`](Self::set_backend_secret) on a blocking thread.
    ///
    /// # Errors
    /// As `set_backend_secret`, or when the task fails.
    pub async fn set_backend_secret_async(
        self,
        source: String,
        name: String,
        value: String,
    ) -> Result<(), SecretsError> {
        tokio::task::spawn_blocking(move || self.set_backend_secret(&source, &name, &value))
            .await
            .map_err(|e| SecretsError::Task(e.to_string()))?
    }

    /// [`delete_backend_secret`](Self::delete_backend_secret) on a blocking
    /// thread.
    ///
    /// # Errors
    /// As `delete_backend_secret`, or when the task fails.
    pub async fn delete_backend_secret_async(
        self,
        source: String,
        name: String,
    ) -> Result<(), SecretsError> {
        tokio::task::spawn_blocking(move || self.delete_backend_secret(&source, &name))
            .await
            .map_err(|e| SecretsError::Task(e.to_string()))?
    }

    /// The session tokens, as last written.
    pub(crate) fn sessions(&self) -> HashMap<String, TokenMeta> {
        self.inner.contents.lock().unwrap().sessions.clone()
    }

    /// Replace the session tokens, and write the file. Blocking.
    pub(crate) fn set_sessions(
        &self,
        sessions: HashMap<String, TokenMeta>,
    ) -> Result<(), SecretsError> {
        self.update(|contents| contents.sessions = sessions)
    }

    /// Apply `change` to a copy of the contents, write the copy, then keep it.
    /// The lock is held throughout, so writes land in the order the changes
    /// were made, and what is in memory is never ahead of the file.
    fn update(&self, change: impl FnOnce(&mut Contents)) -> Result<(), SecretsError> {
        let mut contents = self.inner.contents.lock().unwrap();
        let mut next = contents.clone();
        change(&mut next);
        if let Some(path) = &self.inner.path {
            write(path, &next)?;
        }
        *contents = next;
        Ok(())
    }
}

/// Write `contents` to `path` at mode 0600, creating its directory.
fn write(path: &Path, contents: &Contents) -> Result<(), SecretsError> {
    let mut text = ron::ser::to_string_pretty(contents, ron::ser::PrettyConfig::default())?;
    text.push('\n');
    let failed = |source| SecretsError::Write {
        path: path.to_path_buf(),
        source,
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(failed)?;
    }
    write_atomic_private(path, text.as_bytes()).map_err(failed)
}

/// Move a file that does not parse out of the way, keeping it.
fn set_aside(path: &Path, reason: &ron::error::SpannedError) -> Result<(), SecretsError> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".unreadable-{stamp}"));
    let aside = PathBuf::from(aside);
    std::fs::rename(path, &aside).map_err(|source| SecretsError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    error!(
        "{} does not parse ({reason}). Moved it to {} and started with no secrets: \
         clients ask for consent again, and backends' API keys must be entered again.",
        path.display(),
        aside.display()
    );
    info!("Nothing in {} was deleted", aside.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FILE_NAME, Secrets};
    use crate::auth::identity::PeerIdentity;
    use crate::auth::tokens::TokenMeta;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    fn token(grantee: PeerIdentity) -> TokenMeta {
        let now = chrono::Utc::now();
        TokenMeta {
            app_name: "secrets-test".to_string(),
            scopes: vec!["status".to_string()],
            grantee,
            issued_at: now,
            expires_at: now + chrono::Duration::days(30),
        }
    }

    /// Both kinds of grantee. The grantee is an internally tagged enum, the
    /// kind of type RON is least sure to read back, and one kind holds an
    /// `Option` as well.
    fn grantees() -> [PeerIdentity; 2] {
        [
            PeerIdentity::Native {
                exe_path: "/usr/bin/super-test-app".into(),
                flatpak_app_id: Some("com.example.App".to_string()),
            },
            PeerIdentity::Web {
                origin: "https://example.com".to_string(),
            },
        ]
    }

    #[test]
    fn what_is_written_is_read_back_by_the_next_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/super-test").join(FILE_NAME);

        let secrets = Secrets::at(path.clone()).unwrap();
        secrets
            .set_backend_secret("github.com/acme/openai", "OPENAI_API_KEY", "sk-1")
            .unwrap();
        let sessions: HashMap<_, _> = grantees()
            .into_iter()
            .enumerate()
            .map(|(i, grantee)| (format!("token-{i}"), token(grantee)))
            .collect();
        secrets.set_sessions(sessions).unwrap();

        let next = Secrets::at(path.clone()).unwrap();
        assert_eq!(
            next.get_backend_secret("github.com/acme/openai", "OPENAI_API_KEY")
                .as_deref(),
            Some("sk-1")
        );
        let read = next.sessions();
        for (i, grantee) in grantees().into_iter().enumerate() {
            let meta = read.get(&format!("token-{i}")).expect("the token survives");
            assert_eq!(meta.app_name, "secrets-test");
            assert_eq!(meta.grantee, grantee);
        }
    }

    #[test]
    fn the_file_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        Secrets::at(path.clone())
            .unwrap()
            .set_backend_secret("src", "KEY", "v")
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_deleted_secret_is_gone_and_deleting_twice_is_fine() {
        let secrets = Secrets::in_memory();
        secrets.set_backend_secret("src", "KEY", "v").unwrap();
        assert!(secrets.has_backend_secret("src", "KEY"));
        secrets.delete_backend_secret("src", "KEY").unwrap();
        assert!(!secrets.has_backend_secret("src", "KEY"));
        secrets.delete_backend_secret("src", "KEY").unwrap();
    }

    /// No file yet is the first start: no secrets, and nothing written until
    /// the first change.
    #[test]
    fn no_file_is_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let secrets = Secrets::at(path.clone()).unwrap();
        assert!(secrets.sessions().is_empty());
        assert!(!path.exists());
    }

    /// A file that does not parse is kept, beside the new one, rather than
    /// replaced by the first write.
    #[test]
    fn a_file_that_does_not_parse_is_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(&path, "(sessions: {").unwrap();

        let secrets = Secrets::at(path.clone()).unwrap();
        assert!(secrets.sessions().is_empty());
        assert!(!path.exists());
        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(aside.len(), 1);
        assert!(aside[0].starts_with("secrets.ron.unreadable-"), "{aside:?}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(&aside[0])).unwrap(),
            "(sessions: {"
        );
    }

    /// A write that fails changes nothing, so what is in memory never runs
    /// ahead of the file.
    #[test]
    fn a_failed_write_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let secrets = Secrets::at(state.join(FILE_NAME)).unwrap();
        // Then a file takes the directory's place, so it cannot be created.
        std::fs::write(&state, b"").unwrap();
        assert!(secrets.set_backend_secret("src", "KEY", "v").is_err());
        assert!(!secrets.has_backend_secret("src", "KEY"));
    }
}
