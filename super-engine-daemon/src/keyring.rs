// SPDX-License-Identifier: GPL-3.0-only
//! Secure secret storage using the system keyring (e.g. GNOME Keyring, `KWallet`).
//!
//! Everything lives under the product's service name (`super-stt`,
//! `super-tts`). Backend secrets are stored under per-backend accounts
//! `backend:<source>:<name>` (written by the settings app, read at model
//! load), which keeps them out of config files entirely.
//!
//! The same service also holds the daemon's HTTP session map, under
//! `<short name>-sessions` (`stt-sessions`, `tts-sessions`) — see
//! [`TokenStore`](crate::auth::tokens::TokenStore) and
//! [`Keyring::get_sessions_blob`].

use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use super_engine_protocol::ProductSpec;

/// Errors from keyring access. Every variant's `Display` carries the account
/// and the underlying cause.
#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    /// Opening, reading, writing, or deleting a system-keyring entry failed.
    #[error("keyring access failed for {account}: {source}")]
    Backend {
        account: String,
        #[source]
        source: keyring::Error,
    },
    /// The `spawn_blocking` keyring task panicked or was cancelled.
    #[error("keyring task failed: {0}")]
    Task(String),
}

impl KeyringError {
    fn backend(account: &str, source: keyring::Error) -> Self {
        Self::Backend {
            account: account.to_string(),
            source,
        }
    }
}

/// Keyring account for a backend secret: `backend:<source>:<name>`, where
/// `source` is the backend's repo id (e.g. `github.com/super-stt/openai`).
/// This is the generic per-backend secret store the settings app writes to.
#[must_use]
fn backend_secret_account(source: &str, name: &str) -> String {
    format!("backend:{source}:{name}")
}

/// Process-global in-memory secret store, used in place of the system keyring
/// by [`Keyring::in_memory`] and when the product's `KEYRING_MOCK` variable is
/// set.
///
/// The `keyring` crate's mock backend returns a fresh, isolated credential per
/// `Entry::new`, so a set-then-read round-trip across separate calls cannot
/// share state — which makes the real secret behavior untestable headlessly.
/// This map gives secret access stable, process-wide persistence in tests (CI
/// is headless; touching the real secret service hangs on an unlock prompt)
/// while leaving production behavior on the real keyring untouched.
///
/// The map lives for the whole process, so tests sharing it must use unique
/// account keys to avoid collisions.
fn mock_store() -> &'static Mutex<HashMap<String, String>> {
    static STORE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether the product's `KEYRING_MOCK` variable (`SUPER_STT_KEYRING_MOCK`)
/// requests the in-memory store. Honored only in debug builds (tests / CI); a
/// release binary ignores the variable entirely, so a stray or injected one
/// can't reroute every backend API key and the session store into a
/// non-persistent, unencrypted in-process map (audit 2 Tier 1 #6).
#[cfg(debug_assertions)]
fn keyring_mock_env_set(product: &ProductSpec) -> bool {
    std::env::var_os(product.env("KEYRING_MOCK")).is_some()
}

#[cfg(not(debug_assertions))]
fn keyring_mock_env_set(_: &ProductSpec) -> bool {
    false
}

/// One product's secrets: the system keyring under the product's service
/// name, or the in-process store tests use instead.
#[derive(Clone, Copy, Debug)]
pub struct Keyring {
    product: &'static ProductSpec,
    in_memory: bool,
}

impl Keyring {
    /// The system keyring, unless the product's `KEYRING_MOCK` variable asks
    /// for the in-memory store (debug builds only).
    #[must_use]
    pub fn system(product: &'static ProductSpec) -> Self {
        Self {
            product,
            in_memory: cfg!(test) || keyring_mock_env_set(product),
        }
    }

    /// The process-global in-memory store, never the system keyring. For a
    /// daemon's own unit tests, which must not touch the developer's secrets.
    #[must_use]
    pub fn in_memory(product: &'static ProductSpec) -> Self {
        Self {
            product,
            in_memory: true,
        }
    }

    /// The keyring account holding the daemon's HTTP session map, e.g.
    /// `stt-sessions`. See [`TokenStore`](crate::auth::tokens::TokenStore) for
    /// the schema. The map is a single secret rather than one entry per session
    /// because the `keyring` crate doesn't expose enumeration — keeping the
    /// whole map under one key turns bootstrap into a single `get_password`
    /// and mutations into a single `set_password`.
    #[must_use]
    pub fn sessions_account(&self) -> String {
        format!("{}-sessions", self.product.short_name)
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry, KeyringError> {
        keyring::Entry::new(self.product.slug, account)
            .map_err(|e| KeyringError::backend(account, e))
    }

    /// Read one account.
    fn get(&self, account: &str) -> Result<Option<String>, KeyringError> {
        if self.in_memory {
            return Ok(mock_store()
                .lock()
                .expect("mock keyring store poisoned")
                .get(account)
                .cloned());
        }
        match self.entry(account)?.get_password() {
            Ok(p) => Ok(Some(p)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(KeyringError::backend(account, e)),
        }
    }

    /// Write one account.
    fn set(&self, account: &str, value: &str) -> Result<(), KeyringError> {
        if self.in_memory {
            mock_store()
                .lock()
                .expect("mock keyring store poisoned")
                .insert(account.to_string(), value.to_string());
            return Ok(());
        }
        self.entry(account)?
            .set_password(value)
            .map_err(|e| KeyringError::backend(account, e))
    }

    /// Delete one account; absent is success.
    fn delete(&self, account: &str) -> Result<(), KeyringError> {
        if self.in_memory {
            mock_store()
                .lock()
                .expect("mock keyring store poisoned")
                .remove(account);
            return Ok(());
        }
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(KeyringError::backend(account, e)),
        }
    }

    /// Read a backend secret (e.g. `OPENAI_API_KEY` for a given backend).
    /// Returns `Ok(None)` if not set.
    ///
    /// # Errors
    ///
    /// Returns an error if the keyring is unavailable or access fails.
    pub fn get_backend_secret(
        &self,
        source: &str,
        name: &str,
    ) -> Result<Option<String>, KeyringError> {
        let account = backend_secret_account(source, name);
        self.get(&account).map_err(|e| {
            warn!("Failed to read backend secret {name} ({account}): {e}");
            e
        })
    }

    /// Store (or replace) a backend secret.
    ///
    /// # Errors
    /// Returns an error if the keyring is unavailable or the write fails.
    pub fn set_backend_secret(
        &self,
        source: &str,
        name: &str,
        value: &str,
    ) -> Result<(), KeyringError> {
        self.set(&backend_secret_account(source, name), value)
    }

    /// Delete a stored backend secret. Missing entries are treated as success.
    ///
    /// # Errors
    /// Returns an error if the keyring is unavailable or the delete fails.
    pub fn delete_backend_secret(&self, source: &str, name: &str) -> Result<(), KeyringError> {
        self.delete(&backend_secret_account(source, name))
    }

    /// Whether a backend secret currently has a stored value.
    ///
    /// # Errors
    /// Returns an error if the keyring is unavailable or access fails.
    pub fn has_backend_secret(&self, source: &str, name: &str) -> Result<bool, KeyringError> {
        Ok(self.get(&backend_secret_account(source, name))?.is_some())
    }

    // Async wrappers for the backend-secret accessors. A keyring lookup goes
    // through DBus to the secret service and can stall for seconds on a locked
    // keyring; the sync forms above are called from async request handlers, so
    // route them through `spawn_blocking` to keep those calls off the async
    // runtime (Tier 3 #4).

    /// Async form of [`Self::get_backend_secret`], run on a blocking thread.
    ///
    /// # Errors
    /// Returns an error if the keyring is unavailable or access fails.
    pub async fn get_backend_secret_async(
        self,
        source: String,
        name: String,
    ) -> Result<Option<String>, KeyringError> {
        tokio::task::spawn_blocking(move || self.get_backend_secret(&source, &name))
            .await
            .map_err(|e| KeyringError::Task(e.to_string()))?
    }

    /// Async form of [`Self::set_backend_secret`], run on a blocking thread.
    ///
    /// # Errors
    /// Returns an error if the keyring is unavailable or the write fails.
    pub async fn set_backend_secret_async(
        self,
        source: String,
        name: String,
        value: String,
    ) -> Result<(), KeyringError> {
        tokio::task::spawn_blocking(move || self.set_backend_secret(&source, &name, &value))
            .await
            .map_err(|e| KeyringError::Task(e.to_string()))?
    }

    /// Async form of [`Self::delete_backend_secret`], run on a blocking thread.
    ///
    /// # Errors
    /// Returns an error if the keyring is unavailable or the delete fails.
    pub async fn delete_backend_secret_async(
        self,
        source: String,
        name: String,
    ) -> Result<(), KeyringError> {
        tokio::task::spawn_blocking(move || self.delete_backend_secret(&source, &name))
            .await
            .map_err(|e| KeyringError::Task(e.to_string()))?
    }

    /// Async form of [`Self::has_backend_secret`], run on a blocking thread.
    ///
    /// # Errors
    /// Returns an error if the keyring is unavailable or access fails.
    pub async fn has_backend_secret_async(
        self,
        source: String,
        name: String,
    ) -> Result<bool, KeyringError> {
        tokio::task::spawn_blocking(move || self.has_backend_secret(&source, &name))
            .await
            .map_err(|e| KeyringError::Task(e.to_string()))?
    }

    /// Read the daemon's persisted HTTP session blob.
    ///
    /// Returns `Ok(None)` if the entry doesn't exist yet (first run / fresh
    /// install). The caller is responsible for parsing the JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the keyring is unavailable or access fails.
    pub fn get_sessions_blob(&self) -> Result<Option<String>, KeyringError> {
        // Surface the read before it happens: on a *locked* keyring this call
        // blocks on the secret-service unlock prompt, potentially for a long
        // time. Logging first means a stalled startup is explained in the
        // journal ("waiting on keyring unlock") instead of looking like a
        // silent hang.
        info!(
            "Reading the persisted session store from the system keyring; if the keyring \
             is locked, the daemon will wait here until it is unlocked"
        );
        match self.get(&self.sessions_account()) {
            Ok(Some(blob)) => {
                debug!("Loaded persisted session blob from keyring");
                Ok(Some(blob))
            }
            Ok(None) => {
                debug!("No persisted session blob in keyring (fresh install)");
                Ok(None)
            }
            Err(e) => {
                warn!("Failed to read session blob from keyring: {e}");
                Err(e)
            }
        }
    }

    /// Write the daemon's HTTP session blob. The value is the JSON-serialized
    /// full sessions map; passing an empty map clears previously-stored
    /// sessions.
    ///
    /// # Errors
    ///
    /// Returns an error if the keyring is unavailable or the write fails.
    pub fn set_sessions_blob(&self, value: &str) -> Result<(), KeyringError> {
        self.set(&self.sessions_account(), value)?;
        debug!("Persisted session blob to keyring");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Keyring;
    use super_engine_protocol::{SUPER_STT, SUPER_TTS};

    /// Round-trips a backend secret through the in-memory store. Uses a unique
    /// account so it cannot collide with other tests sharing the process-global
    /// store.
    #[test]
    fn set_then_has_then_delete_roundtrips() {
        let keyring = Keyring::in_memory(&SUPER_STT);
        let (src, name) = ("github.com/acme/phase-a", "roundtrip_api_key");
        let _ = keyring.delete_backend_secret(src, name); // clean slate
        assert!(!keyring.has_backend_secret(src, name).unwrap());
        keyring.set_backend_secret(src, name, "sk-123").unwrap();
        assert!(keyring.has_backend_secret(src, name).unwrap());
        keyring.delete_backend_secret(src, name).unwrap();
        assert!(!keyring.has_backend_secret(src, name).unwrap());
        keyring.delete_backend_secret(src, name).unwrap(); // idempotent
    }

    #[test]
    fn sessions_blob_roundtrips() {
        let keyring = Keyring::in_memory(&SUPER_TTS);
        let blob = r#"{"version":3,"sessions":{}}"#;
        keyring.set_sessions_blob(blob).unwrap();
        assert_eq!(keyring.get_sessions_blob().unwrap().as_deref(), Some(blob));
    }

    /// The accounts are the ones each product shipped with. A change here
    /// strands every installed daemon's sessions under an account it no longer
    /// reads, and every client faces a fresh consent popup.
    #[test]
    fn the_sessions_account_is_the_one_each_product_shipped() {
        assert_eq!(
            Keyring::in_memory(&SUPER_STT).sessions_account(),
            "stt-sessions"
        );
        assert_eq!(
            Keyring::in_memory(&SUPER_TTS).sessions_account(),
            "tts-sessions"
        );
    }
}
