// SPDX-License-Identifier: GPL-3.0-only
//! Who may call a daemon, and for what.
//!
//! A caller asks for a token at `POST /v1/auth/request` ([`routes`]); the
//! daemon identifies it ([`identity`]), asks the user ([`consent`]), and mints
//! a token bound to that caller and the scopes it asked for ([`tokens`]).
//! Every other route sits behind a guard ([`middleware`]) that checks the
//! token, the caller presenting it, and the scope the route needs.
//!
//! An AI assistant is the exception. It calls over TCP with an assistant key
//! ([`assistant_keys`]) the daemon minted when the user connected it, through
//! [`Auth::mint_assistant_key`], and never sees the consent dialog.
//!
//! [`Auth`] holds all of it. A daemon builds one at startup, keeps it in its
//! router state, and exposes it with `axum::extract::FromRef` so the guards
//! and the auth routes can extract it.

pub mod assistant_keys;
pub mod consent;
pub mod identity;
pub mod middleware;
pub mod routes;
pub mod tokens;

use crate::resource_management::ResourceManager;
use crate::secrets::{Secrets, SecretsError};
use consent::{ConsentDialog, ConsentLocks};
use middleware::DenyCache;
use std::sync::Arc;
use super_engine_protocol::ProductSpec;
use tokens::TokenStore;

pub use assistant_keys::AssistantKey;
pub use identity::{PeerIdentity, resolve_peer_identity};
pub use middleware::AuthContext;

/// The product's variable (`<PREFIX>_AUTO_APPROVE`) that, set to `1`,
/// approves every `/auth/request` without showing the consent dialog. Honored
/// only in debug builds, for tests and CI, so a stray variable cannot defeat
/// the consent gate in a shipped binary.
pub const AUTO_APPROVE: &str = "AUTO_APPROVE";

/// The product's variable (`<PREFIX>_TREAT_AS_OFFICIAL`) that, set to `1`, lets
/// every caller with a session through
/// [`require_official_client`](middleware::require_official_client) as if it
/// were one of the product's own clients. Honored only in debug builds, for
/// integration tests whose client is not installed beside the daemon, and
/// never for an assistant key, so a test can still show that an assistant is
/// refused.
pub const TREAT_AS_OFFICIAL: &str = "TREAT_AS_OFFICIAL";

/// What a daemon passes to [`Auth::load`].
pub struct AuthConfig {
    /// The consent dialog: the product it names, and what its scopes grant.
    pub dialog: ConsentDialog,
    /// Where the session tokens and assistant keys persist: the daemon's one
    /// [`Secrets`], shared with whatever else keeps secrets in it.
    pub secrets: Secrets,
    /// Counts each caller's connections and requests.
    pub resource_manager: Arc<ResourceManager>,
    /// The browser origins the TCP listener admits: the user's
    /// `[http.tcp].allowed_origins`, read once at startup.
    pub allowed_origins: Vec<String>,
}

/// A daemon's session tokens and consent state, and what its guards need to
/// check a request against them. Cheap to clone.
#[derive(Clone)]
pub struct Auth {
    inner: Arc<Inner>,
}

struct Inner {
    dialog: ConsentDialog,
    tokens: TokenStore,
    consent_locks: ConsentLocks,
    deny_cache: DenyCache,
    resource_manager: Arc<ResourceManager>,
    allowed_origins: Vec<String>,
    /// Where the product's own clients are installed, in place of the
    /// daemon's own directory, for a test that cannot put one beside the test
    /// binary.
    #[cfg(test)]
    official_dir: Option<std::path::PathBuf>,
}

impl Auth {
    /// Load the persisted session tokens and assistant keys, and set up an
    /// empty consent state. See [`TokenStore::load_persisted`].
    #[must_use]
    pub fn load(config: AuthConfig) -> Self {
        let tokens = TokenStore::load_persisted(config.secrets.clone());
        Self::with_tokens(config, tokens)
    }

    fn with_tokens(config: AuthConfig, tokens: TokenStore) -> Self {
        Self {
            inner: Arc::new(Inner {
                dialog: config.dialog,
                tokens,
                consent_locks: ConsentLocks::default(),
                deny_cache: DenyCache::default(),
                resource_manager: config.resource_manager,
                allowed_origins: config.allowed_origins,
                #[cfg(test)]
                official_dir: None,
            }),
        }
    }

    /// The product this daemon is.
    #[must_use]
    pub fn product(&self) -> &'static ProductSpec {
        self.inner.dialog.product
    }

    /// The session tokens this daemon has issued.
    #[must_use]
    pub fn tokens(&self) -> &TokenStore {
        &self.inner.tokens
    }

    /// Counts each caller's connections and requests.
    #[must_use]
    pub fn resource_manager(&self) -> &Arc<ResourceManager> {
        &self.inner.resource_manager
    }

    /// Mint an assistant key for the assistant `name`, granting `scopes`: the
    /// key's secret, to hand to the assistant, and the key.
    ///
    /// The product calls this when the user connects an assistant; nothing
    /// else mints one, and there is no route for it here. The key is in the
    /// secrets file before this returns. It never expires.
    ///
    /// # Errors
    /// When the secrets file cannot be written. No key is minted then.
    pub async fn mint_assistant_key(
        &self,
        name: &str,
        scopes: &[String],
    ) -> Result<(String, AssistantKey), SecretsError> {
        self.tokens().mint_assistant_key(name, scopes).await
    }

    /// Every assistant key, oldest first, without its secret.
    #[must_use]
    pub fn assistant_keys(&self) -> Vec<AssistantKey> {
        self.tokens().assistant_keys()
    }

    /// The secret of the assistant key `id`, or `None` when there is no such
    /// key.
    #[must_use]
    pub fn assistant_key_secret(&self, id: &str) -> Option<String> {
        self.tokens().assistant_key_secret(id)
    }

    /// Revoke the assistant key `id`, in memory and in the secrets file. It
    /// stops working at once. `false` when there was no such key.
    ///
    /// # Errors
    /// When the secrets file cannot be written. The key keeps working then.
    pub async fn revoke_assistant_key(&self, id: &str) -> Result<bool, SecretsError> {
        self.tokens().revoke_assistant_key(id).await
    }

    /// Whether the TCP listener admits a page from `origin`.
    #[must_use]
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        crate::http::origins::is_origin_allowed(&self.inner.allowed_origins, origin)
    }

    /// Whether `grantee` is one of the product's own clients, installed beside
    /// the daemon. See [`consent::is_official_client`].
    fn is_official(&self, grantee: &PeerIdentity) -> bool {
        #[cfg(test)]
        if let Some(dir) = &self.inner.official_dir {
            return consent::is_official_identity_in(self.product(), dir, grantee);
        }
        consent::is_official_client(self.product(), grantee)
    }

    fn dialog(&self) -> &ConsentDialog {
        &self.inner.dialog
    }

    fn consent_locks(&self) -> &ConsentLocks {
        &self.inner.consent_locks
    }

    fn deny_cache(&self) -> &DenyCache {
        &self.inner.deny_cache
    }
}

#[cfg(test)]
impl Auth {
    /// [`Self::for_tests`], with the product's own clients installed in
    /// `official_dir` rather than beside the test binary.
    pub(crate) fn for_tests_with_official_dir(official_dir: &std::path::Path) -> Self {
        let mut auth = Self::for_tests(&[]);
        Arc::get_mut(&mut auth.inner)
            .expect("a fresh Auth is not shared")
            .official_dir = Some(official_dir.to_path_buf());
        auth
    }

    /// The test product's auth state with no sessions, admitting
    /// `allowed_origins` over TCP.
    pub(crate) fn for_tests(allowed_origins: &[&str]) -> Self {
        fn describe(_: &[String]) -> Vec<&'static str> {
            Vec::new()
        }
        Self::with_tokens(
            AuthConfig {
                dialog: ConsentDialog {
                    product: &super_engine_protocol::test_product::TEST,
                    describe_scopes: describe,
                },
                secrets: Secrets::in_memory(),
                resource_manager: Arc::new(ResourceManager::new()),
                allowed_origins: allowed_origins.iter().map(ToString::to_string).collect(),
            },
            TokenStore::default(),
        )
    }
}
