// SPDX-License-Identifier: GPL-3.0-only
//! Who may call a daemon, and for what.
//!
//! A caller asks for a token at `POST /v1/auth/request` ([`routes`]); the
//! daemon identifies it ([`identity`]), asks the user ([`consent`]), and mints
//! a token bound to that caller and the scopes it asked for ([`tokens`]).
//! Every other route sits behind a guard ([`middleware`]) that checks the
//! token, the caller presenting it, and the scope the route needs.
//!
//! [`Auth`] holds all of it. A daemon builds one at startup, keeps it in its
//! router state, and exposes it with `axum::extract::FromRef` so the guards
//! and the auth routes can extract it.

pub mod consent;
pub mod identity;
pub mod middleware;
pub mod routes;
pub mod tokens;

use crate::keyring::Keyring;
use crate::resource_management::ResourceManager;
use consent::{ConsentDialog, ConsentLocks};
use middleware::DenyCache;
use std::sync::Arc;
use super_engine_protocol::ProductSpec;
use tokens::TokenStore;

pub use identity::{PeerIdentity, resolve_peer_identity};
pub use middleware::AuthContext;

/// The product's variable (`SUPER_STT_AUTO_APPROVE`) that, set to `1`,
/// approves every `/auth/request` without showing the consent dialog. Honored
/// only in debug builds, for tests and CI, so a stray variable cannot defeat
/// the consent gate in a shipped binary.
pub const AUTO_APPROVE: &str = "AUTO_APPROVE";

/// What a daemon passes to [`Auth::load`].
pub struct AuthConfig {
    /// The consent dialog: the product it names, and what its scopes grant.
    pub dialog: ConsentDialog,
    /// Where the session tokens persist.
    pub keyring: Keyring,
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
}

impl Auth {
    /// Load the persisted session tokens and set up an empty consent state.
    ///
    /// Blocks on the system keyring, which waits on its unlock prompt for as
    /// long as the user takes when it is locked, so run it on the blocking
    /// pool.
    ///
    /// # Errors
    /// When the system keyring is unavailable. See
    /// [`TokenStore::load_persisted`].
    pub fn load(config: AuthConfig) -> anyhow::Result<Self> {
        let tokens = TokenStore::load_persisted(config.dialog.product, config.keyring)?;
        Ok(Self::with_tokens(config, tokens))
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

    /// Whether the TCP listener admits a page from `origin`.
    #[must_use]
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        crate::http::origins::is_origin_allowed(&self.inner.allowed_origins, origin)
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
    /// Super STT's auth state with no sessions, admitting `allowed_origins`
    /// over TCP.
    pub(crate) fn for_tests(allowed_origins: &[&str]) -> Self {
        fn describe(_: &[String]) -> Vec<&'static str> {
            Vec::new()
        }
        Self::with_tokens(
            AuthConfig {
                dialog: ConsentDialog {
                    product: &super_engine_protocol::SUPER_STT,
                    describe_scopes: describe,
                },
                keyring: Keyring::in_memory(&super_engine_protocol::SUPER_STT),
                resource_manager: Arc::new(ResourceManager::new()),
                allowed_origins: allowed_origins.iter().map(ToString::to_string).collect(),
            },
            TokenStore::default(),
        )
    }
}
