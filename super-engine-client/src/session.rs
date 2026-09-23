// SPDX-License-Identifier: GPL-3.0-only
//! Session-token cache for HTTP-protocol clients.
//!
//! Two layers of caching, in order of priority:
//!
//! 1. **In-memory cache** (this module's `TOKEN_CACHE`). Hot path —
//!    set on the first successful `obtain` and reused for the rest of
//!    the process's lifetime. No keyring access on cache hit, which
//!    matters a lot when a long-lived widget reconnects in a tight
//!    loop while the daemon is down.
//! 2. **System keyring** (libsecret/KWallet). Cold-start persistence
//!    — read once on first `obtain` to recover a token from a previous
//!    process run. Best-effort write whenever a fresh token is minted.
//!
//! Each app gets its own keyring "user" (see [`keyring_account`]) so they
//! don't overwrite each other's tokens, in the keyring service of the product
//! it is talking to, so an app that talks to both daemons keeps a token for
//! each. The storage value is a [`Stored`] record: the bearer string and the
//! scopes it was minted for. Expiry lives server-side and the daemon returns
//! `invalid_session` if the client presents a stale token.

use crate::http_client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use super_engine_protocol::ProductSpec;
use tokio::sync::Mutex as AsyncMutex;

/// A stored session token and the scope set it was minted for.
///
/// The scopes are here because a bare token cannot answer the question that
/// matters at reuse time: *is this token good for what I am about to do?* A
/// client that grows a feature grows its scope list, and users still holding a
/// token from the version before would otherwise present it forever — every
/// call on the new route answered `403 scope_denied`, and nothing in the
/// cascade below ever replacing it. That is not hypothetical; it is what
/// happened when a settings app added a new library of its own.
///
/// `requested` is what decides reuse, not `granted`: if the user was asked for
/// a scope and declined it, asking again on the next call would raise a consent
/// popup per request. `granted` is kept so a refusal can be explained rather
/// than merely retried.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    token: String,
    /// The scope set this token was requested with.
    #[serde(default)]
    requested: Vec<String>,
    /// The scope set the daemon actually granted, which may be narrower.
    #[serde(default)]
    granted: Vec<String>,
}

impl Stored {
    /// Whether this token was minted for a request covering every scope in
    /// `needed`.
    fn covers(&self, needed: &[&str]) -> bool {
        needed.iter().all(|n| self.requested.iter().any(|r| r == n))
    }

    /// Read a keyring value, which is JSON for anything this version wrote and
    /// a bare token for anything an older one did.
    ///
    /// A bare token records no scopes, so it covers nothing and is replaced on
    /// the next `obtain` — which is exactly the repair an existing install
    /// needs, without anyone having to clear a keyring entry by hand.
    fn parse(raw: &str) -> Self {
        serde_json::from_str(raw).unwrap_or_else(|_| Self {
            token: raw.to_string(),
            requested: Vec::new(),
            granted: Vec::new(),
        })
    }
}

/// Which app is asking, and which product's daemon it is asking.
#[derive(Clone, Copy, Debug)]
pub struct AppId {
    /// The product whose daemon issues the token. Its keyring service
    /// ([`ProductSpec::session_keyring_service`]) is where the token is kept.
    pub product: &'static ProductSpec,
    /// A stable string that uniquely identifies the app (e.g. `"<slug>-cli"`,
    /// `"<slug>-app"`): the keyring "user" the token is stored under.
    pub name: &'static str,
}

impl AppId {
    /// `name`, talking to `product`'s daemon.
    #[must_use]
    pub const fn new(product: &'static ProductSpec, name: &'static str) -> Self {
        Self { product, name }
    }

    /// The key this app's lock and cached token live under in this process.
    /// The product is part of it, so an app talking to both daemons holds a
    /// token for each.
    fn key(self) -> (&'static str, &'static str) {
        (self.product.slug, self.name)
    }
}

type AppKey = (&'static str, &'static str);
type ObtainLock = Arc<AsyncMutex<()>>;
type ObtainLockMap = StdMutex<HashMap<AppKey, ObtainLock>>;

/// Per-`AppId` async mutex registry. Ensures at most one
/// `auth_request` flight is in progress per app at any time so parallel
/// callers (e.g. the settings app's batch of 6 startup GETs) can't each
/// independently spawn a consent popup. Held across the `auth_request`
/// await; tokens cached in the keyring after the first caller wins, so
/// subsequent callers double-check `load()` and skip the network entirely.
static OBTAIN_LOCKS: LazyLock<ObtainLockMap> = LazyLock::new(|| StdMutex::new(HashMap::new()));

fn lock_for(app_id: AppId) -> ObtainLock {
    let mut map = OBTAIN_LOCKS.lock().unwrap();
    map.entry(app_id.key())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

/// In-process token cache. Populated on every successful `obtain`,
/// consulted before any keyring access. This is what lets a tight
/// reconnect loop (e.g. while the daemon is down) avoid hammering the
/// keyring. Cleared by `forget`.
static TOKEN_CACHE: LazyLock<StdMutex<HashMap<AppKey, Stored>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

fn cache_get(app_id: AppId) -> Option<Stored> {
    TOKEN_CACHE.lock().unwrap().get(&app_id.key()).cloned()
}

fn cache_set(app_id: AppId, stored: Stored) {
    TOKEN_CACHE.lock().unwrap().insert(app_id.key(), stored);
}

fn cache_clear(app_id: AppId) {
    TOKEN_CACHE.lock().unwrap().remove(&app_id.key());
}

/// When `product`'s `<PREFIX>_KEYRING_MOCK` is set,
/// route all client-side keyring access (the session-token store this module
/// manages) to an in-memory mock instead of the system secret service.
///
/// This is the client-side twin of the daemon's
/// `install_mock_if_requested`: the CLI / settings app / applet reach the
/// keyring through this module's `load`/`save`/`forget`, and an automated
/// shell or CI run has no unlocked secret service — touching the real one
/// there blocks on an unlock prompt or fails. Call this once at process
/// startup, before any keyring access, as it sets the process-wide default
/// credential builder. A client of both products calls it for each: either
/// variable set is a request for the mock.
pub fn install_mock_keyring_if_requested(product: &ProductSpec) {
    if std::env::var_os(product.env("KEYRING_MOCK")).is_some() {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    }
}

/// The keyring "user" this process stores its token under: the [`AppId`],
/// plus the sandbox it is running in when there is one.
///
/// The bare `AppId` is shared by every build of an app, so a native install
/// and a flatpak of the same app read and write one entry. The daemon binds
/// each token to the caller it granted it to, so the token one of them stored
/// is rejected for the other: with a single shared entry the two take turns
/// invalidating each other, and every alternation costs the user a fresh
/// consent popup. Scoping the account by install keeps them apart. A native
/// install keeps the plain `AppId`, so nothing already stored moves.
fn keyring_account(app_id: AppId) -> String {
    match super_engine_protocol::sandbox::own_app_id() {
        Some(sandbox_id) => format!("{}@flatpak:{sandbox_id}", app_id.name),
        None => app_id.name.to_string(),
    }
}

/// The keyring entry `app_id`'s token lives in: the product's session
/// service, under this install's account.
fn keyring_entry(app_id: AppId) -> keyring::Result<keyring::Entry> {
    keyring::Entry::new(
        &app_id.product.session_keyring_service(),
        &keyring_account(app_id),
    )
}

/// Read the stored token for `app_id`, or None if nothing is stored.
fn load_stored(app_id: AppId) -> Option<Stored> {
    let entry = keyring_entry(app_id).ok()?;
    entry.get_password().ok().map(|raw| Stored::parse(&raw))
}

/// Read the cached token for `app_id`, or None if no token is stored.
///
/// The scopes it was minted for are not returned; [`obtain`] is what needs
/// them, and it reads the record directly.
#[must_use]
pub fn load(app_id: AppId) -> Option<String> {
    load_stored(app_id).map(|s| s.token)
}

/// Persist a token for `app_id`, with the scopes it was `requested` with and
/// the ones the daemon `granted`, to both the in-memory cache and the system
/// keyring. Replaces any previous value. The in-memory side always succeeds;
/// the keyring write is best-effort and its failure is reported via the return
/// value (callers in this module ignore it because the in-memory cache is the
/// source of truth at runtime).
///
/// `requested` is what a later [`obtain`] checks its needs against, so passing
/// a set narrower than the token really covers costs an extra consent popup,
/// and passing a wider one brings back the `scope_denied` dead end this record
/// exists to prevent.
///
/// # Errors
/// Returns an error if the keyring is unavailable or the write fails.
pub fn save(
    app_id: AppId,
    token: &str,
    requested: &[&str],
    granted: &[String],
) -> Result<(), String> {
    let stored = Stored {
        token: token.to_string(),
        requested: requested.iter().map(|s| (*s).to_string()).collect(),
        granted: granted.to_vec(),
    };
    cache_set(app_id, stored.clone());
    let value = serde_json::to_string(&stored)
        .map_err(|e| format!("encoding the session record failed: {e}"))?;
    let entry = keyring_entry(app_id).map_err(|e| format!("keyring access failed: {e}"))?;
    entry
        .set_password(&value)
        .map_err(|e| format!("keyring write failed: {e}"))?;
    Ok(())
}

/// Forget the cached token for `app_id` (both in-memory and the
/// keyring). Idempotent — succeeds even if nothing was stored.
///
/// # Errors
/// Returns an error if the keyring is unavailable.
pub fn forget(app_id: AppId) -> Result<(), String> {
    cache_clear(app_id);
    let entry = keyring_entry(app_id).map_err(|e| format!("keyring access failed: {e}"))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("keyring delete failed: {e}")),
    }
}

/// Get a usable session token for `app_id`. Cascades through three
/// layers, in order:
///
/// 1. **In-memory cache.** Hot path; no I/O, no keyring access.
/// 2. **System keyring.** Cold path on first call after a process
///    start. Populates the in-memory cache on success.
/// 3. **`auth_request`.** Triggers the libcosmic consent popup. Stores
///    the resulting token in both the cache and the keyring (the
///    keyring write is best-effort — if it fails the in-memory cache
///    still keeps the token alive for the rest of the process).
///
/// Concurrency-safe: parallel callers for the same `app_id` are
/// serialized through a per-`AppId` async mutex (double-checked
/// locking against the cache + keyring), so at most one consent popup
/// is ever spawned even when the settings app fires its startup batch
/// of six settings GETs in parallel.
///
/// # Errors
/// Returns an error if `auth_request` fails (user denied, popup
/// dismissed, daemon unreachable, etc.). Keyring write failures are
/// silently absorbed (the token remains usable for this process).
pub async fn obtain(
    socket_path: PathBuf,
    app_id: AppId,
    app_name: &str,
    scopes: &[&str],
) -> http_client::HttpResult<String> {
    // 1. In-memory cache hit — no keyring access, no I/O.
    if let Some(t) = usable(cache_get(app_id), scopes) {
        return Ok(t);
    }

    // 2. Keyring read (one-time per process per AppId, populates the
    //    in-memory cache for subsequent calls).
    if let Some(stored) = load_stored(app_id) {
        if stored.covers(scopes) {
            cache_set(app_id, stored.clone());
            return Ok(stored.token);
        }
        log::info!(
            "the stored session token was minted for {:?} and this needs {scopes:?}; \
             asking for consent again",
            stored.requested
        );
    }

    // 3. Slow path: serialize concurrent first-time obtains so we
    //    don't fire N parallel consent popups.
    let app_lock = lock_for(app_id);
    let _guard = app_lock.lock().await;

    // Re-check after acquiring the lock: another task may have
    // already minted a token while we were waiting.
    if let Some(t) = usable(cache_get(app_id), scopes) {
        return Ok(t);
    }
    if let Some(stored) = load_stored(app_id).filter(|s| s.covers(scopes)) {
        cache_set(app_id, stored.clone());
        return Ok(stored.token);
    }

    let auth = http_client::auth_request(socket_path, app_name, scopes).await?;
    // `save` updates both in-memory cache and keyring; we ignore the
    // keyring half's error so a locked / denied keyring doesn't break
    // the working session.
    let _ = save(app_id, &auth.session_token, scopes, &auth.scopes);
    Ok(auth.session_token)
}

/// The token out of a stored record, if that record covers `scopes`.
fn usable(stored: Option<Stored>, scopes: &[&str]) -> Option<String> {
    stored.filter(|s| s.covers(scopes)).map(|s| s.token)
}

/// Run `op` with the cached or freshly-minted token. On
/// [`HttpError::InvalidSession`] from the daemon, drops the cached
/// token and retries `op` once with a fresh consent flow.
///
/// `op` returns [`http_client::HttpResult`], so the retry decision is the
/// typed [`HttpError::is_invalid_session`] rather than a match on the error's
/// wording. Callers that want a plain string for UI toasts convert at their own
/// boundary (`HttpError: Display`, and `From<HttpError> for String`).
///
/// # Errors
/// Returns the underlying [`HttpError`] if `op` fails for any non-auth reason
/// or if re-auth fails.
pub async fn with_token<F, Fut, T>(
    socket_path: PathBuf,
    app_id: AppId,
    app_name: &str,
    scopes: &[&str],
    op: F,
) -> http_client::HttpResult<T>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = http_client::HttpResult<T>>,
{
    let token = obtain(socket_path.clone(), app_id, app_name, scopes).await?;
    match op(token).await {
        Ok(v) => Ok(v),
        Err(e) if e.is_invalid_session() || e.is_scope_denied() => {
            // Token rejected — drop cache, re-auth, retry once. The retry
            // decision is the typed `HttpError`, not a match on the error's
            // wording.
            //
            // `scope_denied` retries for the same reason `invalid_session`
            // does: the token in hand cannot do the job and a fresh one asked
            // for the right scopes might. It is the backstop for a record
            // `obtain` could not check — one written by an older version, or a
            // scope the daemon stopped honoring. When the user simply declined
            // the scope, the second attempt fails too, and the daemon's own
            // denial cache is what keeps that from becoming a popup per call.
            let _ = forget(app_id);
            let token = obtain(socket_path, app_id, app_name, scopes).await?;
            op(token).await
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super_engine_protocol::test_product::{OTHER, TEST};

    /// A record as `save` would write it: minted for exactly these scopes and
    /// granted all of them.
    fn stored(token: &str, scopes: &[&str]) -> Stored {
        Stored {
            token: token.to_string(),
            requested: scopes.iter().map(|s| (*s).to_string()).collect(),
            granted: scopes.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Verify that once a token is in the in-memory cache, `obtain`
    /// returns it without touching the keyring or the network. We
    /// pass a bogus socket path that would fail if `obtain` fell
    /// through to `auth_request`.
    #[tokio::test]
    async fn obtain_returns_from_cache_without_network() {
        let app_id = AppId::new(&TEST, "test-cache-hit");
        // Manually pre-populate the cache.
        cache_set(app_id, stored("TOK-from-cache", &["test"]));

        let bogus_socket = PathBuf::from("/nonexistent/super-test/socket");
        let result = obtain(bogus_socket, app_id, "Test", &["test"]).await;

        // Cleanup before asserting (in case the assert panics, the
        // global cache stays clean for sibling tests).
        cache_clear(app_id);

        assert_eq!(result.expect("cache hit should succeed"), "TOK-from-cache");
    }

    /// Verify the in-memory cache primitives round-trip cleanly. We
    /// don't exercise `forget`/`save` directly here because both
    /// touch the real system keyring, and a unit test under a locked
    /// keyring would hang on the unlock prompt. The `forget` and
    /// `save` functions invoke `cache_clear` and `cache_set`
    /// respectively as their first action, so a working cache layer
    /// is the necessary-and-sufficient ingredient.
    #[test]
    fn cache_set_get_clear_round_trip() {
        let app_id = AppId::new(&TEST, "test-cache-roundtrip");
        cache_clear(app_id);
        assert!(cache_get(app_id).is_none(), "fresh slot must be empty");

        cache_set(app_id, stored("TOK-a", &["test"]));
        assert_eq!(
            cache_get(app_id).map(|s| s.token),
            Some("TOK-a".to_string())
        );

        // Replace.
        cache_set(app_id, stored("TOK-b", &["test"]));
        assert_eq!(
            cache_get(app_id).map(|s| s.token),
            Some("TOK-b".to_string())
        );

        cache_clear(app_id);
        assert!(cache_get(app_id).is_none(), "clear must drop the entry");
    }

    /// The drift this record exists to catch: a token minted before the client
    /// grew a scope must not be reused for a call that needs it. Reusing it is
    /// how `403 scope_denied` becomes permanent — nothing else in `obtain`
    /// would ever replace it.
    #[test]
    fn a_token_minted_for_fewer_scopes_is_not_reused() {
        let token = stored("TOK", &["settings", "test"]);
        assert!(token.covers(&["settings"]));
        assert!(token.covers(&["settings", "test"]));
        assert!(!token.covers(&["settings", "test_events"]));
        assert!(!token.covers(&["test_events"]));
    }

    /// Coverage is decided by what was *asked for*, not by what came back. A
    /// user who declines a scope has answered the question, and asking again on
    /// every call would raise a consent popup per request.
    #[test]
    fn a_declined_scope_does_not_re_ask_on_every_call() {
        let declined = Stored {
            token: "TOK".to_string(),
            requested: vec!["settings".to_string(), "test_events".to_string()],
            granted: vec!["settings".to_string()],
        };
        assert!(declined.covers(&["settings", "test_events"]));
    }

    /// An entry written before this record existed is a bare token. It covers
    /// nothing, so the next `obtain` replaces it — which is the repair an
    /// installed app needs without anyone clearing a keyring entry by hand.
    #[test]
    fn a_legacy_bare_token_is_replaced_rather_than_presented() {
        let legacy = Stored::parse("TOK-from-an-older-build");
        assert_eq!(legacy.token, "TOK-from-an-older-build");
        assert!(legacy.requested.is_empty());
        assert!(!legacy.covers(&["settings"]));
        // Nothing is asked of a caller that needs nothing, so an empty need is
        // still covered — `obtain` with no scopes has nothing to re-ask for.
        assert!(legacy.covers(&[]));
    }

    /// What `save` writes, `parse` reads back.
    #[test]
    fn a_stored_record_round_trips_through_its_json() {
        let original = stored("TOK", &["settings", "test_events"]);
        let raw = serde_json::to_string(&original).expect("a record must encode");
        let parsed = Stored::parse(&raw);
        assert_eq!(parsed.token, "TOK");
        assert!(parsed.covers(&["settings", "test_events"]));
    }

    /// One app talking to both daemons holds a token for each: the product is
    /// part of the key, so caching one never hands it to the other.
    #[test]
    fn one_app_keeps_a_token_per_product() {
        let test = AppId::new(&TEST, "test-two-products");
        let other = AppId::new(&OTHER, "test-two-products");
        cache_set(test, stored("TOK-test", &["test"]));
        cache_set(other, stored("TOK-other", &["other"]));

        let (from_test, from_other) = (
            cache_get(test).map(|s| s.token),
            cache_get(other).map(|s| s.token),
        );
        cache_clear(test);
        let after_clear = cache_get(other).map(|s| s.token);
        cache_clear(other);

        assert_eq!(from_test.as_deref(), Some("TOK-test"));
        assert_eq!(from_other.as_deref(), Some("TOK-other"));
        assert_eq!(
            after_clear.as_deref(),
            Some("TOK-other"),
            "forgetting one product's token must leave the other's"
        );
    }
}
