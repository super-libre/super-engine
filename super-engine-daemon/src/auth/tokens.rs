// SPDX-License-Identifier: GPL-3.0-only
//! The session tokens a daemon has issued, and their copy in the secrets file.

use crate::auth::identity::PeerIdentity;
use crate::secrets::Secrets;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use log::{info, warn};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// A signal to the single-writer persist task. The sessions snapshot itself is
/// NOT carried here — it lives in the [`SessionPersister`]'s capacity-1
/// latest-wins mailbox, so a burst of mutations while a write is in flight
/// can't queue full-map clones (audit 2 Tier 3 #7). These messages are tiny.
// `Flush`'s field is only read in `persist_loop` (`#[cfg(not(test))]`), but the
// constructor compiles under test too, so it reads as dead code there.
#[cfg_attr(test, allow(dead_code))]
enum PersistMsg {
    /// A snapshot is pending in the mailbox; drain and write it.
    Wake,
    /// Write the latest pending snapshot, then signal completion via the oneshot.
    /// The shutdown path uses this so a token minted or revoked in the final
    /// moments is durably written before `process::exit` skips the task (audit 2
    /// Tier 1 #5).
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Process-global handle to the live persist task's channel. Registered when the
/// single production `TokenStore` is created ([`SessionPersister::spawn`], only
/// in non-test builds). [`flush_persisted_sessions`] uses it to drain queued
/// writes on shutdown. `None` in `cargo test` builds (no task is spawned) and
/// until the production store exists.
static PERSIST_FLUSH: std::sync::OnceLock<mpsc::UnboundedSender<PersistMsg>> =
    std::sync::OnceLock::new();

/// Drain any queued session snapshots to the secrets file before the daemon
/// exits.
///
/// The persist task is fire-and-forget; the shutdown path's `process::exit`
/// would otherwise skip it, losing a token minted or revoked in the sub-second
/// window before shutdown (audit 2 Tier 1 #5). Bounded by `timeout` so a
/// stalled write can't hang shutdown indefinitely.
pub async fn flush_persisted_sessions(timeout: Duration) {
    let Some(tx) = PERSIST_FLUSH.get() else {
        return; // no production persist task (test build, or store never created)
    };
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    if tx.send(PersistMsg::Flush(ack_tx)).is_err() {
        return; // persist task already ended
    }
    match tokio::time::timeout(timeout, ack_rx).await {
        Ok(Ok(())) => info!("Session store flushed to the secrets file on shutdown"),
        Ok(Err(_)) => {} // ack sender dropped: task ended without acking
        Err(_) => warn!(
            "Session-store flush timed out after {}s on shutdown; queued writes may be lost",
            timeout.as_secs()
        ),
    }
}

/// Single-writer handle for persisting the sessions map to the secrets file.
///
/// `mint`/`revoke`/`validate` are sync fns called from async request handlers;
/// writing the whole file inline blocks a runtime worker on an `fsync`, and two
/// concurrent mutations dropping their `Mutex` guard before writing
/// would race the on-disk order. Funnelling every snapshot through one task over
/// this channel keeps the blocking write off the request path *and* serializes
/// the writes so the last submitted snapshot is the last one written (audit
/// Tier 3 #35). Callers submit under the in-memory lock so channel order matches
/// lock order (audit 2 Tier 1 #4). The snapshot rides in a capacity-1 latest-wins
/// mailbox (`pending`) rather than the channel, so a slow write can't back up a
/// queue of full-map clones (audit 2 Tier 3 #7).
#[derive(Clone)]
pub(crate) struct SessionPersister {
    /// Capacity-1, latest-wins mailbox holding the not-yet-written snapshot.
    /// Older snapshots are strict subsets of the newest, so replacing is safe.
    pending: Arc<Mutex<Option<HashMap<String, TokenMeta>>>>,
    /// Tiny wake/flush signals (no snapshot payload).
    tx: mpsc::UnboundedSender<PersistMsg>,
}

impl SessionPersister {
    /// Spawn the single-writer persist task and return a submit handle. In
    /// `cargo test` builds no task is spawned; submissions become no-ops as the
    /// receiver is dropped.
    #[cfg_attr(test, allow(unused_variables))]
    fn spawn(secrets: Secrets) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<PersistMsg>();
        let pending: Arc<Mutex<Option<HashMap<String, TokenMeta>>>> = Arc::new(Mutex::new(None));
        #[cfg(not(test))]
        {
            tokio::spawn(persist_loop(rx, Arc::clone(&pending), secrets));
            // Register the first (production) persister so the shutdown path can
            // drain it. Production creates exactly one `TokenStore` (AppState's);
            // any later store keeps its own channel but won't be flushed.
            let _ = PERSIST_FLUSH.set(tx.clone());
        }
        #[cfg(test)]
        drop(rx);
        Self { pending, tx }
    }

    /// Submit the latest sessions snapshot for persistence. Replaces any
    /// not-yet-written snapshot in the capacity-1 mailbox (latest wins) and
    /// signals the task only on the empty→pending transition, so at most one wake
    /// is ever in flight (audit 2 Tier 3 #7). Best-effort: a closed channel (test
    /// builds) just means the write is skipped — the in-memory map stays
    /// authoritative.
    fn submit(&self, snapshot: HashMap<String, TokenMeta>) {
        let newly_pending = {
            let mut slot = self.pending.lock().unwrap();
            let was_empty = slot.is_none();
            *slot = Some(snapshot);
            was_empty
        };
        if newly_pending {
            let _ = self.tx.send(PersistMsg::Wake);
        }
    }
}

/// The persist task: on each wake, drain the signal backlog (collecting any flush
/// request), take the latest snapshot from the capacity-1 mailbox, write it, then
/// ack the flush — so a shutdown flush is acked only after the latest state is on
/// disk.
#[cfg(not(test))]
async fn persist_loop(
    mut rx: mpsc::UnboundedReceiver<PersistMsg>,
    pending: Arc<Mutex<Option<HashMap<String, TokenMeta>>>>,
    secrets: Secrets,
) {
    while let Some(first) = rx.recv().await {
        let mut flush_ack: Option<tokio::sync::oneshot::Sender<()>> = None;
        let mut msg = Some(first);
        while let Some(m) = msg {
            if let PersistMsg::Flush(ack) = m {
                flush_ack = Some(ack);
            }
            msg = rx.try_recv().ok();
        }
        // Take the latest pending snapshot (capacity-1, latest-wins). A new
        // `submit` after this take re-arms `pending` and sends a fresh Wake, so
        // nothing is lost.
        let snapshot = pending.lock().unwrap().take();
        if let Some(snapshot) = snapshot {
            persist_snapshot(snapshot, secrets.clone()).await;
        }
        if let Some(ack) = flush_ack {
            let _ = ack.send(());
        }
    }
}

/// Write one snapshot to the secrets file on a blocking thread. Runs inside the
/// single persist task, so writes are already serialized. A failed write is
/// logged; the in-memory map stays authoritative, and the next mutation writes
/// the whole map again.
#[cfg(not(test))]
async fn persist_snapshot(snapshot: HashMap<String, TokenMeta>, secrets: Secrets) {
    match tokio::task::spawn_blocking(move || secrets.set_sessions(snapshot)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("Failed to persist sessions: {e}"),
        Err(e) => warn!("Session persist task panicked: {e}"),
    }
}

/// Persistent store of issued session tokens. The in-memory `HashMap`
/// is the hot lookup path; every mutation also writes the whole map
/// back to the [secrets file](crate::secrets) so a daemon restart
/// re-hydrates the same set of valid tokens.
#[derive(Clone)]
pub struct TokenStore {
    pub(crate) inner: Arc<Mutex<HashMap<String, TokenMeta>>>,
    persist: SessionPersister,
}

#[cfg(test)]
impl Default for TokenStore {
    fn default() -> Self {
        Self::empty(Secrets::in_memory())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenMeta {
    /// The name the caller declared when it asked. Persisted for diagnostics.
    pub app_name: String,
    /// The scopes the user granted, sorted and deduplicated.
    pub scopes: Vec<String>,
    /// Who the user approved. Carries its own kind, so a token minted for a
    /// binary can never be matched against a web origin or the reverse — the
    /// comparison in [`Self::matches`] is between whole identities, not between
    /// whichever fields happen to be populated.
    pub grantee: PeerIdentity,
    /// When the user granted it. Persisted for diagnostics.
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl TokenMeta {
    /// Is `identity` the caller this token was granted to?
    ///
    /// Whole-identity equality, which is what keeps the variants from leaking
    /// into each other. Within a native grantee both halves still have to
    /// match: every flatpak resolves to a path inside its own sandbox, so two
    /// different sandboxed apps can present the identical `/app/bin/<name>` and
    /// would otherwise share each other's sessions.
    #[must_use]
    pub fn matches(&self, identity: &PeerIdentity) -> bool {
        &self.grantee == identity
    }

    /// One line naming the grantee, for logs.
    #[must_use]
    pub fn describe_grantee(&self) -> String {
        self.grantee.describe()
    }
}

impl TokenStore {
    /// An empty store with a live persist task (production) / no-op persister
    /// (test builds).
    fn empty(secrets: Secrets) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            persist: SessionPersister::spawn(secrets),
        }
    }

    /// Load the sessions persisted in `secrets`, prune anything already past
    /// its `expires_at`, and write the cleaned set back if pruning removed
    /// entries.
    ///
    /// # Panics
    /// If a thread panicked while holding the store's lock.
    #[must_use]
    pub fn load_persisted(secrets: Secrets) -> Self {
        let loaded = secrets.sessions();
        let total = loaded.len();
        let now = Utc::now();
        let live: HashMap<String, TokenMeta> = loaded
            .into_iter()
            .filter(|(_, meta)| meta.expires_at > now)
            .collect();
        let pruned = total - live.len();
        info!(
            "Loaded {} persisted sessions ({pruned} expired pruned)",
            live.len()
        );
        if pruned > 0
            && let Err(e) = secrets.set_sessions(live.clone())
        {
            warn!("Failed to persist the pruned sessions: {e}");
        }

        let store = Self::empty(secrets);
        *store.inner.lock().unwrap() = live;
        store
    }

    /// Mint a fresh 30-day session token for `(app_name, scopes, identity)`,
    /// insert it into the in-memory map, and submit the updated snapshot to the
    /// persist task. The submit happens under the lock so the persist channel's
    /// order matches lock order (audit 2 Tier 1 #4). Persistence failures are
    /// logged but not propagated — the in-memory map stays authoritative for the
    /// lifetime of the daemon.
    ///
    /// In `cargo test` builds nothing is persisted. End-to-end
    /// behavior across daemon restarts is covered by the integration
    /// smoke tests in each daemon's `tests/http_smoke_full.rs` (which exercise
    /// this crate built without the `test` cfg flag).
    ///
    /// # Panics
    /// If a thread panicked while holding the store's lock.
    #[must_use]
    pub fn mint(
        &self,
        app_name: &str,
        scopes: &[String],
        identity: &PeerIdentity,
    ) -> (String, DateTime<Utc>) {
        let token = generate_token();
        let now = Utc::now();
        let expires_at = now + ChronoDuration::days(30);
        let meta = TokenMeta {
            app_name: app_name.to_string(),
            scopes: scopes.to_vec(),
            grantee: identity.clone(),
            issued_at: now,
            expires_at,
        };
        {
            let mut tokens = self.inner.lock().unwrap();
            tokens.insert(token.clone(), meta);
            // Submit under the lock so the persist channel's order matches lock
            // order. An off-lock submit can invert (two mutations serialize on
            // the Mutex yet reach the channel out of order) and the coalescer
            // would then write a stale subset snapshot — resurrecting a revoked
            // token across restart. `submit` is a non-blocking channel send (the
            // file write happens off-thread in the persist task), so it's safe
            // to hold the std Mutex across it (audit 2 Tier 1 #4).
            self.persist.submit(tokens.clone());
        }
        (token, expires_at)
    }

    /// The session `token` names, or why there is none: `unknown` or
    /// `expired` (an expired token is evicted on the way).
    ///
    /// # Errors
    /// The `invalid_session` reason the caller answers with.
    ///
    /// # Panics
    /// If a thread panicked while holding the store's lock.
    pub fn validate(&self, token: &str) -> Result<TokenMeta, &'static str> {
        // Submit the expired-eviction snapshot under the lock so the persist
        // channel's order matches lock order (audit 2 Tier 1 #4). `submit` is a
        // non-blocking channel send — the file write happens off-thread in the
        // persist task, not here — so it's safe to hold the std Mutex across it.
        // The write is best-effort: the in-memory state is already correct.
        let mut tokens = self.inner.lock().unwrap();
        let Some(meta) = tokens.get(token).cloned() else {
            return Err("unknown");
        };
        if meta.expires_at < Utc::now() {
            tokens.remove(token);
            self.persist.submit(tokens.clone());
            return Err("expired");
        }
        Ok(meta)
    }

    /// Drop a session token immediately and persist the change. Used by
    /// the `/events` exe-watch path on `exe_changed`: a binary
    /// replacement during a long-lived widget connection invalidates
    /// the session, so the daemon revokes the token, emits a `revoked`
    /// SSE event, and closes the stream. Idempotent.
    ///
    /// # Panics
    /// If a thread panicked while holding the store's lock.
    pub fn revoke(&self, token: &str) {
        let mut tokens = self.inner.lock().unwrap();
        if tokens.remove(token).is_some() {
            // Submit under the lock — see `mint` (audit 2 Tier 1 #4).
            self.persist.submit(tokens.clone());
        }
    }
}

fn generate_token() -> String {
    use std::fmt::Write as _;
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("SystemRandom::fill");
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("string write");
    }
    s
}

#[cfg(test)]
mod tests {
    //! Session-token security semantics: expiry + eviction, the
    //! unknown-token path, mint correctness, and revocation. `validate`
    //! and `revoke` are the gates every authenticated request and the
    //! `/events` exe-watch path rely on, so they're exercised directly
    //! here. Under `cfg!(test)` no persist task is spawned and the
    //! `SessionPersister` receiver is dropped, so mint/revoke submissions
    //! are no-ops — none of these write the secrets file.
    use super::{PeerIdentity, TokenMeta, TokenStore};
    use chrono::{Duration as ChronoDuration, Utc};

    /// Insert a token straight into the in-memory map with an arbitrary
    /// `expires_at`, bypassing `mint`'s fixed 30-day TTL so we can pin
    /// the expiry boundary.
    fn insert_with_expiry(store: &TokenStore, token: &str, expires_at: chrono::DateTime<Utc>) {
        let meta = TokenMeta {
            app_name: "test-app".to_string(),
            scopes: vec!["status".to_string()],
            grantee: PeerIdentity::native("/usr/bin/test-client"),
            issued_at: Utc::now() - ChronoDuration::days(1),
            expires_at,
        };
        store.inner.lock().unwrap().insert(token.to_string(), meta);
    }

    /// A freshly minted token validates, carries the scopes + exe it was
    /// minted with, gets a ~30-day expiry, and is a 64-char hex string.
    /// Distinct mints never collide.
    #[test]
    fn mint_then_validate_roundtrips() {
        let store = TokenStore::default();
        let scopes = vec!["test".to_string(), "status".to_string()];
        let exe = PeerIdentity::native("/usr/bin/super-test-cli");

        let (token, expires_at) = store.mint("Super Test CLI", &scopes, &exe);
        assert_eq!(token.len(), 64, "token is 32 random bytes hex-encoded");
        assert!(
            token.chars().all(|c| c.is_ascii_hexdigit()),
            "token must be lowercase hex: {token}"
        );

        // ~30 days out (allow a day of slack on each side for clock/runtime).
        let now = Utc::now();
        assert!(
            expires_at > now + ChronoDuration::days(29)
                && expires_at < now + ChronoDuration::days(31),
            "mint should set a ~30-day expiry, got {expires_at}"
        );

        let meta = store.validate(&token).expect("live token must validate");
        assert_eq!(meta.scopes, scopes, "validated scopes match minted scopes");
        assert!(
            meta.matches(&exe),
            "validated identity matches the minted one"
        );

        // A second mint yields a different token.
        let (token2, _) = store.mint("Super Test CLI", &scopes, &exe);
        assert_ne!(token, token2, "each mint produces a unique token");
    }

    /// A token unknown to the store is rejected with the `unknown`
    /// reason (this becomes `401 invalid_session (unknown)` on the wire).
    #[test]
    fn validate_unknown_token_is_unknown() {
        let store = TokenStore::default();
        assert!(
            matches!(store.validate("never-minted"), Err("unknown")),
            "an unknown token must be rejected as `unknown`"
        );
    }

    /// An expired token is rejected with `expired` AND evicted from the
    /// store, so a second presentation reports `unknown` rather than
    /// `expired` — the daemon never keeps a dead token around.
    #[test]
    fn expired_token_is_rejected_and_evicted() {
        let store = TokenStore::default();
        insert_with_expiry(&store, "stale", Utc::now() - ChronoDuration::seconds(1));

        assert!(
            matches!(store.validate("stale"), Err("expired")),
            "a token past its expiry must be rejected as `expired`"
        );
        assert!(
            !store.inner.lock().unwrap().contains_key("stale"),
            "an expired token must be evicted on validation"
        );
        assert!(
            matches!(store.validate("stale"), Err("unknown")),
            "the evicted token is now simply unknown"
        );
    }

    /// A token whose expiry is still in the future validates cleanly —
    /// the expiry check is strictly `expires_at < now`.
    #[test]
    fn not_yet_expired_token_validates() {
        let store = TokenStore::default();
        insert_with_expiry(&store, "fresh", Utc::now() + ChronoDuration::minutes(1));
        assert!(
            store.validate("fresh").is_ok(),
            "a token with a future expiry must validate"
        );
    }

    /// `revoke` immediately invalidates a live token. This is the
    /// primitive the `/events` exe-watch task calls on `exe_changed`
    /// (a binary swap during a long-lived widget connection), so after
    /// revocation the session is gone and any further use is `unknown`.
    #[test]
    fn revoke_invalidates_a_live_token() {
        let store = TokenStore::default();
        let (token, _) = store.mint(
            "widget",
            &["status".to_string()],
            &PeerIdentity::native("/usr/bin/w"),
        );
        assert!(store.validate(&token).is_ok(), "token valid before revoke");

        store.revoke(&token);
        assert!(
            matches!(store.validate(&token), Err("unknown")),
            "a revoked token must no longer validate"
        );
    }

    /// `revoke` is idempotent: revoking an unknown token (or the same
    /// token twice) is a harmless no-op.
    #[test]
    fn revoke_is_idempotent() {
        let store = TokenStore::default();
        store.revoke("never-existed"); // must not panic
        let (token, _) = store.mint(
            "app",
            &["status".to_string()],
            &PeerIdentity::native("/bin/a"),
        );
        store.revoke(&token);
        store.revoke(&token); // second revoke is still a no-op
        assert!(matches!(store.validate(&token), Err("unknown")));
    }
}
