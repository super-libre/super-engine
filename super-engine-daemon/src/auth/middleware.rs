// SPDX-License-Identifier: GPL-3.0-only
//! The guards every route sits behind: the origin gate on the TCP listener,
//! the token and scope check, and the per-client rate limit.
//!
//! Each takes the daemon's [`Auth`] as its state, so a daemon layers them
//! with `axum::middleware::from_fn_with_state(auth.clone(), guard)`.

use crate::auth::Auth;
use crate::auth::consent::ConsentKey;
use crate::auth::identity::resolve_peer_identity;
use crate::auth::tokens::{TokenMeta, TokenStore};
use crate::http::PeerInfo;
use crate::http::responses::{
    auth_err, error_response, invalid_session, rate_limited, reason, scope_denied,
};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;
use std::sync::{Arc, Mutex};

/// In-memory record of `(exe_path, scopes)` pairs the user has clicked
/// Deny on. Subsequent `/auth/request` calls for the same pair
/// short-circuit to `403 auth_denied` without spawning another
/// consent popup — the user already said no, no point asking again.
///
/// **In-memory only.** The set lives for the daemon's lifetime; a
/// daemon restart resets it so the user gets a fresh chance to grant
/// consent if they want to. This intentionally has no keyring/disk
/// persistence (per spec).
#[derive(Clone, Default)]
pub struct DenyCache {
    pub(crate) inner: Arc<Mutex<std::collections::HashSet<ConsentKey>>>,
}

impl DenyCache {
    /// Whether the user denied `key` earlier in this daemon's life.
    ///
    /// # Panics
    /// If a thread panicked while holding the cache's lock.
    #[must_use]
    pub fn contains(&self, key: &ConsentKey) -> bool {
        self.inner.lock().unwrap().contains(key)
    }

    /// Remember that the user denied `key`.
    ///
    /// # Panics
    /// If a thread panicked while holding the cache's lock.
    pub fn insert(&self, key: ConsentKey) {
        self.inner.lock().unwrap().insert(key);
    }
}

/// The `Origin` of a request, as a borrowed string, or `None` when the header
/// is absent or not valid UTF-8.
fn request_origin(headers: &HeaderMap) -> Option<&str> {
    headers.get("origin").and_then(|v| v.to_str().ok())
}

/// The methods and headers a browser may use once its origin is allowed.
///
/// Spelled out rather than mirrored back from the preflight request: echoing
/// `Access-Control-Request-Headers` would let a page name any header it liked
/// and be told yes, which tells the reader of a preflight nothing about what
/// the daemon actually accepts.
const CORS_ALLOW_METHODS: &str = "GET, POST, PATCH, DELETE, OPTIONS";
const CORS_ALLOW_HEADERS: &str = "authorization, content-type";
/// How long a browser may cache the preflight result. Ten minutes: long enough
/// that a click-heavy settings page is not preflighting every call, short
/// enough that removing an origin from the allowlist takes effect while the
/// user is still watching.
const CORS_MAX_AGE: &str = "600";

/// How much of a refused request's body the daemon reads before it gives up and
/// lets the connection close.
///
/// Enough for the bodies real clients actually send — a settings patch, a short
/// audio clip — but deliberately not a daemon's full upload limit: the caller
/// has already been refused, so there is no reason to let it spend the
/// daemon's time streaming an upload that gets discarded either way.
const REFUSED_BODY_DRAIN_LIMIT: usize = 2 * 1024 * 1024;

/// Answer a request refused on its headers alone, discarding the body it is
/// still sending so that answer can actually be read.
///
/// A rejection decided before the handler runs leaves the body unread, and
/// hyper will not reuse a connection whose request it never finished reading —
/// so it closes. A client partway through an upload sees that close as a write
/// error (`BrokenPipe`) and never reads the `403` saying why it was refused; in
/// a browser that surfaces as a bare "failed to fetch" rather than
/// `scope_denied`. Reading the body out first is what lets the response land.
///
/// Bounded by [`REFUSED_BODY_DRAIN_LIMIT`]; past that the connection closes as
/// it did before. A caller we have already refused is not owed an endless read.
async fn refuse(request: Request<Body>, response: Response) -> Response {
    let mut body = request.into_body();
    let mut drained: usize = 0;
    while let Some(Ok(frame)) = body.frame().await {
        if let Some(data) = frame.data_ref() {
            drained = drained.saturating_add(data.len());
            if drained >= REFUSED_BODY_DRAIN_LIMIT {
                break;
            }
        }
    }
    response
}

/// Gate every TCP request on the user's origin allowlist, and answer browser
/// preflights.
///
/// This is the TCP half of the identity model, and the reason turning the TCP
/// listener on (`[http.tcp].enabled`) exposes nothing by itself. The Unix socket has `SO_PEERCRED`: the kernel names the caller and
/// no client can talk its way out of that. TCP has no equivalent, so the only
/// thing distinguishing one caller from another is the `Origin` header — and a
/// header is a claim, not a proof.
///
/// What makes the claim usable is that it is checked against a list the *user*
/// wrote. A page from an origin they never named is refused here, before it
/// reaches authentication, consent, or a handler. A page from an origin they
/// did name gets exactly the trust they granted it.
///
/// **The check is server-side on purpose.** The CORS headers this also emits
/// are advisory: they instruct a browser to refuse a response, and a
/// non-browser client on the same port ignores them completely. So the
/// allowlist is enforced by *rejecting the request*, and the CORS headers are
/// only there so a browser reports the refusal as a CORS error the developer
/// can read instead of an opaque network failure.
///
/// Unix requests pass through untouched: their identity is already settled, and
/// a browser cannot reach that socket to need any of this.
pub async fn require_allowed_origin(
    State(auth): State<Auth>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // A Unix peer is identified by credentials, not by a header. Note this
    // reads the *connection's* PeerInfo, not the request's origin header, so a
    // Unix caller sending an `Origin` cannot route itself down this path.
    let is_tcp = request
        .extensions()
        .get::<PeerInfo>()
        .is_some_and(|p| p.pid.is_none() && p.uid.is_none());
    if !is_tcp {
        return next.run(request).await;
    }

    let allowed = request_origin(request.headers())
        .filter(|origin| auth.is_origin_allowed(origin))
        .map(str::to_owned);

    let Some(origin) = allowed else {
        log::warn!(
            "TCP request refused: origin {:?} is not in [http.tcp].allowed_origins",
            request_origin(request.headers()).unwrap_or("<absent>"),
        );
        // No CORS headers on the refusal: a browser told nothing is a browser
        // that reports a CORS error, which is the accurate description of what
        // happened. Attaching them would let the page read the body and find
        // out whether an origin is on the list.
        return refuse(
            request,
            auth_err(
                StatusCode::FORBIDDEN,
                "auth_denied",
                reason::ORIGIN_NOT_ALLOWED,
            ),
        )
        .await;
    };

    // A preflight is answered here and never reaches a handler: it carries no
    // credentials by design, so running it through the auth layers below would
    // reject every one of them and no real request would ever follow.
    if request.method() == axum::http::Method::OPTIONS {
        let wants_private_network = request
            .headers()
            .get("access-control-request-private-network")
            .is_some_and(|v| v.as_bytes() == b"true");
        let mut response = cors_headers(&origin, (StatusCode::NO_CONTENT, ()).into_response());
        if wants_private_network {
            // Chrome's Private Network Access check. A page on a public site
            // reaching a loopback address is a privilege escalation in the
            // browser's eyes — the page gets to talk to something only this
            // machine can see — so it asks first, on the preflight, and treats
            // a missing answer as a refusal.
            //
            // Answering yes is not a decision to trust the page. It says the
            // daemon is willing to be addressed from outside the local address
            // space; who may then do anything is still the origin allowlist and
            // the consent dialog, both of which this request has yet to pass.
            // Without it, `allowed_origins = ["*"]` would admit every origin in
            // the daemon and none of the interesting ones in Chrome.
            //
            // The header is echoed only when asked for, so a same-address-space
            // preflight — which is what a page on localhost sends — stays
            // exactly as it was.
            response.headers_mut().insert(
                "access-control-allow-private-network",
                axum::http::HeaderValue::from_static("true"),
            );
        }
        return response;
    }

    // From here the origin is the user's own choice, so it becomes this
    // request's identity.
    let mut peer = request
        .extensions()
        .get::<PeerInfo>()
        .cloned()
        .unwrap_or_else(PeerInfo::tcp);
    peer.web_origin = Some(origin.clone());

    // Register that identity with the resource manager before the rate limiter
    // downstream looks it up.
    //
    // The accept loop registers a connection under whatever the caller was at
    // accept time, and a TCP caller was nobody: its origin arrives on the
    // request, not the connection. So the id registered there ("unknown") is
    // not the id the rate limiter asks about, and `check_rate_limit` treats an
    // unregistered id as a refusal — every authorized request from a browser
    // came back `429`, blaming a quota that had never been counted.
    //
    // Registering here, where the identity is first known, is what makes the
    // two agree. It is idempotent per id, so this is a lookup on all but the
    // first request of each origin.
    let client_id = peer.client_id();
    if let Err(e) = auth
        .resource_manager()
        .register_connection(client_id.clone(), None)
        .await
    {
        log::warn!("connection rejected for {client_id}: {e}");
        return refuse(
            request,
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "connection_rejected",
                "too_many_clients",
            ),
        )
        .await;
    }
    request.extensions_mut().insert(peer);

    cors_headers(&origin, next.run(request).await)
}

/// Attach the CORS headers that let a browser hand `response` to the page.
///
/// `Access-Control-Allow-Origin` echoes the *validated* origin rather than
/// `*`, for two reasons: `*` is incompatible with credentialed requests, and
/// echoing only a value that already passed the allowlist means the header can
/// never name an origin the user did not authorize.
fn cors_headers(origin: &str, mut response: Response) -> Response {
    use axum::http::HeaderValue;
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(origin) {
        headers.insert("access-control-allow-origin", value);
    }
    headers.insert(
        "access-control-allow-methods",
        HeaderValue::from_static(CORS_ALLOW_METHODS),
    );
    headers.insert(
        "access-control-allow-headers",
        HeaderValue::from_static(CORS_ALLOW_HEADERS),
    );
    headers.insert(
        "access-control-max-age",
        HeaderValue::from_static(CORS_MAX_AGE),
    );
    // Responses differ by origin, so a cache keyed on URL alone would serve one
    // origin's response to another.
    headers.insert("vary", HeaderValue::from_static("origin"));
    response
}

/// The token in an `Authorization: Bearer <token>` header, if there is one.
#[must_use]
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_owned)
}

/// The validated session metadata + bearer token, attached to each
/// authorized request as an `axum::Extension` so handlers can read them
/// without re-validating. The bearer string is included so handlers
/// like `/events` can call back into `TokenStore` to revoke on
/// `exe_changed`.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub meta: TokenMeta,
    pub token: String,
}

/// Re-verify that the caller is still the binary the token was minted
/// for, and revoke the token when it isn't.
///
/// [`TokenStore::validate`] proves only that a token exists and hasn't
/// expired, which is not what the daemon authorizes on: the user consented
/// to a *binary*. `docs/protocol/auth.md` states the binding as a
/// per-request property — "If that path changes (upgrade, move,
/// replacement), the next request returns `401 invalid_session` with reason
/// `exe_changed`" — but the only thing enforcing it was the `/events`
/// exe-watch, which sees a client only while it holds an SSE subscription
/// and only every 30 s. Anything else presenting a token minted for another
/// binary was authorized for the token's full 30-day life, with no consent
/// popup anywhere in the flow, because possession was the whole test. A
/// token reachable from a second process — a keyring entry two installs of
/// the same app share, a copied config — is exactly that case.
///
/// A resolved mismatch revokes, matching the `/events` watch rather than
/// merely refusing this one call: the approval named a binary that is not
/// the one calling, so the session is over, not paused.
fn verify_peer_binding(
    tokens: &TokenStore,
    peer: Option<&PeerInfo>,
    meta: &TokenMeta,
    token: &str,
) -> Result<(), &'static str> {
    let Some(identity) = resolve_peer_identity(peer, "authorization") else {
        // Fail closed: an unidentifiable caller cannot be shown to be the
        // approved one. Deliberately not a revoke — an unreadable
        // `/proc/<pid>/exe` is transient (a peer that exited mid-request),
        // unlike a path that genuinely changed.
        return Err(reason::UNKNOWN);
    };
    if meta.matches(&identity) {
        return Ok(());
    }
    log::warn!(
        "session token presented by a different caller: approved={} caller={}; revoking",
        meta.describe_grantee(),
        identity.describe(),
    );
    tokens.revoke(token);
    Err(reason::EXE_CHANGED)
}

/// Validate the bearer token and require that its granted scope set
/// contains `required`. Attaches the [`AuthContext`] on success so the
/// handler can read the scopes/exe without re-validating.
///
/// The guards for the scopes every daemon has are below; a daemon writes one
/// for each scope of its own, as a function that calls this with the scope's
/// name.
pub async fn require_scope(
    required: &str,
    auth: Auth,
    headers: HeaderMap,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(token) = extract_bearer_token(&headers) else {
        return refuse(request, invalid_session(reason::UNKNOWN)).await;
    };
    match auth.tokens().validate(&token) {
        Ok(meta) => {
            if let Err(reason) = verify_peer_binding(
                auth.tokens(),
                request.extensions().get::<PeerInfo>(),
                &meta,
                &token,
            ) {
                return refuse(request, invalid_session(reason)).await;
            }
            if meta.scopes.iter().any(|s| s == required) {
                request.extensions_mut().insert(AuthContext { meta, token });
                next.run(request).await
            } else {
                refuse(request, scope_denied()).await
            }
        }
        Err(reason) => refuse(request, invalid_session(reason)).await,
    }
}

/// The `status` scope: what the daemon is doing.
pub async fn require_status_scope(
    State(auth): State<Auth>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    require_scope("status", auth, headers, request, next).await
}

/// The `settings` scope: the configuration surface.
pub async fn require_settings_scope(
    State(auth): State<Auth>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    require_scope("settings", auth, headers, request, next).await
}

/// The `secrets` scope: writing a backend's API credentials.
pub async fn require_secrets_scope(
    State(auth): State<Auth>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    require_scope("secrets", auth, headers, request, next).await
}

/// Accept any valid bearer token regardless of scope. Used for `/ping`
/// — a no-info-leak liveness probe that all scopes legitimately need.
pub async fn require_any_authenticated(
    State(auth): State<Auth>,
    headers: HeaderMap,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(token) = extract_bearer_token(&headers) else {
        return refuse(request, invalid_session(reason::UNKNOWN)).await;
    };
    match auth.tokens().validate(&token) {
        Ok(meta) => {
            if let Err(reason) = verify_peer_binding(
                auth.tokens(),
                request.extensions().get::<PeerInfo>(),
                &meta,
                &token,
            ) {
                return refuse(request, invalid_session(reason)).await;
            }
            request.extensions_mut().insert(AuthContext { meta, token });
            next.run(request).await
        }
        Err(reason) => refuse(request, invalid_session(reason)).await,
    }
}

/// Per-request rate-limit gate. Layered on every authenticated
/// route group — `/auth/request` is excluded because its abuse
/// model is the consent popup, not per-request quota.
pub async fn require_rate_limit(
    State(auth): State<Auth>,
    axum::Extension(peer): axum::Extension<PeerInfo>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let client_id = peer.client_id();
    match auth.resource_manager().record_request(&client_id).await {
        Ok(()) => next.run(request).await,
        Err(e) => {
            log::warn!("rate-limit hit for {client_id}: {e}");
            refuse(request, rate_limited()).await
        }
    }
}

#[cfg(test)]
mod tests {
    //! Deny-cache identity. The cache short-circuits `/auth/request` to
    //! `403 auth_denied (user_denied_cached)` so a binary the user
    //! already rejected can't re-trigger the consent popup. Its key is
    //! the `(identity, scopes)` pair — the same identity the consent
    //! flow is verified against — so denial must be scoped to that exact
    //! caller and that exact scope set, nothing broader.
    use super::DenyCache;
    use crate::auth::consent::ConsentKey;
    use crate::auth::identity::PeerIdentity;

    #[test]
    fn deny_cache_remembers_a_denied_pair() {
        let cache = DenyCache::default();
        let key: ConsentKey = (
            PeerIdentity::native("/usr/bin/evil"),
            vec!["settings".to_string(), "transcribe".to_string()],
        );
        assert!(!cache.contains(&key), "a fresh cache denies nothing");
        cache.insert(key.clone());
        assert!(
            cache.contains(&key),
            "a denied (exe, scopes) pair must be remembered"
        );
    }

    #[test]
    fn deny_cache_is_scoped_to_exe_and_scope_set() {
        let cache = DenyCache::default();
        let denied: ConsentKey = (
            PeerIdentity::native("/usr/bin/evil"),
            vec!["settings".to_string()],
        );
        cache.insert(denied.clone());

        // Same scopes, different binary → not denied (a fresh consent prompt).
        let other_exe: ConsentKey = (PeerIdentity::native("/usr/bin/other"), denied.1.clone());
        assert!(
            !cache.contains(&other_exe),
            "denial must not leak across binaries"
        );

        // Same binary, different scope set → not denied.
        let other_scopes: ConsentKey = (denied.0.clone(), vec!["status".to_string()]);
        assert!(
            !cache.contains(&other_scopes),
            "denial must not leak across scope sets"
        );
    }
}

/// The deny cache's contract: keyed on the caller and the scope set but not
/// the self-reported name, a set rather than a list, and empty for every new
/// daemon.
#[cfg(test)]
mod deny_cache_tests {
    use super::DenyCache;
    use crate::auth::consent::ConsentKey;
    use crate::auth::identity::PeerIdentity;

    fn deny_key(exe: &str, scope: &str) -> ConsentKey {
        (PeerIdentity::native(exe), vec![scope.to_string()])
    }

    /// Different `(exe_path, scope)` pairs must be distinguished —
    /// otherwise an unrelated binary's denial would poison every
    /// other binary's consent flow. `app_name` is intentionally NOT
    /// part of the key: it's client-controlled, so a misbehaving
    /// caller could otherwise bypass a deny by rotating its declared
    /// app name. Two requests from the same binary in the same scope
    /// SHOULD collide regardless of `app_name`.
    #[test]
    fn deny_cache_distinguishes_keys_by_each_component() {
        let cache = DenyCache::default();
        let app_a = deny_key("/usr/bin/a", "daemon_status");
        // What "App A" renamed to "Renamed App" presents: the same key,
        // since the name is not part of it.
        let same_path_renamed = deny_key("/usr/bin/a", "daemon_status");
        let other_path = deny_key("/usr/bin/a-renamed", "daemon_status");
        let other_scope = deny_key("/usr/bin/a", "settings");

        cache.insert(app_a.clone());
        assert!(cache.contains(&app_a));
        assert!(
            cache.contains(&same_path_renamed),
            "same exe_path + scope must collide regardless of declared app_name \
             (denial sticks to the binary, not the self-reported name)"
        );
        assert!(
            !cache.contains(&other_path),
            "different exe_path must not collide"
        );
        assert!(
            !cache.contains(&other_scope),
            "different scope must not collide"
        );
    }

    /// `insert` is a set add, not a list append — calling it twice
    /// with the same key is a no-op. We're not strictly testing
    /// `HashSet` semantics (that's stdlib's job); we're documenting
    /// the contract `DenyCache` exposes so a future refactor can't
    /// accidentally swap it for a duplicating store.
    #[test]
    fn deny_cache_insert_is_idempotent() {
        let cache = DenyCache::default();
        let key = deny_key("/usr/bin/app", "status");
        cache.insert(key.clone());
        cache.insert(key.clone());
        cache.insert(key.clone());
        // Internal length check: ensures we didn't grow a duplicate
        // entry that would leak memory across many denies.
        assert_eq!(cache.inner.lock().unwrap().len(), 1);
        assert!(cache.contains(&key));
    }

    /// The cache is purely in-memory and lives on the daemon's
    /// [`Auth`](crate::auth::Auth). Two independent `DenyCache::default()`
    /// instances must not share state — that's what gives us the "daemon
    /// restart clears the deny cache" guarantee documented in auth.md.
    #[test]
    fn deny_cache_instances_do_not_share_state() {
        let a = DenyCache::default();
        let b = DenyCache::default();
        let key = deny_key("/usr/bin/app", "daemon_status");

        a.insert(key.clone());
        assert!(a.contains(&key));
        assert!(
            !b.contains(&key),
            "a fresh DenyCache (e.g. after daemon restart) must start empty"
        );
    }
}

#[cfg(test)]
mod peer_binding_tests {
    //! Per-request token-to-binary binding. `docs/protocol/auth.md` calls a
    //! token "tied to the binary's `/proc/<pid>/exe` at issue time", and says
    //! that when that stops matching, "the next request returns `401
    //! invalid_session` with reason `exe_changed`" — so the check belongs on
    //! every authorized call, not only on the `/events` exe-watch tick.
    use super::verify_peer_binding;
    use crate::auth::identity::PeerIdentity;
    use crate::auth::tokens::TokenStore;
    use crate::http::PeerInfo;
    use crate::http::responses::reason;
    use std::path::PathBuf;

    /// A peer that is this very test process — the caller and the minted
    /// binary are then the same file by construction.
    fn self_peer() -> PeerInfo {
        PeerInfo::unix(Some(std::process::id()), None)
    }

    /// This process's identity, resolved the way the daemon resolves a
    /// caller's.
    ///
    /// Through `resolve_peer_identity` rather than by reading the exe path
    /// directly, because *which* syscall names a process's binary is
    /// per-platform (`/proc/<pid>/exe` on Linux, `proc_pidpath` on macOS) and
    /// restating one of them here made these tests Linux-only. It is also the
    /// more faithful fixture: what is under test is the binding — whether a
    /// token minted for one identity still matches the caller — not how an
    /// executable is looked up, which `consent`'s own tests cover.
    fn own_identity() -> PeerIdentity {
        crate::auth::identity::resolve_peer_identity(Some(&self_peer()), "peer_binding_tests")
            .expect("this process must be able to identify itself")
    }

    /// The ordinary case: the binary the user approved is the one calling.
    /// It passes, and passing must not disturb the session.
    #[test]
    fn caller_matching_the_minted_binary_is_accepted() {
        let store = TokenStore::default();
        let (token, _) = store.mint("Test App", &["status".to_string()], &own_identity());
        let meta = store.validate(&token).expect("freshly minted token");

        assert_eq!(
            verify_peer_binding(&store, Some(&self_peer()), &meta, &token),
            Ok(()),
            "the binary the token was minted for must still be authorized"
        );
        assert!(
            store.validate(&token).is_ok(),
            "an accepted call must leave the token alone"
        );
    }

    /// The case this check exists for: a token minted for one binary is
    /// presented by a different one. That is what a keyring entry shared
    /// between two installs of the same app produces, and possession alone
    /// must not be enough — the daemon's answer is `exe_changed`, and the
    /// session ends rather than merely failing this one call.
    #[test]
    fn a_different_binary_presenting_the_token_is_rejected_and_revoked() {
        let store = TokenStore::default();
        let approved = PeerIdentity::native("/usr/local/bin/super-stt-app");
        let (token, _) = store.mint("Test App", &["secrets".to_string()], &approved);
        let meta = store.validate(&token).expect("freshly minted token");

        assert_eq!(
            verify_peer_binding(&store, Some(&self_peer()), &meta, &token),
            Err(reason::EXE_CHANGED),
            "a caller that is not the approved binary must be refused"
        );
        assert!(
            matches!(store.validate(&token), Err("unknown")),
            "a mismatch must revoke the token, not just refuse the one request"
        );
    }

    /// Two sandboxed apps present the same executable path, because each
    /// resolves it inside its own sandbox. They must not share a session:
    /// without the sandbox id in the identity, a grant to one would authorize
    /// every other flatpak that ships a binary at the same path.
    #[test]
    fn two_flatpaks_sharing_an_exe_path_are_different_callers() {
        let store = TokenStore::default();
        let granted = PeerIdentity::Native {
            exe_path: PathBuf::from("/app/bin/super-stt-app"),
            flatpak_app_id: Some("ai.menjivar.SuperSTT".to_string()),
        };
        let impostor = PeerIdentity::Native {
            exe_path: PathBuf::from("/app/bin/super-stt-app"),
            flatpak_app_id: Some("org.example.Stranger".to_string()),
        };
        let (token, _) = store.mint("Test App", &["transcribe".to_string()], &granted);
        let meta = store.validate(&token).expect("freshly minted token");

        assert!(meta.matches(&granted), "the granted app still matches");
        assert!(
            !meta.matches(&impostor),
            "a different flatpak must not match on the path alone"
        );
    }

    /// A native binary and a sandboxed one at the same path are likewise
    /// different callers — the host path is real, the sandboxed one only
    /// looks like it.
    #[test]
    fn a_sandboxed_caller_never_matches_a_native_grant_at_the_same_path() {
        let store = TokenStore::default();
        let native = PeerIdentity::native("/usr/local/bin/super-stt-app");
        let sandboxed = PeerIdentity::Native {
            exe_path: PathBuf::from("/usr/local/bin/super-stt-app"),
            flatpak_app_id: Some("org.example.Stranger".to_string()),
        };
        let (token, _) = store.mint("Test App", &["settings".to_string()], &native);
        let meta = store.validate(&token).expect("freshly minted token");

        assert!(
            !meta.matches(&sandboxed),
            "a sandbox that puts its binary at the approved host path must not inherit the grant"
        );
    }

    /// An unidentifiable peer fails closed, but is not treated as a
    /// mismatch: `/proc/<pid>/exe` going unreadable is transient (the peer
    /// exited mid-request), and destroying a live session over it would
    /// force a consent popup the user never asked for.
    #[test]
    fn an_unverifiable_peer_is_refused_without_revoking() {
        let store = TokenStore::default();
        let (token, _) = store.mint("Test App", &["status".to_string()], &own_identity());
        let meta = store.validate(&token).expect("freshly minted token");

        assert_eq!(
            verify_peer_binding(&store, None, &meta, &token),
            Err(reason::UNKNOWN),
            "no PeerInfo at all means the caller cannot be identified"
        );
        let pidless = PeerInfo::unix(None, Some(1000));
        assert_eq!(
            verify_peer_binding(&store, Some(&pidless), &meta, &token),
            Err(reason::UNKNOWN),
            "credentials without a pid cannot be resolved to a binary either"
        );
        assert!(
            store.validate(&token).is_ok(),
            "an unreadable /proc entry must not destroy a live session"
        );
    }
}

/// The web half of the identity model: a token minted for one origin must not
/// be usable by another, and a web grant must never satisfy a native one.
///
/// These are the same guarantees `peer_binding_tests` asserts for binaries.
/// They are worth stating separately because the two identities travel by
/// different routes — a binary is resolved from the kernel, an origin is
/// carried on [`PeerInfo::web_origin`] after the allowlist check — and a
/// regression in either direction would be silent.
#[cfg(test)]
mod web_binding_tests {
    use super::{PeerInfo, TokenStore, reason, verify_peer_binding};
    use crate::auth::identity::PeerIdentity;

    /// A `PeerInfo` as the origin gate leaves it once `origin` has passed the
    /// user's allowlist.
    fn gated(origin: &str) -> PeerInfo {
        let mut peer = PeerInfo::tcp();
        peer.web_origin = Some(origin.to_string());
        peer
    }

    #[test]
    fn a_token_minted_for_one_origin_is_refused_to_another() {
        let store = TokenStore::default();
        let granted = PeerIdentity::web("http://127.0.0.1:8910");
        let (token, _) = store.mint("Docs", &["settings".to_string()], &granted);
        let meta = store.validate(&token).expect("freshly minted token");

        assert_eq!(
            verify_peer_binding(&store, Some(&gated("http://127.0.0.1:8910")), &meta, &token),
            Ok(()),
            "the origin the user approved still matches"
        );
        assert_eq!(
            verify_peer_binding(&store, Some(&gated("http://127.0.0.1:9999")), &meta, &token),
            Err(reason::EXE_CHANGED),
            "a second allowlisted origin must not inherit the first one's session"
        );
    }

    /// Both origins being on the allowlist is what makes this worth asserting:
    /// passing the gate is permission to *ask*, not permission to use whatever
    /// token happens to be lying around.
    #[test]
    fn a_web_caller_never_satisfies_a_native_grant() {
        let store = TokenStore::default();
        let native = PeerIdentity::native("/usr/local/bin/super-stt-app");
        let (token, _) = store.mint("App", &["settings".to_string()], &native);
        let meta = store.validate(&token).expect("freshly minted token");

        assert_eq!(
            verify_peer_binding(&store, Some(&gated("http://127.0.0.1:8910")), &meta, &token),
            Err(reason::EXE_CHANGED),
            "a page must not present a token granted to a binary"
        );
    }

    /// The mirror image: a page's token is no use to a process on the socket,
    /// which is the direction that would matter if a token ever leaked out of a
    /// browser into a local process.
    #[test]
    fn a_native_caller_never_satisfies_a_web_grant() {
        let store = TokenStore::default();
        let web = PeerIdentity::web("http://127.0.0.1:8910");
        let (token, _) = store.mint("Docs", &["settings".to_string()], &web);
        let meta = store.validate(&token).expect("freshly minted token");

        // This very test process, which is a real resolvable binary.
        let peer = PeerInfo::unix(Some(std::process::id()), None);
        assert_eq!(
            verify_peer_binding(&store, Some(&peer), &meta, &token),
            Err(reason::EXE_CHANGED),
            "a binary must not present a token granted to a web origin"
        );
    }

    /// A TCP connection that never passed the origin gate carries no identity,
    /// so it cannot be shown to be anyone — the fail-closed case.
    #[test]
    fn an_ungated_tcp_peer_cannot_be_identified() {
        let store = TokenStore::default();
        let web = PeerIdentity::web("http://127.0.0.1:8910");
        let (token, _) = store.mint("Docs", &["settings".to_string()], &web);
        let meta = store.validate(&token).expect("freshly minted token");

        assert_eq!(
            verify_peer_binding(&store, Some(&PeerInfo::tcp()), &meta, &token),
            Err(reason::UNKNOWN),
            "no origin and no credentials means no identity"
        );
        assert!(
            store.validate(&token).is_ok(),
            "an unidentifiable caller must not destroy a live session"
        );
    }
}

/// The guards as a router runs them: what each lets through, and what it
/// answers when it does not.
#[cfg(test)]
mod guard_tests {
    use super::{require_allowed_origin, require_scope, require_status_scope};
    use crate::auth::Auth;
    use crate::auth::identity::resolve_peer_identity;
    use crate::http::PeerInfo;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use tower::ServiceExt as _;

    /// Send `request` through `router` as the caller `peer`; the status and body
    /// that come back.
    async fn call(router: Router, peer: PeerInfo, request: Request<Body>) -> (StatusCode, String) {
        let response = router
            .layer(axum::Extension(peer))
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body reads");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn origin_gated(auth: &Auth) -> Router {
        Router::new()
            .route("/", get(|| async { "reached" }))
            .layer(from_fn_with_state(auth.clone(), require_allowed_origin))
    }

    fn get_from(origin: Option<&str>) -> Request<Body> {
        let mut request = Request::get("/");
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        request.body(Body::empty()).expect("request builds")
    }

    /// A page from an origin the user never listed is refused before it
    /// reaches anything, consent dialog included.
    #[tokio::test]
    async fn an_unlisted_origin_is_refused_on_tcp() {
        let auth = Auth::for_tests(&["http://127.0.0.1:8910"]);
        let (status, body) = call(
            origin_gated(&auth),
            PeerInfo::tcp(),
            get_from(Some("https://example.test")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("origin_not_allowed"), "{body}");
    }

    /// A listed origin gets through, and is told so in the CORS headers.
    #[tokio::test]
    async fn a_listed_origin_reaches_the_route() {
        let auth = Auth::for_tests(&["http://127.0.0.1:8910"]);
        let response = origin_gated(&auth)
            .layer(axum::Extension(PeerInfo::tcp()))
            .oneshot(get_from(Some("http://127.0.0.1:8910")))
            .await
            .expect("the router answers");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "http://127.0.0.1:8910"
        );
    }

    /// The allowlist is the TCP listener's: a Unix peer's identity comes from
    /// the kernel, so an `Origin` header it sends changes nothing.
    #[tokio::test]
    async fn a_unix_peer_is_not_origin_gated() {
        let auth = Auth::for_tests(&[]);
        let (status, body) = call(
            origin_gated(&auth),
            PeerInfo::unix(Some(1), Some(1000)),
            get_from(Some("https://example.test")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, "reached");
    }

    fn scope_gated(auth: &Auth) -> Router {
        Router::new()
            .route("/", get(|| async { "reached" }))
            .layer(from_fn_with_state(auth.clone(), require_status_scope))
    }

    fn get_with_token(token: &str) -> Request<Body> {
        Request::get("/")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request builds")
    }

    /// This test process, as the Unix socket would name it.
    fn self_peer() -> PeerInfo {
        PeerInfo::unix(Some(std::process::id()), None)
    }

    #[tokio::test]
    async fn no_token_is_an_invalid_session() {
        let auth = Auth::for_tests(&[]);
        let request = Request::get("/").body(Body::empty()).expect("builds");
        let (status, body) = call(scope_gated(&auth), self_peer(), request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(body.contains("invalid_session"), "{body}");
    }

    /// A valid token held by the caller it was minted for, but for another
    /// scope: refused with `scope_denied`, not `invalid_session`, so the
    /// client knows to ask for the scope rather than for a new token.
    #[tokio::test]
    async fn a_token_without_the_scope_is_denied() {
        let auth = Auth::for_tests(&[]);
        let me = resolve_peer_identity(Some(&self_peer()), "guard_tests").expect("identifiable");
        let (token, _) = auth.tokens().mint("Test", &["settings".to_string()], &me);
        let (status, body) = call(scope_gated(&auth), self_peer(), get_with_token(&token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("scope_denied"), "{body}");
    }

    #[tokio::test]
    async fn a_token_with_the_scope_reaches_the_route() {
        let auth = Auth::for_tests(&[]);
        let me = resolve_peer_identity(Some(&self_peer()), "guard_tests").expect("identifiable");
        let (token, _) = auth.tokens().mint("Test", &["status".to_string()], &me);
        let (status, body) = call(scope_gated(&auth), self_peer(), get_with_token(&token)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, "reached");
    }

    /// A product's own scope goes through [`require_scope`] the same way.
    #[tokio::test]
    async fn a_product_scope_is_checked_by_name() {
        let auth = Auth::for_tests(&[]);
        let me = resolve_peer_identity(Some(&self_peer()), "guard_tests").expect("identifiable");
        let (token, _) = auth.tokens().mint("Test", &["transcribe".to_string()], &me);
        let router =
            Router::new()
                .route("/", get(|| async { "reached" }))
                .layer(from_fn_with_state(
                    auth.clone(),
                    |axum::extract::State(auth): axum::extract::State<Auth>,
                     headers,
                     request,
                     next| async move {
                        require_scope("transcribe", auth, headers, request, next).await
                    },
                ));
        let (status, body) = call(router, self_peer(), get_with_token(&token)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

/// [`refuse`] reads what the refused caller is still sending, up to its limit.
#[cfg(test)]
mod refuse_tests {
    use super::{REFUSED_BODY_DRAIN_LIMIT, refuse};
    use axum::body::Body;
    use axum::extract::Request;
    use axum::response::IntoResponse;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const CHUNK: usize = 64 * 1024;

    /// A request whose body is `chunks` chunks of [`CHUNK`] bytes, and a
    /// count of how many bytes anything has read out of it.
    fn counted_request(chunks: usize) -> (Request<Body>, Arc<AtomicUsize>) {
        let read = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&read);
        let stream = futures_util::stream::iter((0..chunks).map(move |_| {
            counter.fetch_add(CHUNK, Ordering::SeqCst);
            Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; CHUNK]))
        }));
        let request = Request::builder()
            .body(Body::from_stream(stream))
            .expect("request builds");
        (request, read)
    }

    /// The case the drain exists for: a body well past a socket buffer is
    /// read to the end, so the refusal can be written back rather than the
    /// connection reset under the client's upload.
    #[tokio::test]
    async fn a_refused_body_is_read_to_the_end() {
        let (request, read) = counted_request(16); // 1 MiB
        let response = refuse(request, "refused".into_response()).await;
        assert_eq!(read.load(Ordering::SeqCst), 16 * CHUNK);
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    /// A caller already refused is not owed an endless read: past the limit
    /// the daemon stops, and the connection closes as it did before.
    #[tokio::test]
    async fn a_refused_body_is_read_no_further_than_the_limit() {
        let (request, read) = counted_request(4 * REFUSED_BODY_DRAIN_LIMIT / CHUNK);
        let _ = refuse(request, "refused".into_response()).await;
        assert_eq!(read.load(Ordering::SeqCst), REFUSED_BODY_DRAIN_LIMIT);
    }
}
