// SPDX-License-Identifier: GPL-3.0-only
//! `POST /v1/auth/request` and `GET /v1/auth/status`: getting a token, and
//! checking the one held.
//!
//! A daemon registers these with `utoipa_axum::routes!`, which reads each
//! path back off its `#[utoipa::path]`:
//!
//! ```ignore
//! .routes(routes!(super_engine_daemon::auth::routes::auth_request))
//! ```
//!
//! The `429` and `ErrorEnvelope` bodies they document refer to the daemon's
//! own `ErrorEnvelope` schema by name, since its `error_code` enum is the
//! product's.

use crate::auth::Auth;
use crate::auth::consent::{
    ConsentDecision, ConsentKey, ask_user_for_consent, is_official_client, normalize_scopes,
};
use crate::auth::identity::{PeerIdentity, resolve_peer_identity};
use crate::auth::middleware::AuthContext;
use crate::http::PeerInfo;
use crate::http::responses::{auth_err, invalid_session, reason};
use crate::http::wire::ReasonEnvelope;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super_engine_protocol::scopes::is_known_scope;

#[derive(Deserialize, Debug, utoipa::ToSchema)]
pub struct AuthRequestBody {
    /// The name shown to the user in the consent popup. Self-reported and
    /// therefore untrusted: the daemon identifies you by your binary, and a
    /// previous denial sticks to that binary whatever name you send next.
    #[schema(example = "My App")]
    pub app_name: String,
    /// The scopes to request, at least one. Every entry must be known or the
    /// whole request is refused; ask only for what you need, since the user
    /// sees the list.
    #[schema(example = json!(["status", "settings"]))]
    pub scopes: Vec<String>,
    /// Your app's version. Accepted for forwards compatibility; unused today.
    #[serde(default)]
    #[schema(example = "0.1")]
    pub version: Option<String>,
}

/// A freshly minted session token.
#[derive(Serialize, utoipa::ToSchema)]
pub struct AuthOk {
    /// Always `success`.
    #[schema(example = "success")]
    pub status: &'static str,
    /// Send this as `Authorization: Bearer <token>` on every other endpoint.
    /// Bound to the approved binary — it stops working if that binary changes
    /// on disk.
    pub session_token: String,
    /// The scopes actually granted, sorted and deduplicated.
    pub scopes: Vec<String>,
    /// RFC 3339 expiry, 30 days out.
    pub expires_at: String,
}

/// `403 user_denied_cached` if the user previously clicked Deny for this exact
/// `(identity, scopes)` pair in this daemon's lifetime, else `None`. Checked both
/// up front and again under the consent lock (a concurrent caller may have been
/// denied while we queued behind their popup); `context` labels which.
fn cached_deny_response(auth: &Auth, consent_key: &ConsentKey, context: &str) -> Option<Response> {
    if !auth.deny_cache().contains(consent_key) {
        return None;
    }
    let (identity, scopes) = consent_key;
    log::info!(
        "auth_request denied from cache ({context}): caller={} scopes={}",
        identity.describe(),
        scopes.join(" ")
    );
    Some(auth_err(
        StatusCode::FORBIDDEN,
        "auth_denied",
        reason::USER_DENIED_CACHED,
    ))
}

/// `403 uid_mismatch` when the caller is a process belonging to another user,
/// else `None`.
///
/// Checked BEFORE spawning a popup or touching consent state. Socket perms
/// `0o660` + the product's group mean a second user in that group can otherwise pop
/// dialogs on the daemon owner's desktop in another app's name. `peer_cred` is
/// `None` only on platforms without `SO_PEERCRED` — treated as fail-closed,
/// since we expect Linux.
///
/// A web caller is exempt because there is no uid to compare, not because the
/// check is optional: it has already passed the origin allowlist, which is the
/// gate that stands in for this one on the TCP listener. The exemption keys off
/// the request's *own* validated origin rather than a header, so a Unix peer
/// cannot claim it by sending an `Origin`.
fn reject_foreign_uid(peer: Option<&PeerInfo>) -> Option<Response> {
    if peer.is_some_and(|p| p.web_origin.is_some()) {
        return None;
    }
    let daemon_uid = unsafe { libc::geteuid() };
    match peer.and_then(|p| p.uid) {
        Some(uid) if uid == daemon_uid => None,
        Some(uid) => {
            log::warn!(
                "auth_request rejected: peer uid {uid} differs from daemon uid {daemon_uid}"
            );
            Some(auth_err(
                StatusCode::FORBIDDEN,
                "auth_denied",
                reason::UID_MISMATCH,
            ))
        }
        None => {
            log::warn!("auth_request rejected: peer uid unavailable");
            Some(auth_err(
                StatusCode::FORBIDDEN,
                "auth_denied",
                reason::UID_MISMATCH,
            ))
        }
    }
}

/// First-party short-circuit for `auth_request`: a trusted co-located
/// client binary skips the popup and mints immediately. `None` means
/// the peer is not first-party and the normal consent flow proceeds.
fn official_client_response(
    auth: &Auth,
    body: &AuthRequestBody,
    scopes: &[String],
    identity: &PeerIdentity,
    consent_key: ConsentKey,
    ok_response: &dyn Fn(String, DateTime<Utc>) -> Response,
) -> Option<Response> {
    if !is_official_client(auth.product(), identity) {
        return None;
    }
    log::info!(
        "auth_request auto-approved for first-party client: app={} caller={} scopes={}",
        body.app_name,
        identity.describe(),
        scopes.join(" ")
    );
    Some(finalize_consent_decision(
        ConsentDecision::Allow,
        auth,
        body,
        scopes,
        identity,
        consent_key,
        ok_response,
    ))
}

#[utoipa::path(
    post,
    path = "/auth/request",
    tag = "auth",
    summary = "Ask the user for a session token",
    description = "\
The consent handshake, and the only endpoint reachable without a token.

The daemon reads `SO_PEERCRED` on your connection, resolves `/proc/<pid>/exe`, and \
shows the user a popup naming that binary and the scopes you asked for. On Allow it \
mints a 32-byte token bound to that binary and valid for 30 days.

A denial is remembered for the `(binary, scopes)` pair for the rest of the daemon's \
lifetime and answers `403` immediately without re-prompting — renaming your app does \
not clear it, since the key is the binary. Restarting the daemon does.

Do not call this to find out whether a token you already hold is still good: that is \
`GET /auth/status`, which never prompts.

Setting the product's `AUTO_APPROVE` variable to `1` in the daemon's environment \
(`SUPER_STT_AUTO_APPROVE` for Super STT, `SUPER_TTS_AUTO_APPROVE` for Super TTS) skips \
the popup entirely; it is honored only in debug builds, for tests and CI, so a stray \
environment variable cannot defeat the consent gate in a shipped binary.",
    request_body = AuthRequestBody,
    responses(
        (status = 200, description = "The user approved. Store the token.", body = AuthOk),
        (status = 400, description = "Body was missing or malformed (`invalid_body`), or `scopes` was empty or named an unknown scope (`invalid_scope`).", body = ReasonEnvelope),
        (status = 403, description = "\
The user denied or dismissed the popup (`user_denied`, `user_dismissed`), a previous \
denial for this binary and scope set still stands (`user_denied_cached`), the \
connecting user is not the daemon's own (`uid_mismatch`), the daemon could not \
resolve your binary and so refused to identify you (`peer_unverifiable`), or the \
popup could not be shown (`popup_failed`).", body = ReasonEnvelope),
        (status = 429, description = "Per-client rate limit hit; back off and retry.", body = ref("#/components/schemas/ErrorEnvelope")),
    ),
)]
pub async fn auth_request(
    State(auth): State<Auth>,
    peer: Option<axum::Extension<PeerInfo>>,
    body: Option<axum::Json<AuthRequestBody>>,
) -> Response {
    let Some(axum::Json(body)) = body else {
        return auth_err(StatusCode::BAD_REQUEST, "auth_denied", reason::INVALID_BODY);
    };

    // Validate the requested scope set: non-empty and every entry a known
    // scope. Normalize (sort + dedup) so the consent key and granted set
    // don't depend on the order the client listed them.
    if body.scopes.is_empty()
        || !body
            .scopes
            .iter()
            .all(|s| is_known_scope(auth.product(), s))
    {
        return auth_err(
            StatusCode::BAD_REQUEST,
            "auth_denied",
            reason::INVALID_SCOPE,
        );
    }
    let scopes = normalize_scopes(&body.scopes);

    if let Some(rejection) = reject_foreign_uid(peer.as_ref().map(|p| &p.0)) {
        return rejection;
    }

    // Resolve the calling binary via /proc/<pid>/exe. If it can't be resolved
    // (missing peer credentials/pid, or a kernel/proc permission denial), fail
    // closed: consent verifies a *binary*, so we refuse rather than prompt with
    // an unverifiable `<unknown>` identity or mint a token bound to it (audit 2
    // Tier 3 #9). Each failure mode is logged inside `resolve_peer_exe`.
    let Some(identity) = resolve_peer_identity(peer.as_ref().map(|p| &p.0), "auth_request") else {
        log::warn!("auth_request rejected: could not verify the requesting binary (fail-closed)");
        return auth_err(
            StatusCode::FORBIDDEN,
            "auth_denied",
            reason::PEER_UNVERIFIABLE,
        );
    };

    // Helper to build the success response for a (token, expires_at)
    // pair. Used by both reuse-scan paths (fast and slow) and the
    // post-mint path so they all serialize the same JSON shape.
    let ok_response = |token: String, expires_at: DateTime<Utc>| -> Response {
        let payload = AuthOk {
            status: "success",
            session_token: token,
            scopes: scopes.clone(),
            expires_at: expires_at.to_rfc3339(),
        };
        (
            StatusCode::OK,
            [("content-type", "application/json")],
            serde_json::to_string(&payload).unwrap_or_default(),
        )
            .into_response()
    };

    // `auth_request` always runs the consent flow — no token
    // validation, no identity-only reuse. Clients that have a valid
    // cached token never reach this endpoint; they go straight to
    // `/ping`/`/events`/etc., where the bearer header is validated
    // by `TokenStore::validate`. Clients that hit `auth_request`
    // do so precisely because they need a fresh token, and the
    // consistent semantic is "request fresh consent".

    let consent_key: ConsentKey = (identity.clone(), scopes.clone());

    // First-party binaries co-located with the daemon skip the popup
    // (docs/protocol/auth.md § First-party clients); downstream is
    // identical to a popup-approved grant. See `is_official_client`
    // for the trust rationale.
    if let Some(resp) = official_client_response(
        &auth,
        &body,
        &scopes,
        &identity,
        consent_key.clone(),
        &ok_response,
    ) {
        return resp;
    }

    // Sticky-deny short-circuit. If the user previously clicked Deny for this
    // exact (exe_path, scope) pair in this daemon's lifetime, reject immediately
    // without spawning another popup. The cache is cleared by daemon restart;
    // there's no other reset path on purpose. `app_name` is not part of the key
    // because a misbehaving client could otherwise rotate it to bypass deny.
    if let Some(resp) = cached_deny_response(&auth, &consent_key, "user previously denied") {
        return resp;
    }

    // Serialize concurrent first-time requests for the same identity
    // so we don't spawn N consent popups when N clients race. Each
    // racer still gets its own popup, but they happen one at a time
    // rather than stacking on screen. The lock entry is released by
    // `ConsentLocks::release` after the flow completes so the
    // registry doesn't grow unboundedly.
    let lock = auth.consent_locks().lock_for(consent_key.clone());
    let response = {
        let _guard = lock.lock().await;

        // Re-check the deny cache: a concurrent caller for the same pair may
        // have been denied while we were queued behind their popup.
        if let Some(resp) = cached_deny_response(&auth, &consent_key, "concurrent caller denied") {
            resp
        } else {
            // Auto-approve if the daemon is in test/CI mode. Honored only in
            // debug builds: compiled out of release so a stray/injected env var
            // can't silently defeat the human consent gate in a shipped binary
            // (audit 2 Tier 1 #6; mirrors the #30 consent-timer release gating).
            let auto_approve_env = auth.product().env(super::AUTO_APPROVE);
            #[cfg(debug_assertions)]
            let auto_approve = std::env::var(&auto_approve_env).is_ok_and(|v| v == "1");
            #[cfg(not(debug_assertions))]
            let auto_approve = false;

            let decision = if auto_approve {
                log::info!(
                    "{auto_approve_env}=1 set; auto-approving auth_request for {} ({})",
                    body.app_name,
                    identity.describe()
                );
                ConsentDecision::Allow
            } else {
                ask_user_for_consent(auth.dialog(), &body.app_name, &scopes, &identity).await
            };

            finalize_consent_decision(
                decision,
                &auth,
                &body,
                &scopes,
                &identity,
                consent_key.clone(),
                &ok_response,
            )
        }
    };

    // Prune the consent-locks registry entry. If another in-flight
    // auth_request is still waiting on the same key, `release` keeps
    // the entry; once everyone is done it gets removed.
    auth.consent_locks().release(&consent_key, &lock);

    response
}

/// Resolve a [`ConsentDecision`] into the matching HTTP response,
/// folding in the side effects each branch needs (token mint on
/// Allow, deny-cache insert on Deny). Extracted out of `auth_request`
/// to keep that handler under the workspace's clippy line cap.
fn finalize_consent_decision(
    decision: ConsentDecision,
    auth: &Auth,
    body: &AuthRequestBody,
    scopes: &[String],
    identity: &PeerIdentity,
    consent_key: ConsentKey,
    ok_response: &dyn Fn(String, DateTime<Utc>) -> Response,
) -> Response {
    match decision {
        ConsentDecision::Allow => {
            let (token, expires_at) = auth.tokens().mint(&body.app_name, scopes, identity);
            log::info!(
                "auth_request approved: app={} scopes={}",
                body.app_name,
                scopes.join(" ")
            );
            ok_response(token, expires_at)
        }
        ConsentDecision::Deny => {
            // Sticky: remember this (exe, scopes) pair so the next
            // request from the same binary is auto-denied without
            // re-prompting. In-memory only — daemon restart resets.
            log::info!(
                "auth_request denied by user; caching deny for app={} scopes={}",
                body.app_name,
                scopes.join(" ")
            );
            auth.deny_cache().insert(consent_key);
            auth_err(StatusCode::FORBIDDEN, "auth_denied", reason::USER_DENIED)
        }
        ConsentDecision::Dismissed => {
            // *Don't* cache Dismissed (e.g. user closed the popup
            // without making a choice, the helper crashed, etc.).
            // Treat as transient — the next request gets a fresh
            // popup.
            auth_err(StatusCode::FORBIDDEN, "auth_denied", reason::USER_DISMISSED)
        }
        ConsentDecision::PopupFailed => {
            auth_err(StatusCode::FORBIDDEN, "auth_denied", reason::POPUP_FAILED)
        }
    }
}

/// What the token currently held is good for.
#[derive(Serialize, utoipa::ToSchema)]
pub struct AuthStatusOk {
    /// Always `success`.
    #[schema(example = "success")]
    pub status: &'static str,
    /// The scopes the token was minted under.
    #[schema(example = json!(["status", "settings"]))]
    pub scopes: Vec<String>,
    /// RFC 3339 expiry, so a headless client can renew before it lapses.
    pub expires_at: String,
}

/// `GET /v1/auth/status` — no-side-effect probe that the bearer token
/// is still valid. The `require_any_authenticated` middleware has
/// already validated the token and inserted [`AuthContext`] into the
/// request extensions by the time this handler runs, so reaching the
/// handler at all means the token was good. The handler reports back
/// the scope set it was minted under and the expiry timestamp so a
/// headless / CLI client can fail-fast on a soon-to-expire token
/// without invoking the consent UI.
///
/// Errors (`401 invalid_session` with `data.reason` of `unknown`,
/// `expired`, or `exe_changed`) are produced upstream by
/// `require_any_authenticated` before this handler runs.
#[utoipa::path(
    get,
    path = "/auth/status",
    tag = "auth",
    summary = "Check the held token without prompting",
    description = "\
Reports what the presented token is good for, and never opens a consent popup — \
which is what makes it the right probe for a headless or CLI client. Reaching this \
handler at all means the token validated.

Use it to fail fast on a token about to expire, rather than discovering it \
mid-operation. `GET /ping` proves the daemon is up; this proves the token still is.",
    security(("session_token" = [])),
    responses(
        (status = 200, description = "The token is valid.", body = AuthStatusOk),
        (status = 401, description = "Token unknown, expired, or its binary changed — re-run the consent handshake.", body = ReasonEnvelope),
        (status = 429, description = "Per-client rate limit hit; back off and retry.", body = ref("#/components/schemas/ErrorEnvelope")),
    ),
)]
#[allow(
    clippy::unused_async,
    reason = "an axum handler; a daemon's router is what calls it"
)]
pub async fn auth_status(ctx: Option<axum::Extension<AuthContext>>) -> Response {
    let Some(axum::Extension(ctx)) = ctx else {
        return invalid_session(reason::UNKNOWN);
    };
    let payload = AuthStatusOk {
        status: "success",
        scopes: ctx.meta.scopes.clone(),
        expires_at: ctx.meta.expires_at.to_rfc3339(),
    };
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::to_string(&payload).unwrap_or_default(),
    )
        .into_response()
}
