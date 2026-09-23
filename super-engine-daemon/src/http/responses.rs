// SPDX-License-Identifier: GPL-3.0-only
//! The error bodies the auth guards answer with.
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Canonical error response builder for the `{ "status": "error",
/// "message": <message>, "data": { "reason": <reason> } }` shape.
///
/// All error responses that carry a `data.reason` field route through
/// this function so the JSON shape is defined in exactly one place.
#[must_use]
pub fn error_response(status: StatusCode, message: &str, reason: &str) -> Response {
    let body = serde_json::json!({
        "status":  "error",
        "message": message,
        "data":    { "reason": reason }
    });
    (
        status,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Wire-level `reason` string constants used in `data.reason` fields.
/// Values are the exact `snake_case` strings the protocol specifies;
/// callers MUST use these rather than inline literals.
pub mod reason {
    // invalid_session reasons
    pub const UNKNOWN: &str = "unknown";
    /// The caller is no longer the one the token was minted for: a binary
    /// whose `/proc/<pid>/exe` changed, or a different web origin.
    /// `docs/protocol/auth.md` specifies this as a *per-request* outcome ("the
    /// next request returns `401 invalid_session` with reason `exe_changed`"),
    /// not just the `/events` exe-watch's 30 s tick. The name says `exe`
    /// because that was the only grantee kind when it was written.
    pub const EXE_CHANGED: &str = "exe_changed";

    // auth_denied reasons
    pub const INVALID_BODY: &str = "invalid_body";
    pub const INVALID_SCOPE: &str = "invalid_scope";
    pub const UID_MISMATCH: &str = "uid_mismatch";
    pub const USER_DENIED_CACHED: &str = "user_denied_cached";
    pub const USER_DENIED: &str = "user_denied";
    pub const USER_DISMISSED: &str = "user_dismissed";
    pub const POPUP_FAILED: &str = "popup_failed";
    /// The daemon could not resolve the peer's executable (`SO_PEERCRED`/pid
    /// missing, or `/proc/<pid>/exe` unreadable), so it can't verify *which*
    /// binary is asking — consent requires a verifiable binary, so it fails
    /// closed (audit 2 Tier 3 #9).
    pub const PEER_UNVERIFIABLE: &str = "peer_unverifiable";
    /// A request on the TCP listener sent no `Origin`, or sent one the user has
    /// not put in `[http.tcp].allowed_origins`. It is the TCP counterpart of
    /// [`UID_MISMATCH`]: on the Unix socket the kernel says who is calling, and
    /// here the allowlist is the only thing that does.
    pub const ORIGIN_NOT_ALLOWED: &str = "origin_not_allowed";
}

#[must_use]
pub fn invalid_session(reason: &'static str) -> Response {
    error_response(StatusCode::UNAUTHORIZED, "invalid_session", reason)
}

#[must_use]
pub fn scope_denied() -> Response {
    let body = serde_json::json!({
        "status":  "error",
        "message": "scope_denied",
    });
    (
        StatusCode::FORBIDDEN,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

#[must_use]
pub fn rate_limited() -> Response {
    let body = serde_json::json!({
        "status":  "error",
        "message": "rate_limited",
    });
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

#[must_use]
pub fn auth_err(status: StatusCode, message: &str, reason: &str) -> Response {
    error_response(status, message, reason)
}
