// SPDX-License-Identifier: GPL-3.0-only
//! The error bodies the auth guards answer with.
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Canonical error response builder for the `{ "status": "error",
/// "error_code": <code>, "message": <code>, "data": { "reason": <reason> } }`
/// shape.
///
/// All error responses that carry a `data.reason` field route through
/// this function so the JSON shape is defined in exactly one place.
///
/// `code` is both the `error_code` every error carries, which clients switch
/// on, and the `message`, where clients older than `error_code` look for it.
#[must_use]
pub fn error_response(status: StatusCode, code: &str, reason: &str) -> Response {
    let body = serde_json::json!({
        "status":     "error",
        "error_code": code,
        "message":    code,
        "data":       { "reason": reason }
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
    /// An assistant key was presented by a caller other than the assistant
    /// route it is for: over the Unix socket, or from a browser page. The key
    /// is refused there but not revoked, so the assistant holding it keeps
    /// working.
    pub const WRONG_CALLER: &str = "wrong_caller";

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
    /// A request on an assistant route arrived over TCP with an `Origin`, so
    /// it came from a browser page. Assistant routes are for programs that
    /// present an assistant key, and a page is refused there whatever key it
    /// holds.
    pub const BROWSER_NOT_ALLOWED: &str = "browser_not_allowed";
    /// A request on an assistant route arrived over TCP with a `Host` that is
    /// not `127.0.0.1`, `localhost` or `[::1]`. The listener is on the
    /// loopback interface, so any other host is a name pointed at it from
    /// outside, as DNS rebinding does.
    pub const HOST_NOT_ALLOWED: &str = "host_not_allowed";
}

#[must_use]
pub fn invalid_session(reason: &'static str) -> Response {
    error_response(StatusCode::UNAUTHORIZED, "invalid_session", reason)
}

#[must_use]
pub fn scope_denied() -> Response {
    // The identifier twice, as in `error_response`.
    let body = serde_json::json!({
        "status":     "error",
        "error_code": "scope_denied",
        "message":    "scope_denied",
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
        "status":     "error",
        "error_code": "rate_limited",
        "message":    "rate_limited",
    });
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

#[must_use]
pub fn auth_err(status: StatusCode, code: &str, reason: &str) -> Response {
    error_response(status, code, reason)
}

#[cfg(test)]
mod tests {
    use super::{StatusCode, auth_err, invalid_session, rate_limited, reason, scope_denied};
    use axum::response::Response;

    async fn body_of(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body");
        serde_json::from_slice(&bytes).expect("a JSON body")
    }

    /// Every auth error carries its identifier as `error_code`, the field the
    /// contract says every error has, and still as `message`, where clients
    /// older than `error_code` look for it.
    #[tokio::test]
    async fn auth_errors_carry_their_code_in_both_fields() {
        for (resp, code) in [
            (invalid_session(reason::UNKNOWN), "invalid_session"),
            (scope_denied(), "scope_denied"),
            (rate_limited(), "rate_limited"),
            (
                auth_err(StatusCode::FORBIDDEN, "auth_denied", reason::USER_DENIED),
                "auth_denied",
            ),
        ] {
            let body = body_of(resp).await;
            assert_eq!(body["status"], "error", "{body}");
            assert_eq!(body["error_code"], code, "{body}");
            assert_eq!(body["message"], code, "{body}");
        }
    }
}
