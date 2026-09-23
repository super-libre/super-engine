// SPDX-License-Identifier: GPL-3.0-only
use super::error::{HttpError, HttpResult};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use serde::de::DeserializeOwned;

/// All endpoints are served under the `/v1` URL prefix. The request
/// builders below prepend this automatically, so call sites use bare
/// paths like `/ping`, `/transcribe`, `/events` — the actual
/// URL on the wire is `/v1/ping`, `/v1/transcribe`, etc.
pub(crate) const API_PREFIX: &str = "/v1";

/// The host every request names. HTTP/1.1 requires one, and over a Unix
/// socket there is no host to name, so this is the one `curl --unix-socket`
/// sends. The daemon does not read it, which is what lets one client serve
/// both products without being told which it is talking to.
pub(crate) const HOST: &str = "localhost";

/// Body type so a GET/DELETE (empty) and a POST (JSON) share one hyper request
/// type. `http_body_util::Either` supplies the `Body` impl — both arms are
/// `Bytes` bodies with an `Infallible` error — replacing a hand-rolled `unsafe`
/// pin projection (this crate's only `unsafe`).
pub(crate) type RequestBody = http_body_util::Either<Empty<Bytes>, Full<Bytes>>;

pub(crate) fn build_get(path: &str, token: Option<&str>) -> Result<Request<RequestBody>, String> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{HOST}{API_PREFIX}{path}"))
        .header("host", HOST);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder
        .body(http_body_util::Either::Left(Empty::new()))
        .map_err(|e| format!("Failed to build request: {e}"))
}

pub(crate) fn build_post_json(
    path: &str,
    body: &serde_json::Value,
    token: Option<&str>,
) -> Result<Request<RequestBody>, String> {
    let body_bytes = serde_json::to_vec(body).map_err(|e| format!("Failed to encode body: {e}"))?;
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{HOST}{API_PREFIX}{path}"))
        .header("host", HOST)
        .header("content-type", "application/json")
        .header("content-length", body_bytes.len().to_string());
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder
        .body(http_body_util::Either::Right(Full::new(Bytes::from(
            body_bytes,
        ))))
        .map_err(|e| format!("Failed to build request: {e}"))
}

pub(crate) fn build_post_bytes(
    path: &str,
    content_type: &str,
    body: Vec<u8>,
    token: Option<&str>,
) -> Result<Request<RequestBody>, String> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{HOST}{API_PREFIX}{path}"))
        .header("host", HOST)
        .header("content-type", content_type)
        .header("content-length", body.len().to_string());
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder
        .body(http_body_util::Either::Right(Full::new(Bytes::from(body))))
        .map_err(|e| format!("Failed to build request: {e}"))
}

pub(crate) fn build_patch_json(
    path: &str,
    body: &serde_json::Value,
    token: Option<&str>,
) -> Result<Request<RequestBody>, String> {
    let body_bytes = serde_json::to_vec(body).map_err(|e| format!("Failed to encode body: {e}"))?;
    let mut builder = Request::builder()
        .method(Method::PATCH)
        .uri(format!("http://{HOST}{API_PREFIX}{path}"))
        .header("host", HOST)
        .header("content-type", "application/json")
        .header("content-length", body_bytes.len().to_string());
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder
        .body(http_body_util::Either::Right(Full::new(Bytes::from(
            body_bytes,
        ))))
        .map_err(|e| format!("Failed to build request: {e}"))
}

pub(crate) fn build_delete(
    path: &str,
    token: Option<&str>,
) -> Result<Request<RequestBody>, String> {
    let mut builder = Request::builder()
        .method(Method::DELETE)
        .uri(format!("http://{HOST}{API_PREFIX}{path}"))
        .header("host", HOST);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder
        .body(http_body_util::Either::Left(Empty::new()))
        .map_err(|e| format!("Failed to build request: {e}"))
}

/// Extract the `data.reason` field from an error body, falling back to
/// `fallback` when the body is malformed or carries no reason.
pub(crate) fn parse_reason(body: &[u8], fallback: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    parsed
        .get("data")
        .and_then(|d| d.get("reason"))
        .and_then(|r| r.as_str())
        .unwrap_or(fallback)
        .to_string()
}

/// The `data.reason` of a 401 body. Centralized so the `invalid_session`
/// sites stay consistent.
pub(crate) fn parse_invalid_session_reason(body: &[u8]) -> String {
    parse_reason(body, "unknown")
}

/// **The** conversion from a non-success response to a typed [`HttpError`].
///
/// Every non-2xx path funnels through here so the rule lives in one place.
/// It previously did not: four call sites each re-derived it, and the typed
/// `send_request` path omitted the check entirely — handing error envelopes to
/// the success-type deserializer, which then blamed whichever success field it
/// found missing (a rate-limited uninstall surfaced as ``missing field
/// `uninstalled` at line 1 column 43``).
///
/// `401` keeps its own variant because callers re-authenticate on it; every
/// other status is an operational failure described by [`daemon_error`].
///
/// Note `/auth/request` deliberately does *not* use this: a 4xx there means the
/// user declined consent, which is [`HttpError::AuthDenied`], not a daemon
/// error.
#[must_use]
pub fn error_for_status(status: hyper::StatusCode, body: &[u8]) -> HttpError {
    if status == hyper::StatusCode::UNAUTHORIZED {
        return HttpError::InvalidSession {
            reason: parse_invalid_session_reason(body),
        };
    }
    // A 403 is only a scope refusal when the daemon says so. Every other 403
    // — the registry's, or anything a future route adds — stays an
    // operational failure, because re-authenticating would not fix it and the
    // consent popup it would raise is worse than the error it replaces.
    if status == hyper::StatusCode::FORBIDDEN && names_scope_denied(body) {
        return HttpError::ScopeDenied;
    }
    daemon_error(status, body)
}

/// Whether a 403 body is the daemon's `scope_denied` envelope.
fn names_scope_denied(body: &[u8]) -> bool {
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    ["error_code", "error", "message"]
        .iter()
        .any(|key| parsed.get(key).and_then(serde_json::Value::as_str) == Some("scope_denied"))
}

/// Build an [`HttpError`] from a non-success, non-401 response body.
///
/// The daemon answers failures with one of several `{"status":"error", …}`
/// envelopes, all of which name the failure in `error_code` (the stable
/// machine identifier — `error` is the registry envelope's legacy spelling of
/// the same value) and/or `message` (human text). None of them share a shape
/// with any endpoint's success type, so a non-2xx body must be turned into an
/// error rather than deserialized.
///
/// Prefer [`error_for_status`] — it adds the `401` case. This is separate only
/// so the daemon's envelope-contract test can assert on the operational
/// mapping directly.
#[must_use]
pub fn daemon_error(status: hyper::StatusCode, body: &[u8]) -> HttpError {
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let field = |key: &str| {
        parsed
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let code = field("error_code").or_else(|| field("error"));
    let detail = match (code, field("message")) {
        // Envelopes that carry no human text set `message` to the code itself;
        // don't say it twice.
        (Some(code), Some(message)) if code == message => Some(code),
        (Some(code), Some(message)) => Some(format!("{code}: {message}")),
        (Some(text), None) | (None, Some(text)) => Some(text),
        (None, None) => None,
    };
    let status = status.as_u16();
    HttpError::Other(detail.map_or_else(
        || format!("daemon returned HTTP {status}"),
        |detail| format!("{detail} (HTTP {status})"),
    ))
}

/// Map non-success statuses on the `/events` subscribe call to the
/// typed [`HttpError`] surface (so the caller can `match` on
/// `InvalidSession` for re-auth) and pass through 2xx responses
/// unchanged.
pub(crate) async fn check_subscribe_status(
    response: hyper::Response<hyper::body::Incoming>,
) -> HttpResult<hyper::Response<hyper::body::Incoming>> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = collect_body(response).await?;
    Err(error_for_status(status, &body))
}

/// Upper bound on how long a **non-interactive** request waits for the
/// daemon's response headers. A daemon that accepts the connection but
/// never answers — e.g. wedged mid-startup, before its accept loop is
/// serving — would otherwise hang the caller forever. That is exactly how
/// a stuck daemon used to freeze the app's startup probe with no error.
///
/// Deliberately *not* applied to the consent-bearing `/auth/request`
/// (see [`open`]'s `timeout` param): that call is held open while a human
/// clicks Allow/Deny and may type a keyring password, so a machine timer
/// must never race it. Sized generously even for the machine calls so a
/// slow model reload still completes; a daemon that is simply *down*
/// fails fast at `connect()` and never reaches this bound.
pub(crate) const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// Open an HTTP/1.1 connection over a fresh Unix socket, run one request,
/// and return the streaming response. Shared by every call path.
///
/// `timeout` bounds the wait for the daemon's response headers. Pass
/// `Some(_)` for machine-to-machine calls so a wedged daemon can't hang
/// the caller forever. Pass `None` for `/auth/request`, which the daemon
/// legitimately holds open while the user responds to the consent popup
/// (and possibly a keyring-unlock prompt) — bounding it would cut the user
/// off mid-decision.
pub(crate) async fn open(
    socket_path: &std::path::PathBuf,
    req: hyper::Request<RequestBody>,
    timeout: Option<std::time::Duration>,
) -> HttpResult<hyper::Response<hyper::body::Incoming>> {
    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                HttpError::Other(
                    "Daemon HTTP listener not running. Start the daemon first.".to_string(),
                )
            }
            _ => HttpError::Other(format!("Connection failed: {e}")),
        })?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| HttpError::Other(format!("HTTP handshake failed: {e}")))?;
    let conn_task = tokio::spawn(async move {
        if let Err(e) = conn.await {
            // Hyper's own `Display` is a category — an I/O failure prints as
            // the bare "connection error" — and the thing worth reading is
            // always the source under it. Walk the chain, or this line says
            // nothing at all on the one day somebody reads it.
            use std::fmt::Write as _;
            let mut detail = e.to_string();
            let mut source = std::error::Error::source(&e);
            while let Some(cause) = source {
                let _ = write!(detail, ": {cause}");
                source = cause.source();
            }
            log::debug!("http connection ended: {detail}");
        }
    });
    // On success `conn_task` keeps driving the connection so the body
    // (incl. long-lived `/events` streams) can be read; on timeout we abort
    // it so a dead connection doesn't leak a background task.
    let send = sender.send_request(req);
    let result = match timeout {
        Some(dur) => match tokio::time::timeout(dur, send).await {
            Ok(result) => result,
            Err(_elapsed) => {
                conn_task.abort();
                return Err(HttpError::Other(format!(
                    "Daemon did not respond within {}s (it may be stuck or still starting up)",
                    dur.as_secs()
                )));
            }
        },
        None => send.await,
    };
    result.map_err(|e| HttpError::Other(format!("Request failed: {e}")))
}

/// Collect a response body to bytes.
pub(crate) async fn collect_body(
    response: hyper::Response<hyper::body::Incoming>,
) -> HttpResult<Bytes> {
    Ok(response
        .into_body()
        .collect()
        .await
        .map_err(|e| HttpError::Other(format!("Failed to read response: {e}")))?
        .to_bytes())
}

/// Run a request and deserialize the JSON body into `T`. `401` becomes
/// `HttpError::InvalidSession`.
pub(crate) async fn send_request<T: DeserializeOwned>(
    socket_path: &std::path::PathBuf,
    req: hyper::Request<RequestBody>,
) -> HttpResult<T> {
    send_request_with_timeout(socket_path, req, Some(REQUEST_TIMEOUT)).await
}

/// Like [`send_request`] but with a caller-chosen header timeout. Pass
/// `None` for a long-running call whose response the daemon only sends once
/// the work finishes — e.g. a model switch that streams multi-GB weights
/// first. The fixed [`REQUEST_TIMEOUT`] would otherwise abort the connection
/// mid-switch and cancel the daemon-side load; progress is observed
/// out-of-band via the `download_progress` SSE topic instead.
pub(crate) async fn send_request_with_timeout<T: DeserializeOwned>(
    socket_path: &std::path::PathBuf,
    req: hyper::Request<RequestBody>,
    timeout: Option<std::time::Duration>,
) -> HttpResult<T> {
    let response = open(socket_path, req, timeout).await?;
    let status = response.status();
    let body = collect_body(response).await?;
    // Only a 2xx body is an instance of `T`. Deserializing an error envelope
    // into the success type reports a missing success field instead of the
    // failure the daemon actually named — see [`error_for_status`].
    if !status.is_success() {
        return Err(error_for_status(status, &body));
    }
    serde_json::from_slice::<T>(&body)
        .map_err(|e| HttpError::Other(format!("Failed to parse response: {e}")))
}

/// Like [`post_json`] but without the fixed header timeout — for a
/// long-running write whose response the daemon only sends once the work
/// completes (notably `POST /active_model`, a model switch that may stream
/// multi-GB weights first). Bounding it with [`REQUEST_TIMEOUT`] would drop
/// the connection mid-switch and cancel the daemon-side load; callers track
/// progress via the `download_progress` SSE topic instead.
///
/// # Errors
/// Returns [`HttpError::InvalidSession`] on `401`; [`HttpError::Other`] on
/// connection, HTTP, body encoding, or parse failure.
pub async fn post_json_no_timeout<T: DeserializeOwned>(
    socket_path: std::path::PathBuf,
    token: &str,
    path: &str,
    body: &serde_json::Value,
) -> HttpResult<T> {
    let req = build_post_json(path, body, Some(token))?;
    send_request_with_timeout::<T>(&socket_path, req, None).await
}

/// `GET <path>` deserialized into `T`.
///
/// # Errors
/// Returns [`HttpError::InvalidSession`] on `401`; [`HttpError::Other`] on
/// connection, HTTP, or parse failure.
pub async fn get_json<T: DeserializeOwned>(
    socket_path: std::path::PathBuf,
    token: &str,
    path: &str,
) -> HttpResult<T> {
    let req = build_get(path, Some(token))?;
    send_request::<T>(&socket_path, req).await
}

/// `POST <path>` with a JSON body, deserialized into `T`.
///
/// # Errors
/// Returns [`HttpError::InvalidSession`] on `401`; [`HttpError::Other`] on
/// connection, HTTP, body encoding, or parse failure.
pub async fn post_json<T: DeserializeOwned>(
    socket_path: std::path::PathBuf,
    token: &str,
    path: &str,
    body: &serde_json::Value,
) -> HttpResult<T> {
    let req = build_post_json(path, body, Some(token))?;
    send_request::<T>(&socket_path, req).await
}

/// `POST <path>` with a raw body of `content_type`, deserialized into `T`.
///
/// For payloads that are already bytes — a recording, an image — where base64
/// inside a JSON envelope would cost a third of the size and a parser pass for
/// nothing.
///
/// # Errors
/// Returns [`HttpError::InvalidSession`] on `401`; [`HttpError::Other`] on
/// connection, HTTP, or parse failure.
pub async fn post_bytes<T: DeserializeOwned>(
    socket_path: std::path::PathBuf,
    token: &str,
    path: &str,
    content_type: &str,
    body: Vec<u8>,
) -> HttpResult<T> {
    let req = build_post_bytes(path, content_type, body, Some(token))?;
    send_request::<T>(&socket_path, req).await
}

/// `PATCH <path>` with a JSON body, deserialized into `T`.
///
/// # Errors
/// Returns [`HttpError::InvalidSession`] on `401`; [`HttpError::Other`] on
/// connection, HTTP, body encoding, or parse failure.
pub async fn patch_json<T: DeserializeOwned>(
    socket_path: std::path::PathBuf,
    token: &str,
    path: &str,
    body: &serde_json::Value,
) -> HttpResult<T> {
    let req = build_patch_json(path, body, Some(token))?;
    send_request::<T>(&socket_path, req).await
}

/// One server-sent event: the block's `event:` name, when it names one, and
/// its `data:` lines, joined with `\n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event:` field.
    pub event: Option<String>,
    /// The `data:` field.
    pub data: String,
}

/// `POST <path>` with a JSON body, read as a stream of server-sent events.
///
/// For an endpoint that holds the connection open and reports as it goes, the
/// way Super STT's `/transcribe` sends each preview and then the result. A
/// daemon that refuses the request answers with its error envelope, not a
/// stream, so a non-2xx is returned as that error like every other call.
/// Failures after the stream has started arrive as `Err` items. Blocks with
/// neither an event name nor data, which is what a keepalive comment is, are
/// skipped. Dropping the stream closes the connection.
///
/// # Errors
/// Returns [`HttpError::InvalidSession`] on `401`; [`HttpError::Other`] on
/// connection, HTTP, or body encoding failure, or any other non-2xx.
pub async fn post_json_events(
    socket_path: std::path::PathBuf,
    token: &str,
    path: &str,
    body: &serde_json::Value,
) -> HttpResult<impl futures_util::Stream<Item = HttpResult<SseEvent>> + Send + 'static> {
    let req = build_post_json(path, body, Some(token))?;
    let response = open(&socket_path, req, Some(REQUEST_TIMEOUT)).await?;
    let status = response.status();
    if !status.is_success() {
        let body = collect_body(response).await?;
        return Err(error_for_status(status, &body));
    }
    Ok(super::sse::block_stream(
        response.into_body(),
        |block| {
            let fields = super::sse::parse_fields(block);
            (fields.event.is_some() || !fields.data.is_empty()).then(|| {
                Ok(SseEvent {
                    event: fields.event.map(str::to_owned),
                    data: fields.data,
                })
            })
        },
        |message| Err(HttpError::Other(message)),
    ))
}

/// `DELETE <path>` deserialized into `T`.
///
/// # Errors
/// Returns [`HttpError::InvalidSession`] on `401`; [`HttpError::Other`] on
/// connection, HTTP, or parse failure.
pub async fn delete_json<T: DeserializeOwned>(
    socket_path: std::path::PathBuf,
    token: &str,
    path: &str,
) -> HttpResult<T> {
    let req = build_delete(path, Some(token))?;
    send_request::<T>(&socket_path, req).await
}

#[cfg(test)]
mod tests {
    use super::{daemon_error, error_for_status};
    use crate::http_client::HttpError;
    use hyper::StatusCode;

    /// A `scope_denied` 403 is typed, because it is the one 403 a caller can
    /// act on: drop the token and ask for the scopes it actually needs. Left
    /// untyped it is an `Other` string that no retry path matches, and a
    /// client holding a token minted before it grew a scope is stuck for good.
    #[test]
    fn a_scope_refusal_is_typed_so_a_caller_can_re_authenticate() {
        let body = br#"{"status":"error","message":"scope_denied"}"#;
        assert!(error_for_status(StatusCode::FORBIDDEN, body).is_scope_denied());
        // The wording the untyped path produced is preserved.
        assert_eq!(
            error_for_status(StatusCode::FORBIDDEN, body).to_string(),
            "scope_denied (HTTP 403)"
        );
    }

    /// Every other 403 stays operational. Re-authenticating would not fix one,
    /// and the consent popup a retry raises is worse than the error it hides.
    #[test]
    fn other_forbidden_responses_are_not_treated_as_scope_refusals() {
        for body in [
            br#"{"status":"error","error_code":"backend_forbidden"}"#.as_slice(),
            br#"{"status":"error","message":"not your voice"}"#.as_slice(),
            b"".as_slice(),
        ] {
            let e = error_for_status(StatusCode::FORBIDDEN, body);
            assert!(!e.is_scope_denied(), "{e} should stay operational");
            assert!(matches!(e, HttpError::Other(_)));
        }
    }

    /// A 401 keeps its own variant: the token is bad rather than narrow.
    #[test]
    fn an_unauthorized_response_is_still_an_invalid_session() {
        let body = br#"{"status":"error","message":"invalid_session","data":{"reason":"expired"}}"#;
        let e = error_for_status(StatusCode::UNAUTHORIZED, body);
        assert!(e.is_invalid_session());
        assert!(!e.is_scope_denied());
    }

    /// A non-2xx body must never reach the `T` deserializer. The daemon's
    /// error envelopes don't share a shape with the endpoint's success type,
    /// so parsing one as `T` reports whichever success field happened to be
    /// missing — burying the actual cause. This is the regression that made a
    /// rate-limited uninstall surface as
    /// ``missing field `uninstalled` at line 1 column 43``.
    #[test]
    fn non_success_status_reports_the_daemon_identifier_not_a_parse_error() {
        let e = daemon_error(
            StatusCode::TOO_MANY_REQUESTS,
            br#"{"status":"error","message":"rate_limited"}"#,
        );
        assert_eq!(e.to_string(), "rate_limited (HTTP 429)");
        assert!(
            !e.to_string().contains("missing field"),
            "the endpoint's success schema must not be blamed for a daemon error"
        );
    }

    /// The registry envelope carries the identifier in `error_code`, plus the
    /// legacy `error` spelling of the same value. One mention is enough.
    #[test]
    fn registry_envelope_uses_error_code_without_repeating_the_legacy_key() {
        let e = daemon_error(
            StatusCode::NOT_FOUND,
            br#"{"status":"error","error_code":"not_found","error":"not_found"}"#,
        );
        assert_eq!(e.to_string(), "not_found (HTTP 404)");
    }

    /// When the daemon supplies both a stable code and a human message, keep
    /// both: the code is what a maintainer greps for, the message is what tells
    /// the user *why* (e.g. the underlying io error behind `remove_failed`).
    #[test]
    fn code_and_message_are_both_preserved() {
        let e = daemon_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"status":"error","error_code":"remove_failed","error":"remove_failed","message":"Permission denied (os error 13)"}"#,
        );
        assert_eq!(
            e.to_string(),
            "remove_failed: Permission denied (os error 13) (HTTP 500)"
        );
    }

    /// `dispatch_command` answers with a `DaemonResponse` whose `message` is
    /// the human text callers used to surface via `require_success`. That text
    /// must survive the earlier status check.
    #[test]
    fn daemon_response_error_keeps_its_human_message() {
        let e = daemon_error(
            StatusCode::BAD_REQUEST,
            br#"{"status":"error","message":"Model not loaded","error_code":"model_not_loaded"}"#,
        );
        assert_eq!(
            e.to_string(),
            "model_not_loaded: Model not loaded (HTTP 400)"
        );
    }

    /// A body that isn't the expected envelope at all (empty, HTML from a
    /// stray proxy, truncated JSON) still has to name the status rather than
    /// invent a field-level complaint.
    #[test]
    fn unrecognized_body_falls_back_to_the_bare_status() {
        assert_eq!(
            daemon_error(StatusCode::BAD_GATEWAY, b"").to_string(),
            "daemon returned HTTP 502"
        );
        assert_eq!(
            daemon_error(StatusCode::FORBIDDEN, b"<html>nope</html>").to_string(),
            "daemon returned HTTP 403"
        );
        // Present-but-empty strings are as useless as absent ones.
        assert_eq!(
            daemon_error(StatusCode::CONFLICT, br#"{"status":"error","message":""}"#).to_string(),
            "daemon returned HTTP 409"
        );
    }
}
